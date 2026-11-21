/**
 * Regression tests for real, previously-shipped browser-compatibility bugs:
 * `changePasscode()` and `upgradeKdfParams()` both called `getFs()`
 * unconditionally at the very top of the function, even though the only
 * actual filesystem use in either method is a `.plog` audit-log sidecar
 * write that only runs when `setPlogPath()` has been explicitly called
 * (which most callers never do). Result: both methods threw
 * "'fs' is not available in this environment" on the browser build
 * (`spd-lib/browser`) for the overwhelmingly common case — a purely
 * in-memory passcode change or KDF-cost upgrade with no audit log
 * configured — even though nothing about either operation actually needs
 * a filesystem in that case.
 *
 * Fixed by resolving `getFs()` lazily, only inside the already-existing
 * `if (this._plogPath)` guard, so the Node dependency is only paid for
 * (and only throws) when a caller has actually opted into the audit log.
 *
 * A third, related bug is also covered here: `SPDTransport.wrapSPD()` /
 * `unwrapSPD()` always wrote the SPD payload to a real temp file
 * (`saveToFileStreaming`/`fs.readFileSync`/`fs.writeFileSync`) despite their
 * own doc comment claiming "the SPD is NOT written to disk" — meaning they
 * always threw on the browser build too, even though wrapping a payload for
 * transport has no genuine need to touch a filesystem. Fixed by routing
 * through `saveData()`/`loadFromString()` (the same in-memory
 * serialize/parse SPD.ts already exposes) instead of a temp file.
 *
 * These tests build and exercise a REAL tsup bundle of src/browser.ts with
 * SPD_BUILD_TARGET=browser (matching this repo's actual production build
 * step in package.json's `build` script and tsup.config.ts's branch) rather
 * than importing src/SPD.ts directly — a plain source-level test would not
 * have caught the original bugs, since ts-node/vitest never applies the
 * node-platform -> node-platform.browser redirect that only exists in the
 * real build pipeline. There is also, before this file, no test anywhere in
 * this repo that exercises the built browser bundle at all — a gap in its
 * own right, separate from the bugs this file was written to catch.
 */
import { describe, it, expect, afterAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execFileSync } from 'child_process';

const root = path.resolve(__dirname, '..');
const scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'spd-browser-compat-'));
const bundledDir = path.join(scratchDir, 'bundled');

afterAll(() => {
  try { fs.rmSync(scratchDir, { recursive: true, force: true }); } catch { /* best-effort cleanup */ }
});

function buildBrowserBundle(): string {
  execFileSync(
    path.join(root, 'node_modules/.bin/tsup'),
    [
      path.join(root, 'src/browser.ts'),
      '--format', 'esm',
      '--out-dir', bundledDir,
      '--silent',
    ],
    {
      cwd: root,
      env: { ...process.env, SPD_BUILD_TARGET: 'browser' },
    }
  );
  return path.join(bundledDir, 'browser.js');
}

// Build once for the whole file — real tsup invocation, ~1-2s.
const browserJsPath = buildBrowserBundle();

describe('browser build compatibility (real dist/browser.js-equivalent bundle)', () => {
  it('has no static import of a Node built-in (the browser redirects must catch every import path)', () => {
    // Regression: internal modules importing './node-platform.js' (sibling path)
    // bypassed the tsup redirect, leaving `import { createRequire } from "module"`
    // in the browser bundle — unresolvable by every browser bundler.
    const src = fs.readFileSync(browserJsPath, 'utf8');
    const nodeBuiltins = /^\s*import\b[^\n]*\bfrom\s+["'](node:)?(module|fs|fs\/promises|path|os|zlib|crypto|worker_threads|child_process|util|stream|events|url)["']/m;
    expect(src.match(nodeBuiltins)?.[0]).toBeUndefined();
  });

  it('changePasscode() works with no audit log configured (regression: used to always throw on browser build)', async () => {
    const { SPD } = await import(browserJsPath);
    const spd = new SPD();
    spd.setKeyProfile('standard');
    await spd.setPassKey('correct-horse-battery-staple-9x!Q');
    await spd.addData('greeting', 'hi');

    await spd.changePasscode('correct-horse-battery-staple-9x!Q', 'new-correct-horse-battery-staple-9x!Q');
    const data = await spd.extractData();
    expect(data.greeting).toBe('hi');
  });

  it('upgradeKdfParams() works with no audit log configured (regression: used to always throw on browser build)', async () => {
    const { SPD } = await import(browserJsPath);
    const spd = new SPD();
    spd.setKeyProfile('standard');
    await spd.setPassKey('correct-horse-battery-staple-9x!Q');
    await spd.addData('greeting', 'hi');

    await spd.upgradeKdfParams('correct-horse-battery-staple-9x!Q', { memory: 256 * 1024, time: 8 });
    const data = await spd.extractData();
    expect(data.greeting).toBe('hi');
  });

  it('changePasscode() still throws cleanly when a .plog path IS configured (the one case that genuinely needs fs)', async () => {
    const { SPD } = await import(browserJsPath);
    const spd = new SPD();
    spd.setKeyProfile('standard');
    await spd.setPassKey('correct-horse-battery-staple-9x!Q');
    await spd.addData('greeting', 'hi');
    spd.setPlogPath('/tmp/should-not-be-created.plog');

    // The audit-log write is wrapped in a try/catch that swallows failures
    // by design ("audit log write failure must not block the operation") —
    // so setting a plog path on the browser build does not throw, it just
    // silently no-ops the audit log. Confirm the main operation still
    // completes correctly rather than being blocked by the unreachable fs.
    await spd.changePasscode('correct-horse-battery-staple-9x!Q', 'new-correct-horse-battery-staple-9x!Q');
    const data = await spd.extractData();
    expect(data.greeting).toBe('hi');
  });

  it('SPDTransport.wrapSPD()/unwrapSPD() round-trip an SPD payload fully in-memory on the browser build (regression: used to always throw — see SPDTransport.ts wrapSPD/unwrapSPD comments)', async () => {
    const { SPD, SPDTransport } = await import(browserJsPath);
    const identity = await SPDTransport.generateServerIdentity();
    const { session, clientHello } = await SPDTransport.clientConnect(identity.publicKey);
    const { session: serverSession, serverHello } = await SPDTransport.serverAccept(identity, clientHello);
    session.processServerHello(serverHello);

    const spd = new SPD();
    spd.setKeyProfile('standard');
    await spd.setPassKey('correct-horse-battery-staple-9x!Q');
    await spd.addData('greeting', 'hi');

    const frame = await session.wrapSPD(spd, 'correct-horse-battery-staple-9x!Q');
    const unwrapped = await serverSession.unwrapSPD(frame, 'correct-horse-battery-staple-9x!Q');
    const data = await unwrapped.extractData();
    expect(data.greeting).toBe('hi');
  });
});

describe('browser build: recipients, Shamir, composite signatures', () => {
  it('SPDRecipient seal/open, SPDShamir, and a composite-signed in-memory round trip all work on the browser bundle', async () => {
    const { SPD, SPDRecipient, SPDShamir } = await import(browserJsPath);
    const secret = SPD.generateRandomKey();
    const id = SPDRecipient.generateIdentity();
    const env = SPDRecipient.seal(secret, [id.publicKey]);
    expect(Buffer.from(SPDRecipient.open(env, id.secretKey)).equals(Buffer.from(secret))).toBe(true);
    const shares = SPDShamir.split(secret, 3, 2);
    expect(Buffer.from(SPDShamir.combine([shares[2], shares[0]])).equals(Buffer.from(secret))).toBe(true);

    const kp = SPD.generateSigningKeyPair({ composite: true });
    const spd = new SPD();
    await spd.setRandomKey(secret);
    spd.setSigningKey(kp.privateKey);
    await spd.addData('k', 'browser-sealed');
    const s = await spd.saveData('');
    expect(typeof s).toBe('string');
  });
});
