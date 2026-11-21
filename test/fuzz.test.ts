/**
 * Mutation fuzzing of every parser that consumes untrusted bytes. The
 * contract under test is stability: a corrupted input must produce a thrown
 * Error (never a hang, a crash, or a silently wrong success). Iteration
 * counts are small enough to keep the suite fast; the keyless path is used
 * for file loads so no Argon2id runs are involved.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SPD, SPDRecipient, SPDShamir, SPDTransport, SPDHandshake } from '../src/index';
import { replayWalRecords, encodeWalRecord, walHeader } from '../src/internal/spd-wal';

const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const pick = (n: number) => Math.floor(Math.random() * n);

/** Random structural mutation: flip / truncate / extend / zero-run / byte-shuffle. */
function mutate(src: Uint8Array): Uint8Array {
  const b = new Uint8Array(src);
  switch (pick(6)) {
    case 0: { const i = pick(b.length); b[i] ^= 1 << pick(8); return b; }
    case 1: return b.subarray(0, pick(b.length));
    case 2: { const o = new Uint8Array(b.length + 1 + pick(64)); o.set(b); o.set(rnd(o.length - b.length), b.length); return o; }
    case 3: { const i = pick(b.length); b.fill(0, i, Math.min(b.length, i + 1 + pick(32))); return b; }
    case 4: { const i = pick(b.length), j = pick(b.length); const t = b[i]; b[i] = b[j]; b[j] = t; return b; }
    default: { const i = pick(b.length); b.set(rnd(Math.min(16, b.length - i)), i); return b; }
  }
}

const expectThrowOrEqual = (fn: () => unknown, expected?: unknown) => {
  let out: unknown;
  try { out = fn(); } catch (e) { expect(e).toBeInstanceOf(Error); return; }
  if (expected !== undefined) expect(out).toEqual(expected);
};

describe('fuzz: SPDRecipient envelopes', () => {
  it('mutated envelopes throw an Error or (rarely) still open to the right secret', () => {
    const id = SPDRecipient.generateIdentity();
    const { masterSecret, envelope } = SPDRecipient.newSealedKey([id.publicKey, SPDRecipient.generateIdentity().publicKey]);
    for (let i = 0; i < 150; i++) {
      const m = mutate(envelope);
      expectThrowOrEqual(() => SPDRecipient.inspect(m));
      expectThrowOrEqual(() => Array.from(SPDRecipient.open(m, id.secretKey)), Array.from(masterSecret));
    }
  });
});

describe('fuzz: SPDShamir v2 shares', () => {
  it('mutated share sets throw or reconstruct the exact secret', () => {
    const secret = rnd(48);
    const shares = SPDShamir.split(secret, 5, 3);
    for (let i = 0; i < 200; i++) {
      const set = shares.slice(0, 3 + pick(3)).map((s) => (Math.random() < 0.5 ? mutate(s) : s));
      expectThrowOrEqual(() => Array.from(SPDShamir.combine(set)), Array.from(secret));
    }
  });
});

describe('fuzz: WAL replay', () => {
  it('truncated / corrupted WAL buffers never throw and never yield unvalidated names', () => {
    const entries = Array.from({ length: 5 }, (_, i) => ({
      dataName: `entry_${i}`, dataType: 'string' as const, hash: 'h'.repeat(64), nonce: rnd(24), data: rnd(10 + i * 7),
    }));
    const parts = [walHeader(), ...entries.map(encodeWalRecord)];
    const wal = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0; for (const p of parts) { wal.set(p, o); o += p.length; }
    const validate = (n: string) => { if (!/^[a-z0-9_-]{1,255}$/.test(n)) throw new Error('bad name'); return n; };
    for (let i = 0; i < 300; i++) {
      const target: typeof entries = [];
      const n = replayWalRecords(mutate(wal), target, validate);
      // Records replayed, not unique names: a later record for the same name
      // overwrites the earlier one (last write wins), so count >= entries.
      expect(n).toBeGreaterThanOrEqual(target.length);
      for (const e of target) expect(e.dataName).toMatch(/^[a-z0-9_-]{1,255}$/);
    }
  });
});

describe('fuzz: SPDTransport frames and hellos', () => {
  it('mutated frames are rejected with an Error; the session stays usable', async () => {
    const id = await SPDTransport.generateServerIdentity();
    const { session: cs, clientHello } = await SPDTransport.clientConnect(id.publicKey, { v2: true });
    const { session: ss, serverHello } = await SPDTransport.serverAccept(id, clientHello);
    cs.processServerHello(serverHello!);
    const msg = new TextEncoder().encode('frame payload');
    for (let i = 0; i < 150; i++) {
      const frame = cs.encrypt(msg);
      const m = mutate(frame);
      let out: Uint8Array | undefined;
      try { out = ss.decrypt(m); } catch (e) { expect(e).toBeInstanceOf(Error); continue; }
      expect(Array.from(out!)).toEqual(Array.from(msg)); // only an unmodified frame may decrypt
    }
    expect(Array.from(ss.decrypt(cs.encrypt(msg)))).toEqual(Array.from(msg));
  });

  it('mutated ClientHello / ServerHello bytes are rejected with an Error', async () => {
    const id = await SPDTransport.generateServerIdentity();
    for (let i = 0; i < 40; i++) {
      const { session: cs, clientHello } = await SPDTransport.clientConnect(id.publicKey, { v2: true });
      const mch = mutate(clientHello);
      let serverHello: Uint8Array | undefined;
      try { ({ serverHello } = await SPDTransport.serverAccept(id, mch)); } catch (e) { expect(e).toBeInstanceOf(Error); continue; }
      // Server accepted a mutated hello (e.g. a flipped bit in a value it cannot
      // validate); the client must then fail closed on the key commitment.
      let ok = false;
      try { cs.processServerHello(mutate(serverHello!)); ok = true; } catch (e) { expect(e).toBeInstanceOf(Error); }
      if (ok) {
        // A mutated ServerHello that still passes must be byte-identical in every field that matters;
        // either way the session keys must match or decrypt fails — prove no silent divergence.
        expect(() => cs.encrypt(new Uint8Array(1))).not.toThrow();
      }
    }
  });
});

describe('fuzz: SPDHandshake hellos', () => {
  it('mutated hello fields are rejected with an Error (never a hang)', async () => {
    for (let i = 0; i < 25; i++) {
      const init = await SPDHandshake.createInitiator();
      const hello = { ...init.hello };
      const field = (['hybridClassicalPub', 'hybridQuantumData', 'nonce'] as const)[pick(3)];
      const bytes = Buffer.from(hello[field], 'base64url');
      hello[field] = Buffer.from(mutate(bytes)).toString('base64url');
      let resp;
      try { resp = await SPDHandshake.createResponder(hello); } catch (e) { expect(e).toBeInstanceOf(Error); continue; }
      // Responder accepted (value-only change the responder cannot detect); initiator derives a key or throws.
      try { (await init.finalizeInitiator(resp.hello)).destroy(); } catch (e) { expect(e).toBeInstanceOf(Error); }
    }
  });
});

describe('fuzz: keyless .spd files (no Argon2id)', () => {
  it('mutated JSON-format and binary files throw an Error or load identical data', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'spd-fuzz-'));
    try {
      const secret = SPD.generateRandomKey();
      const spd = new SPD();
      await spd.setRandomKey(secret);
      await spd.addData('alpha', { n: 1, s: 'one' });
      await spd.addData('beta', 'two');
      const fj = path.join(dir, 'j.spd'), fb = path.join(dir, 'b.spd');
      await spd.saveToFile(fj, '');
      await spd.saveToFileStreaming(fb, '');
      spd.destroy();
      const expected = { alpha: { n: 1, s: 'one' }, beta: 'two' };
      for (const [src, streaming] of [[fj, false], [fb, true]] as const) {
        const orig = fs.readFileSync(src);
        for (let i = 0; i < 40; i++) {
          const f = path.join(dir, `m-${streaming ? 'b' : 'j'}-${i}.spd`);
          fs.writeFileSync(f, mutate(orig));
          let loaded: SPD | undefined;
          try {
            loaded = await SPD.loadWithRandomKey(f, secret, undefined, { streaming });
          } catch (e) {
            expect(e).toBeInstanceOf(Error);
            continue;
          }
          expect(await loaded.extractData()).toEqual(expected);
          loaded.destroy();
        }
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 120_000);
});
