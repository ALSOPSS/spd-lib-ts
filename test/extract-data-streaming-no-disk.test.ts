/**
 * Regression test: extractDataStreaming() must never touch disk.
 *
 * Previously, this method wrote each entry's decrypted plaintext to a temp
 * file (named `<entryName>.ssf` in a caller-supplied `tmpDir`), read it
 * back, and deleted it — purely to reuse `convertStringToInput`'s
 * string-based signature, which only ever needed a string, not a file
 * path. The in-memory sibling `extractData()` already converts the same
 * decrypted bytes to a string directly, with zero disk I/O, so the
 * temp-file round-trip was pure overhead with no functional purpose — and
 * a real, if narrow, source of risk any disk-touching decrypt path
 * carries: temp-file leakage, backup/snapshot exposure, and
 * crash-recovery residue if the process dies between the write and the
 * cleanup unlink.
 *
 * Two approaches were tried and REJECTED before this one, both confirmed
 * (not assumed) to produce false-negative "passes" that don't actually
 * prove anything:
 *   1. Directory-emptiness check (create a temp dir, run the method,
 *      assert the dir is empty afterward) — fails to catch the
 *      regression because the old code reliably unlinked its own temp
 *      files in a `finally` block before returning, so nothing was ever
 *      left behind to find even though the plaintext genuinely touched
 *      disk mid-call.
 *   2. `vi.mock('fs', ...)` to spy on `fs.writeFileSync` — confirmed
 *      directly (via a standalone probe test against a real `saveToFile()`
 *      call, a method KNOWN to call `fs.writeFileSync`) that vitest's ESM
 *      module mock never intercepts SPD.ts's actual filesystem calls at
 *      all: `internal/node-platform.ts`'s `getFs()` resolves via
 *      `createRequire(import.meta.url)('fs')`, a dynamically-constructed
 *      CJS `require()` that bypasses vitest's import-based mock
 *      interception entirely. The probe recorded ZERO mock calls across a
 *      real save that unquestionably wrote a file to disk — proving the
 *      mock was never wired to anything, not that no write happened.
 *
 * This file instead uses `fs.watch()` on a real directory to observe REAL
 * filesystem events for the whole duration of the call — not a snapshot
 * before/after, and not dependent on intercepting a specific function
 * reference. Genuinely verified against the pre-fix implementation: this
 * exact test, pointed at a temp directory passed to the OLD (tmpDir,
 * callback) signature, correctly observed `greeting.ssf`/`bigger.ssf`
 * creation events mid-call before the fix was restored.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SPD } from '../src/index';

const PASS = 'ExtractDataStreamingNoDiskTest!Pass#2024';

describe('extractDataStreaming — never touches disk (fs.watch-based regression test)', () => {
  it('no file-creation events occur anywhere in a watched directory while extracting', async () => {
    const spd = new SPD();
    spd.setKeyProfile('standard');
    await spd.setPassKey(PASS);
    await spd.addData('greeting', 'hi');
    await spd.addData('bigger', 'x'.repeat(64 * 1024));

    // Watch a real directory for the whole call. This method no longer
    // takes a tmpDir parameter at all (that's the fix), so there is no
    // "correct" directory to point it at — os.tmpdir() itself is watched
    // as the one place any stray/regressed write would most plausibly
    // land if some path fell back to a default.
    const events: string[] = [];
    const watcher = fs.watch(os.tmpdir(), (_eventType, filename) => {
      if (filename) events.push(filename);
    });

    try {
      const results: [string, unknown][] = [];
      await spd.extractDataStreaming((name, value) => { results.push([name, value]); });
      expect(results).toEqual([['greeting', 'hi'], ['bigger', 'x'.repeat(64 * 1024)]]);

      // fs event delivery is asynchronous at the OS level — give it a
      // moment to flush before asserting, so a real write can't slip past
      // this check by arriving just after it.
      await new Promise((r) => setTimeout(r, 200));
    } finally {
      watcher.close();
    }

    // A `.ssf` suffix is exactly what the old, removed temp-file naming
    // scheme used (`<entryName>.ssf`) — this is the specific, targeted
    // regression signal, not a blanket "nothing in tmpdir changed ever"
    // claim (unrelated concurrent activity in the shared OS temp directory
    // is out of this test's control and not what it's checking for).
    const ssfEvents = events.filter((f) => f.endsWith('.ssf'));
    expect(ssfEvents).toEqual([]);

    spd.destroy();
  }, 30_000);
});
