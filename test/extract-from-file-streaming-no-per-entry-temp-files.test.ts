/**
 * Regression test: extractFromFileStreaming() must never write PER-ENTRY
 * temp files (`<name>_enc.ssf` / `<name>_dec.ssf`).
 *
 * This method still legitimately writes ONE whole-plaintext temp file
 * (`_spd_plaintext.ssf`) — verifying the whole-file MAC before trusting
 * anything requires the complete decompressed plaintext, and holding an
 * arbitrarily large file's plaintext in RAM simultaneously is exactly what
 * this constant-memory method exists to avoid. That one disk touch is
 * genuinely load-bearing and is NOT what this test is about.
 *
 * What WAS removed: each entry's encrypted blob (`encBuf`, already a plain
 * in-memory Uint8Array read from the plaintext temp file) used to be
 * written straight back out to its own `_enc.ssf` temp file and read back
 * unchanged, and the decrypted plaintext was written to a second `_dec.ssf`
 * temp file and read back too — purely to reuse `convertStringToInput`'s
 * string-based signature, which only ever needed a string, not a file
 * path. Neither round-trip served any functional purpose, and both were a
 * real, if narrow, source of temp-file-leakage/crash-residue risk.
 *
 * Two approaches were tried and REJECTED before this one (same story as
 * extract-data-streaming-no-disk.test.ts, see that file's header for the
 * full explanation of each): a during-callback directory snapshot (fails
 * because this method's per-entry cleanup runs in a `finally` block
 * BEFORE `callback` is invoked, not after, so even the OLD code's temp
 * files are already gone by the time any callback-scoped check could see
 * them), and `vi.mock('fs', ...)` (confirmed via a standalone probe that
 * vitest's ESM mock never intercepts SPD.ts's actual filesystem calls at
 * all, since they resolve through `createRequire(import.meta.url)('fs')`,
 * not a statically-analyzable `import`).
 *
 * This file uses `fs.watch()` on `tmpDir` to observe REAL filesystem
 * events for the whole duration of the call. Genuinely verified against
 * the pre-fix implementation: this exact test correctly observed
 * `alpha_enc.ssf`/`alpha_dec.ssf`/etc. creation events before the fix was
 * restored.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SPD } from '../src/index';

const PASS = 'ExtractFromFileStreamingNoPerEntryTempTest!2024';

describe('extractFromFileStreaming — no per-entry temp files (fs.watch-based regression test)', () => {
  it('only the whole-plaintext temp file is ever created — never a per-entry _enc.ssf/_dec.ssf', async () => {
    const f = path.join(os.tmpdir(), `spd-test-${Date.now()}-${Math.random().toString(36).slice(2)}.spd`);
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'spd-test-dir-'));

    try {
      const spd = new SPD();
      spd.setKeyProfile('standard');
      await spd.setPassKey(PASS);
      await spd.addData('alpha', 'one');
      await spd.addData('beta', 'two');
      await spd.addData('gamma', 'three');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      SPD.clearKeyCache();

      const events: string[] = [];
      const watcher = fs.watch(d, (_eventType, filename) => {
        if (filename) events.push(filename);
      });

      try {
        const results: Array<[string, unknown]> = [];
        await SPD.extractFromFileStreaming(f, PASS, d, (name, value) => { results.push([name, value]); });
        expect(results).toEqual([['alpha', 'one'], ['beta', 'two'], ['gamma', 'three']]);

        await new Promise((r) => setTimeout(r, 200));
      } finally {
        watcher.close();
      }

      const perEntryEvents = events.filter((f) => /_enc\.ssf$|_dec\.ssf$/.test(f));
      expect(perEntryEvents).toEqual([]);

      // Sanity: confirm the watcher actually saw the ONE legitimate
      // whole-plaintext temp file — proves the watcher genuinely observed
      // real fs activity during the call, not that it silently saw
      // nothing at all (which would make the assertion above trivially,
      // uselessly true).
      const wholeFileEvents = events.filter((f) => f === '_spd_plaintext.ssf');
      expect(wholeFileEvents.length).toBeGreaterThan(0);
    } finally {
      try { fs.unlinkSync(f); } catch {}
      try { fs.unlinkSync(f + '.seq'); } catch {}
      fs.rmSync(d, { recursive: true, force: true });
    }
  }, 30_000);
});
