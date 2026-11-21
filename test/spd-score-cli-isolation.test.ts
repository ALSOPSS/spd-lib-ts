/**
 * Regression test for a real, previously-shipped bug: importing `scoreSPD`
 * (or anything from spd-score.ts) into a bundle that also happens to be
 * that bundle's own directly-executed entry point used to incorrectly
 * auto-run the CLI scorer and call `process.exit()` — because the old
 * detection ("was this file executed directly?") compared `process.argv[1]`
 * against `__filename`, which under a `shims: true`-style bundler polyfill
 * (tsup, and others) is ONE shared value for the whole bundle, not
 * per-source-file. Any consumer whose own bundle merely imported `scoreSPD`
 * alongside unrelated entry logic would see that shared `__filename` equal
 * `process.argv[1]` whenever the bundle itself ran — incorrectly triggering
 * spd-score.ts's CLI auto-run before the consumer's own code ever executed.
 *
 * The fix was architectural (see spd-score.ts's comment where the old guard
 * used to live): `main()` is now exported but never auto-invoked from
 * spd-score.ts itself. A separate, dedicated `spd-score-cli.ts` (never
 * re-exported by any library entry point) is the only thing that calls it
 * unconditionally — so there is no bundling scenario where importing this
 * codebase's library surface can run the CLI or exit the process.
 *
 * This test verifies the fix with a REAL tsup bundle (shims: true, matching
 * this repo's actual production build config) executed as a real Node
 * subprocess — not a mock — because the bug only manifests under that exact
 * combination and a plain unit-level import test would not have caught it
 * (confirmed: this test fails against the pre-fix code, see the git history
 * / session notes for the original reproduction).
 */
import { describe, it, expect, afterAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execFileSync } from 'child_process';

const root = path.resolve(__dirname, '..');
const scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'spd-score-isolation-'));

afterAll(() => {
  try { fs.rmSync(scratchDir, { recursive: true, force: true }); } catch { /* best-effort cleanup */ }
});

describe('spd-score.ts import isolation (regression: bundled auto-run bug)', () => {
  it(
    'a bundled consumer script that only imports scoreSPD reaches its own end-of-script marker ' +
    'without the CLI scorer auto-running or calling process.exit()',
    () => {
      const entryPath = path.join(scratchDir, 'consumer-entry.mjs');
      fs.writeFileSync(
        entryPath,
        [
          `import { scoreSPD } from '${path.join(root, 'src/spd-score.ts').replace(/\\/g, '/')}';`,
          `console.log('typeof scoreSPD:', typeof scoreSPD);`,
          `console.log('REACHED_END_OF_SCRIPT');`,
        ].join('\n'),
        'utf8'
      );

      const bundledDir = path.join(scratchDir, 'bundled');
      // Real tsup bundle with shims:true — matches this repo's actual
      // production build config (see tsup.config.ts) and is exactly the
      // configuration under which the original bug reproduced.
      execFileSync(
        path.join(root, 'node_modules/.bin/tsup'),
        [entryPath, '--format', 'esm', '--shims', '--out-dir', bundledDir, '--silent'],
        { cwd: root }
      );

      const bundledJs = path.join(bundledDir, 'consumer-entry.js');
      const bundledMjs = path.join(bundledDir, 'consumer-entry.mjs');
      fs.copyFileSync(bundledJs, bundledMjs); // force ESM regardless of any package.json nearby

      const output = execFileSync(process.execPath, [bundledMjs], { encoding: 'utf8' });

      expect(output).toContain('typeof scoreSPD: function');
      expect(output).toContain('REACHED_END_OF_SCRIPT');
      // The CLI report header would appear in output if the bug regressed.
      expect(output).not.toMatch(/SPD SECURITY SCORE REPORT/);
    },
    30_000 // real bundling + subprocess execution — generous but bounded timeout
  );
});
