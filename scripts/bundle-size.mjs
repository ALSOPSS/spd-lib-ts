/**
 * Measures what a consumer's bundler would ship from `spd-lib/browser`:
 * an SPD-only import and the full browser entry, minified, with the
 * package's runtime dependencies kept external (the bundler adds them).
 * Prints both sizes; `--check` fails if either exceeds its budget.
 */
import { build } from 'esbuild';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BUDGET_KB = { spdOnly: 160, full: 200 };
const external = ['@noble/*', 'hash-wasm'];

async function size(contents) {
  const r = await build({
    stdin: { contents, resolveDir: root, loader: 'js' },
    bundle: true, minify: true, format: 'esm', platform: 'browser',
    write: false, external, logLevel: 'silent',
  });
  return r.outputFiles[0].contents.byteLength / 1024;
}

const spdOnly = await size(`export { SPD } from './dist/browser.js';`);
const full    = await size(`export * from './dist/browser.js';`);
console.log(`spd-lib/browser, minified, @noble/* + hash-wasm external:`);
console.log(`  SPD only   : ${spdOnly.toFixed(0)} KB (budget ${BUDGET_KB.spdOnly})`);
console.log(`  full entry : ${full.toFixed(0)} KB (budget ${BUDGET_KB.full})`);
if (process.argv.includes('--check') && (spdOnly > BUDGET_KB.spdOnly || full > BUDGET_KB.full)) {
  console.error('bundle-size: budget exceeded');
  process.exit(1);
}
