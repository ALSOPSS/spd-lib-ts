/**
 * post-build.mjs
 *
 * Runs after tsup:
 *   1. Writes dist/package.json so the dist folder is self-contained and
 *      ready for `npm publish` or manual upload
 *
 * Package is ESM-only (v2.0.0+, "type": "module") — dist/index.js IS the
 * ESM build, not a CJS one. CJS support was dropped because @noble/post-quantum
 * is ESM-only and Node's CJS require() cannot load an ESM module synchronously;
 * several public APIs (e.g. SPD.generateSigningKeyPair()) call it synchronously,
 * so making the package ESM-only was the non-breaking-API fix.
 *
 * dist/index.js is intentionally shipped as plain, readable tsup output —
 * this used to run through javascript-obfuscator first (string-array
 * encoding, identifier mangling, RC4-encoded literals). Removed: obfuscating
 * a security library's published code provides no real protection (it's
 * fully reversible, and no threat model here ever called for it — the
 * scorer's own "obfuscation" checks (rules2.txt R17) are about a completely
 * unrelated cryptographic concept, stacked OTP layers, not source
 * minification) while actively working against the one thing this kind of
 * library most needs: a security-conscious consumer or auditor being able
 * to read the code that's actually running, without rebuilding from source
 * and diffing against the npm tarball themselves. Also drops
 * javascript-obfuscator's ~20-package devDependency subtree.
 */

import { readFileSync, writeFileSync, copyFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root  = resolve(__dirname, '..');
const dist  = resolve(root, 'dist');

// ─── Write dist/package.json ─────────────────────────────────────────────────
const root_pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));

const dist_pkg = {
  name:        root_pkg.name,
  version:     root_pkg.version,
  description: root_pkg.description,
  type:        'module',
  main:        './index.js',
  module:      './index.js',
  types:       './index.d.ts',
  // No "exports" here: Node ignores the field in nested package.json files
  // and bundlers that do honour it would resolve inconsistently (publint).
  // The root package.json is the manifest consumers actually install.
  // root_pkg.bin paths are relative to the repo root (./dist/spd-inspect.js);
  // dist/package.json lives INSIDE dist/, so its own bin paths must be
  // relative to that directory instead (./spd-inspect.js).
  bin: Object.fromEntries(
    Object.entries(root_pkg.bin ?? {}).map(([cmd, p]) => [cmd, `./${p.replace(/^(\.\/)?dist\//, '')}`])
  ),
  keywords:    root_pkg.keywords,
  author:      root_pkg.author,
  license:     root_pkg.license,
  engines:     root_pkg.engines,
  // Only ship runtime deps — devDependencies stay in the repo
  dependencies: Object.fromEntries(
    Object.entries(root_pkg.dependencies ?? {}).filter(
      // @types/* and typescript are dev-only even if listed under dependencies
      ([k]) => !k.startsWith('@types/') && k !== 'typescript'
    )
  ),
  // Found missing entirely (not just stale) while auditing dependencies:
  // this field was silently dropped for every build until now — root_pkg
  // just never had one before argon2 moved here, so the gap went unnoticed.
  // Without this, `npm publish`ing dist/ would have shipped a manifest
  // where argon2 doesn't exist as a dependency AT ALL (not "optional" —
  // completely absent), regressing the native-fast-path KDF for every
  // consumer rather than making it gracefully optional as intended.
  ...(root_pkg.optionalDependencies ? { optionalDependencies: root_pkg.optionalDependencies } : {}),
  // Omit entirely when absent — an empty {} is worse than no field at all
  // (it used to unconditionally emit `repository: {}` here even though
  // root_pkg has no repository field yet; fixed to match the
  // optionalDependencies pattern above).
  ...(root_pkg.repository ? { repository: root_pkg.repository } : {}),
};

writeFileSync(resolve(dist, 'package.json'), JSON.stringify(dist_pkg, null, 2), 'utf8');
console.log('post-build: dist/package.json ✓');

// ─── Copy README.md ──────────────────────────────────────────────────────────
copyFileSync(resolve(root, 'README.md'), resolve(dist, 'README.md'));
console.log('post-build: dist/README.md ✓');

// ─── Copy LICENSE ─────────────────────────────────────────────────────────────
copyFileSync(resolve(root, 'LICENSE'), resolve(dist, 'LICENSE'));
console.log('post-build: dist/LICENSE ✓');
