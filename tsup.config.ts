import { defineConfig } from 'tsup';
import * as path from 'path';

// Set by `npm run build`'s browser step only (SPD_BUILD_TARGET=browser
// tsup src/browser.ts ...) — every other invocation (main index.ts, web.ts,
// score.ts, the CLI tools, the worker) is unaffected. tsup's esbuildOptions
// callback only receives { format }, not which entry file is being built, so
// the branch has to happen here, in plain Node code, reading an env var set
// per-invocation in package.json's build script — not inside esbuildOptions.
const isBrowserBuild = process.env.SPD_BUILD_TARGET === 'browser';

// Redirects every import of internal/node-platform.js to
// internal/node-platform.browser.js — throwing stubs instead of the real
// one's static `import { createRequire } from 'module'`, which browser
// bundlers can't resolve at all (see that file's own header comment for the
// full story). This and the portable-zlib redirect below are the ONLY
// differences between the main and browser builds; everything else in the
// module graph (SPD.ts's crypto path, SPDTransport, SPDVault, SPDShamir,
// SPDHandshake) is identical and already portable. A plain esbuild `alias`
// can't do this — esbuild rejects alias keys that look like relative/
// absolute paths (only bare package specifiers are allowed), so a small
// onResolve plugin does the redirect instead.
const nodePlatformBrowserRedirect = {
  name: 'node-platform-browser-redirect',
  setup(build: import('esbuild').PluginBuild) {
    build.onResolve({ filter: /(^|\/)node-platform\.js$/ }, () => ({
      path: path.resolve('src/internal/node-platform.browser.ts'),
    }));
  },
};

// Redirects every import of internal/portable-zlib.js to
// internal/portable-zlib.browser.js — the native CompressionStream-backed
// implementation — for the browser build ONLY. The default
// internal/portable-zlib.js is now a thin re-export of Node's real, native
// zlib (see its own header comment): SPD.ts/SPDWriter.ts/
// spd-encrypt-worker.ts are Node-only regardless, so the default (dev/test/
// Node-build) import keeps Node's synchronous zlib codec. Only
// the browser build genuinely needs the portable implementation, since
// Node's `zlib` module doesn't exist there at all.
const portableZlibBrowserRedirect = {
  name: 'portable-zlib-browser-redirect',
  setup(build: import('esbuild').PluginBuild) {
    build.onResolve({ filter: /(^|\/)portable-zlib\.js$/ }, () => ({
      path: path.resolve('src/internal/portable-zlib.browser.ts'),
    }));
  },
};

export default defineConfig({
  // shims: true injects a build-time __dirname/__filename polyfill (derived
  // from import.meta.url) into ESM output. Needed because the package is
  // ESM-only (v2.0.0+) but src/SPD.ts uses __dirname to resolve
  // spd-encrypt-worker.js at runtime for the worker_threads addMany() path —
  // without this, that reference would throw ReferenceError in the built
  // output even though it works fine under ts-node/vitest (CJS, real __dirname).
  //
  // Disabled for the browser build specifically: the shim itself statically
  // imports Node's `path` module (and eagerly calls path.dirname() at module
  // load) to compute __dirname — but the browser build's worker_threads path
  // is never reachable at all (node-platform.browser.ts throws before
  // getWorkerThreads() could ever be called), so __dirname is genuinely dead
  // code there. Leaving shims on would still force every browser bundler to
  // resolve `path`, undoing the whole point of the node-platform redirect.
  shims: !isBrowserBuild,
  esbuildPlugins: isBrowserBuild ? [nodePlatformBrowserRedirect, portableZlibBrowserRedirect] : [],
});
