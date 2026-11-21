/**
 * Lazy, synchronous access to Node-only built-ins (`fs`, `path`, `os`,
 * `worker_threads`).
 *
 * SPD.ts's file-I/O, WAL, worker-thread, and machine-binding methods need
 * these; the large majority of SPD's methods (in-memory encrypt/decrypt,
 * addData/getData, key derivation, etc.) do not. A static top-level
 * `import * as fs from 'fs'` forces every consumer — including a browser
 * bundler that will never call those methods — to resolve a module with no
 * browser equivalent, which fails at bundle time, not just at runtime.
 *
 * These accessors defer resolution until a FILE-IO/WORKER/PLATFORM-MISC
 * method actually runs, so a bundler targeting a browser can resolve/tree-
 * shake `SPD` itself without needing an `fs` shim, as long as the calling
 * code never actually invokes a method that calls one of these accessors.
 * Calling a FILE-IO/WORKER method in an environment where the built-in
 * genuinely doesn't exist throws a clear "not supported outside Node"
 * error instead of a vague failure deep in file-handling logic.
 *
 * Uses `createRequire(import.meta.url)` — the same lazy-load pattern
 * already used for the native `argon2` addon in spd-crypto.ts — rather
 * than a bare `require(...)` call: esbuild/tsup rewrites every bare
 * `require` identifier in ESM bundle output (including inside a
 * `typeof require` check) into a shim that throws for non-literal
 * specifiers in real ESM Node. See spd-crypto.ts's header comment for the
 * full story; the same trap applies here.
 *
 * All accessors keep the existing synchronous calling convention for
 * FILE-IO methods (no async conversion, no breaking API change) — Node's
 * `require()` is itself synchronous, so this works even from ESM.
 *
 * NOTE: unlike spd-crypto.ts's native-argon2 probe, `createRequire` itself
 * IS imported statically from `module` below — a lazy/computed-specifier
 * version was tried and reverted after direct testing showed esbuild's
 * `__require` shim throws `"Dynamic require of \"module\" is not
 * supported"` in real ESM Node for ANY non-literal specifier, static or
 * runtime-computed alike (the shim's fallback fires on invocation, not on
 * bundle-time resolution, so obscuring the string doesn't help). Since
 * these accessors must stay synchronous (a deliberate constraint — FILE-IO
 * methods must not become async), the only working alternative is dynamic
 * `import('module')`, which is inherently async. The static import means a
 * pure browser bundle of the full index.ts barrel still fails to resolve
 * `module` — accepted tradeoff; real app bundlers (Vite/webpack/Rollup)
 * tree-shake unreachable FILE-IO call sites in practice, and browser
 * consumers should import an in-memory-only subset directly.
 */

import { createRequire } from 'module';

type FsModule = typeof import('fs');
type PathModule = typeof import('path');
type OsModule = typeof import('os');
type WorkerThreadsModule = typeof import('worker_threads');

let _fs: FsModule | undefined;
let _path: PathModule | undefined;
let _os: OsModule | undefined;
let _workerThreads: WorkerThreadsModule | undefined;

function nodeRequire(specifier: string): unknown {
  return createRequire(import.meta.url)(specifier);
}

function notAvailable(name: string, cause: unknown): never {
  const err = new Error(
    `'${name}' is not available in this environment — this method requires Node.js.`
  );
  (err as { cause?: unknown }).cause = cause;
  throw err;
}

export function getFs(): FsModule {
  if (!_fs) {
    try {
      _fs = nodeRequire('fs') as FsModule;
    } catch (e) {
      notAvailable('fs', e);
    }
  }
  return _fs;
}

export function getPath(): PathModule {
  if (!_path) {
    try {
      _path = nodeRequire('path') as PathModule;
    } catch (e) {
      notAvailable('path', e);
    }
  }
  return _path;
}

export function getOs(): OsModule {
  if (!_os) {
    try {
      _os = nodeRequire('os') as OsModule;
    } catch (e) {
      notAvailable('os', e);
    }
  }
  return _os;
}

export function getWorkerThreads(): WorkerThreadsModule {
  if (!_workerThreads) {
    try {
      _workerThreads = nodeRequire('worker_threads') as WorkerThreadsModule;
    } catch (e) {
      notAvailable('worker_threads', e);
    }
  }
  return _workerThreads;
}
