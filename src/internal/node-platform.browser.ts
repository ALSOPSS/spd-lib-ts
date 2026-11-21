/**
 * Browser-safe stand-in for node-platform.ts, with the exact same exported
 * function signatures. Every accessor throws immediately instead of
 * attempting `createRequire` (which needs Node's `module` built-in — the
 * one thing that made the real node-platform.ts unresolvable by browser
 * bundlers even though the functions it exposes are never actually called
 * outside Node).
 *
 * Wired in only for the `spd-lib/browser` entry point via an esbuild
 * alias in tsup.config.ts (`./internal/node-platform.js` →
 * `./internal/node-platform.browser.js`) — the main `spd-lib` entry
 * (desktop/Node) still uses the real node-platform.ts unchanged.
 *
 * Calling any FILE-IO/WORKER method (saveToFile, loadFromFileStreaming,
 * addMany's worker-thread path, machine-binding, etc.) through the browser
 * build throws this same clear "not supported outside Node" error that the
 * real node-platform.ts throws when the built-in genuinely can't load — so
 * callers see identical, expected behavior either way, just without ever
 * attempting (and failing at bundle time) to resolve `fs`/`path`/`os`/
 * `worker_threads`/`module`.
 */

type FsModule = typeof import('fs');
type PathModule = typeof import('path');
type OsModule = typeof import('os');
type WorkerThreadsModule = typeof import('worker_threads');

function notAvailable(name: string): never {
  throw new Error(
    `'${name}' is not available in this environment — this method requires Node.js. ` +
    `You're using the spd-lib/browser entry point, which never attempts to load ` +
    `Node built-ins — use the in-memory encrypt/decrypt/addData/extractData API instead ` +
    `of file-I/O methods, or switch to the main 'spd-lib' entry in a Node environment.`
  );
}

export function getFs(): FsModule {
  notAvailable('fs');
}

export function getPath(): PathModule {
  notAvailable('path');
}

export function getOs(): OsModule {
  notAvailable('os');
}

export function getWorkerThreads(): WorkerThreadsModule {
  notAvailable('worker_threads');
}
