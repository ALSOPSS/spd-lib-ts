/**
 * Node-native `zlib` — the default `internal/portable-zlib.js` every shared
 * and Node-only file imports. Swapped for `internal/portable-zlib.browser.ts`
 * (native CompressionStream/DecompressionStream) at build time by
 * `tsup.config.ts`'s `portableZlibBrowserRedirect` esbuild plugin, for the
 * browser build ONLY — the same mechanism already used to redirect
 * `internal/node-platform.js` to its browser stub. Shared code (SPD.ts) uses
 * the async `inflate()`/`deflate()`; Node-only code may use the sync forms.
 *
 * Byte-format compatibility between the two backends is exact (RFC 1950
 * zlib-wrapped stream, `78 9c` prefix) — see test/portable-zlib.test.ts.
 */
import { deflateSync, inflateSync as nodeInflateSync, createDeflate, createInflate } from 'zlib';
export { deflateSync, createDeflate, createInflate };

export interface InflateSyncOptions { maxOutputLength?: number }

/**
 * `maxOutputLength` caps the decompressed size (throws RangeError when exceeded) — the decompression-bomb guard for whole-file inflates.
 *
 * Node's inflate stops at the zlib stream end and silently ignores anything
 * after it; the browser's DecompressionStream rejects such trailing junk. Check
 * the consumed length so both builds accept exactly the same byte strings.
 */
export function inflateSync(data: Uint8Array, opts?: InflateSyncOptions): Uint8Array {
  const { buffer, engine } = nodeInflateSync(data, { ...opts, info: true }) as unknown as
    { buffer: Uint8Array; engine: { bytesWritten: number } };
  if (engine.bytesWritten !== data.length) {
    throw new Error('inflate: trailing data after the end of the compressed stream');
  }
  return buffer;
}

/** Async forms shared with the browser build (which only has the async CompressionStream API). Node runs the sync codec underneath. */
export async function inflate(data: Uint8Array, opts?: InflateSyncOptions): Promise<Uint8Array> {
  return inflateSync(data, opts);
}
export async function deflate(data: Uint8Array, opts?: { level?: number }): Promise<Uint8Array> {
  return deflateSync(data, opts);
}
