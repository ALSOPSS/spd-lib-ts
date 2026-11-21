/**
 * Browser / Deno / Bun zlib: the platform's native `CompressionStream` /
 * `DecompressionStream` with format `'deflate'`, which is the RFC 1950
 * zlib-wrapped stream (`78 9c` prefix) — byte-compatible with Node's
 * `zlib.deflateSync` / `inflateSync` used by the Node build, so `.spd` data
 * written by either side is readable by the other (test/portable-zlib.test.ts
 * checks both directions against real Node zlib).
 *
 * Swapped in for `internal/portable-zlib.ts` at build time by tsup.config.ts
 * for the browser build only. This replaced the `fflate` dependency: native
 * codecs are faster, carry no third-party code, and the API is available in
 * every evergreen browser (Safari ≥ 16.4), Node ≥ 18, Deno and Bun.
 *
 * Native compression is async-only, so the shared code paths in SPD.ts use
 * the async `inflate()` / `deflate()`; the Node module provides the same
 * async functions over its sync codec. The compression `level` cannot be set
 * through CompressionStream — the platform default is used here.
 */

export interface InflateSyncOptions { maxOutputLength?: number }

async function pump(stream: ReadableStream<Uint8Array>, max?: number): Promise<Uint8Array> {
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.length;
      // Decompression-bomb guard: abort as soon as the running total exceeds the
      // cap, before the whole output is materialised.
      if (max !== undefined && total > max) {
        await reader.cancel();
        throw new RangeError(`inflate: output exceeds maxOutputLength (${max} bytes)`);
      }
      parts.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const out = new Uint8Array(total);
  let pos = 0;
  for (const p of parts) { out.set(p, pos); pos += p.length; }
  return out;
}

function run(data: Uint8Array, ts: { readable: ReadableStream<Uint8Array>; writable: WritableStream<BufferSource> }, max?: number): Promise<Uint8Array> {
  const writer = ts.writable.getWriter();
  // Write and close concurrently with reading; a failed write surfaces through the read side.
  void writer.write(data as Uint8Array<ArrayBuffer>).then(() => writer.close()).catch(() => { /* reported by pump() */ });
  return pump(ts.readable, max);
}

export function deflate(data: Uint8Array, _opts?: { level?: number }): Promise<Uint8Array> {
  return run(data, new CompressionStream('deflate'));
}

export async function inflate(data: Uint8Array, opts?: InflateSyncOptions): Promise<Uint8Array> {
  try {
    return await run(data, new DecompressionStream('deflate'), opts?.maxOutputLength);
  } catch (e) {
    if (e instanceof RangeError) throw e;
    throw new Error('inflate: invalid or corrupt zlib data');
  }
}

// ─── Node-only surface, present so Node-only modules bundled into the browser
// build (SPDWriter, streaming file paths) still resolve their imports. Every
// path that reaches these has already thrown "requires Node.js" from the
// node-platform stub; they throw the same if ever called directly.

const NODE_ONLY = 'zlib: synchronous/streaming compression requires Node.js — the browser build uses the async inflate()/deflate()';
export function deflateSync(_data: Uint8Array, _opts?: { level?: number }): Uint8Array { throw new Error(NODE_ONLY); }
export function inflateSync(_data: Uint8Array, _opts?: InflateSyncOptions): Uint8Array { throw new Error(NODE_ONLY); }
export function createDeflate(_opts?: { level?: number }): never { throw new Error(NODE_ONLY); }
export function createInflate(): never { throw new Error(NODE_ONLY); }
