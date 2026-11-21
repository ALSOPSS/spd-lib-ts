/**
 * Portable replacement for Node's `crypto` module's hash/HMAC/random
 * primitives, used throughout SPD.ts/SPDWriter.ts/SPDTransport.ts
 * and SPDHandshake.ts. Pure JS via @noble/hashes and @noble/curves — no
 * native bindings, works identically in Node and browsers.
 *
 * Verified byte-identical to Node's crypto.createHash/createHmac output for
 * every algorithm this codebase actually uses (sha256, sha512, sha3-256,
 * sha3-512), including chained `.update()` calls, before this module was
 * introduced. `randomBytes`/`getRandomValues` both delegate to the Web
 * Crypto `globalThis.crypto.getRandomValues`, itself a Node 18+ and
 * universal-browser primitive — no import needed for that part at all.
 *
 * Deliberately mimics Node's `crypto.createHash(algo)` / `crypto.createHmac(algo, key)`
 * chainable shape (`.update(...).update(...).digest()`) so call sites that
 * used the real Node module need minimal changes — mostly just swapping the
 * import.
 *
 * Uses plain `Uint8Array` everywhere instead of Node's `Buffer` — `Buffer`
 * has no native equivalent outside Node (browsers, Deno, Workers need a
 * polyfill), so returning it from a "portable" module would silently
 * reintroduce the exact dependency this module exists to remove. Encoding
 * helpers (`bytesToHex`, `bytesToBase64`, etc.) below replace the
 * `buf.toString(encoding)` / `Buffer.from(str, encoding)` convenience Buffer
 * used to provide.
 */

import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';
import { hmac as nobleHmac } from '@noble/hashes/hmac.js';
import { scryptAsync } from '@noble/hashes/scrypt.js';
import type { CHash } from '@noble/hashes/utils.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';

export type SupportedHashAlgo = 'sha256' | 'sha512' | 'sha3-256' | 'sha3-512';

const HASHES: Record<SupportedHashAlgo, CHash> = {
  sha256,
  sha512,
  'sha3-256': sha3_256,
  'sha3-512': sha3_512,
};

function resolveHash(algo: string): CHash {
  const h = HASHES[algo as SupportedHashAlgo];
  if (!h) throw new Error(`Unsupported hash algorithm: ${algo}`);
  return h;
}

// ─── Encoding helpers (Buffer-free) ────────────────────────────────────────
//
// `bytesToHex`/`hexToBytes`/`utf8ToBytes`/`concatBytes` are re-exported
// as-is from @noble/hashes/utils.js — same trusted implementation already
// used throughout this codebase's crypto internals, no need to reimplement.
// Base64/base64url have no noble equivalent and no universal runtime
// primitive as of this codebase's Node floor (`Uint8Array.prototype.toBase64`
// landed too late — Node 22.19+/24 — to rely on against the `>=20.19.0`
// engines floor, and browser support is likewise inconsistent), so they're
// hand-rolled here and verified against RFC 4648 test vectors.
export { bytesToHex, hexToBytes, utf8ToBytes, concatBytes };

export function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

const B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function encodeBase64Generic(bytes: Uint8Array, chars: string, pad: boolean): string {
  let out = '';
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += chars[(n >> 18) & 63] + chars[(n >> 12) & 63] + chars[(n >> 6) & 63] + chars[n & 63];
  }
  const remaining = bytes.length - i;
  if (remaining === 1) {
    const n = bytes[i] << 16;
    out += chars[(n >> 18) & 63] + chars[(n >> 12) & 63] + (pad ? '==' : '');
  } else if (remaining === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += chars[(n >> 18) & 63] + chars[(n >> 12) & 63] + chars[(n >> 6) & 63] + (pad ? '=' : '');
  }
  return out;
}

function decodeBase64Generic(str: string, chars: string): Uint8Array {
  const clean = str.replace(/=+$/, '');
  const lookup = new Int16Array(128).fill(-1);
  for (let i = 0; i < chars.length; i++) lookup[chars.charCodeAt(i)] = i;
  const out = new Uint8Array(Math.floor((clean.length * 6) / 8));
  let outPos = 0;
  let bitBuf = 0;
  let bitCount = 0;
  for (let i = 0; i < clean.length; i++) {
    const code = clean.charCodeAt(i);
    const val = code < 128 ? lookup[code] : -1;
    if (val < 0) throw new Error(`Invalid base64 character: ${clean[i]}`);
    bitBuf = (bitBuf << 6) | val;
    bitCount += 6;
    if (bitCount >= 8) {
      bitCount -= 8;
      out[outPos++] = (bitBuf >> bitCount) & 0xff;
    }
  }
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  return encodeBase64Generic(bytes, B64_CHARS, true);
}

export function base64ToBytes(str: string): Uint8Array {
  return decodeBase64Generic(str, B64_CHARS);
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return encodeBase64Generic(bytes, B64URL_CHARS, false);
}

export function base64UrlToBytes(str: string): Uint8Array {
  return decodeBase64Generic(str, B64URL_CHARS);
}

export class PortableHash {
  private inner: ReturnType<CHash['create']>;
  constructor(algo: string) {
    this.inner = resolveHash(algo).create();
  }
  update(data: Uint8Array | string): this {
    this.inner.update(typeof data === 'string' ? utf8ToBytes(data) : data);
    return this;
  }
  digest(): Uint8Array;
  digest(encoding: 'hex'): string;
  digest(encoding?: 'hex'): Uint8Array | string {
    const out = this.inner.digest();
    return encoding === 'hex' ? bytesToHex(out) : out;
  }
}

export class PortableHmac {
  private inner: ReturnType<typeof nobleHmac.create>;
  constructor(algo: string, key: Uint8Array | string) {
    const keyBytes = typeof key === 'string' ? utf8ToBytes(key) : key;
    this.inner = nobleHmac.create(resolveHash(algo), keyBytes);
  }
  update(data: Uint8Array | string): this {
    this.inner.update(typeof data === 'string' ? utf8ToBytes(data) : data);
    return this;
  }
  digest(): Uint8Array;
  digest(encoding: 'hex'): string;
  digest(encoding?: 'hex'): Uint8Array | string {
    const out = this.inner.digest();
    return encoding === 'hex' ? bytesToHex(out) : out;
  }
}

export function createHash(algo: string): PortableHash {
  return new PortableHash(algo);
}

export function createHmac(algo: string, key: Uint8Array | string): PortableHmac {
  return new PortableHmac(algo, key);
}

export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// Web Crypto's getRandomValues() caps a single call at 65536 bytes (a spec
// requirement enforced identically by Node and browsers) — crypto.randomBytes()
// has no such limit, so callers requesting more than that need chunking.
// Found via a real test failure (SPD.benchmark() requests 1 MiB) — do not
// remove this chunking loop as unnecessary complexity.
const GET_RANDOM_VALUES_MAX_BYTES = 65536;

export function randomBytes(len: number): Uint8Array {
  const buf = new Uint8Array(len);
  for (let offset = 0; offset < len; offset += GET_RANDOM_VALUES_MAX_BYTES) {
    const end = Math.min(offset + GET_RANDOM_VALUES_MAX_BYTES, len);
    globalThis.crypto.getRandomValues(buf.subarray(offset, end) as Uint8Array<ArrayBuffer>);
  }
  return buf;
}

type TypedArray = Uint8Array | Uint16Array | Uint32Array | Int8Array | Int16Array | Int32Array;

export function getRandomValues<T extends TypedArray>(buf: T): T {
  // getRandomValues rejects a SharedArrayBuffer-backed view at the Web
  // Crypto spec level (both Node and browsers) — this cast otherwise
  // suppresses that as a compile-time caller error, so the runtime error a
  // caller would hit ("...SharedArrayBuffer...") reads as unrelated to the
  // actual mistake. No call site in this codebase passes one today, but
  // fail with a clear message instead of a cryptic one if that ever
  // changes.
  //
  // `typeof SharedArrayBuffer !== 'undefined'` guard is load-bearing, not
  // decorative: most browsers remove the SharedArrayBuffer global entirely
  // unless the page is served with COOP/COEP cross-origin-isolation headers
  // (the vast majority of ordinary websites don't set these) — referencing
  // the bare identifier there throws ReferenceError before this check can
  // even run, crashing every setPassKey()/getRandomValues() call. Found via
  // a real headless-Chrome test with no isolation headers set (confirmed
  // this is genuinely the common case, not an edge case).
  if (typeof SharedArrayBuffer !== 'undefined' && buf.buffer instanceof SharedArrayBuffer) {
    throw new Error('getRandomValues: buffer must not be backed by a SharedArrayBuffer');
  }
  const elemsPerChunk = Math.floor(GET_RANDOM_VALUES_MAX_BYTES / buf.BYTES_PER_ELEMENT);
  for (let offset = 0; offset < buf.length; offset += elemsPerChunk) {
    const end = Math.min(offset + elemsPerChunk, buf.length);
    globalThis.crypto.getRandomValues(buf.subarray(offset, end) as Uint8Array<ArrayBuffer>);
  }
  return buf;
}

/**
 * Portable scrypt (RFC 7914) via @noble/hashes — verified byte-identical to
 * Node's crypto.scrypt for the same (password, salt, N, r, p, dkLen).
 * `maxmem` is accepted for call-site compatibility but @noble/hashes uses
 * its own default cap; pass the same N/r/p this codebase already uses and
 * it works within noble's default 1GiB+1KiB limit.
 */
export interface ScryptOpts {
  N: number;
  r: number;
  p: number;
  maxmem?: number;
}

export async function scrypt(
  password: Uint8Array,
  salt: Uint8Array,
  keylen: number,
  opts: ScryptOpts
): Promise<Uint8Array> {
  return scryptAsync(password, salt, {
    N: opts.N,
    r: opts.r,
    p: opts.p,
    dkLen: keylen,
    maxmem: opts.maxmem,
  });
}

export function randomInt(min: number, max: number): number {
  const range = max - min;
  if (range <= 0) throw new Error('randomInt: max must be greater than min');
  const bytesNeeded = Math.ceil(Math.log2(range) / 8) || 1;
  const maxValid = Math.floor(256 ** bytesNeeded / range) * range;
  const buf = new Uint8Array(bytesNeeded);
  let value: number;
  do {
    globalThis.crypto.getRandomValues(buf);
    value = buf.reduce((acc, b) => acc * 256 + b, 0);
  } while (value >= maxValid);
  return min + (value % range);
}
