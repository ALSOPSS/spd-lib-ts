/**
 * SPDShamir — Shamir's Secret Sharing over GF(256).
 *
 * Splits a byte-array secret into `n` shares, any `k` of which can
 * reconstruct the original (k-of-n threshold scheme).
 *
 * ## Security properties
 *  - Information-theoretically secure: fewer than `k` shares reveal
 *    nothing about the secret.
 *  - Integrity-checked (v2 shares): `combine()` throws — instead of silently
 *    returning garbage — on too few shares, shares from different `split()`
 *    calls, or a corrupted/forged share. A 32-byte SHA3-256 tag of the secret
 *    is appended to the secret *before* splitting, so the tag is itself
 *    secret-shared and reveals nothing below the threshold.
 *  - Arithmetic is done in GF(2^8) with the irreducible polynomial
 *    x^8 + x^4 + x^3 + x + 1 (0x11b — same as AES), branch-free.
 *
 * ## Usage
 *
 * ```ts
 * import { SPDShamir } from 'spd-lib';
 *
 * const secret = new TextEncoder().encode('my 32-byte secret key material!');
 * const shares = SPDShamir.split(secret, 5, 3);   // 5 shares, 3 required
 * const rebuilt = SPDShamir.combine(shares.slice(1, 4)); // any 3
 * ```
 *
 * ## Wire format (v2, written by `split()`)
 *
 *   [0x00 marker][0x02 version][k][x][16B set id][f(x) for each payload byte]
 *
 * payload = secret ‖ SHA3-256("spd-shamir-v2" ‖ setId ‖ k ‖ secret). The
 * leading 0x00 is unambiguous: a legacy v1 share starts with its
 * x-coordinate, which is never 0.
 *
 * Legacy v1 shares (`[x][f(x)...]`, no integrity check) are still accepted by
 * `combine()`.
 *
 * Shares may be base64url-encoded for storage / transmission.
  */

import * as crypto from './internal/portable-crypto.js';
import { bytesToBase64Url, base64UrlToBytes, utf8ToBytes } from './internal/portable-crypto.js';

export type SPDShamirShare = Uint8Array;

// ─── GF(2^8) arithmetic ───────────────────────────────────────────────────────

// AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1 = 0x11b (reduction constant 0x1b)

function gfMul(a: number, b: number): number {
  // Branchless shift-and-add (Russian-peasant) multiply: no secret-dependent
  // branches or table lookups. A branchy or log/exp-table GF(256) multiply
  // leaks share/secret bytes through timing — HashiCorp Vault CVE-2023-25000
  // (cache-timing on log/exp tables); this is the same formulation Vault
  // adopted in its fix. `-(bit)` is 0 or all-ones, used as a select mask.
  let r = 0;
  for (let i = 7; i >= 0; i--) {
    r = (-((b >>> i) & 1) & a) ^ (-(r >>> 7) & 0x1b) ^ ((r << 1) & 0xff);
  }
  return r;
}

function gfAdd(a: number, b: number): number {
  return a ^ b;
}

/** GF(256) multiplicative inverse: a^(2^8 - 2) = a^254 = a^(-1), via square-and-multiply (254 = 11111110b). */
function gfInv(a: number): number {
  if (a === 0) throw new Error('GF(256): cannot invert 0');
  let r = 1;
  let base = a;
  let exp = 254;
  while (exp > 0) {
    if (exp & 1) r = gfMul(r, base);
    base = gfMul(base, base);
    exp >>= 1;
  }
  return r;
}

// ─── Polynomial evaluation / interpolation ───────────────────────────────────

/**
 * Evaluate a polynomial with given coefficients at x in GF(256).
 * coefficients[0] = constant term (= secret byte)
 */
function polyEval(coefficients: Uint8Array, x: number): number {
  let result = 0;
  let xpow   = 1;
  for (let i = 0; i < coefficients.length; i++) {
    result = gfAdd(result, gfMul(coefficients[i], xpow));
    xpow   = gfMul(xpow, x);
  }
  return result;
}

/**
 * Lagrange interpolation at x=0 to reconstruct the constant term (= secret byte).
 * `points` is an array of (x, y) pairs in GF(256).
 */
function interpolate(points: Array<[number, number]>): number {
  let secret = 0;
  for (let i = 0; i < points.length; i++) {
    const [xi, yi] = points[i];
    let num = 1;
    let den = 1;
    for (let j = 0; j < points.length; j++) {
      if (i === j) continue;
      const [xj] = points[j];
      num = gfMul(num, xj);
      den = gfMul(den, gfAdd(xi, xj));
    }
    const lagrange = gfMul(num, gfInv(den));
    secret = gfAdd(secret, gfMul(yi, lagrange));
  }
  return secret;
}

// ─── Split / recover cores ────────────────────────────────────────────────────

/** Evaluate a fresh random degree-(k-1) polynomial per payload byte at x = 1..n. Returns n rows of y-values. */
function splitBytes(payload: Uint8Array, n: number, k: number): Uint8Array[] {
  const len = payload.length;
  const rows: Uint8Array[] = Array.from({ length: n }, () => new Uint8Array(len));
  const randBuf = crypto.randomBytes((k - 1) * len);
  let randOffset = 0;
  const coeff = new Uint8Array(k);
  for (let byteIdx = 0; byteIdx < len; byteIdx++) {
    coeff[0] = payload[byteIdx];
    for (let c = 1; c < k; c++) coeff[c] = randBuf[randOffset++];
    for (let i = 0; i < n; i++) rows[i][byteIdx] = polyEval(coeff, i + 1);
  }
  coeff.fill(0);
  randBuf.fill(0);
  return rows;
}

/** Lagrange-interpolate each byte position at x = 0. `ys[i]` is read from `offset`. */
function recoverBytes(xs: number[], ys: Uint8Array[], offset: number, len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let byteIdx = 0; byteIdx < len; byteIdx++) {
    out[byteIdx] = interpolate(xs.map((x, i) => [x, ys[i][offset + byteIdx]]));
  }
  return out;
}

function assertDistinctNonzeroXs(xs: number[]): void {
  if (new Set(xs).size !== xs.length) {
    throw new Error('SPDShamir: duplicate x-coordinates in shares');
  }
  if (xs.some(x => x === 0)) {
    throw new Error('SPDShamir: x-coordinate 0 is reserved for the secret');
  }
}

// ─── v2 format ────────────────────────────────────────────────────────────────

const V2_MARKER    = 0x00;
const V2_VERSION   = 0x02;
const SET_ID_BYTES = 16;
const TAG_BYTES    = 32;
const V2_HEADER    = 4 + SET_ID_BYTES; // marker, version, k, x, set id
const TAG_LABEL    = utf8ToBytes('spd-shamir-v2');

function integrityTag(setId: Uint8Array, k: number, secret: Uint8Array): Uint8Array {
  return crypto.createHash('sha3-256')
    .update(TAG_LABEL).update(setId).update(Uint8Array.of(k)).update(secret)
    .digest();
}

function combineV2(shares: SPDShamirShare[]): Uint8Array {
  const first = shares[0];
  if (first.length < V2_HEADER + TAG_BYTES + 1) throw new Error('SPDShamir: share too short');
  if (first[1] !== V2_VERSION) throw new Error(`SPDShamir: unsupported share version ${first[1]}`);
  const k = first[2];
  const setId = first.subarray(4, V2_HEADER);
  for (const s of shares) {
    if (s.length !== first.length || s[0] !== V2_MARKER || s[1] !== V2_VERSION) {
      throw new Error('SPDShamir: all shares must have the same length and format');
    }
    if (s[2] !== k || !crypto.timingSafeEqual(s.subarray(4, V2_HEADER), setId)) {
      throw new Error('SPDShamir: shares come from different split() calls');
    }
  }
  const xs = shares.map(s => s[3]);
  assertDistinctNonzeroXs(xs);
  if (shares.length < k) {
    throw new Error(`SPDShamir: need at least ${k} shares to combine (got ${shares.length})`);
  }

  const payloadLen = first.length - V2_HEADER;
  const payload = recoverBytes(xs.slice(0, k), shares.slice(0, k), V2_HEADER, payloadLen);
  const secret = payload.slice(0, payloadLen - TAG_BYTES);
  const tag = payload.subarray(payloadLen - TAG_BYTES);
  const ok = crypto.timingSafeEqual(tag, integrityTag(setId, k, secret));
  payload.fill(0);
  if (!ok) {
    secret.fill(0);
    throw new Error('SPDShamir: integrity check failed — a share is corrupted or forged');
  }
  return secret;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export class SPDShamir {
  /**
   * Split `secret` into `n` v2 shares with threshold `k`.
   * Any `k` shares can reconstruct the secret; fewer than `k` reveal nothing.
   *
   * @param secret  The byte-array to protect (any length > 0).
   * @param n       Total number of shares to generate (2 ≤ n ≤ 255).
   * @param k       Reconstruction threshold (2 ≤ k ≤ n).
   * @returns       Array of `n` shares (see the module's wire-format notes).
   */
  static split(secret: Uint8Array, n: number, k: number): SPDShamirShare[] {
    if (n < 2 || n > 255) throw new Error('SPDShamir: n must be 2–255');
    if (k < 2 || k > n)   throw new Error('SPDShamir: k must be 2–n');
    if (secret.length === 0) throw new Error('SPDShamir: secret must not be empty');

    const setId = crypto.randomBytes(SET_ID_BYTES);
    const tag = integrityTag(setId, k, secret);
    const payload = new Uint8Array(secret.length + TAG_BYTES);
    payload.set(secret, 0);
    payload.set(tag, secret.length);
    const rows = splitBytes(payload, n, k);
    payload.fill(0);

    return rows.map((ys, i) => {
      const share = new Uint8Array(V2_HEADER + ys.length);
      share[0] = V2_MARKER;
      share[1] = V2_VERSION;
      share[2] = k;
      share[3] = i + 1;
      share.set(setId, 4);
      share.set(ys, V2_HEADER);
      ys.fill(0);
      return share;
    });
  }

  /**
   * Combine `k` (or more) shares to reconstruct the original secret.
   *
   * For v2 shares (everything `split()` writes) this throws on fewer than
   * `k` shares, shares from different `split()` calls, or any corrupted or
   * forged share — it never returns a wrong secret silently.
   *
   * Legacy v1 shares (from older versions) carry no threshold or integrity
   * data: with those, too few, mixed, or corrupted shares still silently
   * produce garbage of the expected length.
   *
   * @param shares  At least `k` shares, all from the SAME `split()` call. Order does not matter.
   */
  static combine(shares: SPDShamirShare[]): Uint8Array {
    if (shares.length < 2) throw new Error('SPDShamir: need at least 2 shares to combine');
    if (shares[0][0] === V2_MARKER) return combineV2(shares);

    // ── Legacy v1: [x][f(x)...] ──
    const len = shares[0].length - 1;
    if (len <= 0) throw new Error('SPDShamir: shares must have length > 1');
    for (const s of shares) {
      if (s.length !== shares[0].length) {
        throw new Error('SPDShamir: all shares must have the same length');
      }
    }
    const xs = shares.map(s => s[0]);
    assertDistinctNonzeroXs(xs);
    return recoverBytes(xs, shares, 1, len);
  }

  /**
   * Encode a share to a base64url string for safe storage/transmission.
   */
  static encodeShare(share: SPDShamirShare): string {
    return bytesToBase64Url(share);
  }

  /**
   * Decode a base64url-encoded share back to `Uint8Array`.
   */
  static decodeShare(encoded: string): SPDShamirShare {
    return base64UrlToBytes(encoded);
  }
}

/** @internal Exposed only for the exhaustive GF(256) test. */
export const __testing__ = { gfMul, gfInv };
