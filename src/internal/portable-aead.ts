/**
 * XChaCha20-Poly1305 AEAD (draft-irtf-cfrg-xchacha-03) for SPD — a thin
 * wrapper over @noble/ciphers (audited, pure JS, constant-time Poly1305,
 * works in Node, browsers, Deno, Bun and Workers).
 *
 * This module previously held a from-spec ChaCha20/Poly1305 implementation,
 * kept to avoid adding @noble/ciphers as a new dependency. That reason no
 * longer holds — @noble/post-quantum >= 0.7.1 already depends on
 * @noble/ciphers — so SPD now uses the audited implementation directly
 * rather than maintaining its own copy of security-critical cipher code.
 * The on-disk format is unchanged: both produce standard
 * AEAD_XChaCha20_Poly1305 output.
 *
 * The wrapper keeps SPD's own contract on top of noble's:
 *  - explicit key/nonce length errors,
 *  - a uniform 'authentication failed' error on any decrypt failure
 *    (no distinction between tag mismatch and malformed input).
 *
 * `__testing__` re-exposes each underlying primitive (ChaCha20 block,
 * Poly1305, HChaCha20, AEAD_CHACHA20_POLY1305) so
 * test/portable-aead-vectors.test.ts can keep checking every layer against
 * the RFC 8439 / draft-irtf-cfrg-xchacha-03 vectors and libsodium.
 */

import { chacha20, chacha20poly1305, hchacha, xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { Poly1305, poly1305 } from '@noble/ciphers/_poly1305.js';

export const XCHACHA20_POLY1305_KEY_BYTES = 32;
export const XCHACHA20_POLY1305_NONCE_BYTES = 24;
export const XCHACHA20_POLY1305_TAG_BYTES = 16;

/**
 * XChaCha20-Poly1305 AEAD encryption. `key` 32 bytes, `nonce` 24 bytes.
 * Returns ciphertext concatenated with a 16-byte tag.
 */
export function xchacha20poly1305Encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(0)
): Uint8Array {
  if (key.length !== XCHACHA20_POLY1305_KEY_BYTES) throw new Error('xchacha20poly1305: key must be 32 bytes');
  if (nonce.length !== XCHACHA20_POLY1305_NONCE_BYTES) throw new Error('xchacha20poly1305: nonce must be 24 bytes');
  return xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
}

/**
 * XChaCha20-Poly1305 AEAD decryption. Throws if the tag doesn't verify.
 */
export function xchacha20poly1305Decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertextAndTag: Uint8Array,
  aad: Uint8Array = new Uint8Array(0)
): Uint8Array {
  if (key.length !== XCHACHA20_POLY1305_KEY_BYTES) throw new Error('xchacha20poly1305: key must be 32 bytes');
  if (nonce.length !== XCHACHA20_POLY1305_NONCE_BYTES) throw new Error('xchacha20poly1305: nonce must be 24 bytes');
  try {
    return xchacha20poly1305(key, nonce, aad).decrypt(ciphertextAndTag);
  } catch {
    throw new Error('authentication failed');
  }
}

// ─── Primitive adapters exposed ONLY for the RFC-vector test suite ─────────

const SIGMA32 = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]); // "expand 32-byte k"

function u8ToU32le(b: Uint8Array): Uint32Array {
  const out = new Uint32Array(b.length / 4);
  for (let i = 0; i < out.length; i++) {
    out[i] = (b[i * 4] | (b[i * 4 + 1] << 8) | (b[i * 4 + 2] << 16) | (b[i * 4 + 3] << 24)) >>> 0;
  }
  return out;
}

function u32leToU8(w: Uint32Array): Uint8Array {
  const out = new Uint8Array(w.length * 4);
  for (let i = 0; i < w.length; i++) {
    out[i * 4] = w[i];
    out[i * 4 + 1] = w[i] >>> 8;
    out[i * 4 + 2] = w[i] >>> 16;
    out[i * 4 + 3] = w[i] >>> 24;
  }
  return out;
}

export const __testing__ = {
  /** RFC 8439 §2.3 block function: 64 bytes of keystream for (key, counter, 12-byte nonce). */
  chacha20Block: (key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array =>
    chacha20(key, nonce, new Uint8Array(64), undefined, counter),
  chacha20Xor: (key: Uint8Array, counter: number, nonce: Uint8Array, data: Uint8Array): Uint8Array =>
    chacha20(key, nonce, data, undefined, counter),
  poly1305Mac: (msg: Uint8Array, key: Uint8Array): Uint8Array => poly1305(msg, key),
  /** RFC 8439 §2.6: first 32 bytes of the counter-0 block. */
  poly1305KeyGen: (key: Uint8Array, nonce: Uint8Array): Uint8Array =>
    chacha20(key, nonce, new Uint8Array(32), undefined, 0),
  chacha20poly1305Encrypt: (key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array =>
    chacha20poly1305(key, nonce, aad).encrypt(plaintext),
  chacha20poly1305Decrypt: (key: Uint8Array, nonce: Uint8Array, ciphertextAndTag: Uint8Array, aad: Uint8Array): Uint8Array => {
    try {
      return chacha20poly1305(key, nonce, aad).decrypt(ciphertextAndTag);
    } catch {
      throw new Error('authentication failed');
    }
  },
  /** draft-irtf-cfrg-xchacha-03 §2.2: 32-byte subkey from key + 16-byte nonce input. */
  hchacha20: (key: Uint8Array, nonceInput: Uint8Array): Uint8Array => {
    const out = new Uint32Array(8);
    hchacha(SIGMA32, u8ToU32le(key), u8ToU32le(nonceInput), out);
    return u32leToU8(out);
  },
  Poly1305,
};
