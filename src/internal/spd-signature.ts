/**
 * File-signature primitives for SPD: ML-DSA-65 (FIPS 204), optionally
 * hedged with Ed25519 as a PQ/T composite.
 *
 * Why a composite: ML-DSA is new. If a flaw is found in it (or in an
 * implementation of it), a composite signature stays unforgeable as long as
 * Ed25519 holds, and vice versa against a quantum adversary. This follows the
 * design of draft-ietf-lamps-pq-composite-sigs (ML-DSA-65 + Ed25519 is one
 * of its registered pairs): both components sign one domain-separated message
 * representative and a verifier accepts only if BOTH verify. It is not
 * wire-compatible with the LAMPS encoding (SPD does not use X.509).
 *
 * Key and signature encodings are plain concatenations, so the existing
 * single-`Uint8Array` plumbing carries either kind; the length decides:
 *
 *   ML-DSA-65 only : pk 1952 | sk 4032 | sig 3309
 *   composite      : pk 1984 | sk 4064 | sig 3373   (ML-DSA part first)
 *
 * Non-separability: a composite verifier rejects a lone ML-DSA signature and
 * an ML-DSA-only verifier rejects a composite one — each by length, before
 * any cryptography runs — so a signature can never be "downgraded" by
 * stripping one component.
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { utf8ToBytes, concatBytes } from './portable-crypto.js';

const ML = ml_dsa65.lengths as { publicKey: number; secretKey: number; signature: number }; // 1952 / 4032 / 3309
const ED_PK = 32, ED_SK = 32, ED_SIG = 64;

export const ML_DSA65_PUBLIC_KEY_BYTES = ML.publicKey;
export const ML_DSA65_SECRET_KEY_BYTES = ML.secretKey;
export const ML_DSA65_SIGNATURE_BYTES  = ML.signature;
export const COMPOSITE_PUBLIC_KEY_BYTES = ML.publicKey + ED_PK;
export const COMPOSITE_SECRET_KEY_BYTES = ML.secretKey + ED_SK;
export const COMPOSITE_SIGNATURE_BYTES  = ML.signature + ED_SIG;

/** Domain separator: both components sign LABEL ‖ mac, never the bare MAC. */
const COMPOSITE_LABEL = utf8ToBytes('spd-file-sig-composite-mldsa65-ed25519-v1');

export type SigningKeyKind = 'ml-dsa-65' | 'composite';

export function signingKeyKind(secretKey: Uint8Array): SigningKeyKind {
  if (secretKey.length === ML.secretKey) return 'ml-dsa-65';
  if (secretKey.length === COMPOSITE_SECRET_KEY_BYTES) return 'composite';
  throw new Error(
    `Signing key must be ${ML.secretKey} bytes (ML-DSA-65) or ${COMPOSITE_SECRET_KEY_BYTES} bytes (ML-DSA-65 + Ed25519 composite); got ${secretKey.length}`
  );
}

export function verifyKeyKind(publicKey: Uint8Array): SigningKeyKind {
  if (publicKey.length === ML.publicKey) return 'ml-dsa-65';
  if (publicKey.length === COMPOSITE_PUBLIC_KEY_BYTES) return 'composite';
  throw new Error(
    `Verify key must be ${ML.publicKey} bytes (ML-DSA-65) or ${COMPOSITE_PUBLIC_KEY_BYTES} bytes (ML-DSA-65 + Ed25519 composite); got ${publicKey.length}`
  );
}

export function generateSigningKeyPair(composite = false): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const ml = ml_dsa65.keygen();
  if (!composite) return { privateKey: ml.secretKey, publicKey: ml.publicKey };
  const ed = ed25519.keygen();
  const out = { privateKey: concatBytes(ml.secretKey, ed.secretKey), publicKey: concatBytes(ml.publicKey, ed.publicKey) };
  ml.secretKey.fill(0);
  ed.secretKey.fill(0);
  return out;
}

/** Sign a file MAC. Output length identifies the kind (3309 or 3373 bytes). */
export function signFileMac(mac: Uint8Array, secretKey: Uint8Array): Uint8Array {
  if (signingKeyKind(secretKey) === 'ml-dsa-65') return ml_dsa65.sign(mac, secretKey);
  const msg = concatBytes(COMPOSITE_LABEL, mac);
  const mlSig = ml_dsa65.sign(msg, secretKey.subarray(0, ML.secretKey), { context: COMPOSITE_LABEL });
  const edSig = ed25519.sign(msg, secretKey.subarray(ML.secretKey));
  return concatBytes(mlSig, edSig);
}

/** Verify a file MAC signature. Never throws; wrong kind/length is simply `false`. */
export function verifyFileMac(signature: Uint8Array, mac: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    if (verifyKeyKind(publicKey) === 'ml-dsa-65') {
      return signature.length === ML.signature && ml_dsa65.verify(signature, mac, publicKey);
    }
    if (signature.length !== COMPOSITE_SIGNATURE_BYTES) return false;
    const msg = concatBytes(COMPOSITE_LABEL, mac);
    const mlOk = ml_dsa65.verify(signature.subarray(0, ML.signature), msg, publicKey.subarray(0, ML.publicKey), { context: COMPOSITE_LABEL });
    const edOk = ed25519.verify(signature.subarray(ML.signature), msg, publicKey.subarray(ML.publicKey));
    return mlOk && edOk; // both evaluated: no early exit on the first failure
  } catch {
    return false;
  }
}
