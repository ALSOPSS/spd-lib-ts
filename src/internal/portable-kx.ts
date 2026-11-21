/**
 * Custom, dependency-free implementation of libsodium's `crypto_kx`
 * (X25519 key exchange + directional session-key derivation), replacing
 * `sodium.crypto_kx_keypair` / `crypto_kx_client_session_keys` /
 * `crypto_kx_server_session_keys` in SPDTransport.ts.
 *
 * WHY THIS EXISTS: see portable-aead.ts's header comment — same rationale
 * (libsodium lacks a single well-maintained cross-language binding; a new
 * dependency to fix that would cut against lowering total dependency
 * count). The ECDH half of this (X25519 keypair generation and shared-
 * secret computation) already has a working precedent in SPDHandshake.ts
 * via @noble/curves (already a direct dependency) — this module reuses
 * that. The other half — `crypto_kx`'s directional key derivation via
 * BLAKE2b — has no existing precedent in this codebase and is implemented
 * here from libsodium's own published C source
 * (crypto_kx/crypto_kx.c, upstream jedisct1/libsodium), using
 * @noble/hashes' blake2b (already a direct dependency).
 *
 * Algorithm (verbatim from libsodium's crypto_kx_client_session_keys /
 * crypto_kx_server_session_keys, both hash in the SAME order — the
 * direction comes from which half of the output each side calls rx vs tx,
 * not from a different hash input):
 *
 *   q = X25519(my_secret_key, their_public_key)
 *   keys[0..64) = BLAKE2b-512(q || client_pk || server_pk)
 *   client: rx = keys[0..32), tx = keys[32..64)
 *   server: tx = keys[0..32), rx = keys[32..64)
 *
 * (so client.rx === server.tx and client.tx === server.rx, as required for
 * a session cipher where each side reads what the other writes)
 *
 * Verified against real libsodium output — see
 * test/portable-kx-vectors.test.ts (random cross-checks: our client/server
 * session keys match sodium.crypto_kx_client_session_keys /
 * crypto_kx_server_session_keys byte-for-byte for the same keypairs).
 */

import { x25519 } from '@noble/curves/ed25519.js';
import { blake2b } from '@noble/hashes/blake2.js';

export const KX_PUBLICKEYBYTES = 32;
export const KX_SECRETKEYBYTES = 32;
export const KX_SESSIONKEYBYTES = 32;

export interface KxKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** Generates a fresh X25519 keypair, in the same {publicKey, privateKey} shape libsodium's crypto_kx_keypair() returns. */
export function kxKeypair(): KxKeyPair {
  const kp = x25519.keygen();
  return { publicKey: kp.publicKey, privateKey: kp.secretKey };
}

export interface KxSessionKeys {
  sharedRx: Uint8Array;
  sharedTx: Uint8Array;
}

function deriveSharedKeys(
  q: Uint8Array,
  clientPk: Uint8Array,
  serverPk: Uint8Array
): Uint8Array {
  const h = blake2b.create({ dkLen: 64 });
  h.update(q);
  h.update(clientPk);
  h.update(serverPk);
  return h.digest();
}

/**
 * Client-side session key derivation. `clientSecretKey`/`clientPublicKey`
 * are the client's own ephemeral X25519 keypair; `serverPublicKey` is the
 * server's (long-term or ephemeral) public key.
 */
export function kxClientSessionKeys(
  clientPublicKey: Uint8Array,
  clientSecretKey: Uint8Array,
  serverPublicKey: Uint8Array
): KxSessionKeys {
  const q = x25519.getSharedSecret(clientSecretKey, serverPublicKey);
  const keys = deriveSharedKeys(q, clientPublicKey, serverPublicKey);
  return {
    sharedRx: keys.subarray(0, 32),
    sharedTx: keys.subarray(32, 64),
  };
}

/**
 * Server-side session key derivation. `serverSecretKey`/`serverPublicKey`
 * are the server's own keypair; `clientPublicKey` is the client's.
 */
export function kxServerSessionKeys(
  serverPublicKey: Uint8Array,
  serverSecretKey: Uint8Array,
  clientPublicKey: Uint8Array
): KxSessionKeys {
  const q = x25519.getSharedSecret(serverSecretKey, clientPublicKey);
  const keys = deriveSharedKeys(q, clientPublicKey, serverPublicKey);
  return {
    sharedTx: keys.subarray(0, 32),
    sharedRx: keys.subarray(32, 64),
  };
}
