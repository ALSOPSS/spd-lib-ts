/**
 * Verification for src/internal/portable-kx.ts — the custom X25519 +
 * BLAKE2b-based `crypto_kx` replacement for libsodium's
 * crypto_kx_keypair/crypto_kx_client_session_keys/crypto_kx_server_session_keys.
 *
 * libsodium's crypto_kx has no published official test vectors (unlike
 * ChaCha20/Poly1305's RFC 8439), so this is verified by direct cross-check
 * against libsodium-wrappers' own WASM-compiled implementation — the actual
 * reference this replaces — using random keypairs and confirming
 * byte-identical output, plus the fundamental directional property
 * (client.rx === server.tx, client.tx === server.rx) that makes a
 * client/server session cipher work at all.
 */
import { describe, it, expect } from 'vitest';
import sodium from 'libsodium-wrappers';
import { kxKeypair, kxClientSessionKeys, kxServerSessionKeys } from '../src/internal/portable-kx.js';

describe('portable-kx: keypair generation', () => {
  it('produces a public key libsodium agrees is the correct X25519 scalarmult_base of the private key', async () => {
    await sodium.ready;
    for (let i = 0; i < 20; i++) {
      const kp = kxKeypair();
      const sodiumDerivedPub = sodium.crypto_scalarmult_base(kp.privateKey);
      expect(Buffer.from(sodiumDerivedPub).toString('hex')).toBe(Buffer.from(kp.publicKey).toString('hex'));
    }
  });
});

describe('portable-kx: session key derivation matches libsodium', () => {
  it('matches sodium.crypto_kx_client_session_keys / crypto_kx_server_session_keys byte-for-byte, both directions', async () => {
    await sodium.ready;
    for (let i = 0; i < 30; i++) {
      const client = kxKeypair();
      const server = kxKeypair();

      const ourClientKeys = kxClientSessionKeys(client.publicKey, client.privateKey, server.publicKey);
      const ourServerKeys = kxServerSessionKeys(server.publicKey, server.privateKey, client.publicKey);

      const sodiumClientKeys = sodium.crypto_kx_client_session_keys(client.publicKey, client.privateKey, server.publicKey);
      const sodiumServerKeys = sodium.crypto_kx_server_session_keys(server.publicKey, server.privateKey, client.publicKey);

      expect(Buffer.from(ourClientKeys.sharedRx).toString('hex')).toBe(Buffer.from(sodiumClientKeys.sharedRx).toString('hex'));
      expect(Buffer.from(ourClientKeys.sharedTx).toString('hex')).toBe(Buffer.from(sodiumClientKeys.sharedTx).toString('hex'));
      expect(Buffer.from(ourServerKeys.sharedRx).toString('hex')).toBe(Buffer.from(sodiumServerKeys.sharedRx).toString('hex'));
      expect(Buffer.from(ourServerKeys.sharedTx).toString('hex')).toBe(Buffer.from(sodiumServerKeys.sharedTx).toString('hex'));
    }
  });

  it('satisfies the directional property: client.rx === server.tx and client.tx === server.rx', () => {
    for (let i = 0; i < 30; i++) {
      const client = kxKeypair();
      const server = kxKeypair();

      const clientKeys = kxClientSessionKeys(client.publicKey, client.privateKey, server.publicKey);
      const serverKeys = kxServerSessionKeys(server.publicKey, server.privateKey, client.publicKey);

      expect(Buffer.from(clientKeys.sharedRx).toString('hex')).toBe(Buffer.from(serverKeys.sharedTx).toString('hex'));
      expect(Buffer.from(clientKeys.sharedTx).toString('hex')).toBe(Buffer.from(serverKeys.sharedRx).toString('hex'));
    }
  });
});
