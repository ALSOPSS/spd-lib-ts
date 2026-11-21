/**
 * RFC-vector verification for src/internal/portable-aead.ts — the custom
 * ChaCha20/Poly1305/XChaCha20-Poly1305 implementation that replaces
 * libsodium-wrappers' XChaCha20-Poly1305 AEAD primitive.
 *
 * Every test vector here is copied VERBATIM from the official specs:
 *   - RFC 8439 (ChaCha20 and Poly1305 for IETF Protocols) — sections
 *     2.3.2 (block function), 2.4.2 (encryption), 2.5.2 (Poly1305 MAC),
 *     2.6.2 (Poly1305 key generation), 2.8.2 (full AEAD_CHACHA20_POLY1305).
 *   - draft-irtf-cfrg-xchacha-03 (XChaCha: eXtended-nonce ChaCha and
 *     AEAD_XChaCha20_Poly1305) — Appendix A.2.1 (HChaCha20, and full
 *     XChaCha20 keystream), Appendix A.3.1 (full AEAD_XCHACHA20_POLY1305).
 *
 * This intentionally checks each primitive INDEPENDENTLY (block function,
 * Poly1305 alone, HChaCha20 alone) as well as the full composed AEAD, so a
 * bug at any one layer is caught at its own layer rather than only
 * detectable (or worse, invisible) at the top level.
 */
import { describe, it, expect } from 'vitest';
import { xchacha20poly1305Encrypt, xchacha20poly1305Decrypt, __testing__ } from '../src/internal/portable-aead.js';

function hex(s: string): Uint8Array {
  const clean = s.replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

function toHex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
}

describe('portable-aead: RFC 8439 ChaCha20 block function (§2.3.2)', () => {
  it('matches the official test vector', () => {
    const key = hex('00010203 04050607 08090a0b 0c0d0e0f 10111213 14151617 18191a1b 1c1d1e1f');
    const nonce = hex('00000009 0000004a 00000000');
    const counter = 1;
    const expected = hex(
      '10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4' +
      'c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e' +
      'd2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2' +
      'b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e'
    );
    const out = __testing__.chacha20Block(key, counter, nonce);
    expect(toHex(out)).toBe(toHex(expected));
  });
});

describe('portable-aead: RFC 8439 ChaCha20 encryption (§2.4.2)', () => {
  it('matches the official test vector', () => {
    const key = hex('00010203 04050607 08090a0b 0c0d0e0f 10111213 14151617 18191a1b 1c1d1e1f');
    const nonce = hex('00000000 0000004a 00000000');
    const plaintext = new TextEncoder().encode(
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    );
    const expected = hex(
      '6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81' +
      'e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b' +
      'f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57' +
      '16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8' +
      '07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e' +
      '52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36' +
      '5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42' +
      '87 4d'
    );
    const out = __testing__.chacha20Xor(key, 1, nonce, plaintext);
    expect(toHex(out)).toBe(toHex(expected));
  });
});

describe('portable-aead: RFC 8439 Poly1305 MAC (§2.5.2)', () => {
  it('matches the official test vector', () => {
    const key = hex('85 d6 be 78 57 55 6d 33 7f 44 52 fe 42 d5 06 a8 01 03 80 8a fb 0d b2 fd 4a bf f6 af 41 49 f5 1b');
    const msg = new TextEncoder().encode('Cryptographic Forum Research Group');
    const expected = hex('a8 06 1d c1 30 51 36 c6 c2 2b 8b af 0c 01 27 a9');
    const out = __testing__.poly1305Mac(msg, key);
    expect(toHex(out)).toBe(toHex(expected));
  });

  // The streaming Poly1305 class (introduced for the AEAD allocation
  // optimization — see chacha20poly1305Encrypt/Decrypt) must track 16-byte
  // block boundaries correctly no matter how a caller splits its update()
  // calls. Verified directly against the same RFC vector, chunked many
  // different ways, since this carry-buffer logic isn't otherwise exercised
  // by any single-call test.
  it('streaming Poly1305 class matches the RFC vector regardless of update() chunking', () => {
    const key = hex('85 d6 be 78 57 55 6d 33 7f 44 52 fe 42 d5 06 a8 01 03 80 8a fb 0d b2 fd 4a bf f6 af 41 49 f5 1b');
    const msg = new TextEncoder().encode('Cryptographic Forum Research Group'); // 34 bytes
    const expected = hex('a8 06 1d c1 30 51 36 c6 c2 2b 8b af 0c 01 27 a9');

    const chunkings: number[][] = [
      [msg.length],
      Array(msg.length).fill(1),
      [1, 15, 16, 2],
      [16, 16, 2],
      [17, 17],
      [0, msg.length],
      [5, 0, msg.length - 5],
    ];

    for (const chunking of chunkings) {
      const p = new __testing__.Poly1305(key);
      let offset = 0;
      for (const len of chunking) {
        p.update(msg.subarray(offset, offset + len));
        offset += len;
      }
      expect(offset).toBe(msg.length);
      expect(toHex(p.digest())).toBe(toHex(expected));
    }
  });

  it('streaming Poly1305 class matches poly1305Mac for random chunkings of a larger message', () => {
    const key = new Uint8Array(32);
    globalThis.crypto.getRandomValues(key);
    const msg = new Uint8Array(5000);
    globalThis.crypto.getRandomValues(msg);
    const expected = toHex(__testing__.poly1305Mac(msg, key));

    for (let trial = 0; trial < 10; trial++) {
      const p = new __testing__.Poly1305(key);
      let offset = 0;
      while (offset < msg.length) {
        const chunkLen = Math.min(msg.length - offset, 1 + Math.floor(Math.random() * 40));
        p.update(msg.subarray(offset, offset + chunkLen));
        offset += chunkLen;
      }
      expect(toHex(p.digest())).toBe(expected);
    }
  });
});

describe('portable-aead: RFC 8439 Poly1305 key generation (§2.6.2)', () => {
  it('matches the official test vector', () => {
    const key = hex('80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f');
    const nonce = hex('00 00 00 00 00 01 02 03 04 05 06 07');
    const expected = hex('8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71 a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46');
    const out = __testing__.poly1305KeyGen(key, nonce);
    expect(toHex(out)).toBe(toHex(expected));
  });
});

describe('portable-aead: RFC 8439 full AEAD_CHACHA20_POLY1305 (§2.8.2)', () => {
  it('matches the official test vector', () => {
    const key = hex('80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f');
    const nonce = hex('07 00 00 00 40 41 42 43 44 45 46 47');
    const aad = hex('50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7');
    const plaintext = new TextEncoder().encode(
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    );
    const expectedCiphertext = hex(
      'd3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2' +
      'a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6' +
      '3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b' +
      '1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36' +
      '92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58' +
      'fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc' +
      '3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b' +
      '61 16'
    );
    const expectedTag = hex('1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91');

    const encrypted = __testing__.chacha20poly1305Encrypt(key, nonce, plaintext, aad);
    const ciphertext = encrypted.subarray(0, encrypted.length - 16);
    const tag = encrypted.subarray(encrypted.length - 16);
    expect(toHex(ciphertext)).toBe(toHex(expectedCiphertext));
    expect(toHex(tag)).toBe(toHex(expectedTag));

    const decrypted = __testing__.chacha20poly1305Decrypt(key, nonce, encrypted, aad);
    expect(toHex(decrypted)).toBe(toHex(plaintext));
  });

  it('rejects a tampered ciphertext (tag mismatch)', () => {
    const key = hex('80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f');
    const nonce = hex('07 00 00 00 40 41 42 43 44 45 46 47');
    const aad = hex('50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7');
    const plaintext = new TextEncoder().encode('short message');
    const encrypted = __testing__.chacha20poly1305Encrypt(key, nonce, plaintext, aad);
    const tampered = new Uint8Array(encrypted);
    tampered[0] ^= 0xff;
    expect(() => __testing__.chacha20poly1305Decrypt(key, nonce, tampered, aad)).toThrow(/authentication failed/);
  });
});

describe('portable-aead: draft-irtf-cfrg-xchacha-03 HChaCha20 (Appendix A.2.1)', () => {
  it('matches the official test vector', () => {
    const key = hex('00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f');
    const nonceInput = hex('00 00 00 09 00 00 00 4a 00 00 00 00 31 41 59 27');
    const expected = hex(
      '82 41 3b 42 27 b2 7b fe d3 0e 42 50 8a 87 7d 73' +
      'a0 f9 e4 d5 8a 74 a8 53 c1 2e c4 13 26 d3 ec dc'
    );
    const out = __testing__.hchacha20(key, nonceInput);
    expect(toHex(out)).toBe(toHex(expected));
  });
});

describe('portable-aead: full AEAD_XCHACHA20_POLY1305 (draft-irtf-cfrg-xchacha-03 Appendix A.3.1)', () => {
  it('matches the official test vector', () => {
    const key = hex('80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f');
    const nonce = hex('40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57'); // 24 bytes
    const aad = hex('50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7');
    const plaintext = hex(
      '4c616469657320616e642047656e746c656d656e206f662074686520636c6173' +
      '73206f66202739393a204966204920636f756c64206f6666657220796f75206f' +
      '6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73' +
      '637265656e20776f756c642062652069742e'
    );
    const expectedCiphertext = hex(
      'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb' +
      '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452' +
      '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9' +
      '21f9664c97637da9768812f615c68b13b52e'
    );
    const expectedTag = hex('c0875924c1c7987947deafd8780acf49');

    const encrypted = xchacha20poly1305Encrypt(key, nonce, plaintext, aad);
    const ciphertext = encrypted.subarray(0, encrypted.length - 16);
    const tag = encrypted.subarray(encrypted.length - 16);
    expect(toHex(ciphertext)).toBe(toHex(expectedCiphertext));
    expect(toHex(tag)).toBe(toHex(expectedTag));

    const decrypted = xchacha20poly1305Decrypt(key, nonce, encrypted, aad);
    expect(toHex(decrypted)).toBe(toHex(plaintext));
  });

  it('round-trips with no AAD', () => {
    const key = hex('80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f');
    const nonce = hex('40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57');
    const plaintext = new TextEncoder().encode('a message with no additional data');
    const encrypted = xchacha20poly1305Encrypt(key, nonce, plaintext);
    const decrypted = xchacha20poly1305Decrypt(key, nonce, encrypted);
    expect(toHex(decrypted)).toBe(toHex(plaintext));
  });

  it('rejects a tampered ciphertext', () => {
    const key = hex('80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f');
    const nonce = hex('40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57');
    const plaintext = new TextEncoder().encode('tamper test');
    const encrypted = xchacha20poly1305Encrypt(key, nonce, plaintext);
    const tampered = new Uint8Array(encrypted);
    tampered[tampered.length - 1] ^= 0xff; // flip a bit in the tag itself
    expect(() => xchacha20poly1305Decrypt(key, nonce, tampered)).toThrow(/authentication failed/);
  });

  it('rejects wrong AAD', () => {
    const key = hex('80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f');
    const nonce = hex('40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57');
    const plaintext = new TextEncoder().encode('aad test');
    const encrypted = xchacha20poly1305Encrypt(key, nonce, plaintext, new TextEncoder().encode('correct-aad'));
    expect(() => xchacha20poly1305Decrypt(key, nonce, encrypted, new TextEncoder().encode('wrong-aad'))).toThrow(/authentication failed/);
  });

  it('rejects wrong key', () => {
    const key = hex('80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f');
    const wrongKey = hex('00 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f');
    const nonce = hex('40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57');
    const plaintext = new TextEncoder().encode('key test');
    const encrypted = xchacha20poly1305Encrypt(key, nonce, plaintext);
    expect(() => xchacha20poly1305Decrypt(wrongKey, nonce, encrypted)).toThrow(/authentication failed/);
  });
});

describe('portable-aead: differential vs libsodium', () => {
  const rand = (n: number) => crypto.getRandomValues(new Uint8Array(n));
  const LENGTHS = [0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256, 1000, 4096, 60001];

  it('XChaCha20-Poly1305 is byte-identical both directions (random + unaligned inputs)', async () => {
    const { default: sodium } = await import('libsodium-wrappers');
    await sodium.ready;
    for (let trial = 0; trial < 300; trial++) {
      const len = trial < LENGTHS.length ? LENGTHS[trial] : (trial * 7919) % 3000;
      const key = rand(32);
      const nonce = rand(24);
      const aad = rand(trial % 40);
      // Offset by 1..3 bytes so the word-aligned fast path and the byte fallback are both exercised.
      const shift = trial % 4;
      const backing = rand(len + shift);
      const pt = backing.subarray(shift);
      const ours = xchacha20poly1305Encrypt(key, nonce, pt, aad);
      const theirs = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(pt, aad, null, nonce, key);
      expect(toHex(ours)).toBe(toHex(theirs));
      expect(toHex(xchacha20poly1305Decrypt(key, nonce, theirs, aad))).toBe(toHex(pt));
    }
  });

  // Literal RFC 8439 §2.5.1 formula in BigInt — a test oracle only (BigInt is variable-time).
  function poly1305Reference(msg: Uint8Array, key: Uint8Array): Uint8Array {
    const le = (b: Uint8Array) => b.reduceRight((acc, x) => (acc << 8n) | BigInt(x), 0n);
    const p = (1n << 130n) - 5n;
    const r = le(key.subarray(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
    let acc = 0n;
    for (let i = 0; i < msg.length; i += 16) {
      const block = msg.subarray(i, i + 16);
      acc = ((acc + le(block) + (1n << BigInt(8 * block.length))) * r) % p;
    }
    let tag = (acc + le(key.subarray(16))) & ((1n << 128n) - 1n);
    const out = new Uint8Array(16);
    for (let i = 0; i < 16; i++) { out[i] = Number(tag & 0xffn); tag >>= 8n; }
    return out;
  }

  it('Poly1305 matches the RFC formula on carry/reduction edge cases (all-0xff keys and messages)', () => {
    const fills = [0x00, 0x01, 0xfb, 0xfe, 0xff];
    for (const kf of fills) {
      for (const mf of fills) {
        for (const len of LENGTHS) {
          const key = new Uint8Array(32).fill(kf);
          const msg = new Uint8Array(len).fill(mf);
          expect(toHex(__testing__.poly1305Mac(msg, key))).toBe(toHex(poly1305Reference(msg, key)));
        }
      }
    }
    for (let trial = 0; trial < 300; trial++) {
      const key = rand(32);
      const msg = rand((trial * 131) % 2000);
      expect(toHex(__testing__.poly1305Mac(msg, key))).toBe(toHex(poly1305Reference(msg, key)));
    }
  });
});
