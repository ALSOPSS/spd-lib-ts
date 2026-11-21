/**
 * SPDRecipient — public-key (asymmetric) recipients for SPD, post-quantum
 * hybrid.
 *
 * SPD's symmetric core is unlocked either by a passphrase (Argon2id) or by a
 * 96-byte random master secret (`SPD.setRandomKey`). This module lets that
 * master secret be *sealed to one or more public keys*, so a file can be
 * encrypted for recipients who never share a passphrase — the same model as
 * age / PGP recipients, with a PQ/T hybrid KEM:
 *
 *   KEM  = MLKEM768-X25519 (ML-KEM-768 + X25519; the hybrid KEM of
 *          draft-ietf-hpke-pq and age v1.3's `age1pq` recipients, via
 *          @noble/post-quantum's `ml_kem768_x25519`, whose combiner hashes
 *          both shared secrets plus the X25519 ciphertext and public key —
 *          the IND-CCA-preserving shape of NIST SP 800-227 §4.6.2)
 *   wrap = HKDF-SHA3-512(ss, salt = label, info = kemCt ‖ recipientPk)
 *   body = CMT-4 XChaCha20-Poly1305(wrapKey, nonce = 0, aad = header, master)
 *
 * The AEAD body carries SPD's usual 32-byte key commitment, so a stanza can
 * only be opened by the key that produced it (no partitioning oracles across
 * stanzas). The nonce is fixed at zero because every wrap key is fresh: each
 * stanza has its own KEM encapsulation.
 *
 * ## Envelope wire format (v1)
 *
 *   "SPDR" | 0x01 version | 0x01 kem id (MLKEM768-X25519) | count (1..255)
 *   then `count` stanzas of: kemCt (1120 B) ‖ body (32 cmt + 96 + 16 tag)
 *
 * The envelope is not secret and does not identify recipients (no key tags);
 * `open()` simply tries every stanza. Store it next to the `.spd` file.
 *
 * ## Usage
 *
 * ```ts
 * // Recipient, once:
 * const id = SPDRecipient.generateIdentity();        // keep id.secretKey private
 * publish(SPDRecipient.encodePublicKey(id.publicKey)); // "spdpq1..." string
 *
 * // Sender:
 * const { masterSecret, envelope } = SPDRecipient.newSealedKey([alicePk, bobPk]);
 * const spd = new SPD();
 * await spd.setRandomKey(masterSecret);
 * masterSecret.fill(0);
 * await spd.addData('report', data);
 * await spd.saveToFile('report.spd', '');            // keyless mode ignores the passcode
 * // send report.spd + envelope
 *
 * // Recipient:
 * const master = SPDRecipient.open(envelope, id.secretKey);
 * const spd = await SPD.loadWithRandomKey('report.spd', master);
 * master.fill(0);
 * ```
 */

import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import * as crypto from './internal/portable-crypto.js';
import { utf8ToBytes, concatBytes, bytesToBase64Url, base64UrlToBytes } from './internal/portable-crypto.js';
import { aeadEncrypt, aeadDecrypt, CMT_BLOCK_BYTES } from './internal/spd-crypto.js';

export interface SPDRecipientIdentity {
  /** 1216-byte MLKEM768-X25519 encapsulation key. Share freely. */
  publicKey: Uint8Array;
  /** 32-byte seed; the public key is re-derivable from it. Keep private. */
  secretKey: Uint8Array;
}

export interface SPDRecipientEnvelopeInfo {
  version: number;
  kem: 'MLKEM768-X25519';
  recipientCount: number;
}

const MAGIC            = utf8ToBytes('SPDR');
const VERSION          = 0x01;
const KEM_MLKEM768_X25519 = 0x01;
const HEADER_BYTES     = 4 + 1 + 1 + 1;
const MASTER_BYTES     = 96; // SPD.generateRandomKey() / setRandomKey() width
const WRAP_KEY_BYTES   = 32;
const TAG_BYTES        = 16;
const NONCE_BYTES      = 24;
const KEM              = ml_kem768_x25519;
const PK_BYTES         = KEM.lengths.publicKey;
const SK_BYTES         = KEM.lengths.secretKey;
const CT_BYTES         = KEM.lengths.cipherText!;
const BODY_BYTES       = CMT_BLOCK_BYTES + MASTER_BYTES + TAG_BYTES;
const STANZA_BYTES     = CT_BYTES + BODY_BYTES;
const WRAP_SALT        = utf8ToBytes('spd-recipient-v1/mlkem768x25519');
const PK_PREFIX        = 'spdpq1.';

/** HKDF-SHA3-512 extract+expand to a 32-byte wrap key, bound to this stanza's KEM ciphertext and recipient key. */
function wrapKey(sharedSecret: Uint8Array, kemCt: Uint8Array, recipientPk: Uint8Array): Uint8Array {
  const prk = crypto.createHmac('sha3-512', WRAP_SALT).update(sharedSecret).digest();
  const okm = crypto.createHmac('sha3-512', prk)
    .update(kemCt).update(recipientPk).update(Uint8Array.of(0x01))
    .digest();
  prk.fill(0);
  const key = okm.slice(0, WRAP_KEY_BYTES);
  okm.fill(0);
  return key;
}

function header(count: number): Uint8Array {
  return concatBytes(MAGIC, Uint8Array.of(VERSION, KEM_MLKEM768_X25519, count));
}

function assertPublicKey(pk: Uint8Array, what = 'public key'): void {
  if (!(pk instanceof Uint8Array) || pk.length !== PK_BYTES) {
    throw new Error(`SPDRecipient: ${what} must be a ${PK_BYTES}-byte MLKEM768-X25519 public key`);
  }
}

export class SPDRecipient {
  private constructor() { /* static-only */ }

  /** Generate a recipient identity. `secretKey` is a 32-byte seed. */
  static generateIdentity(): SPDRecipientIdentity {
    const { publicKey, secretKey } = KEM.keygen();
    return { publicKey, secretKey };
  }

  /** Re-derive the public key from a 32-byte secret seed. */
  static publicKeyFromSecret(secretKey: Uint8Array): Uint8Array {
    if (!(secretKey instanceof Uint8Array) || secretKey.length !== SK_BYTES) {
      throw new Error(`SPDRecipient: secret key must be ${SK_BYTES} bytes`);
    }
    return KEM.getPublicKey(secretKey);
  }

  /**
   * Seal `masterSecret` (96 bytes, from `SPD.generateRandomKey()`) to every
   * public key in `recipients`. Any one of them can `open()` the result.
   */
  static seal(masterSecret: Uint8Array, recipients: Uint8Array[]): Uint8Array {
    if (!(masterSecret instanceof Uint8Array) || masterSecret.length !== MASTER_BYTES) {
      throw new Error(`SPDRecipient: masterSecret must be ${MASTER_BYTES} bytes (SPD.generateRandomKey())`);
    }
    if (!Array.isArray(recipients) || recipients.length < 1 || recipients.length > 255) {
      throw new Error('SPDRecipient: need 1–255 recipients');
    }
    recipients.forEach((pk, i) => assertPublicKey(pk, `recipients[${i}]`));

    const hdr = header(recipients.length);
    const nonce = new Uint8Array(NONCE_BYTES);
    const out = new Uint8Array(HEADER_BYTES + STANZA_BYTES * recipients.length);
    out.set(hdr, 0);
    let pos = HEADER_BYTES;
    for (const pk of recipients) {
      const { cipherText, sharedSecret } = KEM.encapsulate(pk);
      const key = wrapKey(sharedSecret, cipherText, pk);
      sharedSecret.fill(0);
      const body = aeadEncrypt(masterSecret, hdr, nonce, key);
      key.fill(0);
      out.set(cipherText, pos); pos += CT_BYTES;
      out.set(body, pos);       pos += BODY_BYTES;
    }
    return out;
  }

  /**
   * Generate a fresh master secret and seal it to `recipients` in one step.
   * Pass `masterSecret` to `spd.setRandomKey()` and zero it afterwards.
   */
  static newSealedKey(recipients: Uint8Array[]): { masterSecret: Uint8Array; envelope: Uint8Array } {
    const masterSecret = crypto.randomBytes(MASTER_BYTES);
    return { masterSecret, envelope: SPDRecipient.seal(masterSecret, recipients) };
  }

  /**
   * Open an envelope with a recipient's secret key, returning the 96-byte
   * master secret. Throws a single uniform error if no stanza opens (wrong
   * identity, tampered envelope, or unsupported format).
   */
  static open(envelope: Uint8Array, secretKey: Uint8Array): Uint8Array {
    if (!(secretKey instanceof Uint8Array) || secretKey.length !== SK_BYTES) {
      throw new Error(`SPDRecipient: secret key must be ${SK_BYTES} bytes`);
    }
    const info = SPDRecipient.inspect(envelope);
    const hdr = envelope.subarray(0, HEADER_BYTES);
    const pk = KEM.getPublicKey(secretKey);
    const nonce = new Uint8Array(NONCE_BYTES);
    let master: Uint8Array | undefined;
    for (let i = 0; i < info.recipientCount && !master; i++) {
      const start = HEADER_BYTES + i * STANZA_BYTES;
      const ct = envelope.subarray(start, start + CT_BYTES);
      const body = envelope.subarray(start + CT_BYTES, start + STANZA_BYTES);
      let key: Uint8Array | undefined;
      try {
        // ML-KEM uses implicit rejection (a wrong key yields a random secret, no
        // error); the key-committing AEAD below is what decides.
        const ss = KEM.decapsulate(ct, secretKey);
        key = wrapKey(ss, ct, pk);
        ss.fill(0);
        master = aeadDecrypt(body, hdr, nonce, key);
      } catch {
        /* not ours, or tampered — try the next stanza */
      } finally {
        key?.fill(0);
      }
    }
    if (!master) throw new Error('SPDRecipient: no stanza could be opened with this identity');
    return master;
  }

  /** Parse and validate an envelope header without any secret key. */
  static inspect(envelope: Uint8Array): SPDRecipientEnvelopeInfo {
    if (!(envelope instanceof Uint8Array) || envelope.length < HEADER_BYTES) {
      throw new Error('SPDRecipient: not an SPD recipient envelope');
    }
    if (!crypto.timingSafeEqual(envelope.subarray(0, 4), MAGIC)) {
      throw new Error('SPDRecipient: not an SPD recipient envelope');
    }
    const version = envelope[4];
    const kemId = envelope[5];
    const count = envelope[6];
    if (version !== VERSION) throw new Error(`SPDRecipient: unsupported envelope version ${version}`);
    if (kemId !== KEM_MLKEM768_X25519) throw new Error(`SPDRecipient: unsupported KEM id ${kemId}`);
    if (count < 1 || envelope.length !== HEADER_BYTES + STANZA_BYTES * count) {
      throw new Error('SPDRecipient: envelope length does not match its recipient count');
    }
    return { version, kem: 'MLKEM768-X25519', recipientCount: count };
  }

  /** Encode a public key as a `spdpq1.<base64url>` string for sharing. */
  static encodePublicKey(publicKey: Uint8Array): string {
    assertPublicKey(publicKey);
    return PK_PREFIX + bytesToBase64Url(publicKey);
  }

  static decodePublicKey(encoded: string): Uint8Array {
    if (typeof encoded !== 'string' || !encoded.startsWith(PK_PREFIX)) {
      throw new Error(`SPDRecipient: public key string must start with "${PK_PREFIX}"`);
    }
    const pk = base64UrlToBytes(encoded.slice(PK_PREFIX.length));
    assertPublicKey(pk);
    return pk;
  }
}
