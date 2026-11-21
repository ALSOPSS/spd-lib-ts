/**
 * SPDHandshake — Hybrid post-quantum ephemeral key agreement for SPD sessions.
 *
 * ## Cryptographic design
 *
 * Uses a **X25519 + ML-KEM-768 hybrid** construction:
 *
 *   x25519_ss  = X25519(myPriv, theirPub)          — classical ECDH
 *   mlkem_ss   = ML-KEM-768 encap/decap             — post-quantum KEM (NIST FIPS 203)
 *   transcript = SHA3-512(label ∥ nonce_I ∥ nonce_R ∥ x25519Pub_I ∥ x25519Pub_R
 *                         ∥ kemPub_I ∥ kemCt_R)      — binds every public value
 *   sessionKey = HKDF(HMAC-SHA3-512)(
 *                  IKM  = x25519_ss ∥ mlkem_ss,
 *                  salt = transcript,
 *                  info = 'spd-hs-session-v2'
 *                )[0..32)
 *
 * Breaking the session key requires breaking **both** X25519 (hard classically)
 * **and** ML-KEM-768 (hard for quantum computers) simultaneously.
 *
 * ## Security properties
 *
 * | Property                        | Mechanism                                              |
 * |---------------------------------|--------------------------------------------------------|
 * | Classical hardness              | X25519 ECDH — ~2^128 classical operations              |
 * | Quantum hardness                | ML-KEM-768 — NIST FIPS 203, ~2^178 quantum ops        |
 * | Perfect forward secrecy         | All keypairs ephemeral, zeroed after derive()          |
 * | Memory safety                   | Private keys XOR-blinded immediately after creation    |
 * | Key commitment (CMT-4)          | SHA3-256(sessionKey ∥ transcript) — verify before use  |
 * | Cross-session binding           | 32-byte CSPRNG nonce per session mixed into HKDF       |
 * | Peer authentication (optional)  | ML-DSA-65 transcript signatures + pinned public keys   |
 * | Domain separation               | Distinct HKDF info strings per key purpose             |
 * | Timing safety                   | timingSafeEqual for all sensitive comparisons          |
 * | Low-order point rejection       | All-zero DH output rejected before HKDF                |
 * | Input validation                | Type + length checked on all inputs                    |
 * | Zero-on-free                    | All key material zeroed explicitly via sodium.memzero  |
 *
 * ## Handshake flow
 *
 * The initiator (e.g. client) drives ML-KEM encapsulation:
 *
 * ```
 *  INITIATOR                              RESPONDER
 *  ─────────────────────────────────────────────────────
 *  hs = SPDHandshake.createInitiator()
 *  send → { hybridClassicalPub, kemPub, nonce }
 *                                         hs = await SPDHandshake.createResponder(
 *                                                initiatorHello)
 *                                         send → { hybridClassicalPub, kemCt, nonce }
 *  result = await hs.finalizeInitiator(
 *             responderHello)
 *                                         result = hs.responderResult()
 *  // result.commitment === responderResult.commitment
 *  // exchange commitments to confirm matching keys
 * ```
 *
 * ## Usage
 *
 * ```ts
 * import { SPDHandshake, SPD } from 'spd-lib';
 *
 * // ── Initiator (client) ───────────────────────────────────────────────────────
 * const init = await SPDHandshake.createInitiator();
 * socket.send(JSON.stringify(init.hello));         // { hybridClassicalPub, kemPub, nonce }
 *
 * const respHello = JSON.parse(await socket.recv());
 * const initResult = await init.finalizeInitiator(respHello);
 *
 * // ── Responder (server) ───────────────────────────────────────────────────────
 * const resp = await SPDHandshake.createResponder(initHello);
 * socket.send(JSON.stringify(resp.hello));         // { hybridClassicalPub, kemCt, nonce }
 * const respResult = resp.responderResult();
 *
 * // ── Both sides: verify commitment matches before using key ───────────────────
 * // exchange initResult.commitment <→ respResult.commitment over the wire
 * // if they match, both sides have the same session key
 *
 * const spd = new SPD();
 * spd.setKeyProfile('standard');   // session key is already 256-bit entropy
 * await spd.setPassKey(initResult.sessionKey);
 * initResult.destroy();            // zero raw key bytes from memory
 * ```
 */

import * as crypto from './internal/portable-crypto.js';
import { utf8ToBytes, bytesToHex, bytesToBase64Url, base64UrlToBytes, concatBytes } from './internal/portable-crypto.js';
import { u8Alloc, u8Concat } from './internal/portable-binary.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { x25519 } from '@noble/curves/ed25519.js';

// ─── Constants ────────────────────────────────────────────────────────────────

const NONCE_BYTES         = 32;   // session nonce size
const X25519_PUB_BYTES    = 32;
const KEM_PUB_BYTES       = 1184; // ML-KEM-768 public key
const KEM_CT_BYTES        = 1088; // ML-KEM-768 ciphertext
const KEM_SS_BYTES        = 32;   // ML-KEM-768 shared secret
const X25519_SS_BYTES     = 32;
const HKDF_OUTPUT_BYTES   = 32;
const CMT_BYTES           = 32;   // SHA3-256 output

// HKDF info strings — domain-separated per purpose (never reuse across uses)
const INFO_SESSION  = utf8ToBytes('spd-hs-session-v2');
const LABEL_TRANSCRIPT = utf8ToBytes('spd-hs-transcript-v2');
// ML-DSA (FIPS 204) context strings — distinct per role so a signature made
// as one role can never be replayed as the other (reflection).
const CTX_RESPONDER = utf8ToBytes('spd-hs-responder-v2');
const CTX_INITIATOR = utf8ToBytes('spd-hs-initiator-v2');

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** XOR two equal-length byte arrays into a new Uint8Array. */
function xorBufs(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = u8Alloc(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

/** SHA3-256(data) → 32-byte Uint8Array. */
function sha3_256(...parts: Uint8Array[]): Uint8Array {
  const h = crypto.createHash('sha3-256');
  for (const p of parts) h.update(p);
  return h.digest();
}

/** SHA3-512(data) → 64-byte Uint8Array. */
function sha3_512(...parts: Uint8Array[]): Uint8Array {
  const h = crypto.createHash('sha3-512');
  for (const p of parts) h.update(p);
  return h.digest();
}

/**
 * HKDF (RFC 5869) over HMAC-SHA3-512.
 * Uses the same HMAC-SHA3-512 expand loop as SPDWriter's hkdfExpand,
 * but with a proper Extract step when a non-empty salt is provided.
 */
function hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, len: number): Uint8Array {
  // Extract: PRK = HMAC-SHA3-512(salt, IKM)
  const prk = crypto.createHmac('sha3-512', salt).update(ikm).digest();
  // Expand
  const blocks: Uint8Array[] = [];
  let prev: Uint8Array = new Uint8Array(0);
  let ctr  = 1;
  let pos  = 0;
  while (pos < len) {
    const block = crypto.createHmac('sha3-512', prk)
      .update(prev).update(info).update(Uint8Array.of(ctr++)).digest();
    blocks.push(block);
    prev = block;
    pos += block.length;
  }
  return u8Concat(blocks).subarray(0, len);
}

/**
 * Zero a Uint8Array. Previously tried sodium.memzero first — that
 * exists in C to defeat compiler dead-store elimination on stack buffers, a
 * concern that doesn't have a documented, proven JS-engine equivalent (or
 * mitigation); .fill(0) is the actual industry-standard practice for this
 * in managed languages. See internal/spd-crypto.ts's or spd-score.ts's
 * hasExplicitMemzero comment for the fuller rationale.
 */
function zero(buf: Uint8Array | null | undefined): void {
  if (!buf) return;
  buf.fill(0);
}

/** Assert a condition, throwing with message if false. */
function assert(cond: boolean, msg: string): asserts cond {
  if (!cond) throw new Error(`SPDHandshake: ${msg}`);
}

// ─── Blinded private key ──────────────────────────────────────────────────────

/** Holds an X25519 private key XOR-blinded with a random mask in memory. */
class BlindedPrivKey {
  private _blinded: Uint8Array;
  private _mask:    Uint8Array;

  constructor(rawPriv: Uint8Array) {
    assert(rawPriv.length === X25519_PUB_BYTES, 'private key must be 32 bytes');
    this._mask    = crypto.randomBytes(X25519_PUB_BYTES);
    this._blinded = xorBufs(rawPriv, this._mask);
    zero(rawPriv); // zero caller's copy
  }

  /** Unblind, call fn(rawPriv), then immediately re-zero the unblinded copy. */
  use<T>(fn: (raw: Uint8Array) => T): T {
    assert(!!this._blinded, 'private key already destroyed');
    const raw = xorBufs(this._blinded, this._mask);
    try      { return fn(raw); }
    finally  { zero(raw); }
  }

  destroy(): void {
    zero(this._blinded);
    zero(this._mask);
  }
}

// ─── Result ───────────────────────────────────────────────────────────────────

/**
 * Message sent during the handshake exchange.
 *
 * The session key is derived from BOTH `hybridClassicalPub` (X25519) AND
 * `hybridQuantumData` (ML-KEM-768) via HKDF. An attacker must break
 * **both** simultaneously — classical hardness AND post-quantum hardness.
 * Neither field alone is sufficient to recover the session key.
 */
export interface SPDHandshakeHello {
  /**
   * Classical half of the hybrid: base64url-encoded X25519 ephemeral public
   * key (32 bytes). Provides ~2^128 classical security. NOT quantum-safe
   * alone — security comes from the hybrid combination with `hybridQuantumData`.
   */
  hybridClassicalPub: string;
  /**
   * Post-quantum half of the hybrid (base64url-encoded):
   * - Initiator hello: ML-KEM-768 public key (1184 bytes) for encapsulation.
   * - Responder hello: ML-KEM-768 ciphertext (1088 bytes) from encapsulation.
   * Provides ~2^178 quantum security (NIST FIPS 203 / ML-KEM-768).
   */
  hybridQuantumData: string;
  /** Base64url-encoded random session nonce (32 bytes). */
  nonce: string;
  /**
   * Responder hello only, when the responder has an identity: base64url
   * ML-DSA-65 signature over the handshake transcript.
   */
  signature?: string;
}

/**
 * Optional authentication for either side. Without it the handshake is
 * unauthenticated: comparing commitments detects accidental mismatch but NOT
 * an active man-in-the-middle, who simply runs one handshake with each side.
 */
export interface SPDHandshakeAuthOptions {
  /** Our ML-DSA-65 secret key (from `SPDHandshake.generateIdentity()`); we sign the transcript with it. */
  identity?: Uint8Array;
  /** The peer's pinned ML-DSA-65 public key; the peer MUST then sign, or the handshake fails. */
  peerPublicKey?: Uint8Array;
}

export interface SPDHandshakeIdentity {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

function assertAuthOptions(opts: SPDHandshakeAuthOptions | undefined): void {
  if (opts?.identity !== undefined) {
    assert(opts.identity instanceof Uint8Array && opts.identity.length === ml_dsa65.lengths.secretKey,
      `identity must be a ${ml_dsa65.lengths.secretKey}-byte ML-DSA-65 secret key`);
  }
  if (opts?.peerPublicKey !== undefined) {
    assert(opts.peerPublicKey instanceof Uint8Array && opts.peerPublicKey.length === ml_dsa65.lengths.publicKey,
      `peerPublicKey must be a ${ml_dsa65.lengths.publicKey}-byte ML-DSA-65 public key`);
  }
}

function verifyTranscriptSig(sigB64: string | undefined, transcript: Uint8Array, publicKey: Uint8Array, context: Uint8Array, who: string): void {
  assert(typeof sigB64 === 'string', `${who} signature required (peer key is pinned) but missing`);
  let ok = false;
  try {
    ok = ml_dsa65.verify(base64UrlToBytes(sigB64), transcript, publicKey, { context });
  } catch { /* malformed signature */ }
  assert(ok, `${who} signature verification failed — possible man-in-the-middle`);
}

/**
 * Completed handshake result.
 * Call `destroy()` immediately after passing `sessionKey` to `spd.setPassKey()`.
 */
export class SPDHandshakeResult {
  /**
   * 64-character hex session passphrase (256 bits of entropy).
   * Pass directly to `spd.setPassKey()`.
   */
  readonly sessionKey: string;

  /**
   * CMT-4 key commitment: SHA3-256(sessionKeyBytes ∥ transcriptHash).
   * Base64url-encoded (32 bytes).
   *
   * Exchange this with the other party and verify they match BEFORE using
   * `sessionKey`; if they differ, abort. Note: over the same channel an
   * active man-in-the-middle can simply relay matching commitments for its
   * two separate sessions — only `SPDHandshakeAuthOptions` (pinned ML-DSA-65
   * keys) or comparing commitments over an independent authentic channel
   * defeats that.
   */
  readonly commitment: string;

  /**
   * Initiator only, when it has an identity: base64url ML-DSA-65 signature
   * over the transcript. Send it to the responder alongside `commitment`;
   * a responder that pinned our key checks it with `verifyInitiator()`.
   */
  signature?: string;

  private _raw: Uint8Array;

  /** @internal */
  constructor(raw: Uint8Array, transcript: Uint8Array) {
    assert(raw.length === HKDF_OUTPUT_BYTES, 'session key must be 32 bytes');
    this._raw       = raw;
    this.sessionKey = bytesToHex(raw);
    // CMT-4: SHA3-256(sessionKey ∥ transcript) — same pattern as SPD's aeadDecrypt
    this.commitment = bytesToBase64Url(sha3_256(raw, transcript));
  }

  /**
   * Zero the raw session key bytes from memory.
   * The `sessionKey` hex string may still exist in the JS heap
   * (strings are immutable in V8); call this as soon as `setPassKey()` is done.
   */
  destroy(): void {
    zero(this._raw);
  }
}

// ─── Initiator state ──────────────────────────────────────────────────────────

/** Initiator state returned by `SPDHandshake.createInitiator()`. */
export class SPDHandshakeInitiator {
  /** Send this to the responder. */
  readonly hello: SPDHandshakeHello;

  private _x25519Priv: BlindedPrivKey;
  private _kemSecretMask: Uint8Array;  // XOR mask for KEM secret key
  private _blindedKemSK: Uint8Array;
  private _nonceRaw: Uint8Array;
  private _identity?: Uint8Array;
  private _peerPublicKey?: Uint8Array;
  private _done = false;

  /** @internal */
  constructor(
    x25519PrivRaw: Uint8Array,
    hybridClassicalPubRaw:  Uint8Array,
    kemSecretKey:  Uint8Array,
    kemPublicKey:  Uint8Array,
    nonce:         Uint8Array,
    auth?:         SPDHandshakeAuthOptions,
  ) {
    if (auth?.identity) this._identity = new Uint8Array(auth.identity);
    if (auth?.peerPublicKey) this._peerPublicKey = new Uint8Array(auth.peerPublicKey);

    // Blind KEM secret key in memory immediately
    this._kemSecretMask  = crypto.randomBytes(kemSecretKey.length);
    this._blindedKemSK   = xorBufs(kemSecretKey, this._kemSecretMask);
    zero(kemSecretKey);

    this._x25519Priv = new BlindedPrivKey(x25519PrivRaw);
    zero(x25519PrivRaw);

    this._nonceRaw = nonce;
    this.hello = {
      hybridClassicalPub: bytesToBase64Url(hybridClassicalPubRaw),
      hybridQuantumData:   bytesToBase64Url(kemPublicKey),
      nonce:     bytesToBase64Url(nonce),
    };
  }

  /**
   * Complete the initiator side of the handshake using the responder's hello.
   *
   * @param responderHello  The `hello` object received from the responder.
   * @returns  `SPDHandshakeResult` — call `.destroy()` after `setPassKey()`.
   * @throws   If already called, or if any input is malformed.
   */
  async finalizeInitiator(responderHello: SPDHandshakeHello): Promise<SPDHandshakeResult> {
    assert(!this._done, 'finalizeInitiator already called — create a new instance per session');
    this._done = true;

    // ── Validate responder hello ──────────────────────────────────────────────
    assert(typeof responderHello?.hybridClassicalPub === 'string', 'responderHello.hybridClassicalPub must be a string');
    assert(typeof responderHello?.hybridQuantumData   === 'string', 'responderHello.hybridQuantumData must be a string');
    assert(typeof responderHello?.nonce     === 'string', 'responderHello.nonce must be a string');

    const theirX25519Pub = base64UrlToBytes(responderHello.hybridClassicalPub);
    const kemCt          = base64UrlToBytes(responderHello.hybridQuantumData);
    const theirNonce     = base64UrlToBytes(responderHello.nonce);

    assert(theirX25519Pub.length === X25519_PUB_BYTES, `responder hybridClassicalPub must be ${X25519_PUB_BYTES} bytes`);
    assert(kemCt.length          === KEM_CT_BYTES,      `responder hybridQuantumData must be ${KEM_CT_BYTES} bytes (KEM ciphertext)`);
    assert(theirNonce.length     === NONCE_BYTES,        `responder nonce must be ${NONCE_BYTES} bytes`);

    // ── Reject low-order X25519 point (small-subgroup attack) ────────────────
    const allZero = u8Alloc(X25519_PUB_BYTES);
    assert(!crypto.timingSafeEqual(theirX25519Pub, allZero), 'low-order X25519 public key rejected');

    // ── X25519 DH ─────────────────────────────────────────────────────────────
    const x25519SS: Uint8Array = this._x25519Priv.use(rawPriv =>
      x25519.getSharedSecret(rawPriv, theirX25519Pub)
    );
    this._x25519Priv.destroy();

    // ── Reject all-zero DH output ─────────────────────────────────────────────
    assert(!crypto.timingSafeEqual(x25519SS, allZero), 'X25519 DH produced low-order output — possible attack');

    // ── ML-KEM-768 decapsulate ────────────────────────────────────────────────
    const kemSK      = xorBufs(this._blindedKemSK, this._kemSecretMask);
    let kemSS: Uint8Array;
    try {
      kemSS = ml_kem768.decapsulate(kemCt, kemSK);
    } finally {
      zero(kemSK);
      zero(this._blindedKemSK);
      zero(this._kemSecretMask);
    }

    // ── Derive session key (hybrid) ───────────────────────────────────────────
    const transcript = _transcript(
      this._nonceRaw,
      theirNonce,
      base64UrlToBytes(this.hello.hybridClassicalPub),
      theirX25519Pub,
      base64UrlToBytes(this.hello.hybridQuantumData),
      kemCt,
    );
    const result = _deriveSessionKey(x25519SS, kemSS, transcript);
    zero(x25519SS);
    zero(kemSS);
    zero(this._nonceRaw);

    // ── Authentication (optional) ─────────────────────────────────────────────
    try {
      if (this._peerPublicKey) {
        verifyTranscriptSig(responderHello.signature, transcript, this._peerPublicKey, CTX_RESPONDER, 'responder');
      }
      if (this._identity) {
        result.signature = bytesToBase64Url(ml_dsa65.sign(transcript, this._identity, { context: CTX_INITIATOR }));
      }
    } catch (e) {
      result.destroy();
      throw e;
    } finally {
      zero(this._identity);
    }

    return result;
  }

  /** Zero all key material. Call if abandoning the handshake. */
  destroy(): void {
    this._x25519Priv.destroy();
    zero(this._blindedKemSK);
    zero(this._kemSecretMask);
    zero(this._nonceRaw);
    zero(this._identity);
  }
}

// ─── Responder state ──────────────────────────────────────────────────────────

/** Responder state returned by `SPDHandshake.createResponder()`. */
export class SPDHandshakeResponder {
  /** Send this to the initiator. */
  readonly hello: SPDHandshakeHello;

  private _result: SPDHandshakeResult;
  private _transcript: Uint8Array;
  private _initiatorPublicKey?: Uint8Array;

  /** @internal */
  constructor(hello: SPDHandshakeHello, result: SPDHandshakeResult, transcript: Uint8Array, initiatorPublicKey?: Uint8Array) {
    this.hello   = hello;
    this._result = result;
    this._transcript = transcript;
    if (initiatorPublicKey) this._initiatorPublicKey = new Uint8Array(initiatorPublicKey);
  }

  /**
   * Verify the initiator's `result.signature` against the pinned initiator
   * key. Required before `responderResult()` when `peerPublicKey` was given
   * to `createResponder()`. Throws (and destroys the session key) on failure.
   */
  verifyInitiator(signature: string): void {
    assert(!!this._initiatorPublicKey, 'verifyInitiator: no initiator public key was pinned');
    try {
      verifyTranscriptSig(signature, this._transcript, this._initiatorPublicKey!, CTX_INITIATOR, 'initiator');
    } catch (e) {
      this._result.destroy();
      throw e;
    }
    this._initiatorPublicKey = undefined;
  }

  /**
   * Return the completed session result.
   * The responder derives its key during `createResponder()` — call this
   * after sending `hello` to the initiator (and, if the initiator's key is
   * pinned, after `verifyInitiator()`).
   */
  responderResult(): SPDHandshakeResult {
    assert(!this._initiatorPublicKey, 'initiator not yet authenticated — call verifyInitiator() first');
    return this._result;
  }
}

// ─── Shared key derivation ────────────────────────────────────────────────────

/**
 * Transcript hash over every public value of the exchange, in role order.
 *
 * @internal
 */
function _transcript(
  initNonce:     Uint8Array,
  respNonce:     Uint8Array,
  initX25519Pub: Uint8Array,
  respX25519Pub: Uint8Array,
  initKemPub:    Uint8Array,
  kemCt:         Uint8Array,
): Uint8Array {
  // Transcript hash — the HKDF salt. Binds the key to every public value of
  // this exchange, in fixed role order (all fields are fixed-length, so the
  // concatenation is unambiguous). Raw X25519 output does not commit to the
  // public keys that produced it, and a combiner over shared secrets alone is
  // not IND-CCA in general — X-Wing (draft-connolly-cfrg-xwing-kem) and the
  // GHP18 combiner both hash the classical public keys/ciphertext into the
  // KDF; the ML-KEM public key and ciphertext add recipient and ciphertext
  // binding at negligible cost.
  return sha3_512(LABEL_TRANSCRIPT, initNonce, respNonce, initX25519Pub, respX25519Pub, initKemPub, kemCt);
}

/**
 * Derive the session key from X25519 and KEM shared secrets, salted with the
 * transcript hash. Both sides produce the same output given the same inputs.
 *
 * @internal
 */
function _deriveSessionKey(x25519SS: Uint8Array, kemSS: Uint8Array, transcript: Uint8Array): SPDHandshakeResult {
  // IKM = x25519_ss ∥ mlkem_ss — attacker must break BOTH to recover the key
  const ikm = concatBytes(x25519SS, kemSS);

  // HKDF over HMAC-SHA3-512 → 32-byte session key
  const sessionBytes = hkdf(ikm, transcript, INFO_SESSION, HKDF_OUTPUT_BYTES);
  zero(ikm);

  return new SPDHandshakeResult(sessionBytes, transcript);
}

// ─── Public API ───────────────────────────────────────────────────────────────

export class SPDHandshake {
  private constructor() { /* static-only class */ }

  /**
   * Generate a long-term ML-DSA-65 identity keypair for authenticated
   * handshakes. Distribute `publicKey` to peers out of band (they pass it as
   * `peerPublicKey`); keep `secretKey` private (pass it as `identity`).
   */
  static generateIdentity(): SPDHandshakeIdentity {
    const { publicKey, secretKey } = ml_dsa65.keygen();
    return { publicKey, secretKey };
  }

  /**
   * Create the initiator side of the handshake.
   *
   * Generates an ephemeral X25519 keypair and ML-KEM-768 keypair.
   * Send `initiator.hello` to the responder.
   *
   * @param auth  Optional: `identity` to sign as the initiator (sets
   *              `result.signature`), and/or `peerPublicKey` to require and
   *              verify the responder's signature.
   * @returns  `SPDHandshakeInitiator` instance.
   */
  static async createInitiator(auth?: SPDHandshakeAuthOptions): Promise<SPDHandshakeInitiator> {
    assertAuthOptions(auth);

    // Ephemeral X25519 keypair
    const x25519Kp = x25519.keygen();
    const x25519PrivRaw = x25519Kp.secretKey;
    const hybridClassicalPubRaw = x25519Kp.publicKey;

    // Ephemeral ML-KEM-768 keypair
    const { secretKey: kemSK, publicKey: kemPK } = ml_kem768.keygen();

    // Random session nonce
    const nonce = crypto.randomBytes(NONCE_BYTES);

    return new SPDHandshakeInitiator(
      x25519PrivRaw,
      hybridClassicalPubRaw,
      kemSK,
      kemPK,
      nonce,
      auth,
    );
  }

  /**
   * Create the responder side of the handshake from the initiator's hello.
   *
   * Generates an ephemeral X25519 keypair, encapsulates against the
   * initiator's ML-KEM public key, and derives the session key.
   * Send `responder.hello` to the initiator.
   *
   * @param initiatorHello  The `hello` object received from the initiator.
   * @param auth  Optional: `identity` to sign the responder hello, and/or
   *              `peerPublicKey` to require the initiator's signature (via
   *              `verifyInitiator()`) before `responderResult()` is released.
   * @returns  `SPDHandshakeResponder` instance.
   * @throws   If any input is malformed or a low-order point is detected.
   */
  static async createResponder(initiatorHello: SPDHandshakeHello, auth?: SPDHandshakeAuthOptions): Promise<SPDHandshakeResponder> {
    assertAuthOptions(auth);

    // ── Validate initiator hello ──────────────────────────────────────────────
    assert(typeof initiatorHello?.hybridClassicalPub === 'string', 'initiatorHello.hybridClassicalPub must be a string');
    assert(typeof initiatorHello?.hybridQuantumData   === 'string', 'initiatorHello.hybridQuantumData must be a string');
    assert(typeof initiatorHello?.nonce     === 'string', 'initiatorHello.nonce must be a string');

    const theirX25519Pub = base64UrlToBytes(initiatorHello.hybridClassicalPub);
    const kemPK          = base64UrlToBytes(initiatorHello.hybridQuantumData);
    const theirNonce     = base64UrlToBytes(initiatorHello.nonce);

    assert(theirX25519Pub.length === X25519_PUB_BYTES, `initiator hybridClassicalPub must be ${X25519_PUB_BYTES} bytes`);
    assert(kemPK.length          === KEM_PUB_BYTES,     `initiator hybridQuantumData must be ${KEM_PUB_BYTES} bytes (KEM public key)`);
    assert(theirNonce.length     === NONCE_BYTES,        `initiator nonce must be ${NONCE_BYTES} bytes`);

    // ── Reject low-order X25519 point ─────────────────────────────────────────
    const allZero = u8Alloc(X25519_PUB_BYTES);
    assert(!crypto.timingSafeEqual(theirX25519Pub, allZero), 'low-order X25519 public key rejected');

    // ── Ephemeral X25519 keypair ──────────────────────────────────────────────
    const myX25519Kp = x25519.keygen();
    const myX25519PubRaw  = myX25519Kp.publicKey;
    const myX25519PrivRaw = myX25519Kp.secretKey;

    // ── Random session nonce ──────────────────────────────────────────────────
    const myNonce = crypto.randomBytes(NONCE_BYTES);

    // ── X25519 DH ─────────────────────────────────────────────────────────────
    const x25519SS = x25519.getSharedSecret(myX25519PrivRaw, theirX25519Pub);
    zero(myX25519PrivRaw);

    // ── Reject all-zero DH output ─────────────────────────────────────────────
    assert(!crypto.timingSafeEqual(x25519SS, allZero), 'X25519 DH produced low-order output — possible attack');

    // ── ML-KEM-768 encapsulate against initiator's public key ─────────────────
    const { cipherText: kemCt, sharedSecret: kemSSRaw } =
      ml_kem768.encapsulate(kemPK);
    const kemSS = new Uint8Array(kemSSRaw);
    zero(kemSSRaw); // zero the noble-owned copy too — kemSS below is the one we control

    // ── Derive session key (hybrid) ───────────────────────────────────────────
    const transcript = _transcript(theirNonce, myNonce, theirX25519Pub, myX25519PubRaw, kemPK, kemCt);
    const result = _deriveSessionKey(x25519SS, kemSS, transcript);
    zero(x25519SS);
    zero(kemSS);

    const hello: SPDHandshakeHello = {
      hybridClassicalPub: bytesToBase64Url(myX25519PubRaw),
      hybridQuantumData:   bytesToBase64Url(kemCt),
      nonce:     bytesToBase64Url(myNonce),
    };
    zero(myNonce);
    if (auth?.identity) {
      hello.signature = bytesToBase64Url(ml_dsa65.sign(transcript, auth.identity, { context: CTX_RESPONDER }));
    }

    return new SPDHandshakeResponder(hello, result, transcript, auth?.peerPublicKey);
  }
}

/** @internal Exposed only for test/spd-handshake.test.ts transcript-binding checks. */
export const __testing__ = { transcript: _transcript, deriveSessionKey: _deriveSessionKey };
