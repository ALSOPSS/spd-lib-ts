/**
 * SPDTransport — authenticated, forward-secret client↔server secure channel.
 *
 * ## Protocol versions
 *
 *  V1 (original): ephemeral Curve25519 ECDH only
 *  V2 (v29+):     hybrid Curve25519 + ML-KEM-768, ML-DSA-65 certificate pinning,
 *                 PSK session resumption
 *
 * ## What it provides
 *
 *  - **Ephemeral ECDH handshake** (Curve25519, X25519 + BLAKE2b directional
 *    session-key split — same algorithm as libsodium's `crypto_kx`, see
 *    internal/portable-kx.ts) so every session produces a fresh pair of
 *    symmetric session keys.
 *  - **ML-KEM-768 hybrid**: the server encapsulates to the client's ephemeral
 *    ML-KEM public key; the KEM shared secret is concatenated with both ECDH
 *    shares before key derivation, so breaking EITHER primitive alone does not
 *    compromise the session:
 *      IKM  = c2sShare ‖ s2cShare ‖ kemSS
 *      PRK  = HMAC-SHA3-512(key=sessionSalt, IKM ‖ "spd-transport-v1-hkdf-info")
 *      c2s, s2c, pskExport = HMAC-SHA3-512(PRK, label ‖ 0x01)[0..32)
 *  - **ML-DSA-65 certificate pinning**: the server's long-term identity can
 *    include an ML-DSA-65 signing key pair; clients pin the ML-DSA public key
 *    and the server signs each ServerHello, preventing MitM. A client that
 *    does not pin cannot check the signature at all: it relies on the server's
 *    static Curve25519 key alone (classical). `setStrictMode(true)` refuses
 *    such clients, as well as unsigned servers.
 *  - **PSK session resumption**: a pre-shared key of exactly 32 bytes (e.g.
 *    from `exportPSK()`) can be mixed into the key derivation, allowing clients
 *    to resume a prior session with an additional secret layer:
 *      IKM' = IKM ⊕ HMAC-SHA3-512(key=psk, "spd-transport-v2-psk" ‖ IKM),
 *    the 64-byte HMAC repeated over the IKM's length.
 *  - **Forward secrecy**: all ephemeral key material is zeroed after handshake.
 *  - **Two independent session streams**: `clientToServer` and `serverToClient`,
 *    each with a monotonic 64-bit counter mixed into the XChaCha20-Poly1305
 *    nonce — prevents nonce reuse and blocks replay attacks.
 *  - **Message authentication**: every frame carries a Poly1305 tag.
 *  - **Optional SPD payload wrapping**: `wrapSPD` / `unwrapSPD` let you
 *    transmit an in-memory SPD binary payload over the channel.
 *
 * ## Threat model
 *
 *  ✅ Network eavesdropper — cannot read any session payload
 *  ✅ Replay attack — monotonic counter prevents replaying old frames
 *  ✅ Past-session decryption after key compromise — forward secrecy
 *  ✅ Active MitM — ML-DSA-65 certificate pinning + ECDH server auth
 *  ✅ Harvest-now-decrypt-later (quantum) — ML-KEM-768 hybrid
 *  ✅ PSK gives additional session binding layer for high-security deployments
 *  ✅ Key commitment token prevents key mismatch from going undetected
 *  ✅ Sliding window replay protection tolerates mild network reordering (window=1024)
 *  ✅ Traffic analysis resistance — optional 64-byte block padding
 *
 * ## V2 ClientHello wire format (1249 bytes)
 *
 *  [1B    version         ]  = TRANSPORT_VERSION_V2 (2)
 *  [32B   ecdhEphemeralPub]  client's ephemeral Curve25519 public key
 *  [32B   sessionSalt     ]  random HKDF salt (public)
 *  [1184B kemEphemeralPub ]  client's ephemeral ML-KEM-768 public key
 *
 * ## V2 ServerHello wire format (1 + 1088 + 3309 + 32 = 4430 bytes)
 *
 *  [1B    version        ]  = TRANSPORT_VERSION_V2 (2)
 *  [1088B kemCiphertext  ]  ML-KEM-768 ciphertext (encapsulated by server to client's kemPub)
 *  [3309B signature      ]  ML-DSA-65 signature over SHA3-512("spd-transport-v2-transcript-sig-v2" ‖ ClientHello
 *                           ‖ kemCiphertext ‖ serverStaticPub ‖ keyCommitment)
 *                           — present only if server has a signing key; all zeros if absent
 *  [32B   keyCommitment  ]  HMAC-SHA3-256(c2sKey||s2cKey, "spd-transport-key-commit-v1")
 *                           — client verifies this to detect key mismatch / active MitM
 *
 * ## Usage
 *
 * ```ts
 * // ── Server side ──────────────────────────────────────────────────────────
 * const serverIdentity = await SPDTransport.generateServerIdentity();
 * // Optional: add ML-DSA-65 signing
 * const signingPair    = SPDTransport.generateCertKeyPair();
 * serverIdentity.signingPrivKey = signingPair.privateKey;
 * serverIdentity.signingPubKey  = signingPair.publicKey;
 *
 * const { session, serverHello } = await SPDTransport.serverAccept(serverIdentity, clientHello);
 * session.decrypt(encryptedFrame);
 * session.encrypt(responseBytes);
 *
 * // ── Client side ──────────────────────────────────────────────────────────
 * const { session, clientHello } = await SPDTransport.clientConnect(serverPublicKey, {
 *   pinnedSigningKey: serverSigningPubKey,  // optional cert pin
 *   psk:             sharedSecret32,        // optional PSK
 * });
 * send(clientHello);
 * const serverHello = receive(); // get serverHello from server
 * await session.processServerHello(serverHello);
 * session.encrypt(payload);
 *
 * // ── PSK session resumption ────────────────────────────────────────────────
 * const psk = session.exportPSK();   // save after first handshake
 * // next connection:
 * const { session: session2, clientHello: ch2 } = await SPDTransport.clientConnect(
 *   serverPublicKey, { psk }
 * );
 * ```
 */

import * as crypto from './internal/portable-crypto.js';
import { utf8ToBytes, concatBytes, bytesToBase64Url, bytesToBase64, base64ToBytes } from './internal/portable-crypto.js';
import { u8Alloc, writeBigUInt64BE, readBigUInt64BE, writeUInt16BE } from './internal/portable-binary.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 }  from '@noble/post-quantum/ml-dsa.js';
import { SPD } from './SPD.js';
import { getFs } from './internal/node-platform.js';
import { plainAeadEncrypt, plainAeadDecrypt } from './internal/spd-crypto.js';
import { kxKeypair, kxClientSessionKeys, kxServerSessionKeys } from './internal/portable-kx.js';

// ─── Constants ────────────────────────────────────────────────────────────────

/** Version byte in every ClientHello and frame header (V1: Curve25519 only). */
const TRANSPORT_VERSION    = 1;
/** Version 2: adds ML-KEM-768 hybrid + ML-DSA-65 certificate pinning. */
const TRANSPORT_VERSION_V2 = 2;

/**
 * Domain-separation labels for HKDF-SHA3-512 session key derivation.
 * Using separate labels ensures the two stream keys are independent.
 */
const LABEL_C2S        = utf8ToBytes('spd-transport-v1-client-to-server');
const LABEL_S2C        = utf8ToBytes('spd-transport-v1-server-to-client');
const LABEL_KDF        = utf8ToBytes('spd-transport-v1-hkdf-info');
const LABEL_PSK        = utf8ToBytes('spd-transport-v2-psk');
const LABEL_KEM        = utf8ToBytes('spd-transport-v2-kem');
const LABEL_KEY_COMMIT = utf8ToBytes('spd-transport-key-commit-v1');
const LABEL_SIG_V2     = utf8ToBytes('spd-transport-v2-transcript-sig-v2');

/**
 * V2 signed transcript: SHA3-512(label ‖ ClientHello ‖ kemCT ‖ server static
 * X25519 pub ‖ keyCommit). Signing only kemCT‖salt‖ecdhPub (the previous
 * message) left the client's ML-KEM public key, the version byte and the
 * server identity unbound — a substituted kemPub produced a validly signed
 * ServerHello and was caught only by the key-commitment check.
 */
function v2SignedTranscript(clientHello: Uint8Array, kemCT: Uint8Array, serverStaticPub: Uint8Array, keyCommit: Uint8Array): Uint8Array {
  return crypto.createHash('sha3-512')
    .update(LABEL_SIG_V2).update(clientHello).update(kemCT).update(serverStaticPub).update(keyCommit)
    .digest();
}

/** XChaCha20-Poly1305 nonce size (libsodium). */
const XCHACHA_NONCE_BYTES = 24;

/** Poly1305 tag appended to every encrypted frame. */
const POLY1305_TAG_BYTES = 16;

/** Key commitment appended to ServerHello V2 (HMAC-SHA3-256 output). */
const KEY_COMMIT_BYTES = 32;

/** Sliding window replay protection — accept counters within this range below highWater. */
const REPLAY_WINDOW_SIZE = BigInt(1024); // 1024-entry bitmask — replay requires forging position within window

/** Frame padding block size (bytes). Pads plaintext to a multiple of this value. */
const FRAME_PAD_BLOCK = 64;

// ML-KEM-768 constants
const ML_KEM_PUBLIC_KEY_BYTES  = 1184;
const ML_KEM_CIPHERTEXT_BYTES  = 1088;

// ML-DSA-65 constants
const ML_DSA_PUBLIC_KEY_BYTES  = 1952;
const ML_DSA_SIGNATURE_BYTES   = 3309;

// V1 ClientHello: [1B version][32B ecdhPub][32B sessionSalt] = 65 bytes
const CLIENT_HELLO_V1_BYTES = 1 + 32 + 32;

// V2 ClientHello: [1B version][32B ecdhPub][32B sessionSalt][1184B kemPub] = 1249 bytes
const CLIENT_HELLO_V2_BYTES = 1 + 32 + 32 + ML_KEM_PUBLIC_KEY_BYTES;

// V2 ServerHello: [1B version][1088B kemCiphertext][3309B signature][32B keyCommit] = 4430 bytes
const SERVER_HELLO_V2_BYTES = 1 + ML_KEM_CIPHERTEXT_BYTES + ML_DSA_SIGNATURE_BYTES + KEY_COMMIT_BYTES;

// ─── Types ────────────────────────────────────────────────────────────────────

export interface SPDServerIdentity {
  /** Curve25519 public key — distribute to clients out-of-band. */
  publicKey:  Uint8Array;
  /** Curve25519 private key — keep secret, never transmit. */
  privateKey: Uint8Array;
  /** Optional ML-DSA-65 signing private key for certificate authentication. */
  signingPrivKey?: Uint8Array;
  /** Optional ML-DSA-65 signing public key — pin this on the client side. */
  signingPubKey?:  Uint8Array;
}

/** Options for `clientConnect`. */
export interface SPDClientConnectOptions {
  /**
   * Use V2 protocol (ML-KEM hybrid).  Default: true when server supports it.
   * Set to false to force V1 (legacy interop).
   */
  v2?: boolean;
  /**
   * Pinned ML-DSA-65 public key.  When set, the client will verify the
   * server's signature in the ServerHello and reject if verification fails.
   */
  pinnedSigningKey?: Uint8Array;
  /**
   * Pre-shared key (exactly 32 bytes) mixed into session key derivation.
   * Provides an extra secret layer for PSK session resumption.
   */
  psk?: Uint8Array;
  /**
   * Enable frame padding to hide payload sizes (traffic analysis resistance).
   * Pads plaintext to the next multiple of 64 bytes before encryption.
   * Default: false.
   */
  padding?: boolean;
}

/**
 * Transport-agnostic byte I/O for `SPDTransport.connect`/`accept`. Implement
 * this over whatever real channel you have — a WebSocket, a TCP socket, an
 * HTTP long-poll exchange — and `connect`/`accept` drive the handshake
 * round-trip for you instead of you manually shuttling `clientHello`/
 * `serverHello` and remembering to call `processServerHello`.
 *
 * `send`/`receive` are called exactly once each per handshake for V1, and
 * (send, receive) then possibly nothing further for V2 client-side, or
 * (receive, send) for V2 server-side — `connect`/`accept` never call them
 * more than the protocol actually requires.
 */
export interface SPDTransportIo {
  /** Send raw bytes to the other party. */
  send(bytes: Uint8Array): void | Promise<void>;
  /** Receive the next raw byte payload from the other party. */
  receive(): Uint8Array | Promise<Uint8Array>;
}

/**
 * A live, established session between two peers.
 * Maintains independent monotonic counters for each direction.
 */
export interface SPDSession {
  /**
   * Encrypt `plaintext` for transmission in this session's direction.
   * Returns a self-contained frame: [1B version][8B counter][ciphertext+tag]
   * Nonce is derived from counter (not transmitted) to save 24 bytes per frame.
   */
  encrypt(plaintext: Uint8Array): Uint8Array;

  /**
   * Decrypt a frame received from the remote peer.
   * Throws if the tag is invalid, the version is wrong, or the counter is
   * outside the 1024-entry sliding replay window.
   */
  decrypt(frame: Uint8Array): Uint8Array;

  /**
   * Serialize `spd` to its binary format in memory and encrypt the result as a
   * single transport frame.  The SPD is NOT written to disk.
   */
  wrapSPD(spd: SPD, passcode: string): Promise<Uint8Array>;

  /**
   * Decrypt a frame produced by `wrapSPD` and load the embedded SPD binary.
   * Returns a ready-to-use SPD instance.
   */
  unwrapSPD(frame: Uint8Array, passcode: string): Promise<SPD>;

  /**
   * Export a 32-byte PSK derived from the session key material.
   * Store this to enable fast PSK resumption on the next connection.
   */
  exportPSK(): Uint8Array;

  /**
   * Bytes remaining on the send counter before `encrypt()` starts throwing
   * ("nonce counter exhausted — re-key required"). The counter is a 64-bit
   * monotonic value, so exhaustion at real-world message rates is not a
   * practical concern for the overwhelming majority of sessions — this
   * exists so a long-lived session (e.g. a persistent server connection
   * open for months, processing many messages per second) can proactively
   * re-key on its own schedule instead of discovering exhaustion as a
   * thrown error mid-stream. Compare against `isNearExhaustion()` for a
   * simple boolean check instead of picking your own threshold.
   */
  sendCounterRemaining(): bigint;

  /**
   * True once fewer than `thresholdFraction` (default 1%) of the send
   * counter's total range remains. When this flips true, perform a fresh
   * `SPDTransport.connect`/`accept` (or `clientConnect`/`serverAccept`)
   * handshake and switch the caller's read/write paths to the new session
   * well before the old one would start throwing.
   */
  isNearExhaustion(thresholdFraction?: number): boolean;

  /** Zero all session key material.  Call when the session is complete. */
  destroy(): void;
}

// ─── Internal session implementation ─────────────────────────────────────────

class SPDSessionImpl implements SPDSession {
  private _c2sKey: Uint8Array;   // client→server encryption key
  private _s2cKey: Uint8Array;   // server→client encryption key
  private _sendKey: Uint8Array;  // whichever direction this peer sends
  private _recvKey: Uint8Array;  // whichever direction this peer receives
  private _pskExport: Uint8Array; // exportable PSK derived during handshake
  private _sendCounter = BigInt(0);
  // Sliding window replay protection
  private _recvHighWater = BigInt(-1);  // highest counter seen
  private _recvWindow    = BigInt(0);   // bitmask: bit i set → (highWater-i) seen
  private _padding: boolean;

  constructor(
    c2sKey: Uint8Array,
    s2cKey: Uint8Array,
    isClient: boolean,
    pskExport: Uint8Array,
    padding = false
  ) {
    this._c2sKey    = c2sKey;
    this._s2cKey    = s2cKey;
    this._sendKey   = isClient ? c2sKey : s2cKey;
    this._recvKey   = isClient ? s2cKey : c2sKey;
    this._pskExport = pskExport;
    this._padding   = padding;
  }

  /** Build a 24-byte XChaCha20 nonce from an 8-byte counter (counter in bytes 0-7, zeros in 8-23). */
  private static buildNonce(counter: bigint): Uint8Array {
    const nonce = new Uint8Array(XCHACHA_NONCE_BYTES);
    const view  = new DataView(nonce.buffer);
    view.setBigUint64(0, counter, false); // big-endian, bytes 0-7
    // bytes 8-23 remain zero
    return nonce;
  }

  sendCounterRemaining(): bigint {
    const max = 2n ** 64n - 1n;
    return this._sendCounter >= max ? 0n : max - this._sendCounter;
  }

  isNearExhaustion(thresholdFraction = 0.01): boolean {
    if (thresholdFraction <= 0 || thresholdFraction > 1) {
      throw new Error('SPDSession: thresholdFraction must be in (0, 1]');
    }
    const max = 2n ** 64n - 1n;
    // bigint has no native float multiply — scale thresholdFraction to an
    // integer numerator/denominator pair instead of losing precision to a
    // Number(max) round-trip (max is ~1.8e19, well past Number's exact-
    // integer range of 2^53).
    const denom = 1_000_000n;
    const numer = BigInt(Math.round(thresholdFraction * Number(denom)));
    const thresholdCount = (max * numer) / denom;
    return this.sendCounterRemaining() <= thresholdCount;
  }

  encrypt(plaintext: Uint8Array): Uint8Array {
    if (!this._sendKey) throw new Error('SPDSession: already destroyed');
    // Guard against nonce counter wrap-around.  XChaCha20 uses a 192-bit nonce
    // but we only fill the first 64 bits from the counter; once exhausted the
    // same (key, nonce) pair would be reused, breaking confidentiality and
    // integrity irrecoverably.
    if (this._sendCounter >= (2n ** 64n - 1n)) {
      throw new Error('SPDSession: nonce counter exhausted — re-key required');
    }

    const counter    = this._sendCounter++;
    const counterBuf = u8Alloc(8);
    writeBigUInt64BE(counterBuf, counter);
    const nonce = SPDSessionImpl.buildNonce(counter);

    // Optional padding: prepend 2-byte original length, pad to multiple of FRAME_PAD_BLOCK
    let msg: Uint8Array;
    if (this._padding) {
      const lenBuf = u8Alloc(2);
      const origLen = plaintext.length;
      if (origLen > 0xfffd) throw new Error('SPDSession: plaintext too large for padded frame');
      writeUInt16BE(lenBuf, origLen);
      const combined = concatBytes(lenBuf, plaintext);
      const padded   = combined.length % FRAME_PAD_BLOCK === 0
        ? combined
        : concatBytes(combined, u8Alloc(FRAME_PAD_BLOCK - (combined.length % FRAME_PAD_BLOCK)));
      msg = padded;
    } else {
      msg = plaintext;
    }

    const ct = plainAeadEncrypt(msg, null, nonce, this._sendKey);

    // Frame: [1B version][8B counter BE][ciphertext+tag]  (nonce is NOT sent — rebuilt from counter)
    return concatBytes(
      new Uint8Array([TRANSPORT_VERSION]),
      counterBuf,
      ct,
    );
  }

  decrypt(frame: Uint8Array): Uint8Array {
    if (!this._recvKey) throw new Error('SPDSession: already destroyed');
    // Minimum: 1 (version) + 8 (counter) + 0 (empty plaintext) + 16 (Poly1305 tag)
    if (frame.length < 1 + 8 + POLY1305_TAG_BYTES) {
      throw new Error('SPDSession: frame too short');
    }

    let offset = 0;
    const version = frame[offset++];
    if (version !== TRANSPORT_VERSION) {
      throw new Error(`SPDSession: unsupported frame version ${version}`);
    }

    const counter = readBigUInt64BE(frame, offset); offset += 8;
    const ct      = frame.subarray(offset);

    // ── Sliding window replay protection ────────────────────────────────────
    // Compute the window check/update but do NOT commit it (_recvWindow/
    // _recvHighWater) until AFTER the AEAD tag is verified below. Committing
    // first would let an attacker who can inject frames (without breaking
    // the cipher) mark a counter "seen" via a forged/corrupted frame, then
    // have a later legitimate retransmission at that same counter wrongly
    // rejected as a replay — a real frame dropped because of a fake one.
    const hw = this._recvHighWater;
    let newWindow: bigint;
    let newHighWater: bigint;
    if (counter > hw) {
      const advance = counter - hw;
      newWindow = advance >= REPLAY_WINDOW_SIZE
        ? BigInt(1)                              // reset window, mark slot 0 (current)
        : (this._recvWindow << advance) | BigInt(1);
      newHighWater = counter;
    } else {
      const age = hw - counter;
      if (age >= REPLAY_WINDOW_SIZE) {
        throw new Error(`SPDSession: replay detected — counter ${counter} outside window`);
      }
      const bit = BigInt(1) << age;
      if (this._recvWindow & bit) {
        throw new Error(`SPDSession: replay detected — counter ${counter} already seen`);
      }
      newWindow = this._recvWindow | bit;
      newHighWater = hw;
    }

    const nonce = SPDSessionImpl.buildNonce(counter);

    let plain: Uint8Array;
    try {
      plain = plainAeadDecrypt(new Uint8Array(ct), null, nonce, this._recvKey);
    } catch {
      throw new Error('SPDSession: authentication failed — possible tampering or wrong session key');
    }

    // Authenticated — now safe to commit the replay-window update.
    this._recvWindow = newWindow;
    this._recvHighWater = newHighWater;

    // Strip padding if enabled: read 2-byte length prefix
    if (this._padding) {
      if (plain.length < 2) throw new Error('SPDSession: padded frame too short');
      const origLen = (plain[0] << 8) | plain[1];
      if (origLen + 2 > plain.length) throw new Error('SPDSession: invalid padding length');
      return plain.subarray(2, 2 + origLen);
    }

    return plain;
  }

  async wrapSPD(spd: SPD, passcode: string): Promise<Uint8Array> {
    // Genuinely in-memory — no temp file. Previously wrote `spd` to a real
    // temp file via saveToFileStreaming() and read it back despite this
    // method's own doc comment claiming "the SPD is NOT written to disk";
    // that also meant this method (and unwrapSPD) always threw on the
    // browser build (spd-lib/browser), where fs/os/path are unavailable
    // by design, even though wrapping an SPD payload for transport has no
    // real need to touch a filesystem. saveData()/loadFromString() already
    // do the same buildSerializedPayload()/parseSerializedPayload() work
    // SPD.ts uses for file I/O, just returning/accepting base64 in memory.
    const bytes = base64ToBytes(await spd.saveData(passcode));
    return this.encrypt(bytes);
  }

  async unwrapSPD(frame: Uint8Array, passcode: string): Promise<SPD> {
    // See wrapSPD's comment — same fix, same reasoning.
    const bytes = this.decrypt(frame);
    return await SPD.loadFromString(bytesToBase64(bytes), passcode);
  }

  exportPSK(): Uint8Array {
    if (!this._pskExport) throw new Error('SPDSession: already destroyed');
    return new Uint8Array(this._pskExport);
  }

  destroy(): void {
    if (this._c2sKey)    (this._c2sKey).fill(0);
    if (this._s2cKey)    (this._s2cKey).fill(0);
    if (this._pskExport) (this._pskExport).fill(0);
    (this as any)._c2sKey      = undefined;
    (this as any)._s2cKey      = undefined;
    (this as any)._sendKey     = undefined;
    (this as any)._recvKey     = undefined;
    (this as any)._pskExport   = undefined;
    (this as any)._recvWindow  = undefined;
  }
}

// ─── Key derivation ────────────────────────────────────────────────────────────

/**
 * HKDF-SHA3-512: derive two independent 32-byte session keys from combined IKM.
 *
 * PRK    = HMAC-SHA3-512(salt=sessionSalt, IKM=ikm)
 * c2sKey = HMAC-SHA3-512(PRK, LABEL_C2S || 0x01)[0..32)
 * s2cKey = HMAC-SHA3-512(PRK, LABEL_S2C || 0x01)[0..32)
 * psk    = HMAC-SHA3-512(PRK, LABEL_PSK || 0x01)[0..32)
 */
function deriveSessionKeys(
  ikm: Uint8Array,
  sessionSalt: Uint8Array
): { c2sKey: Uint8Array; s2cKey: Uint8Array; pskExport: Uint8Array } {
  const prk = crypto
    .createHmac('sha3-512', sessionSalt)
    .update(ikm)
    .update(LABEL_KDF)
    .digest();

  const c2s = crypto
    .createHmac('sha3-512', prk)
    .update(concatBytes(LABEL_C2S, new Uint8Array([0x01])))
    .digest()
    .subarray(0, 32);

  const s2c = crypto
    .createHmac('sha3-512', prk)
    .update(concatBytes(LABEL_S2C, new Uint8Array([0x01])))
    .digest()
    .subarray(0, 32);

  const psk = crypto
    .createHmac('sha3-512', prk)
    .update(concatBytes(LABEL_PSK, new Uint8Array([0x01])))
    .digest()
    .subarray(0, 32);

  prk.fill(0);
  return {
    c2sKey:    new Uint8Array(c2s),
    s2cKey:    new Uint8Array(s2c),
    pskExport: new Uint8Array(psk),
  };
}

/**
 * Derive the 32-byte key commitment token appended to ServerHello.
 * Allows the client to verify that server-derived keys match its own derivation.
 *
 * commitment = HMAC-SHA3-256(c2sKey || s2cKey, LABEL_KEY_COMMIT)[0..32)
 */
function deriveKeyCommitment(c2sKey: Uint8Array, s2cKey: Uint8Array): Uint8Array {
  const commitKey = concatBytes(c2sKey, s2cKey);
  const out = crypto.createHmac('sha3-256', commitKey).update(LABEL_KEY_COMMIT).digest();
  commitKey.fill(0);
  return out;
}

/**
 * Mix a PSK into the session IKM using HKDF-style extraction.
 * pskMixed = HMAC-SHA3-512(key=psk, data=LABEL_PSK || ikm)[0..ikm.length)
 */
function mixPSK(ikm: Uint8Array, psk: Uint8Array): Uint8Array {
  const mixed = crypto
    .createHmac('sha3-512', psk)
    .update(LABEL_PSK)
    .update(ikm)
    .digest();
  // XOR the HMAC output into the IKM (truncated or extended as needed)
  const out = u8Alloc(ikm.length);
  for (let i = 0; i < ikm.length; i++) {
    out[i] = ikm[i] ^ mixed[i % mixed.length];
  }
  return out;
}

/** A PSK, when given, must be exactly 32 bytes (what `exportPSK()` returns). */
function assertPsk(psk: Uint8Array | undefined): void {
  if (psk === undefined) return;
  if (!(psk instanceof Uint8Array) || psk.length !== 32) {
    throw new Error(
      `SPDTransport: PSK must be exactly 32 bytes (got ${psk instanceof Uint8Array ? psk.length : typeof psk})`
    );
  }
}

// ─── SPDTransport static API ──────────────────────────────────────────────────

export class SPDTransport {

  // ── Strict mode ───────────────────────────────────────────────────────────

  /**
   * When strict mode is enabled, `serverAccept` will reject any V2 ClientHello
   * unless the server identity has a signing key pair (ML-DSA-65), and the
   * server will always include a real signature in the ServerHello.
   * `clientConnect` likewise refuses to start without `pinnedSigningKey`
   * (and refuses V1, which has no signature): an unpinned client cannot tell a
   * signed ServerHello from an unsigned one, so it would silently accept a
   * session authenticated only by the server's classical Curve25519 key.
   */
  private static _strictMode = false;

  static setStrictMode(enabled: boolean): void {
    SPDTransport._strictMode = enabled;
  }

  static isStrictMode(): boolean {
    return SPDTransport._strictMode;
  }

  /**
   * When enabled (the default, as of v2), `serverAccept` rejects any V1
   * ClientHello (classical-only Curve25519 ECDH, no ML-KEM-768 hybrid) —
   * every session is forced onto the V2 hybrid path. Independent of
   * `setStrictMode` (which only concerns ML-DSA-65 signature enforcement
   * within V2).
   *
   * Previously defaulted to `false`: `serverAccept` silently auto-dispatched
   * to V1 for any V1-shaped hello, so a server intending to guarantee
   * harvest-now-decrypt-later resistance (this class's own documented
   * threat-model claim) had no way to actually enforce it by default — any
   * client, or an active downgrade attacker who simply sent a
   * stripped-down V1 hello, silently got a classical-only session instead,
   * with nothing in the README pointing at this flag at all. Flipped to
   * default-safe: quantum-resistant hybrid sessions are now what you get
   * without doing anything, matching the "post-quantum-hardened" framing
   * this whole library is built around. Call `setRequireV2(false)` if you
   * genuinely need V1 interop with an old peer that predates the hybrid
   * handshake — that's the only reason to turn this off.
   */
  private static _requireV2 = true;

  static setRequireV2(enabled: boolean): void {
    SPDTransport._requireV2 = enabled;
  }

  static isRequireV2(): boolean {
    return SPDTransport._requireV2;
  }

  // ── Server identity ───────────────────────────────────────────────────────

  /**
   * Generate a long-term Curve25519 server identity key pair.
   * Store `privateKey` securely (e.g. in a hardware key store or SPD vault).
   * Distribute `publicKey` to clients out-of-band.
   */
  static async generateServerIdentity(): Promise<SPDServerIdentity> {
    const kp = kxKeypair();
    return {
      publicKey:  kp.publicKey,
      privateKey: kp.privateKey,
    };
  }

  /**
   * Generate an ML-DSA-65 certificate key pair for server signing.
   * Set `signingPrivKey` + `signingPubKey` on the server identity, and
   * distribute `publicKey` to clients as a pinned cert.
   */
  static generateCertKeyPair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
    const seed = crypto.randomBytes(32);
    const kp   = ml_dsa65.keygen(seed);
    seed.fill(0);
    return { privateKey: kp.secretKey, publicKey: kp.publicKey };
  }

  /**
   * Save a server identity to files:
   *   `<path>.pub`  (Curve25519 public key, safe to distribute)
   *   `<path>.key`  (Curve25519 private key, mode 0600)
   *   `<path>.cert` (ML-DSA-65 public key, safe to distribute; optional)
   *   `<path>.csig` (ML-DSA-65 private key, mode 0600; optional)
   */
  static saveServerIdentity(basePath: string, identity: SPDServerIdentity): void {
    const fs = getFs();
    fs.writeFileSync(basePath + '.pub',  identity.publicKey,  { mode: 0o644 });
    fs.writeFileSync(basePath + '.key',  identity.privateKey, { mode: 0o600 });
    if (identity.signingPubKey)  fs.writeFileSync(basePath + '.cert', identity.signingPubKey,  { mode: 0o644 });
    if (identity.signingPrivKey) fs.writeFileSync(basePath + '.csig', identity.signingPrivKey, { mode: 0o600 });
  }

  /**
   * Load a server identity previously saved with `saveServerIdentity`.
   */
  static loadServerIdentity(basePath: string): SPDServerIdentity {
    const fs = getFs();
    const identity: SPDServerIdentity = {
      publicKey:  new Uint8Array(fs.readFileSync(basePath + '.pub')),
      privateKey: new Uint8Array(fs.readFileSync(basePath + '.key')),
    };
    try { identity.signingPubKey  = new Uint8Array(fs.readFileSync(basePath + '.cert')); } catch {}
    try { identity.signingPrivKey = new Uint8Array(fs.readFileSync(basePath + '.csig')); } catch {}
    return identity;
  }

  // ── Client side ──────────────────────────────────────────────────────────

  /**
   * Initiate a new V2 session as the client (ML-KEM-768 hybrid + optional PSK + cert pinning).
   *
   * Returns `{ session, clientHello }`.  After receiving the ServerHello, call
   * `await session.processServerHello(serverHello)` to complete the handshake.
   *
   * @param serverPublicKey  The server's Curve25519 long-term public key.
   * @param options          Optional: pinnedSigningKey, psk, v2 flag.
   */
  static async clientConnect(
    serverPublicKey: Uint8Array,
    options?: SPDClientConnectOptions
  ): Promise<{ session: SPDClientHandshake; clientHello: Uint8Array }> {

    const useV2 = options?.v2 !== false; // default V2
    assertPsk(options?.psk);
    if (SPDTransport._strictMode && (!useV2 || !options?.pinnedSigningKey)) {
      throw new Error(
        'SPDTransport: strict mode requires the client to pin the server signing key (ML-DSA-65) and use V2'
      );
    }

    if (!useV2) {
      // V1 legacy path — V1 has no ServerHello step, so the returned session
      // is immediately usable. Wrapped in V1SessionAsClientHandshake (rather
      // than force-cast via `as any`) so the declared return type here is
      // honest: `.session` really does satisfy SPDClientHandshake, with
      // `processServerHello` throwing a clear error instead of silently
      // doing nothing if a caller mistakenly calls it on a V1 session.
      const { session, clientHello } = await SPDTransport._clientConnectV1(serverPublicKey, options?.psk);
      return { session: new V1SessionAsClientHandshake(session), clientHello };
    }

    // 1. Generate ephemeral Curve25519 key pair
    const ecdhEphemeral = kxKeypair();

    // 2. Generate ephemeral ML-KEM-768 key pair
    const kemSeed        = crypto.randomBytes(64);
    const kemEphemeral   = ml_kem768.keygen(kemSeed);
    kemSeed.fill(0); // the seed alone reconstructs the KEM secret key

    // 3. Fresh session salt
    const sessionSalt = crypto.randomBytes(32);

    // 4. Compute ECDH shared secret (client side)
    const ecdhKeys = kxClientSessionKeys(
      ecdhEphemeral.publicKey,
      ecdhEphemeral.privateKey,
      serverPublicKey
    );

    // 5. Build ClientHello V2: [1B version][32B ecdhPub][32B sessionSalt][1184B kemPub]
    const clientHello = concatBytes(
      new Uint8Array([TRANSPORT_VERSION_V2]),
      ecdhEphemeral.publicKey,
      sessionSalt,
      kemEphemeral.publicKey,
    );

    // Return a handshake object; session keys finalized after serverHello
    const handshake = new SPDClientHandshakeImpl(
      ecdhEphemeral,
      kemEphemeral,
      ecdhKeys,
      sessionSalt,
      clientHello,
      serverPublicKey,
      options?.pinnedSigningKey,
      options?.psk,
      options?.padding ?? false
    );

    // Zero ECDH ephemeral private now (KEM secret kept until serverHello)
    (ecdhEphemeral.privateKey).fill(0);

    return { session: handshake as unknown as SPDClientHandshake, clientHello };
  }

  /** V1 legacy clientConnect */
  private static async _clientConnectV1(
    serverPublicKey: Uint8Array,
    psk?: Uint8Array
  ): Promise<{ session: SPDSession; clientHello: Uint8Array }> {
    const ecdhEphemeral = kxKeypair();
    const sessionSalt   = crypto.randomBytes(32);

    const ecdhKeys = kxClientSessionKeys(
      ecdhEphemeral.publicKey,
      ecdhEphemeral.privateKey,
      serverPublicKey
    );

    // Typed as the general `Uint8Array` (not the narrower type @noble/hashes'
    // concatBytes() infers, Uint8Array<ArrayBuffer>) — the `let` would
    // otherwise lock in that narrower type from the first assignment,
    // rejecting mixPSK()'s plain `Uint8Array` return on reassignment. Found
    // via a real build break after upgrading @noble/hashes (2.0.1 -> 2.4.0)
    // tightened concatBytes' inferred return type; not present at 2.0.1.
    const ikm0: Uint8Array = concatBytes(ecdhKeys.sharedTx, ecdhKeys.sharedRx);
    const ikm: Uint8Array = psk ? mixPSK(ikm0, psk) : ikm0;

    const { c2sKey, s2cKey, pskExport } = deriveSessionKeys(ikm, sessionSalt);
    ikm.fill(0);
    ikm0.fill(0);

    (ecdhEphemeral.privateKey).fill(0);
    (ecdhKeys.sharedTx).fill(0);
    (ecdhKeys.sharedRx).fill(0);

    const clientHello = concatBytes(
      new Uint8Array([TRANSPORT_VERSION]),
      ecdhEphemeral.publicKey,
      sessionSalt,
    );

    return { session: new SPDSessionImpl(c2sKey, s2cKey, true, pskExport), clientHello };
  }

  // ── Server side ──────────────────────────────────────────────────────────

  /**
   * Accept an incoming client connection (supports both V1 and V2 ClientHello).
   *
   * For V2: returns `{ session, serverHello }`.  Send `serverHello` to the client
   * so it can finalize key derivation.
   *
   * @param serverIdentity  The server's long-term key pair.
   * @param clientHello     The raw bytes sent by the client.
   * @param psk             Optional PSK (must match client's PSK for session to work).
   */
  static async serverAccept(
    serverIdentity: SPDServerIdentity,
    clientHello:    Uint8Array,
    psk?:           Uint8Array,
    padding?:       boolean
  ): Promise<{ session: SPDSession; serverHello?: Uint8Array }> {

    if (clientHello.length === 0) {
      throw new Error('SPDTransport: empty ClientHello');
    }
    assertPsk(psk);

    const version = clientHello[0];

    if (version === TRANSPORT_VERSION && clientHello.length === CLIENT_HELLO_V1_BYTES) {
      if (SPDTransport._requireV2) {
        throw new Error(
          'SPDTransport: V1 (classical-only) ClientHello rejected — setRequireV2(true) is enabled, ' +
          'every session must use the V2 hybrid (ML-KEM-768) handshake.'
        );
      }
      // V1 path
      const session = await SPDTransport._serverAcceptV1(serverIdentity, clientHello, psk);
      return { session };
    }

    if (version === TRANSPORT_VERSION_V2 && clientHello.length === CLIENT_HELLO_V2_BYTES) {
      // V2 path
      return SPDTransport._serverAcceptV2(serverIdentity, clientHello, psk, padding);
    }

    throw new Error(
      `SPDTransport: unrecognized ClientHello (version=${version}, length=${clientHello.length})`
    );
  }

  /** V1 legacy serverAccept */
  private static async _serverAcceptV1(
    serverIdentity: SPDServerIdentity,
    clientHello:    Uint8Array,
    psk?:           Uint8Array
  ): Promise<SPDSession> {
    let offset = 1; // skip version
    const clientEphemeralPub = new Uint8Array(clientHello.subarray(offset, offset + 32)); offset += 32;
    const sessionSalt        = clientHello.subarray(offset, offset + 32);

    const ecdhKeys = kxServerSessionKeys(
      serverIdentity.publicKey,
      serverIdentity.privateKey,
      clientEphemeralPub
    );

    // Server: sharedRx = client.sharedTx = c2s; sharedTx = client.sharedRx = s2c
    // See the client-side ikm declaration's comment for why this needs an
    // explicit `Uint8Array` annotation (concatBytes' inferred type narrowed
    // in @noble/hashes 2.1+, rejecting mixPSK's plain Uint8Array return).
    const ikm0: Uint8Array = concatBytes(ecdhKeys.sharedRx, ecdhKeys.sharedTx);
    const ikm: Uint8Array = psk ? mixPSK(ikm0, psk) : ikm0;

    const { c2sKey, s2cKey, pskExport } = deriveSessionKeys(ikm, sessionSalt);
    ikm.fill(0);
    ikm0.fill(0);

    (ecdhKeys.sharedTx).fill(0);
    (ecdhKeys.sharedRx).fill(0);

    return new SPDSessionImpl(c2sKey, s2cKey, false, pskExport);
  }

  /** V2 serverAccept: hybrid ECDH + ML-KEM, optional ML-DSA-65 signing */
  private static async _serverAcceptV2(
    serverIdentity: SPDServerIdentity,
    clientHello:    Uint8Array,
    psk?:           Uint8Array,
    padding?:       boolean
  ): Promise<{ session: SPDSession; serverHello: Uint8Array }> {
    let offset = 1; // skip version
    const clientEcdhPub = new Uint8Array(clientHello.subarray(offset, offset + 32)); offset += 32;
    const sessionSalt   = clientHello.subarray(offset, offset + 32);                 offset += 32;
    const clientKemPub  = new Uint8Array(clientHello.subarray(offset, offset + ML_KEM_PUBLIC_KEY_BYTES));

    // 1. ECDH shared secret (server side)
    const ecdhKeys = kxServerSessionKeys(
      serverIdentity.publicKey,
      serverIdentity.privateKey,
      clientEcdhPub
    );

    // 2. ML-KEM-768 encapsulate to client's ephemeral pub → (ciphertext, sharedSecret)
    const { cipherText: kemCT, sharedSecret: kemSS } = ml_kem768.encapsulate(clientKemPub);

    // 3. Combine ECDH + KEM IKM: sharedRx || sharedTx || kemSS
    //    Server: sharedRx = c2s, sharedTx = s2c
    // See the earlier ikm declarations' comments for why the explicit
    // `Uint8Array` annotation is needed (concatBytes' inferred type narrowed
    // in @noble/hashes 2.1+, rejecting mixPSK's plain Uint8Array return).
    const ikm0: Uint8Array = concatBytes(ecdhKeys.sharedRx, ecdhKeys.sharedTx, kemSS);
    kemSS.fill(0);

    // 4. Mix PSK if provided
    const ikm: Uint8Array = psk ? mixPSK(ikm0, psk) : ikm0;

    const { c2sKey, s2cKey, pskExport } = deriveSessionKeys(ikm, sessionSalt);
    ikm.fill(0);
    ikm0.fill(0);

    (ecdhKeys.sharedTx).fill(0);
    (ecdhKeys.sharedRx).fill(0);

    // 5. Build ServerHello: [1B version][1088B kemCT][3309B signature][32B keyCommit]
    //    Signature covers: SHA3-512(label ‖ ClientHello ‖ kemCT ‖ serverStaticPub ‖ keyCommit)
    if (SPDTransport._strictMode && !serverIdentity.signingPrivKey) {
      throw new Error('SPDTransport: strict mode requires server signing key (ML-DSA-65)');
    }
    const keyCommit = deriveKeyCommitment(c2sKey, s2cKey);
    let sigBytes: Uint8Array;
    if (serverIdentity.signingPrivKey) {
      const msgToSign = v2SignedTranscript(clientHello, kemCT, serverIdentity.publicKey, keyCommit);
      sigBytes = ml_dsa65.sign(msgToSign, serverIdentity.signingPrivKey);
    } else {
      sigBytes = new Uint8Array(ML_DSA_SIGNATURE_BYTES); // zeros = no signature
    }

    const serverHello = concatBytes(
      new Uint8Array([TRANSPORT_VERSION_V2]),
      kemCT,
      sigBytes,
      keyCommit,
    );

    return { session: new SPDSessionImpl(c2sKey, s2cKey, false, pskExport, padding), serverHello };
  }

  // ── High-level connect/accept (drives the handshake round-trip for you) ────

  /**
   * Wraps `io.receive()` with an optional deadline so a peer that never
   * replies (dropped connection, hung server, forgotten `send()` call on
   * the other side) fails with a clear, catchable error instead of leaving
   * `connect()`/`accept()` awaiting forever with no diagnostic.
   */
  private static async receiveWithTimeout(io: SPDTransportIo, timeoutMs: number | undefined, what: string): Promise<Uint8Array> {
    if (timeoutMs === undefined) return io.receive();
    let timer: ReturnType<typeof setTimeout>;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`SPDTransport: timed out after ${timeoutMs}ms waiting for ${what}`)), timeoutMs);
    });
    try {
      return await Promise.race([io.receive(), timeout]);
    } finally {
      clearTimeout(timer!);
    }
  }

  /**
   * `clientConnect`/`serverAccept` + `processServerHello` require the caller
   * to manually shuttle `clientHello`/`serverHello` bytes between the two
   * sides and know which handshake step comes next. `connect`/`accept` do
   * that plumbing for you: you provide `send`/`receive` functions that move
   * raw bytes over whatever real transport you have (WebSocket, TCP socket,
   * HTTP long-poll, etc.), and get back a ready-to-use `SPDSession` — no
   * V1-vs-V2 branching, no manual `processServerHello` call to remember.
   *
   * @param timeoutMs  Optional deadline for waiting on the peer's reply
   *   (V2 only — V1 has no reply to wait for). Omit for no timeout (waits
   *   indefinitely, matching the low-level API's behavior).
   */
  static connect(
    serverPublicKey: Uint8Array,
    io: SPDTransportIo,
    options?: SPDClientConnectOptions,
    timeoutMs?: number
  ): Promise<SPDSession> {
    return SPDTransport._connect(serverPublicKey, io, options, timeoutMs);
  }

  private static async _connect(
    serverPublicKey: Uint8Array,
    io: SPDTransportIo,
    options?: SPDClientConnectOptions,
    timeoutMs?: number
  ): Promise<SPDSession> {
    const { session, clientHello } = await SPDTransport.clientConnect(serverPublicKey, options);
    await io.send(clientHello);

    const useV2 = options?.v2 !== false;
    if (!useV2) {
      // V1 has no ServerHello to wait for — the handshake is complete as
      // soon as the ClientHello is sent; `session` is already a plain
      // SPDSession (not an SPDClientHandshake) in this branch.
      return session as SPDSession;
    }

    const serverHello = await SPDTransport.receiveWithTimeout(io, timeoutMs, 'ServerHello');
    const handshake = session as SPDClientHandshake;
    handshake.processServerHello(serverHello);
    return handshake;
  }

  /**
   * Server-side counterpart to `connect()`: waits for a ClientHello via
   * `io.receive()`, accepts it (V1 or V2, whichever the client sent), sends
   * a ServerHello back via `io.send()` if the handshake needs one (V2 only
   * — V1 has none), and returns the ready-to-use session.
   *
   * @param timeoutMs  Optional deadline for waiting on the client's
   *   ClientHello. Omit for no timeout.
   */
  static async accept(
    serverIdentity: SPDServerIdentity,
    io: SPDTransportIo,
    psk?: Uint8Array,
    padding?: boolean,
    timeoutMs?: number
  ): Promise<SPDSession> {
    const clientHello = await SPDTransport.receiveWithTimeout(io, timeoutMs, 'ClientHello');
    const { session, serverHello } = await SPDTransport.serverAccept(serverIdentity, clientHello, psk, padding);
    if (serverHello) await io.send(serverHello);
    return session;
  }

  // ── Utilities ─────────────────────────────────────────────────────────────

  /**
   * Convenience: generate a random 32-byte session token suitable for use as
   * an application-level session ID (e.g. HTTP cookie, WebSocket session key).
   */
  static generateSessionToken(): string {
    return bytesToBase64Url(crypto.randomBytes(32));
  }

  /**
   * Verify that a ClientHello buffer has the correct structure and version
   * without performing the full key exchange.
   */
  static validateClientHello(clientHello: Uint8Array): boolean {
    if (clientHello.length === CLIENT_HELLO_V1_BYTES && clientHello[0] === TRANSPORT_VERSION)  return true;
    if (clientHello.length === CLIENT_HELLO_V2_BYTES && clientHello[0] === TRANSPORT_VERSION_V2) return true;
    return false;
  }
}

// ─── Client handshake (V2) ────────────────────────────────────────────────────

/**
 * Intermediate object returned by `clientConnect` (V2).
 * Call `processServerHello(serverHello)` to finalize key derivation.
 * After that, use `encrypt` / `decrypt` normally.
 */
export interface SPDClientHandshake extends SPDSession {
  /**
   * Process the ServerHello received from the server and finalize session keys.
   * Must be called before `encrypt` or `decrypt`.
   * @param serverHello  Raw bytes received from `serverAccept`.
   */
  processServerHello(serverHello: Uint8Array): void;
}

/**
 * Wraps an already-complete V1 session so `clientConnect`'s return type can
 * honestly be `SPDClientHandshake` for both V1 and V2 without an `as any`
 * cast. V1 has no ServerHello step — the session is ready to use as soon as
 * the ClientHello is built — so every SPDSession method just delegates, and
 * `processServerHello` throws a clear error instead of silently no-op'ing
 * if a caller mistakenly calls it (e.g. after copy-pasting V2 usage code).
 */
class V1SessionAsClientHandshake implements SPDClientHandshake {
  constructor(private readonly inner: SPDSession) {}

  processServerHello(_serverHello: Uint8Array): void {
    throw new Error(
      'SPDTransport: processServerHello() called on a V1 session — V1 has no ServerHello step; ' +
      'the session returned by clientConnect({ v2: false }) is already usable, call encrypt/decrypt directly.'
    );
  }

  encrypt(plaintext: Uint8Array): Uint8Array      { return this.inner.encrypt(plaintext); }
  decrypt(frame: Uint8Array): Uint8Array          { return this.inner.decrypt(frame); }
  wrapSPD(spd: SPD, passcode: string)             { return this.inner.wrapSPD(spd, passcode); }
  unwrapSPD(frame: Uint8Array, passcode: string)  { return this.inner.unwrapSPD(frame, passcode); }
  exportPSK(): Uint8Array                         { return this.inner.exportPSK(); }
  sendCounterRemaining(): bigint                  { return this.inner.sendCounterRemaining(); }
  isNearExhaustion(thresholdFraction?: number): boolean { return this.inner.isNearExhaustion(thresholdFraction); }
  destroy(): void                                 { return this.inner.destroy(); }
}

class SPDClientHandshakeImpl implements SPDClientHandshake {
  private _ecdhEphemeral: { publicKey: Uint8Array; privateKey: Uint8Array };
  private _kemEphemeral:  { publicKey: Uint8Array; secretKey: Uint8Array };
  private _ecdhKeys:      { sharedTx: Uint8Array; sharedRx: Uint8Array };
  private _sessionSalt:   Uint8Array;
  private _pinnedSigningKey?: Uint8Array;
  private _psk?: Uint8Array;
  private _padding: boolean;
  private _clientHello: Uint8Array;
  private _serverStaticPub: Uint8Array;

  // These become set after processServerHello
  private _inner?: SPDSessionImpl;

  constructor(
    ecdhEphemeral: { publicKey: Uint8Array; privateKey: Uint8Array },
    kemEphemeral:  { publicKey: Uint8Array; secretKey: Uint8Array },
    ecdhKeys:      { sharedTx: Uint8Array; sharedRx: Uint8Array },
    sessionSalt:   Uint8Array,
    clientHello:   Uint8Array,
    serverStaticPub: Uint8Array,
    pinnedSigningKey?: Uint8Array,
    psk?: Uint8Array,
    padding = false
  ) {
    this._clientHello      = clientHello;
    this._serverStaticPub  = serverStaticPub;
    this._ecdhEphemeral    = ecdhEphemeral;
    this._kemEphemeral     = kemEphemeral;
    this._ecdhKeys         = ecdhKeys;
    this._sessionSalt      = sessionSalt;
    this._pinnedSigningKey = pinnedSigningKey;
    this._psk              = psk;
    this._padding          = padding;
  }

  processServerHello(serverHello: Uint8Array): void {
    if (this._inner) throw new Error('SPDTransport: processServerHello already called for this session');
    if (serverHello.length !== SERVER_HELLO_V2_BYTES) {
      throw new Error(
        `SPDTransport: invalid ServerHello length ${serverHello.length} (expected ${SERVER_HELLO_V2_BYTES})`
      );
    }

    let offset = 0;
    const version = serverHello[offset++];
    if (version !== TRANSPORT_VERSION_V2) {
      throw new Error(`SPDTransport: unsupported ServerHello version ${version}`);
    }

    const kemCT = new Uint8Array(serverHello.subarray(offset, offset + ML_KEM_CIPHERTEXT_BYTES));
    offset += ML_KEM_CIPHERTEXT_BYTES;
    const sigBytes = new Uint8Array(serverHello.subarray(offset, offset + ML_DSA_SIGNATURE_BYTES));
    offset += ML_DSA_SIGNATURE_BYTES;
    const serverKeyCommit = serverHello.subarray(offset, offset + KEY_COMMIT_BYTES);

    // 1. Verify ML-DSA-65 signature if pinning key is set
    if (this._pinnedSigningKey) {
      const msgToVerify = v2SignedTranscript(this._clientHello, kemCT, this._serverStaticPub, serverKeyCommit);
      const valid = ml_dsa65.verify(sigBytes, msgToVerify, this._pinnedSigningKey);
      if (!valid) {
        throw new Error('SPDTransport: ML-DSA-65 certificate verification failed — possible MitM');
      }
    }

    // 2. ML-KEM-768 decapsulate: recover the shared secret
    const kemSS = ml_kem768.decapsulate(kemCT, this._kemEphemeral.secretKey);

    // 3. Combine ECDH + KEM IKM (client: sharedTx = c2s, sharedRx = s2c)
    // See the earlier ikm declarations' comments for why the explicit
    // `Uint8Array` annotation is needed (concatBytes' inferred type narrowed
    // in @noble/hashes 2.1+, rejecting mixPSK's plain Uint8Array return).
    const ikm0: Uint8Array = concatBytes(this._ecdhKeys.sharedTx, this._ecdhKeys.sharedRx, kemSS);
    kemSS.fill(0);

    // 4. Mix PSK
    const ikm: Uint8Array = this._psk ? mixPSK(ikm0, this._psk) : ikm0;

    const { c2sKey, s2cKey, pskExport } = deriveSessionKeys(ikm, this._sessionSalt);
    ikm.fill(0);
    ikm0.fill(0);

    // 5. Verify key commitment: ensure server derived the same session keys
    const clientKeyCommit = deriveKeyCommitment(c2sKey, s2cKey);
    if (!crypto.timingSafeEqual(clientKeyCommit, serverKeyCommit)) {
      throw new Error('SPDTransport: key commitment mismatch — possible MitM or derivation error');
    }

    // 6. Zero ephemeral key material
    (this._kemEphemeral.secretKey).fill(0);
    (this._ecdhKeys.sharedTx).fill(0);
    (this._ecdhKeys.sharedRx).fill(0);

    this._inner = new SPDSessionImpl(c2sKey, s2cKey, true, pskExport, this._padding);
  }

  private get inner(): SPDSessionImpl {
    if (!this._inner) throw new Error('SPDTransport: must call processServerHello before using session');
    return this._inner;
  }

  encrypt(plaintext: Uint8Array): Uint8Array      { return this.inner.encrypt(plaintext); }
  decrypt(frame: Uint8Array): Uint8Array          { return this.inner.decrypt(frame); }
  wrapSPD(spd: SPD, passcode: string)             { return this.inner.wrapSPD(spd, passcode); }
  unwrapSPD(frame: Uint8Array, passcode: string)  { return this.inner.unwrapSPD(frame, passcode); }
  exportPSK(): Uint8Array                         { return this.inner.exportPSK(); }
  sendCounterRemaining(): bigint                  { return this.inner.sendCounterRemaining(); }
  isNearExhaustion(thresholdFraction?: number): boolean { return this.inner.isNearExhaustion(thresholdFraction); }

  destroy(): void {
    if (this._kemEphemeral?.secretKey) {
      try { (this._kemEphemeral.secretKey).fill(0); } catch {}
    }
    if (this._ecdhKeys?.sharedTx) {
      try { (this._ecdhKeys.sharedTx).fill(0); } catch {}
      try { (this._ecdhKeys.sharedRx).fill(0); } catch {}
    }
    this._inner?.destroy();
    (this as any)._ecdhEphemeral = undefined;
    (this as any)._kemEphemeral  = undefined;
    (this as any)._ecdhKeys      = undefined;
    (this as any)._inner         = undefined;
  }
}
