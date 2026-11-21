import * as zlib from './internal/portable-zlib.js';
import * as crypto from './internal/portable-crypto.js';
import {
  utf8ToBytes, bytesToUtf8, concatBytes, bytesToHex, hexToBytes,
  bytesToBase64, base64ToBytes, bytesToBase64Url, base64UrlToBytes,
} from './internal/portable-crypto.js';
import {
  u8Alloc, u8Concat, u8Equals,
  writeUInt8, readUInt8,
  writeUInt16LE, readUInt16LE,
  writeUInt32LE, readUInt32LE, readUInt32BE,
  writeUIntLE3, readUIntLE3,
  writeBigUInt64LE, readBigUInt64LE, writeBigUInt64BE, readBigUInt64BE,
} from './internal/portable-binary.js';
import { signFileMac, verifyFileMac, signingKeyKind, verifyKeyKind, generateSigningKeyPair as generateFileSigningKeyPair } from './internal/spd-signature.js';
import { getFs, getPath, getOs, getWorkerThreads } from './internal/node-platform.js';
import { walHeader, encodeWalRecord, replayWalRecords } from './internal/spd-wal.js';
import { acquireLock, releaseLock, checkRollback, writeSeqCounter } from './internal/spd-lock.js';
import { generatePassphrase } from './internal/spd-passphrase.js';
import * as keyMaterial from './internal/spd-key-material.js';
import { serializeValue, deserializeValue } from './internal/spd-serialize.js';
import {
  derivePBK, deriveKeys, encryptSalt, decryptSalt, unlockKeys, keyCacheGet, keyCacheEvict,
  keyCacheSet, buildCacheKey, setKeyCacheTtl, clearKeyCache, computeKeyCommitment,
  computeCounterHMAC, buildMerkleRoot, computeMAC, setKeyProvider, deriveEntryKey, deriveNameKey,
  _encryptEntryName, _decryptEntryName, padForCompression, unpadAfterDecompression, aeadEncrypt,
  aeadDecrypt, _encodeKeylessSecret, _decodeKeylessSecret, generateRandomKey, SCRYPT_N_DEFAULT,
  SCRYPT_R_DEFAULT, SCRYPT_P_DEFAULT, ARGON2_MEMORY, ARGON2_TIME, ARGON2_MEMORY_STANDARD,
  ARGON2_TIME_STANDARD, ARGON2_HASH_LEN, ARGON2_SALT_LEN, AEAD_KEY_LEN, HMAC_KEY_LEN,
  ARGON2_MEMORY_HIGH, ARGON2_TIME_HIGH, ARGON2_MEMORY_PARANOID, ARGON2_TIME_PARANOID,
  KEYLESS_SENTINEL, KEYLESS_MASTER_SECRET_LEN, validateArgon2Params, validateScryptParams,
  assertSafeDecryptedName, keyCache, antiForensic,
} from './internal/spd-kdf.js';
export { ARGON2_MEMORY_HIGH, ARGON2_TIME_HIGH, ARGON2_MEMORY_PARANOID, ARGON2_TIME_PARANOID } from './internal/spd-kdf.js';
import {
  otpEncrypt, otpDecrypt, generateSalt, generateOtpKey, assertPhysicalKeyDistrib, requiresAirGap, isAirGapped, wrapTemporalKey, noiseInjection, assertKnowledgeSeparation, multiPadEncrypt, multiPadDecrypt, embedInCarrier, extractFromCarrier, startNoiseBaseline, timeSmear, generateQuantumKey, inflateEntropy, TIME_WINDOW_MS, PHYSICAL_KEY_CHANNEL, KNOWLEDGE_SEP, CHANNEL_NOISE, secureRandomInt,
} from './SPDUtils.js';
import { SPDRecipient } from './SPDRecipient.js';
import type * as fs from 'fs';
import {
  argon2idRaw,
  hkdfExpand as sharedHkdfExpand,
  aeadEncrypt as sharedAeadEncrypt,
  aeadDecrypt as sharedAeadDecrypt,
  plainAeadEncrypt,
  plainAeadDecrypt,
  padForCompression as sharedPadForCompression,
  unpadAfterDecompression as sharedUnpadAfterDecompression,
  deriveEntryKey as sharedDeriveEntryKey,
  checkPassphraseStrength,
} from './internal/spd-crypto.js';
import {
  buildEccSidecar, verifyWithEccSidecar, repairWithEccSidecar,
  type EccOptions,
} from './internal/spd-ecc.js';
import type {
  HashAlgorithm,
  SupportedDataType,
  EncryptedDataEntry,
  SPDPayload,
  WrappedPayload,
  PBKResult,
  EncryptedSaltResult,
  DataInput,
  SupportedValue,
  SPDChunkManifest,
  SPDIndexEntry,
  SPDGetEntryResult,
  SPDInspectResult,
  SPDVerifyResult,
  SPDDiffResult,
  SPDMergeOptions,
  SPDMergeResult,
  SPDSnapshot,
  SPDLogEvent,
  SPDBenchmarkResult,
  SPDRepairResult,
  SPDEccRepairResult,
  SPDKeyProvider,
  SPDSigningKeyPair,
} from './types.js';

// v29: KDF chaining (Argon2id→scrypt), key blinding, ML-DSA-65 file signatures,
//      per-entry Merkle tree, signed write counter, epoch key rotation, ratcheting,
//      configurable wrap-key params, HSM key provider interface, Shamir secret sharing
// v28: default profile raised to "high" (512 MiB/8 passes), 9-word passphrase default;
// v27: 96-byte Argon2id master secret, 64-byte HMAC key (double the v26 size),
//      SPDWriter streaming writer, on-demand getEntry with .spdi index sidecar,
//      Buffer.concat spread fix for large entry counts, deflateAsync for large values
const SPD_VERSION = 29;

// KDF chaining: scrypt parameters applied after Argon2id for `high` / `paranoid` profiles.
// N must be a power of 2; r=8, p=4 are paranoid-grade.
// N=131072 requires ~128 MiB and adds significant time cost — intentional for paranoid.




// Argon2id parameters — stored in every payload so future versions can always
// re-derive correctly even if defaults change.



// Standard profile params — used for salt-wrapping key derivation (profile-independent)
// These MUST NOT change; all existing files have their salt encrypted with these values.







// High-security Argon2id profile — use when deriving keys for long-lived secrets



// Paranoid Argon2id profile — 2 GiB / 16 passes + machine binding
// At 2 GiB per attempt: a 1M-GPU cluster spending the energy budget of
// a small nation still cannot exhaust even a 60-bit passcode space.



// ── Keyless mode (SPD.generateRandomKey / setRandomKey) ────────────────────
// A leading NUL byte (\0) can never appear in a string typed at a keyboard,
// pasted from a password manager, or produced by any realistic human input
// path — so a real passphrase can never collide with this prefix by
// accident. This is NOT a security boundary (derivePBK is only ever called
// from code already inside this trusted library — there is no attacker who
// benefits from "forging" this marker, since forging it just means supplying
// your own already-known secret through a faster path), it is purely an
// internal dispatch marker letting derivePBK recognize "this value is a raw
// high-entropy secret, skip Argon2id" without adding a hidden mode flag to
// any shared static function's signature or relying on mutable global state
// (the exact pattern that caused the KDF-param-tracking bug fixed earlier —
// see _argon2Memory/_argon2Time's doc comment). The dispatch is entirely
// self-contained inside derivePBK; every other function in the KDF chain
// (deriveKeys, encryptSalt, decryptSalt, changePasscode, ratchet, epoch
// rotation, upgradeKdfParams) is completely unmodified and unaware this
// mode exists — they just see a "passcode" string, as always.



/** Key stretching profile names */
export type SPDKeyProfile = 'standard' | 'high' | 'paranoid';

// ─── KDF-parameter bounds (defense against malicious/corrupted file metadata) ─
//
// argon2Memory/argon2Time/wrapArgon2Memory/wrapArgon2Time/scryptN/scryptR/
// scryptP/argon2Parallelism are all stored in the file's own (unauthenticated
// until the HMAC/MAC check later in the same load) JSON metadata block and
// read back out via `meta.xxx ?? DEFAULT` throughout the load/verify/repair
// paths. Before this validation existed, those values were passed straight
// into argon2idRaw/crypto.scrypt with NO bounds check — a crafted file could
// set e.g. wrapArgon2Memory to an extreme value and force a multi-GB
// allocation attempt the moment a caller with the CORRECT passcode tries to
// open it, before the file's authenticity is ever checked (decryptSalt/the
// wrap-key derivation runs before the HMAC verification in several paths).
// These bounds cap every KDF parameter to a generous-but-sane ceiling (well
// above the `paranoid` profile, which is the strongest profile this library
// itself ever produces) so a legitimate file — including hand-tuned
// setWrapArgon2Params()/enableKdfChain() overrides — always passes, while a
// maliciously-inflated value is rejected before it reaches the KDF.







/**
 * Registers a 'data' listener on a real Node `fs.ReadStream` for a callback
 * that only handles binary chunks. Node's own stream types declare 'data'
 * listeners as `(chunk: string | Buffer) => void` because `.setEncoding()`
 * can make a stream emit strings — but none of this codebase's read streams
 * ever call `.setEncoding()`, so every chunk they emit is genuinely always a
 * Buffer. This wrapper makes that assumption explicit and checked at
 * runtime (throwing a clear error if it's ever wrong) instead of silently
 * asserting the narrower callback type past the compiler with `as any`,
 * which would hide a real mistake if a future edit ever added
 * `.setEncoding()` upstream.
 */
function onBinaryData(stream: fs.ReadStream, cb: (chunk: Uint8Array) => void): void {
  stream.on('data', (chunk) => {
    if (typeof chunk === 'string') {
      throw new Error('onBinaryData: stream emitted a string chunk — .setEncoding() must not be used on this stream.');
    }
    cb(chunk);
  });
}




// For v26 files that used a 64-byte hash and 32-byte macKey
const ARGON2_HASH_LEN_V26 = 64;
const HMAC_KEY_LEN_V26    = 32;

/**
 * Resolves the Argon2id master-secret length and HMAC key length for a
 * loaded file's `version` field. v27 widened both (v26: 64/32, v27+: 96/64
 * — see the file-version-history comment near SPD_VERSION's definition).
 *
 * Deliberately factored out of every load-path call site (there were 7
 * near-identical `version >= 27 ? ARGON2_HASH_LEN : ARGON2_HASH_LEN_V26`
 * ternaries scattered across getEntry/merge/repair/both main loaders/both
 * streaming variants before this) — the same "duplicated logic across many
 * call sites" shape that caused the real, previously-fixed KDF-param-
 * tracking bug earlier in this codebase's history: any site that got missed
 * on a future version bump would silently derive keys at the wrong length
 * for files at the boundary, with no test catching it unless that exact
 * call site happened to be exercised (see test/legacy-format-compat.test.ts,
 * which is the first test that would have caught a mistake here).
 */
function legacyKeyLengthsForVersion(version: number | undefined): { argon2HashLen: number; macKeyLen: number } {
  const v = version ?? SPD_VERSION;
  return v >= 27
    ? { argon2HashLen: ARGON2_HASH_LEN, macKeyLen: HMAC_KEY_LEN }
    : { argon2HashLen: ARGON2_HASH_LEN_V26, macKeyLen: HMAC_KEY_LEN_V26 };
}

// Minimum SPD version that this build can read
const SPD_VERSION_MIN = 26;

// Index file magic bytes

// WAL file magic & record delimiter
const SPDX_MAGIC = new Uint8Array([0x53, 0x50, 0x44, 0x58]); // "SPDx" — legacy tail index (plaintext names; read-only)
const SPDY_MAGIC = new Uint8Array([0x53, 0x50, 0x44, 0x79]); // "SPDy" — tail index v2 (HMAC name tags)
const INDEX_TAG_BYTES = 16;
const INDEX_TAG_LABEL = 'spd-index-name-v2';

/** Maximum byte-length of a sanitized entry name (UTF-8). */
const MAX_NAME_BYTES = 255;

/**
 * Same charset `sanitizeName()` enforces at write time — used to validate a
 * name AFTER decryption (`_decryptEntryName`) before it's ever used to build
 * a filesystem path. Entry names are just AEAD-encrypted-then-authenticated
 * data, not schema-constrained the way values are — anyone who can produce
 * a validly-encrypted entry under the file's key (not necessarily the
 * library itself: e.g. a hand-crafted file, or a compromised peer in a
 * wrapSPD/unwrapSPD transport scenario) could otherwise set a decrypted
 * name to `../../../etc/passwd`-style path-traversal content, which
 * extractFromFileStreaming/extractDataStreaming then feed straight into
 * `path.join(tmpDir, name + '.ssf')` — an arbitrary-file-write/delete
 * primitive gated only by "knows the file's key," a materially weaker
 * trust boundary than "wrote this file through the public API."
 */


/**
 * Decodes a `SerializedDataEntry.nonce`/`.data` field, which is either a
 * base64 string (v2.0.1+, written by buildSerializedPayload) or the legacy
 * `number[]` shape (files written by older versions — one JS number per
 * byte, kept readable here for backward compatibility even though nothing
 * in this codebase writes that shape anymore). See SerializedDataEntry's
 * own doc comment in types.ts for why the number[] shape was replaced.
 */
function decodeEntryBytes(value: number[] | string): Uint8Array {
  return typeof value === 'string' ? base64ToBytes(value) : new Uint8Array(value);
}

/**
 * Decodes the outer `{ payload, mac }` wrapper's `payload` field, which is
 * the same base64-string-vs-legacy-number[] situation as
 * `decodeEntryBytes` — `payload` is the entire inner JSON-stringified
 * SPDPayload re-encoded as bytes, so at large file sizes it hit the exact
 * same array-length ceiling `decodeEntryBytes` was written to fix, just
 * one layer further out.
 */
function decodeWrappedPayload(value: number[] | string): Uint8Array {
  return typeof value === 'string' ? base64ToBytes(value) : new Uint8Array(value);
}

/** Key derivation cache TTL in milliseconds.
 *  Set to 0: key caching is disabled — derived keys are never held in memory
 *  beyond a single operation.  Eliminates the window during which a memory
 *  dump can recover the live AEAD key at the cost of re-running Argon2id on
 *  each getEntry() call.
 */


export class SPD {
  private data: EncryptedDataEntry[] = [];
  private keyPair?: { publicKey: Uint8Array };
  private userKey?: Uint8Array;   // 32-byte AEAD key
  private macKey?: Uint8Array;    // 32-byte HMAC key (domain-separated)
  private salt?: Uint8Array;
  private hash: HashAlgorithm = 'sha3-512';
  private compressionLevel: number = 6;  // level 6: ~3× faster than 9 with <5% size penalty
  private fileVersion: number = SPD_VERSION;
  private writeCounter: number = 0;  // monotonically incremented on every save
  private walPath?: string;           // path to the WAL file when enabled
  private walRecordCount: number = 0; // records written since last compaction
  private static readonly WAL_COMPACT_RECORDS = 500;  // auto-compact threshold (records)
  private static readonly WAL_COMPACT_BYTES   = 32 * 1024 * 1024; // 32 MiB

  // ── Entry ACL ─────────────────────────────────────────────────────────────
  private entryRoles: Map<string, string[]> = new Map();
  private currentRole: string | undefined;

  // ── Auto-destruct ─────────────────────────────────────────────────────────
  private maxOpenCount: number = 0;  // 0 = disabled
  private openCount: number = 0;

  // ── Schema validators ─────────────────────────────────────────────────────
  private schemas: Map<string, (v: unknown) => boolean> = new Map();

  // ── Passcode rotation audit log ────────────────────────────────────────────
  private _plogPath?: string;

  // ── Key stretching profile ─────────────────────────────────────────────────
  private keyProfile: SPDKeyProfile = 'high';

  // ── Key blinding (memory-safety: keys stored XORed with a random mask) ─────
  private _keyMask?: Uint8Array;
  private _blindedKey?: Uint8Array;
  private _blindedMacKey?: Uint8Array;
  private _keyBlindingEnabled = false;

  // ── Post-quantum file signatures (ML-DSA-65) ────────────────────────────────
  private _signingKey?: Uint8Array;
  private _verifyKey?: Uint8Array;

  // ── Forward-secrecy ratchet ─────────────────────────────────────────────────
  private _ratchetEnabled = false;

  // ── Epoch key rotation ───────────────────────────────────────────────────────
  private _epochSize = 0;   // 0 = disabled
  private _epochNumber = 0;

  // ── HSM / PKCS#11 key provider ──────────────────────────────────────────────

  // ── KDF chaining ────────────────────────────────────────────────────────────
  private _kdfChain: boolean | undefined; // undefined = profile default (scrypt chain only for 'paranoid')
  private _scryptN = SCRYPT_N_DEFAULT;
  private _scryptR = SCRYPT_R_DEFAULT;
  private _scryptP = SCRYPT_P_DEFAULT;

  // ── Argon2id parallelism (v29+: default 2 for new files) ────────────────────
  private _argon2Parallelism = 4;

  // ── Actual Argon2id cost params currently in effect ─────────────────────────
  // `keyProfile` is just a label (used to pick defaults in setPassKey); the
  // real memory/time this instance's keys were actually derived under is
  // tracked here instead, set on every load path AND on setPassKey. Without
  // this, changePasscode/upgradeKdfParams would have to re-derive "current"
  // params from `keyProfile` via profileParams() — which silently produces
  // the WRONG values for any file whose on-disk params don't match today's
  // profileParams() output for that profile name (e.g. a file saved by an
  // older library version with different profile constants) — exactly the
  // kind of drift a "keep this file secure for a very long time" feature
  // needs to not get wrong.
  private _argon2Memory = ARGON2_MEMORY_STANDARD;
  private _argon2Time   = ARGON2_TIME_STANDARD;

  // ── Wrap-key profile override ────────────────────────────────────────────────
  private _wrapArgon2Memory = ARGON2_MEMORY_STANDARD;
  private _wrapArgon2Time   = ARGON2_TIME_STANDARD;
  private _wrapArgon2Parallelism = 1;

  // ── Keyless mode (setRandomKey / setKeyfileOnly) ────────────────────────────
  // When true, this instance was unlocked with a raw machine-generated secret
  // rather than a human passcode. `_keylessSecretEncoded` holds the sentinel-
  // wrapped string form (see KEYLESS_SENTINEL) so save/load convenience
  // methods can pass it through the existing passcode-shaped plumbing
  // (buildBinaryPayload, encryptSalt, ratchet, epoch rotation, etc.) exactly
  // like an ordinary passphrase, with derivePBK transparently skipping
  // Argon2id for it. Never written to disk.
  private _keylessMode = false;
  private _keylessSecretEncoded: string | undefined;

  /** True while a rotation re-encrypts entries: addData then skips schema checks and WAL writes (values were already validated; the WAL must not mix keys). */
  private _rotating = false;

  /** Re-encrypts already-decrypted entries under the CURRENT keys into `this.data`, carrying decoys over unchanged. */
  private async _reencryptAll(items: Array<{ name: string; parsed: unknown }>, decoys: EncryptedDataEntry[]): Promise<void> {
    this._rotating = true;
    try {
      for (const item of items) await this.addData(item.name, item.parsed);
      this.data.push(...decoys);
    } finally {
      this._rotating = false;
    }
  }

  // ── Structured logger ─────────────────────────────────────────────────────
  private static globalLogger: ((e: SPDLogEvent) => void) | undefined;

  /**
   * Decompression cap for the whole-file zlib inflate of JSON-format `.spd`
   * files (`saveToFile`/`loadFromFile`, `saveData`/`loadFromString`,
   * `loadFromChunks`). That inflate runs BEFORE authentication, so without a
   * cap a few-KB crafted file could expand to many GiB (decompression bomb).
   * The binary streaming paths already abort early on their own limits.
   */
  static maxJsonInflateBytes = 1024 * 1024 * 1024; // 1 GiB

  // ── Key derivation cache ──────────────────────────────────────────────────
  // Caches derived {aeadKey, macKey} for 60 s keyed by hash(passcode + wrapSalt).
  // Eliminates repeated Argon2id work on rapid successive getEntry() calls.
  /** @internal test hook */
  private static get keyCache(): Map<string, unknown> { return keyCache; }

  /** See `internal/spd-kdf.ts` — keyCacheGet (moved; behaviour unchanged). */
  private static keyCacheGet = keyCacheGet;


  /** See `internal/spd-kdf.ts` — keyCacheEvict (moved; behaviour unchanged). */
  private static keyCacheEvict = keyCacheEvict;


  /** See `internal/spd-kdf.ts` — keyCacheSet (moved; behaviour unchanged). */
  private static keyCacheSet = keyCacheSet;


  /** See `internal/spd-kdf.ts` — unlockKeys (moved; behaviour unchanged). */
  private static unlockKeys = unlockKeys;


  /** See `internal/spd-kdf.ts` — buildCacheKey (moved; behaviour unchanged). */
  private static buildCacheKey = buildCacheKey;


  /** See `internal/spd-kdf.ts` — setKeyCacheTtl (moved; behaviour unchanged). */
  static setKeyCacheTtl = setKeyCacheTtl;


  /** See `internal/spd-kdf.ts` — clearKeyCache (moved; behaviour unchanged). */
  static clearKeyCache = clearKeyCache;


  // ── Name collision warnings ───────────────────────────────────────────────
  private static nameCollisionWarnings = false;

  /**
   * Enable developer warnings when two raw entry names map to the same
   * sanitized name (e.g. "user.id" and "user_id" → both become "user_id").
   * Logs to console.warn. Off by default to avoid noise in production.
   */
  static enableNameCollisionWarnings(): void {
    SPD.nameCollisionWarnings = true;
  }

  static disableNameCollisionWarnings(): void {
    SPD.nameCollisionWarnings = false;
  }

  // ── Structured logger ─────────────────────────────────────────────────────

  /**
   * Install a global log handler. Called for key lifecycle events so the host
   * app can feed SPD activity into its own observability pipeline.
   * Pass `undefined` to remove the handler.
   */
  static setLogger(fn: ((e: SPDLogEvent) => void) | undefined): void {
    SPD.globalLogger = fn;
  }

  private static log(event: SPDLogEvent['event'], detail?: Record<string, unknown>): void {
    if (SPD.globalLogger) {
      try { SPD.globalLogger({ event, ts: Date.now(), detail }); } catch { /* never throw from logging */ }
    }
  }

  // ─── Init guard ────────────────────────────────────────────────────────────

  private assertReady(): void {
    if (!this.userKey || !this.macKey || !this.salt) {
      throw new Error('SPD not initialized — call setPassKey() first.');
    }
  }

  async init(): Promise<void> {
  }

  // ─── Key blinding helpers ──────────────────────────────────────────────────

  /**
   * Enable in-memory key blinding: keys are stored XOR'd with a random mask.
   * This reduces the risk of key extraction from memory dumps or cold-boot attacks.
   * Must be called before `setPassKey()`.
   */
  /**
   * @deprecated No-op. XOR "blinding" of in-memory keys never provided a
   * measurable benefit in a managed runtime (mask and masked key live in the
   * same heap), and the previous implementation silently kept the OLD key
   * when an instance was re-keyed. Kept so existing callers keep working.
   */
  enableKeyBlinding(): void {
    this._keyBlindingEnabled = false;
  }

  disableKeyBlinding(): void {
    this._keyBlindingEnabled = false;
    // Unblind in place if currently blinded
    if (this._keyMask && this._blindedKey && this._blindedMacKey) {
      this.userKey = SPD._xorBufs(this._blindedKey, this._keyMask.subarray(0, this._blindedKey.length));
      this.macKey  = SPD._xorBufs(this._blindedMacKey, this._keyMask.subarray(this._blindedKey.length));
      this._blindedKey.fill(0);
      this._blindedMacKey.fill(0);
      this._keyMask.fill(0);
      this._keyMask = undefined;
      this._blindedKey = undefined;
      this._blindedMacKey = undefined;
    }
  }

  private static _xorBufs(a: Uint8Array, b: Uint8Array): Uint8Array {
    const out = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
    return out;
  }

  /** Blind the current userKey and macKey with a fresh random mask. */
  private _blindKeys(): void {
    if (!this._keyBlindingEnabled || !this.userKey || !this.macKey) return;
    // If already blinded, unblind first to get fresh keys
    if (this._blindedKey && this._keyMask) {
      this.userKey = SPD._xorBufs(this._blindedKey, this._keyMask.subarray(0, this._blindedKey.length));
      this.macKey  = SPD._xorBufs(this._blindedMacKey!, this._keyMask.subarray(this._blindedKey.length));
      this._blindedKey.fill(0);
      this._blindedMacKey!.fill(0);
    }
    const keyLen = this.userKey.length;
    const macLen = this.macKey.length;
    const mask = crypto.getRandomValues(new Uint8Array(keyLen + macLen));
    this._keyMask = mask;
    this._blindedKey    = SPD._xorBufs(this.userKey, mask.subarray(0, keyLen));
    this._blindedMacKey = SPD._xorBufs(this.macKey, mask.subarray(keyLen));
    // Zero the plaintext keys from memory
    this.userKey.fill(0);
    this.macKey.fill(0);
    this.userKey = undefined;
    this.macKey  = undefined;
  }

  /** Unblind keys into temporaries, run fn, then re-blind. */
  private _withKeys<T>(fn: (aeadKey: Uint8Array, macKey: Uint8Array) => T): T {
    if (!this._keyBlindingEnabled || !this._blindedKey) {
      // Not blinded — use directly
      return fn(this.userKey!, this.macKey!);
    }
    const keyLen = this._blindedKey.length;
    const mask   = this._keyMask!;
    const aeadKey = SPD._xorBufs(this._blindedKey, mask.subarray(0, keyLen));
    const macKey  = SPD._xorBufs(this._blindedMacKey!, mask.subarray(keyLen));
    let result: T;
    try {
      result = fn(aeadKey, macKey);
    } finally {
      aeadKey.fill(0);
      macKey.fill(0);
    }
    return result;
  }

  private async _withKeysAsync<T>(fn: (aeadKey: Uint8Array, macKey: Uint8Array) => Promise<T>): Promise<T> {
    if (!this._keyBlindingEnabled || !this._blindedKey) {
      return fn(this.userKey!, this.macKey!);
    }
    const keyLen  = this._blindedKey.length;
    const mask    = this._keyMask!;
    const aeadKey = SPD._xorBufs(this._blindedKey, mask.subarray(0, keyLen));
    const macKey  = SPD._xorBufs(this._blindedMacKey!, mask.subarray(keyLen));
    try {
      return await fn(aeadKey, macKey);
    } finally {
      aeadKey.fill(0);
      macKey.fill(0);
    }
  }

  // ─── New security API ──────────────────────────────────────────────────────

  /**
   * Set an ML-DSA-65 signing private key. When set, every `saveToFile` /
   * `saveToFileStreaming` call will embed an ML-DSA-65 signature over the file MAC.
   */
  setSigningKey(privateKey: Uint8Array): void {
    signingKeyKind(privateKey); // throws on a wrong-length key
    // Private copy: destroy() zeroes it, which must never wipe the caller's
    // key out from under them (it previously did, silently).
    this._signingKey = new Uint8Array(privateKey);
  }

  /**
   * Set an ML-DSA-65 verify public key. When set, `loadFromFile` /
   * `loadFromFileStreaming` will verify the embedded signature and reject
   * files that fail verification.
   */
  setVerifyKey(publicKey: Uint8Array): void {
    verifyKeyKind(publicKey); // throws on a wrong-length key
    this._verifyKey = new Uint8Array(publicKey);
  }

  /**
   * Generate a fresh file-signing key pair.
   *
   * Default: ML-DSA-65 (FIPS 204) — 4032-byte private key, 1952-byte public
   * key, 3309-byte signatures.
   *
   * `{ composite: true }`: ML-DSA-65 + Ed25519 hedged pair (after
   * draft-ietf-lamps-pq-composite-sigs) — 4064/1984-byte keys, 3373-byte
   * signatures. A composite signature verifies only if BOTH components verify,
   * so files stay unforgeable if either algorithm is broken. Readers must be
   * given the composite public key; an ML-DSA-only verify key rejects
   * composite signatures (and vice versa) rather than accepting a stripped one.
   */
  static generateSigningKeyPair(opts?: { composite?: boolean }): SPDSigningKeyPair {
    return generateFileSigningKeyPair(opts?.composite === true);
  }

  /** Enable the per-save ratchet. Each save derives a new sub-key from the previous. */
  enableRatchet(): void {
    this._ratchetEnabled = true;
  }

  disableRatchet(): void {
    this._ratchetEnabled = false;
  }

  /**
   * Set the epoch size: every `n` saves, a new random salt is derived and all
   * entries are re-encrypted under a fresh key. Pass 0 to disable.
   */
  setEpochSize(n: number): void {
    this._epochSize = Math.max(0, n);
  }

  /**
   * Enable KDF chaining: after Argon2id, pipe output through scrypt for
   * double-KDF protection. On by default only for the `paranoid` profile
   * (2.0.1: `high` no longer chains — it cost ≈1 GiB and several× the
   * unlock time on top of Argon2id 512 MiB for no change in the best known
   * attack); `disableKdfChain()` turns it off for any profile.
   * @param n  scrypt CPU/memory cost (power of 2, default 2^20)
   * @param r  block size (default 8)
   * @param p  parallelism (default 4)
   */
  enableKdfChain(n = SCRYPT_N_DEFAULT, r = SCRYPT_R_DEFAULT, p = SCRYPT_P_DEFAULT): void {
    this._kdfChain = true;
    this._scryptN  = n;
    this._scryptR  = r;
    this._scryptP  = p;
  }

  disableKdfChain(): void {
    this._kdfChain = false;
  }

  /**
   * Override the Argon2id parameters used to derive the salt-wrapping key.
   * By default, standard params (128 MiB / 6 passes) are used for backward compatibility.
   * Changing these breaks compatibility with existing files unless you also change the reader.
   */
  setWrapKeyProfile(memory: number, time: number, parallelism = 1): void {
    // `parallelism` > 1 runs the salt-unwrap KDF across that many Argon2 lanes
    // (threads in the native tiers) — the main key already uses 4 — which
    // makes every file open ~45% faster at the same memory cost. Files written
    // with it record `wrapArgon2Parallelism` and need a reader that honours it.
    validateArgon2Params(memory, time, parallelism);
    this._wrapArgon2Memory = memory;
    this._wrapArgon2Time   = time;
    this._wrapArgon2Parallelism = parallelism;
  }

  /** See `internal/spd-kdf.ts` — setKeyProvider (moved; behaviour unchanged). */
  static setKeyProvider = setKeyProvider;


  // ─── Passcode management ───────────────────────────────────────────────────

  async changePasscode(oldPasscode: string, newPasscode: string): Promise<void> {
    // `fs` is only actually needed if the optional `.plog` audit-log sidecar
    // is enabled (see the guarded fs.appendFileSync below) — resolved lazily
    // there instead of here so this otherwise-fully-in-memory method doesn't
    // needlessly throw on the browser build for the common case (no audit
    // log configured). Found via real cross-check against dist/browser.js.
    if (this._keylessMode) {
      throw new Error(
        'changePasscode: this instance was unlocked with setRandomKey()/setKeyfileOnly(), not a human passcode. ' +
        'Generate a fresh secret with SPD.generateRandomKey(), call setRandomKey() with it, and re-save instead.'
      );
    }
    if (!oldPasscode || !newPasscode) {
      throw new Error('Old and new passcodes must be provided.');
    }
    // The entropy floor is only meaningful if it's enforced on every path
    // that sets a human passphrase, not just the initial setPassKey() —
    // otherwise a user (or an attacker with transient write access) could
    // silently downgrade a strong passphrase to a weak one via rotation,
    // completely bypassing the check that's supposed to make guessing
    // infeasible in the first place. Found via direct audit: this call was
    // missing entirely before.
    this.checkPasscodeStrength(newPasscode);
    this.assertReady();

    // Use the params THIS instance's keys were actually derived under, not
    // profileParams(keyProfile) — those can silently diverge for a file
    // saved by an older library version whose profile constants differed
    // from today's (see _argon2Memory/_argon2Time's own doc comment).
    const cpMem = this._argon2Memory;
    const cpTime = this._argon2Time;
    const { aeadKey: oldAeadKey, macKey: oldMacKey } = await SPD.deriveKeys(oldPasscode, this.salt!, cpMem, cpTime,
      ARGON2_HASH_LEN, HMAC_KEY_LEN, this._kdfChain ?? false, this._scryptN, this._scryptR, this._scryptP, this._argon2Parallelism);

    // Re-encrypt salt under old passcode to produce a payload identical to what
    // buildSerializedPayload would produce, then verify the MAC matches.
    const { encryptedSalt, saltNonce, wrapSalt } = await SPD.encryptSalt(this.salt!, oldPasscode, this._wrapArgon2Memory, this._wrapArgon2Time, this._wrapArgon2Parallelism);
    const payload: SPDPayload = {
      data: this.data.map((item) => ({
        dataName: item.dataName,
        nonce: bytesToBase64(item.nonce),
        data: bytesToBase64(item.data),
        hash: item.hash,
        dataType: item.dataType,
      })),
      encryptedSalt,
      saltNonce,
      wrapSalt,
      version: SPD_VERSION,
      hashAlgorithm: this.hash,
      argon2Memory: cpMem,
      argon2Time: cpTime,
      keyProfile: this.keyProfile,
    };
    const payloadBuffer = utf8ToBytes(JSON.stringify(payload));
    const expectedMac = SPD.computeMAC(payloadBuffer, oldMacKey, 'application/json');
    const actualMac   = SPD.computeMAC(payloadBuffer, this.macKey!, 'application/json');

    if (!crypto.timingSafeEqual(expectedMac, actualMac)) {
      oldAeadKey.fill(0); oldMacKey.fill(0);
      throw new Error('Authentication failed.');
    }

    // Decrypt all entries with old key (per-entry derived key + AAD)
    // synchronous — no real parallelism to gain from Promise.all here
    const decryptedItems = [];
    const carriedDecoys: EncryptedDataEntry[] = [];
    for (const item of this.data) {
      // Decoy bodies are random bytes with no key relation: carry them across unchanged.
      if (item.dataType === ('_decoy' as unknown as typeof item.dataType)) { carriedDecoys.push(item); continue; }
      const aad     = utf8ToBytes(item.dataName);
      const oldEKey = SPD.deriveEntryKey(oldAeadKey, item.dataName);
      const decrypted = SPD.aeadDecrypt(
        item.data,
        aad,
        new Uint8Array(item.nonce),
        oldEKey
      );
      (oldEKey).fill(0);
      const decompressed = bytesToUtf8(SPD.unpadAfterDecompression(await zlib.inflate(decrypted)));
      decryptedItems.push({
        name: item.dataName,
        parsed: this.convertStringToInput(decompressed, item.dataType),
      });
    }

    // Zero old key material before overwriting
    (oldAeadKey).fill(0);
    (oldMacKey).fill(0);

    // Derive new keys and re-encrypt (use same profile as before)
    const newSalt = crypto.getRandomValues(new Uint8Array(ARGON2_SALT_LEN));
    const { aeadKey: newAeadKey, macKey: newMacKey } = await SPD.deriveKeys(newPasscode, newSalt, cpMem, cpTime,
      ARGON2_HASH_LEN, HMAC_KEY_LEN, this._kdfChain ?? false, this._scryptN, this._scryptR, this._scryptP, this._argon2Parallelism);

    const prevCP = { userKey: this.userKey, macKey: this.macKey, salt: this.salt, data: this.data };
    this.salt    = newSalt;
    this.userKey = newAeadKey;
    this.macKey  = newMacKey;
    this.data    = [];
    try {
      await this._reencryptAll(decryptedItems, carriedDecoys);
    } catch (err) {
      // Atomic: on any failure the instance is exactly as it was (old keys, old entries).
      newAeadKey.fill(0); newMacKey.fill(0);
      this.userKey = prevCP.userKey; this.macKey = prevCP.macKey; this.salt = prevCP.salt; this.data = prevCP.data;
      throw err;
    }
    prevCP.userKey?.fill(0); prevCP.macKey?.fill(0);

    // Write passcode rotation audit log entry
    SPD.log('key_derived', { reason: 'changePasscode' });
    if (this._plogPath) {
      try {
        const fs = getFs();
        const record = JSON.stringify({ ts: Date.now(), event: 'changePasscode' }) + '\n';
        fs.appendFileSync(this._plogPath, record, { mode: 0o600 });
      } catch { /* audit log write failure must not block the operation */ }
    }
  }

  /**
   * Re-derive this file's keys under the SAME passcode but NEW Argon2id cost
   * parameters — for periodically re-hardening long-term archival data as
   * hardware improves, without waiting until someone actually needs to open
   * the file (at which point the original passphrase may no longer be
   * available). Unlike `changePasscode`, the passphrase itself is unchanged;
   * only `memory`/`time`/`parallelism` (and therefore the derived keys and
   * salt) are rotated.
   *
   * New parameters must be >= the current ones in cost (memory AND time) —
   * this method exists to make a file more expensive to attack over time,
   * never less; use `setKeyProfile`/re-save with a lower profile instead if
   * you genuinely need to reduce KDF cost (e.g. moving to constrained
   * hardware), which is a deliberate trade-off this method won't make
   * silently on your behalf.
   *
   * Does NOT re-save to disk — call `saveToFile`/`saveToFileStreaming`
   * after, same as `changePasscode`.
   */
  async upgradeKdfParams(
    passcode: string,
    newParams: { memory: number; time: number; parallelism?: number }
  ): Promise<void> {
    // `fs` is only actually needed for the optional `.plog` audit-log
    // sidecar below — resolved lazily there instead of here so this
    // otherwise-fully-in-memory method doesn't needlessly throw on the
    // browser build when no audit log is configured. Same fix as
    // changePasscode() above.
    if (this._keylessMode) {
      throw new Error(
        'upgradeKdfParams: this instance uses a keyless (setRandomKey()/setKeyfileOnly()) master secret — ' +
        'there is no Argon2id cost to strengthen since a 96-byte CSPRNG secret has no brute-force surface. ' +
        'This method only applies to passphrase-derived instances.'
      );
    }
    if (!passcode) {
      throw new Error('Passcode must be provided.');
    }
    this.assertReady();

    const newMemory = newParams.memory;
    const newTime = newParams.time;
    const newParallelism = newParams.parallelism ?? this._argon2Parallelism;
    validateArgon2Params(newMemory, newTime, newParallelism);

    const curMem = this._argon2Memory;
    const curTime = this._argon2Time;
    if (newMemory < curMem || newTime < curTime) {
      throw new Error(
        `upgradeKdfParams: new params (memory=${newMemory}, time=${newTime}) must be >= current ` +
        `(memory=${curMem}, time=${curTime}) — this method only strengthens a file's KDF cost, ` +
        'never weakens it. Use setKeyProfile + re-save for a deliberate downgrade.'
      );
    }

    const { aeadKey: oldAeadKey, macKey: oldMacKey } = await SPD.deriveKeys(passcode, this.salt!, curMem, curTime,
      ARGON2_HASH_LEN, HMAC_KEY_LEN, this._kdfChain ?? false, this._scryptN, this._scryptR, this._scryptP, this._argon2Parallelism);

    // Verify the passcode is actually correct before doing anything
    // destructive — same MAC-check pattern as changePasscode.
    const { encryptedSalt, saltNonce, wrapSalt } = await SPD.encryptSalt(this.salt!, passcode, this._wrapArgon2Memory, this._wrapArgon2Time, this._wrapArgon2Parallelism);
    const payload: SPDPayload = {
      data: this.data.map((item) => ({
        dataName: item.dataName,
        nonce: bytesToBase64(item.nonce),
        data: bytesToBase64(item.data),
        hash: item.hash,
        dataType: item.dataType,
      })),
      encryptedSalt,
      saltNonce,
      wrapSalt,
      version: SPD_VERSION,
      hashAlgorithm: this.hash,
      argon2Memory: curMem,
      argon2Time: curTime,
      keyProfile: this.keyProfile,
    };
    const payloadBuffer = utf8ToBytes(JSON.stringify(payload));
    const expectedMac = SPD.computeMAC(payloadBuffer, oldMacKey, 'application/json');
    const actualMac   = SPD.computeMAC(payloadBuffer, this.macKey!, 'application/json');
    if (!crypto.timingSafeEqual(expectedMac, actualMac)) {
      (oldAeadKey).fill(0); (oldMacKey).fill(0);
      throw new Error('Authentication failed.');
    }

    // Decrypt all entries with the current (weaker) key.
    // synchronous — no real parallelism to gain from Promise.all here
    const decryptedItems = [];
    const carriedDecoys: EncryptedDataEntry[] = [];
    for (const item of this.data) {
      // Decoy bodies are random bytes with no key relation: carry them across unchanged.
      if (item.dataType === ('_decoy' as unknown as typeof item.dataType)) { carriedDecoys.push(item); continue; }
      const aad     = utf8ToBytes(item.dataName);
      const oldEKey = SPD.deriveEntryKey(oldAeadKey, item.dataName);
      const decrypted = SPD.aeadDecrypt(item.data, aad, new Uint8Array(item.nonce), oldEKey);
      (oldEKey).fill(0);
      const decompressed = bytesToUtf8(SPD.unpadAfterDecompression(await zlib.inflate(decrypted)));
      decryptedItems.push({ name: item.dataName, parsed: this.convertStringToInput(decompressed, item.dataType) });
    }

    (oldAeadKey).fill(0);
    (oldMacKey).fill(0);

    // Fresh salt too — re-deriving under the new cost with the SAME salt
    // would still be a strict improvement, but a fresh salt is free here
    // (we're already re-encrypting everything) and removes any lingering
    // value in an attacker's precomputation against the old salt.
    const newSalt = crypto.getRandomValues(new Uint8Array(ARGON2_SALT_LEN));
    const { aeadKey: newAeadKey, macKey: newMacKey } = await SPD.deriveKeys(passcode, newSalt, newMemory, newTime,
      ARGON2_HASH_LEN, HMAC_KEY_LEN, this._kdfChain ?? false, this._scryptN, this._scryptR, this._scryptP, newParallelism);

    const prevUK = {
      userKey: this.userKey, macKey: this.macKey, salt: this.salt, data: this.data,
      parallelism: this._argon2Parallelism, memory: this._argon2Memory, time: this._argon2Time,
    };
    this.salt    = newSalt;
    this.userKey = newAeadKey;
    this.macKey  = newMacKey;
    this._argon2Parallelism = newParallelism;
    this._argon2Memory = newMemory;
    this._argon2Time   = newTime;
    this.data    = [];
    try {
      await this._reencryptAll(decryptedItems, carriedDecoys);
    } catch (err) {
      newAeadKey.fill(0); newMacKey.fill(0);
      this.userKey = prevUK.userKey; this.macKey = prevUK.macKey; this.salt = prevUK.salt; this.data = prevUK.data;
      this._argon2Parallelism = prevUK.parallelism; this._argon2Memory = prevUK.memory; this._argon2Time = prevUK.time;
      throw err;
    }
    prevUK.userKey?.fill(0); prevUK.macKey?.fill(0);

    SPD.log('key_derived', { reason: 'upgradeKdfParams', memory: newMemory, time: newTime });
    if (this._plogPath) {
      try {
        const fs = getFs();
        const record = JSON.stringify({ ts: Date.now(), event: 'upgradeKdfParams', memory: newMemory, time: newTime }) + '\n';
        fs.appendFileSync(this._plogPath, record, { mode: 0o600 });
      } catch { /* audit log write failure must not block the operation */ }
    }
  }

  /** See `internal/spd-kdf.ts` — deriveKeys (moved; behaviour unchanged). */
  static deriveKeys = deriveKeys;


  /** See `internal/spd-kdf.ts` — computeKeyCommitment (moved; behaviour unchanged). */
  static computeKeyCommitment = computeKeyCommitment;


  /**
   * CMT-4 block size: SHA3-256(key || nonce) prepended to every ciphertext.
   * 32 bytes = one SHA3-256 output.
   */
  private static readonly CMT_BLOCK_BYTES = 32;

  /** See `internal/spd-kdf.ts` — aeadEncrypt (moved; behaviour unchanged). */
  private static aeadEncrypt = aeadEncrypt;


  /** See `internal/spd-kdf.ts` — aeadDecrypt (moved; behaviour unchanged). */
  private static aeadDecrypt = aeadDecrypt;


  /**
   * Pad `data` to a multiple of `blockSize` bytes before compression.
   * A 4-byte LE prefix records the original length so the receiver can strip padding.
   * Using random padding bytes ensures the pad bytes themselves don't compress.
   *
   * This defeats CRIME/BREACH-class compression oracle attacks: the AEAD
   * ciphertext length is now quantised to `blockSize`-byte steps regardless of
   * plaintext content, so an attacker who can observe ciphertext lengths learns
   * nothing about the plaintext.
   */
  private static readonly COMPRESS_PAD_BLOCK = 256;

  /** See `internal/spd-kdf.ts` — padForCompression (moved; behaviour unchanged). */
  private static padForCompression = padForCompression;


  /** See `internal/spd-kdf.ts` — unpadAfterDecompression (moved; behaviour unchanged). */
  private static unpadAfterDecompression = unpadAfterDecompression;


  /** See `internal/spd-kdf.ts` — computeMAC (moved; behaviour unchanged). */
  private static computeMAC = computeMAC;


  /** See `internal/spd-kdf.ts` — deriveEntryKey (moved; behaviour unchanged). */
  static deriveEntryKey = deriveEntryKey;


  /** See `internal/spd-kdf.ts` — deriveNameKey (moved; behaviour unchanged). */
  static deriveNameKey = deriveNameKey;


  /** See `internal/spd-kdf.ts` — _encryptEntryName (moved; behaviour unchanged). */
  private static _encryptEntryName = _encryptEntryName;


  /** See `internal/spd-kdf.ts` — _decryptEntryName (moved; behaviour unchanged). */
  private static _decryptEntryName = _decryptEntryName;


  // ─── Passcode strength ─────────────────────────────────────────────────────

  /**
   * Checks a human-typed passcode's real (not just length-based) entropy,
   * throwing a descriptive error if it's too weak. The actual estimation
   * logic lives in `spd-crypto.ts`'s `checkPassphraseStrength` — shared
   * with `SPDWriter` (previously had NO entropy validation at all) so
   * every passcode-based key-derivation entry point in this codebase
   * enforces the same floor. This wrapper only adds the keyfile bypass,
   * which is SPD-specific instance state with no equivalent in a
   * keyfile-less caller.
   */
  checkPasscodeStrength(passcode: string): boolean {
    // If a keyfile is loaded, ANY passcode is acceptable — the keyfile
    // provides 512 bits of true random entropy regardless of passcode quality.
    if (keyMaterial.hasKeyfile()) return true;
    return checkPassphraseStrength(passcode);
  }

  async setPassKey(passcode: string): Promise<void> {
    this.checkPasscodeStrength(passcode);

    const salt = crypto.getRandomValues(new Uint8Array(ARGON2_SALT_LEN));
    const { memory, time } = SPD.profileParams(this.keyProfile);
    // KDF chain: explicit enable/disable wins; otherwise only 'paranoid' chains scrypt.
    const kdfChain = this._kdfChain ?? this.keyProfile === 'paranoid';
    // deriveKeys already applies machine binding when enabled — no need to repeat here.
    const { aeadKey, macKey } = await SPD.deriveKeys(
      passcode, salt, memory, time, ARGON2_HASH_LEN, HMAC_KEY_LEN,
      kdfChain, this._scryptN, this._scryptR, this._scryptP, this._argon2Parallelism
    );
    this.userKey = aeadKey;
    this.macKey  = macKey;
    this.salt    = salt;
    this._kdfChain = kdfChain; // remember for saving
    this._argon2Memory = memory;
    this._argon2Time   = time;
    // Apply key blinding if enabled
    if (this._keyBlindingEnabled) this._blindKeys();
  }

  /**
   * Unlock this instance with a raw, machine-generated master secret instead
   * of a human-typed passcode — for fully automated/unattended systems (CI
   * secrets, service-to-service storage, anything where there is no human
   * available to type or remember a passphrase at all).
   *
   * The secret must come from `SPD.generateRandomKey()` — 96 bytes of true
   * CSPRNG output. Unlike `setPassKey()`, this deliberately skips Argon2id
   * (and any KDF chaining) entirely: a passphrase needs a slow, memory-hard
   * KDF because a human-chosen secret has limited entropy an attacker can
   * search; a 96-byte CSPRNG secret has 768 bits of entropy with nothing to
   * search, so spending wall-clock time "stretching" it buys no security and
   * only slows down every legitimate unlock. Same encryption (XChaCha20-
   * Poly1305), same file format, same everything else as the passphrase path
   * — only the derivation of the master secret itself differs.
   *
   * You are responsible for storing `masterSecret` somewhere durable and
   * appropriately protected (an OS keychain, a secrets manager, an HSM, a
   * keyfile on separate protected media — see `setKeyfileOnly()` for the
   * last option built in). Losing it means permanent, unrecoverable data
   * loss, exactly like forgetting a passphrase — there is no recovery path,
   * by design.
   *
   * @param masterSecret  Exactly 96 bytes, from `SPD.generateRandomKey()`.
   *
   * @example
   * const secret = SPD.generateRandomKey();
   * await putInSecretsManager('my-app/spd-key', secret); // your own storage
   * const spd = new SPD();
   * await spd.setRandomKey(secret);
   */
  async setRandomKey(masterSecret: Uint8Array): Promise<void> {
    if (!(masterSecret instanceof Uint8Array) || masterSecret.length !== KEYLESS_MASTER_SECRET_LEN) {
      throw new Error(
        `setRandomKey: expected a ${KEYLESS_MASTER_SECRET_LEN}-byte Uint8Array from SPD.generateRandomKey() (got ${masterSecret?.length ?? typeof masterSecret}).`
      );
    }
    const salt = crypto.getRandomValues(new Uint8Array(ARGON2_SALT_LEN));
    const encoded = SPD._encodeKeylessSecret(masterSecret);
    // kdfChain forced false — see this method's doc comment for why chaining
    // a memory-hard function after an already-max-entropy secret is pure
    // wasted cost with no security benefit. Argon2 memory/time are set to 1
    // (the minimum value validateArgon2Params accepts) — meaningless
    // placeholders here since derivePBK's keyless branch never touches them,
    // but they still get written into the meta block on save and re-checked
    // by validateArgon2Params on every load path, so they must be valid
    // integers, not silently copied from whatever profile happens to be set.
    // The `keylessMode` meta flag (see buildBinaryPayload/buildSerializedPayload)
    // is what actually documents "these numbers are not a real KDF cost."
    const { aeadKey, macKey } = await SPD.deriveKeys(
      encoded, salt, 1, 1, ARGON2_HASH_LEN, HMAC_KEY_LEN,
      false, this._scryptN, this._scryptR, this._scryptP, this._argon2Parallelism
    );
    this.userKey = aeadKey;
    this.macKey  = macKey;
    this.salt    = salt;
    this._kdfChain = false;
    this._argon2Memory = 1;
    this._argon2Time   = 1;
    this._keylessMode = true;
    this._keylessSecretEncoded = encoded;
    if (this._keyBlindingEnabled) this._blindKeys();
  }

  /**
   * Convenience wrapper: generates a keyfile-backed random master key (via
   * `SPD.generateKeyfile()`'s existing 64-byte-CSPRNG file format, widened to
   * the 96 bytes `setRandomKey()` requires) and unlocks this instance with
   * it in one call — no passphrase involved anywhere in the flow.
   *
   * The keyfile IS the credential here (not a supplement to a passcode, the
   * way `SPD.loadKeyfile()` + `setPassKey()` works) — protect it exactly as
   * you would a private key: separate storage from the `.spd` file, restricted
   * permissions, and a backup, since losing it means unrecoverable data loss.
   *
   * @example
   * await SPD.generateKeyfileOnly('/secure/vault/my.key');
   * const spd = new SPD();
   * await spd.setKeyfileOnly('/secure/vault/my.key');
   */
  async setKeyfileOnly(keyfilePath: string): Promise<void> {
    const fs = getFs();
    const bytes = fs.readFileSync(keyfilePath);
    if (bytes.length !== KEYLESS_MASTER_SECRET_LEN) {
      throw new Error(
        `setKeyfileOnly: keyfile at ${keyfilePath} must be exactly ${KEYLESS_MASTER_SECRET_LEN} bytes ` +
        `(got ${bytes.length}). Generate one with SPD.generateKeyfileOnly(), not SPD.generateKeyfile() ` +
        '(that one produces a 64-byte file for the separate passphrase-supplementing keyfile feature).'
      );
    }
    await this.setRandomKey(new Uint8Array(bytes));
    SPD.log('keyfile_loaded', { path: keyfilePath, mode: 'keyless' });
  }

  /**
   * Generates a fresh 96-byte CSPRNG master secret and writes it to
   * `filePath` — the keyfile-only counterpart to `SPD.generateRandomKey()`.
   * Load it later with an instance's `setKeyfileOnly(filePath)`.
   *
   * Distinct from `SPD.generateKeyfile()` (64 bytes, a passphrase
   * SUPPLEMENT — see that method's docs) — this file is the entire
   * credential on its own, with no passphrase involved at all.
   */
  static generateKeyfileOnly(filePath: string): void {
    const fs = getFs();
    const bytes = SPD.generateRandomKey();
    fs.writeFileSync(filePath, bytes, { mode: 0o600 });
    bytes.fill(0);
    SPD.log('keyfile_generated', { path: filePath, mode: 'keyless' });
  }

  /**
   * Create an instance already unlocked with a fresh random master secret and
   * seal that secret to `recipients` (MLKEM768-X25519 public keys from
   * `SPDRecipient.generateIdentity()`). Save with `saveToFileSealed()`.
   */
  static async createSealed(recipients: Uint8Array[]): Promise<{ spd: SPD; envelope: Uint8Array }> {
    const { masterSecret, envelope } = SPDRecipient.newSealedKey(recipients);
    const spd = new SPD();
    await spd.setRandomKey(masterSecret);
    masterSecret.fill(0);
    return { spd, envelope };
  }

  /**
   * Save a keyless instance and write its recipient envelope next to it as
   * `<outputPath>.spdr`, sealed to `recipients`. Any listed recipient loads
   * the pair with `SPD.loadFromFileSealed()`. Re-sealing to a new recipient
   * list is just another call with the same instance.
   */
  async saveToFileSealed(
    outputPath: string,
    recipients: Uint8Array[],
    options?: { streaming?: boolean; errorCorrection?: boolean } & EccOptions
  ): Promise<void> {
    if (!this._keylessMode || !this._keylessSecretEncoded) {
      throw new Error('saveToFileSealed: instance must be keyless — use SPD.createSealed() or setRandomKey() first.');
    }
    const master = SPD._decodeKeylessSecret(this._keylessSecretEncoded)!;
    let envelope: Uint8Array;
    try {
      envelope = SPDRecipient.seal(master, recipients);
    } finally {
      master.fill(0);
    }
    const { streaming, ...rest } = options ?? {};
    if (streaming) await this.saveToFileStreaming(outputPath, '', undefined, rest);
    else await this.saveToFile(outputPath, '', rest);
    const fs = getFs();
    const tmp = outputPath + '.spdr.tmp';
    fs.writeFileSync(tmp, envelope, { mode: 0o600 });
    fs.renameSync(tmp, outputPath + '.spdr');
  }

  /**
   * Load a file written by `saveToFileSealed()` as one of its recipients:
   * opens `<filePath>.spdr` with `secretKey` and unlocks the file with the
   * recovered master secret. `envelope` overrides the sidecar if the envelope
   * was delivered separately.
   */
  static async loadFromFileSealed(
    filePath: string,
    secretKey: Uint8Array,
    options?: { envelope?: Uint8Array; verifyKey?: Uint8Array; streaming?: boolean; autoRepair?: boolean }
  ): Promise<SPD> {
    const envelope = options?.envelope ?? new Uint8Array(getFs().readFileSync(filePath + '.spdr'));
    const master = SPDRecipient.open(envelope, secretKey);
    try {
      return await SPD.loadWithRandomKey(filePath, master, options?.verifyKey, {
        streaming: options?.streaming,
        autoRepair: options?.autoRepair,
      });
    } finally {
      master.fill(0);
    }
  }

  /** See `internal/spd-kdf.ts` — generateRandomKey (moved; behaviour unchanged). */
  static generateRandomKey = generateRandomKey;


  /**
   * Rotates a keyless instance to a fresh master secret — the keyless
   * counterpart to `upgradeKdfParams()`/`changePasscode()` for periodic
   * credential rotation in unattended systems (CI secrets, service-to-
   * service storage) where nobody would otherwise think to do this
   * manually. Verifies `currentSecret` is actually correct before doing
   * anything destructive, decrypts every entry under the current secret,
   * generates (or accepts) a new one, re-derives keys with a fresh salt, and
   * re-encrypts every entry under the new secret. Does not save to disk —
   * call `saveToFile`/`saveToFileStreaming` after, same as `upgradeKdfParams`.
   *
   * @param currentSecret  The secret this instance was last unlocked with
   *                       (verified before any destructive change is made).
   * @param newSecret      Optional — a pre-generated replacement (e.g. if
   *                       your secrets manager already minted one). Defaults
   *                       to a fresh `SPD.generateRandomKey()`.
   * @returns The new master secret — store it wherever you store the old one.
   *
   * @example
   * const newSecret = await spd.rotateRandomKey(oldSecret);
   * await spd.saveToFileStreaming('./data.spd', '');
   * await putInYourSecretsManager('my-app/spd-key', newSecret);
   */
  async rotateRandomKey(currentSecret: Uint8Array, newSecret?: Uint8Array): Promise<Uint8Array> {
    if (!this._keylessMode) {
      throw new Error(
        'rotateRandomKey: this instance was not unlocked with setRandomKey()/setKeyfileOnly() — ' +
        'use changePasscode() for a passphrase-derived instance instead.'
      );
    }
    if (!(currentSecret instanceof Uint8Array) || currentSecret.length !== KEYLESS_MASTER_SECRET_LEN) {
      throw new Error(
        `rotateRandomKey: currentSecret must be exactly ${KEYLESS_MASTER_SECRET_LEN} bytes (got ${currentSecret?.length ?? typeof currentSecret}).`
      );
    }
    if (newSecret !== undefined && (!(newSecret instanceof Uint8Array) || newSecret.length !== KEYLESS_MASTER_SECRET_LEN)) {
      throw new Error(
        `rotateRandomKey: newSecret must be exactly ${KEYLESS_MASTER_SECRET_LEN} bytes (got ${newSecret.length}).`
      );
    }
    this.assertReady();

    const currentEncoded = SPD._encodeKeylessSecret(currentSecret);
    const { aeadKey: oldAeadKey, macKey: oldMacKey } = await SPD.deriveKeys(
      currentEncoded, this.salt!, 1, 1, ARGON2_HASH_LEN, HMAC_KEY_LEN,
      false, this._scryptN, this._scryptR, this._scryptP, this._argon2Parallelism
    );

    // Verify currentSecret is actually correct before doing anything
    // destructive — same MAC-check pattern as upgradeKdfParams/changePasscode.
    const { encryptedSalt, saltNonce, wrapSalt } = await SPD.encryptSalt(this.salt!, currentEncoded, this._wrapArgon2Memory, this._wrapArgon2Time, this._wrapArgon2Parallelism);
    const payload: SPDPayload = {
      data: this.data.map((item) => ({
        dataName: item.dataName,
        nonce: bytesToBase64(item.nonce),
        data: bytesToBase64(item.data),
        hash: item.hash,
        dataType: item.dataType,
      })),
      encryptedSalt,
      saltNonce,
      wrapSalt,
      version: SPD_VERSION,
      hashAlgorithm: this.hash,
      argon2Memory: 1,
      argon2Time: 1,
      keyProfile: this.keyProfile,
      keylessMode: true,
    };
    const payloadBuffer = utf8ToBytes(JSON.stringify(payload));
    const expectedMac = SPD.computeMAC(payloadBuffer, oldMacKey, 'application/json');
    const actualMac   = SPD.computeMAC(payloadBuffer, this.macKey!, 'application/json');
    if (!crypto.timingSafeEqual(expectedMac, actualMac)) {
      (oldAeadKey).fill(0); (oldMacKey).fill(0);
      throw new Error('Authentication failed.');
    }

    // Decrypt all entries with the current secret's key.
    // synchronous — no real parallelism to gain from Promise.all here
    const decryptedItems = [];
    const carriedDecoys: EncryptedDataEntry[] = [];
    for (const item of this.data) {
      // Decoy bodies are random bytes with no key relation: carry them across unchanged.
      if (item.dataType === ('_decoy' as unknown as typeof item.dataType)) { carriedDecoys.push(item); continue; }
      const aad     = utf8ToBytes(item.dataName);
      const oldEKey = SPD.deriveEntryKey(oldAeadKey, item.dataName);
      const decrypted = SPD.aeadDecrypt(item.data, aad, new Uint8Array(item.nonce), oldEKey);
      (oldEKey).fill(0);
      const decompressed = bytesToUtf8(SPD.unpadAfterDecompression(await zlib.inflate(decrypted)));
      decryptedItems.push({ name: item.dataName, parsed: this.convertStringToInput(decompressed, item.dataType) });
    }

    (oldAeadKey).fill(0);
    (oldMacKey).fill(0);

    const prevRR = {
      userKey: this.userKey ? new Uint8Array(this.userKey) : undefined,
      macKey: this.macKey ? new Uint8Array(this.macKey) : undefined,
      salt: this.salt ? new Uint8Array(this.salt) : undefined,
      data: this.data, encoded: this._keylessSecretEncoded,
    };
    const finalNewSecret = newSecret ?? SPD.generateRandomKey();
    // The live buffers are replaced (not zeroed) by setRandomKey; wipe them
    // now that copies are held in prevRR for the restore path.
    const liveUK = this.userKey, liveMK = this.macKey;
    this.data = [];
    try {
      await this.setRandomKey(finalNewSecret);
      liveUK?.fill(0); liveMK?.fill(0);
      await this._reencryptAll(decryptedItems, carriedDecoys);
    } catch (err) {
      this.userKey?.fill(0); this.macKey?.fill(0);
      this.userKey = prevRR.userKey; this.macKey = prevRR.macKey; this.salt = prevRR.salt;
      this._keylessSecretEncoded = prevRR.encoded; this.data = prevRR.data;
      throw err;
    }
    prevRR.userKey?.fill(0); prevRR.macKey?.fill(0); prevRR.salt?.fill(0);

    SPD.log('key_derived', { reason: 'rotateRandomKey' });
    if (this._plogPath) {
      const fs = getFs();
      try {
        const record = JSON.stringify({ ts: Date.now(), event: 'rotateRandomKey' }) + '\n';
        fs.appendFileSync(this._plogPath, record, { mode: 0o600 });
      } catch { /* audit log write failure must not block the operation */ }
    }

    return finalNewSecret;
  }

  setHash(hash: HashAlgorithm = 'sha3-512'): void {
    this.hash = hash;
  }

  setCompressionLevel(level: number = 6): void {
    this.compressionLevel = level;
  }

  // ── Entry ACL ─────────────────────────────────────────────────────────────

  /**
   * Restrict an entry to one or more roles. `extractData`, `getEntry`, and the
   * lazy `entries()` iterator will throw if `setRole()` has not been called with
   * a matching role.  Pass an empty array to remove all restrictions.
   */
  restrictEntry(name: string, roles: string[]): void {
    const san = this.sanitizeName(name);
    if (roles.length === 0) { this.entryRoles.delete(san); return; }
    this.entryRoles.set(san, roles.map((r) => r.trim().toLowerCase()));
  }

  /**
   * Set the active role for this instance.  Entries restricted to roles that
   * don't include this value will be inaccessible until the role is changed.
   * Pass `undefined` to clear the role (only unrestricted entries will be readable).
   */
  setRole(role: string | undefined): void {
    this.currentRole = role?.trim().toLowerCase();
  }

  // ── Key stretching profiles ───────────────────────────────────────────────

  /**
   * Set the Argon2id cost profile for this instance.
   * - `'standard'`  — 128 MiB / 6 passes (default, ~500 ms on modern hardware)
   * - `'high'`      — 512 MiB / 8 passes (~2 s)
   * - `'paranoid'`  — 2 GiB  / 16 passes + machine-secret post-KDF (~8–16 s).
   *   Choosing this profile automatically calls `SPD.enableMachineBinding()`
   *   (found via direct audit + a real cross-"machine" test: this doc
   *   comment previously claimed machine binding as part of what
   *   `'paranoid'` does, but nothing actually enabled it — a paranoid-profile
   *   file saved without a SEPARATE, manual `enableMachineBinding()` call
   *   loaded successfully even after simulating a different machine's
   *   identity, proving the claim was false). Machine binding is a global,
   *   process-wide flag (see `enableMachineBinding`'s own doc comment) —
   *   selecting `'paranoid'` anywhere in a process now enables it for every
   *   `SPD` instance in that process, matching that existing global-scope
   *   contract rather than introducing a new, inconsistent instance-scoped
   *   exception. Call `SPD.disableMachineBinding()` afterward if you
   *   specifically need `'paranoid'`'s KDF cost WITHOUT machine binding.
   *
   * Must be set before `setPassKey()`.  The chosen profile's params are embedded
   * in the file so loads always re-derive with the same cost.
   */
  setKeyProfile(profile: SPDKeyProfile): void {
    this.keyProfile = profile;
    if (profile === 'paranoid') SPD.enableMachineBinding();
  }

  /**
   * Enable machine binding: mixes a stable machine-specific secret (derived
   * from `/etc/machine-id`, `hostname`, or a UUID sidecar) into every key
   * derivation via an extra HMAC step.  The resulting key is only reproducible
   * on the originating machine, dramatically raising the cost of offline attacks
   * with a stolen file.
   *
   * Enabling this globally affects all SPD instances in the process.
   * Must be called before `setPassKey()` / `loadFromFile()` / `getEntry()`.
   */
  static enableMachineBinding(): void {
    keyMaterial.enableMachineBinding();
    SPD.clearKeyCache();
  }

  static disableMachineBinding(): void {
    keyMaterial.disableMachineBinding();
    SPD.clearKeyCache();
  }

  /** Resolve Argon2id params from a profile name. */
  static profileParams(profile: SPDKeyProfile): { memory: number; time: number } {
    if (profile === 'paranoid') return { memory: ARGON2_MEMORY_PARANOID, time: ARGON2_TIME_PARANOID };
    if (profile === 'high')     return { memory: ARGON2_MEMORY_HIGH,     time: ARGON2_TIME_HIGH };
    // 'standard' retains original 128 MiB / 6 params for compatibility
    return { memory: 131072, time: 6 };
  }

  /** Returns true if the current role is allowed to read `name`. */
  private canReadEntry(name: string): boolean {
    const allowed = this.entryRoles.get(name);
    if (!allowed || allowed.length === 0) return true;
    if (!this.currentRole) return false;
    return allowed.includes(this.currentRole);
  }

  // ── Auto-destruct ─────────────────────────────────────────────────────────

  /**
   * Configure a maximum open count for auto-destruct.
   * After this many successful `loadFromFile` / `loadFromFileStreaming` calls the
   * file is securely wiped and an error is thrown on the exceeding open.
   * Set to 0 to disable (default).
   */
  setMaxOpenCount(n: number): void {
    if (n < 0) throw new Error('maxOpenCount must be >= 0');
    this.maxOpenCount = n;
  }

  /**
   * Persist the max-open-count limit to a `.maxcount` sidecar alongside `filePath`.
   * Must be called after `saveToFile`/`saveToFileStreaming` so the sidecar is
   * co-located with the file that was actually written.
   * Callers who set a limit should call this immediately after saving.
   */
  static setFileMaxOpenCount(filePath: string, n: number): void {
    const fs = getFs();
    if (n < 0) throw new Error('maxOpenCount must be >= 0');
    fs.writeFileSync(filePath + '.maxcount', String(n), { mode: 0o600 });
  }

  // ── Passcode rotation audit log ────────────────────────────────────────────

  /**
   * Set the path to the passcode rotation audit log (.plog) sidecar file.
   * A JSON-lines record `{ts, event}` is appended whenever `changePasscode` is
   * called.  The file is created if it does not exist (mode 0600).
   * Pass `undefined` to disable.
   */
  setPlogPath(p: string | undefined): void {
    this._plogPath = p;
  }

  // ── Schema validation ─────────────────────────────────────────────────────

  /**
   * Attach a validator function to an entry name.
   * Called before encryption in `addData` and `updateEntry`.
   * Throw or return `false` to reject the value.
   */
  setSchema(name: string, validator: (v: unknown) => boolean): void {
    this.schemas.set(this.sanitizeName(name), validator);
  }

  /** Remove a previously registered schema validator. */
  removeSchema(name: string): void {
    this.schemas.delete(this.sanitizeName(name));
  }

  private applySchema(sanitizedName: string, value: unknown): void {
    const validator = this.schemas.get(sanitizedName);
    if (!validator) return;
    if (!validator(value)) {
      throw new Error(`Schema validation failed for entry "${sanitizedName}".`);
    }
  }

  // ── Snapshot ──────────────────────────────────────────────────────────────

  /**
   * Returns an immutable snapshot of the current encrypted entries.
   * No key material is included — use `restoreSnapshot` to apply.
   */
  snapshot(): SPDSnapshot {
    for (const e of this.data) {
      if (!this.canReadEntry(e.dataName)) {
        throw new Error(`Access denied: entry "${e.dataName}" requires role "${(this.entryRoles.get(e.dataName) ?? []).join('|')}".`);
      }
    }
    return {
      data: this.data.map((e) => ({
        dataName: e.dataName,
        nonce:    e.nonce,
        data:     e.data,
        hash:     e.hash,
        dataType: e.dataType,
      })),
      writeCounter: this.writeCounter,
      ts: Date.now(),
      entryRoles: this.entryRoles.size > 0 ? Object.fromEntries([...this.entryRoles].map(([k, v]) => [k, [...v]])) : undefined,
    };
  }

  /**
   * Replaces the current encrypted entries with those from a snapshot.
   * Key material is unchanged — the snapshot must have been taken from an
   * instance with the same passcode.
   */
  restoreSnapshot(snap: SPDSnapshot): void {
    this.assertReady();
    this.data = snap.data.map((e) => ({
      dataName: e.dataName,
      nonce:    e.nonce,
      data:     e.data,
      hash:     e.hash,
      dataType: e.dataType,
    }));
    // Restore content, never the counter: a lower counter would be written to
    // the .seq sidecar on the next save and weaken rollback detection.
    this.writeCounter = Math.max(this.writeCounter, snap.writeCounter);
    // Merge: a snapshot can add or tighten restrictions, never remove ones in force.
    for (const [k, v] of Object.entries(snap.entryRoles ?? {})) {
      const cur = this.entryRoles.get(k);
      this.entryRoles.set(k, cur ? cur.filter((r) => v.includes(r)) : [...v]);
    }
  }

  // ─── Data management ───────────────────────────────────────────────────────

  sanitizeName(dataName: string): string {
    if (typeof dataName !== 'string') {
      throw new Error('dataName must be a string');
    }
    const normalized = dataName.normalize('NFKC').trim().toLowerCase();
    const sanitized = normalized.replace(/[^a-z0-9_\-]/g, '_');

    const byteLen = utf8ToBytes(sanitized).length;
    if (byteLen > MAX_NAME_BYTES) {
      throw new Error(
        `Entry name too long after sanitization: ${byteLen} bytes (max ${MAX_NAME_BYTES}).`
      );
    }
    if (byteLen === 0) {
      throw new Error('Entry name is empty after sanitization.');
    }

    if (SPD.nameCollisionWarnings && sanitized !== normalized) {
      console.warn(
        `[SPD] Name collision risk: "${dataName}" was sanitized to "${sanitized}". ` +
        'Another name that maps to the same sanitized form would silently overwrite this entry.'
      );
    }

    return sanitized;
  }

  async addData(dataName: string, value: unknown): Promise<void> {
    this.assertReady();
    const sanitized = this.sanitizeName(dataName);
    if (!this._rotating) this.applySchema(sanitized, value);
    const [serialized, dataType] = this.convertInputToString(value);

    const entryKey  = SPD.deriveEntryKey(this.userKey!, sanitized);
    const padded     = SPD.padForCompression(utf8ToBytes(serialized));
    const compressed = await zlib.deflate(padded, { level: this.compressionLevel });
    const nonce      = crypto.randomBytes(24);
    const encrypted  = SPD.aeadEncrypt(compressed, utf8ToBytes(sanitized), nonce, entryKey);
    (entryKey).fill(0);

    const hash = crypto.createHash(this.hash).update(encrypted).digest('hex');

    const entry: EncryptedDataEntry = {
      dataName: sanitized,
      nonce: nonce,
      data: encrypted,
      hash,
      dataType,
    };
    // Overwrite any existing entry with the same sanitized name (matching
    // renameEntry/importEntries convention) rather than appending a second
    // entry sharing one name — two entries with the same dataName used to
    // silently disagree across accessors (extractData returned the last
    // match, getEntry the first).
    const idx = this.data.findIndex((e) => e.dataName === sanitized);
    if (idx === -1) this.data.push(entry);
    else this.data[idx] = entry;
    this.appendToWal(entry);
    SPD.log('entry_added', { name: sanitized });
  }

  async addMany(items: DataInput[]): Promise<void> {
    this.assertReady();

    // Serialize all items first (type detection is synchronous/cheap)
    const serialized: Array<{ name: string; serialized: string; dataType: string }> = [];
    for (const { name, data } of items) {
      const san = this.sanitizeName(name);
      this.applySchema(san, data);
      const [ser, dt] = this.convertInputToString(data);
      serialized.push({ name: san, serialized: ser, dataType: dt });
    }

    const WORKER_THRESHOLD = 256; // use workers only for large batches — spawn overhead ~30ms
    // getOs() is deferred until we know we might actually need the worker
    // path — calling it unconditionally would throw in a non-Node
    // environment (browser/edge) even for a small in-memory-only batch that
    // was never going to spawn a worker (same "helper before its own guard"
    // shape as the previously-fixed appendToWal bug).
    const cpuCount = serialized.length >= WORKER_THRESHOLD
      ? Math.max(1, getOs().cpus().length - 1) // leave one core for event loop
      : 1;

    if (serialized.length >= WORKER_THRESHOLD && cpuCount > 1) {
      // Distribute across worker threads
      const fs = getFs();
      const path = getPath();
      const { Worker } = getWorkerThreads();
      const chunkSize = Math.ceil(serialized.length / cpuCount);
      // Uint8Array (structured-cloned) instead of boxing into a plain
      // number[] first — cheaper for 32 bytes of key material, and (since
      // it's sensitive data) avoids leaving an extra unzeroable copy of the
      // key sitting in a plain array on the sending side.
      const aeadKeyBytes = new Uint8Array(this.userKey!);
      // In compiled output __dirname points to dist/ (.js exists);
      // in tests/source, fall back to the checked-in src/spd-encrypt-worker.js
      // dev shim — worker_threads.Worker uses Node's native module loader,
      // which can't parse .ts directly, and registering a TS loader per-worker
      // (--loader ts-node/esm) turned out to be its own can of worms with this
      // Node version. The shim must be regenerated (`npm run build`, then copy
      // dist/spd-encrypt-worker.js here) any time spd-encrypt-worker.ts or its
      // internal/spd-crypto.ts imports change — see that file's own header.
      // Resolved from import.meta.url (valid in every ESM runtime — plain
      // `__dirname` does not exist in ESM and threw under node/tsx; only the
      // tsup shim and vitest's transform masked it). Worker and fs accept URLs.
      const workerPathJs = new URL('./spd-encrypt-worker.js', import.meta.url);
      const workerPathTs = new URL('./spd-encrypt-worker.ts', import.meta.url);
      const workerPath = fs.existsSync(workerPathJs) ? workerPathJs : workerPathTs;

      const chunks: Array<typeof serialized> = [];
      for (let i = 0; i < serialized.length; i += chunkSize) {
        chunks.push(serialized.slice(i, i + chunkSize));
      }

      let results: Array<Array<{ dataName: string; nonce: number[]; data: number[]; hash: string; dataType: string }>>;
      try {
        results = await Promise.all(chunks.map((chunk) =>
          new Promise<Array<{
            dataName: string; nonce: number[]; data: number[]; hash: string; dataType: string;
          }>>((resolve, reject) => {
            const w = new Worker(workerPath, {
              workerData: {
                items: chunk,
                aeadKeyBytes,
                hashAlgorithm: this.hash,
                compressionLevel: this.compressionLevel,
              },
            });
            // Terminate the worker once it's done its one-shot job, on both
            // the success and error paths — otherwise a worker that errors
            // leaves every OTHER still-running worker in the same batch
            // un-terminated (Promise.all rejects immediately on the first
            // error, but nothing stops the rest from continuing to run,
            // each still holding its own copy of aeadKeyBytes).
            let settled = false;
            w.once('message', (msg: { entries: unknown; error?: string }) => {
              settled = true;
              w.terminate();
              if (msg.error) reject(new Error(msg.error));
              else resolve(msg.entries as any);
            });
            w.once('error', (err) => { settled = true; w.terminate(); reject(err); });
            // A worker killed before replying (OOM, process.exit) otherwise left this pending forever.
            w.once('exit', (code) => { if (!settled) reject(new Error(`addMany: encryption worker exited (code ${code}) before replying`)); });
          })
        ));
      } finally {
        // aeadKeyBytes is a plain copy of the master AEAD key sent to every
        // worker via workerData — zero it here the same way every other
        // key-material buffer in this class is zeroed after use.
        aeadKeyBytes.fill(0);
      }

      const allEntries = results.flat();
      // Same-named entries overwrite in place (matches addData's single-entry
      // behavior) instead of appending a second entry sharing one name — an
      // O(1)-per-lookup local index map keeps this from being O(n*m) against
      // a large existing `this.data`.
      const nameToIdx = new Map(this.data.map((e, i) => [e.dataName, i] as const));
      for (const e of allEntries) {
        const entry = {
          dataName: e.dataName,
          nonce: new Uint8Array(e.nonce),
          data: new Uint8Array(e.data),
          hash: e.hash,
          dataType: e.dataType as typeof this.data[0]['dataType'],
        };
        const idx = nameToIdx.get(e.dataName);
        if (idx === undefined) {
          nameToIdx.set(e.dataName, this.data.length);
          this.data.push(entry);
        } else {
          this.data[idx] = entry;
        }
        this.appendToWal(entry);
        SPD.log('entry_added', { name: e.dataName });
      }
    } else {
      // Single-threaded path for small batches (avoids worker spawn overhead)
      const BATCH = 256;
      for (let i = 0; i < serialized.length; i += BATCH) {
        const batch = serialized.slice(i, i + BATCH);
        const encryptedBatch = await Promise.all(batch.map(async ({ name, serialized: ser, dataType }) => {
          const padded2    = SPD.padForCompression(utf8ToBytes(ser));
          const compressed = await zlib.deflate(padded2, { level: this.compressionLevel });
          const entryKey2  = SPD.deriveEntryKey(this.userKey!, name);
          const nonce      = crypto.randomBytes(24);
          const encrypted  = SPD.aeadEncrypt(compressed, utf8ToBytes(name), nonce, entryKey2);
          (entryKey2).fill(0);
          const hash = crypto.createHash(this.hash).update(encrypted).digest('hex');
          return {
            dataName: name,
            nonce: nonce,
            data: encrypted,
            hash,
            dataType: dataType as typeof this.data[0]['dataType'],
          };
        }));
        // Same-named entries overwrite in place — see the worker-path comment
        // above for why (and why a local index map, not a per-entry findIndex).
        const nameToIdx = new Map(this.data.map((e, i) => [e.dataName, i] as const));
        for (const e of encryptedBatch) {
          const idx = nameToIdx.get(e.dataName);
          if (idx === undefined) {
            nameToIdx.set(e.dataName, this.data.length);
            this.data.push(e);
          } else {
            this.data[idx] = e;
          }
          this.appendToWal(e);
          SPD.log('entry_added', { name: e.dataName });
        }
      }
    }
  }

  async extractData(): Promise<Record<string, unknown>> {
    this.assertReady();

    const BATCH = 256;
    const entries: Array<[string, unknown]> = [];

    for (let i = 0; i < this.data.length; i += BATCH) {
      const batch = this.data.slice(i, i + BATCH);
      // synchronous — no real parallelism to gain from Promise.all here
      const batchEntries = [];
      for (const item of batch) {
        if (item.dataType === ('_decoy' as unknown as typeof item.dataType)) continue;
        if (!this.canReadEntry(item.dataName)) {
          throw new Error(`Access denied: entry "${item.dataName}" requires role "${(this.entryRoles.get(item.dataName) ?? []).join('|')}".`);
        }
        const aad  = this.fileVersion >= 27 ? utf8ToBytes(item.dataName) : null;
        const dKey = this.fileVersion >= 27 ? SPD.deriveEntryKey(this.userKey!, item.dataName) : this.userKey!;
        try {
          const decrypted = this.fileVersion >= 29
            ? SPD.aeadDecrypt(item.data, aad, new Uint8Array(item.nonce), dKey)
            : plainAeadDecrypt(item.data, aad, new Uint8Array(item.nonce), dKey);
          const inflated = await zlib.inflate(decrypted);
          const decompressed = bytesToUtf8(this.fileVersion >= 29
            ? SPD.unpadAfterDecompression(inflated)
            : inflated);
          const parsed = this.convertStringToInput(decompressed, item.dataType);
          if (SPD.isDecoyValue(item.dataType, parsed)) continue;
          batchEntries.push([item.dataName, parsed] as [string, unknown]);
        } catch {
          throw new Error('Authentication failed.');
        } finally {
          if (this.fileVersion >= 27) (dKey as Uint8Array).fill(0);
        }
      }
      entries.push(...batchEntries);
    }

    return Object.fromEntries(entries);
  }

  /** Returns true if an entry with the given name exists. No decryption. */
  has(name: string): boolean {
    const sanitized = this.sanitizeName(name);
    return this.data.some((e) => e.dataName === sanitized);
  }

  /** Returns all entry names in insertion order. No decryption. */
  keys(): string[] {
    return this.data.map((e) => e.dataName);
  }

  /**
   * Lazy decryption iterator — yields `{name, value, dataType}` one entry at a
   * time without loading all entries into memory simultaneously.  Respects entry
   * ACL roles; skips (does not throw) decoy entries silently.
   *
   * @example
   * for await (const {name, value} of spd.entries()) {
   *   console.log(name, value);
   * }
   */
  async *entries(): AsyncGenerator<{ name: string; value: unknown; dataType: string }> {
    this.assertReady();
    for (const item of this.data) {
      if (item.dataType === ('_decoy' as unknown as typeof item.dataType)) continue;
      if (!this.canReadEntry(item.dataName)) {
        throw new Error(`Access denied: entry "${item.dataName}" requires role "${(this.entryRoles.get(item.dataName) ?? []).join('|')}".`);
      }
      const aad  = this.fileVersion >= 27 ? utf8ToBytes(item.dataName) : null;
      const dKey = this.fileVersion >= 27 ? SPD.deriveEntryKey(this.userKey!, item.dataName) : this.userKey!;
      let decompressed: string;
      try {
        const decrypted = this.fileVersion >= 29
          ? SPD.aeadDecrypt(item.data, aad, new Uint8Array(item.nonce), dKey)
          : plainAeadDecrypt(item.data, aad, new Uint8Array(item.nonce), dKey);
        const inflated = await zlib.inflate(decrypted);
        decompressed = bytesToUtf8(this.fileVersion >= 29
          ? SPD.unpadAfterDecompression(inflated)
          : inflated);
      } finally {
        if (this.fileVersion >= 27) (dKey as Uint8Array).fill(0);
      }
      const value = this.convertStringToInput(decompressed, item.dataType);
      if (SPD.isDecoyValue(item.dataType, value)) continue;
      yield { name: item.dataName, value, dataType: item.dataType };
    }
  }

  /**
   * Insert `count` fake encrypted entries whose names are derived from `prefix`.
   * Decoys are indistinguishable from real entries in the binary/JSON file.
   * They are silently skipped by `entries()` and flagged as `_decoy` type so
   * callers that inspect `dataType` can filter them.
   */
  private static isDecoyValue(dataType: string, value: unknown): boolean {
    return dataType === 'string' && typeof value === 'string' && value.startsWith(SPD.DECOY_VALUE_MARKER);
  }

  /** Prefix inside a decoy's encrypted value. Only visible after decryption, so decoys are indistinguishable from real entries on disk. */
  private static readonly DECOY_VALUE_MARKER = '\u0000spd-decoy\u0000';

  async addDecoy(prefix: string, count: number = 1): Promise<void> {
    this.assertReady();
    const san = this.sanitizeName(prefix);
    for (let i = 0; i < count; i++) {
      const name = `${san}_decoy_${bytesToHex(crypto.randomBytes(4))}`;
      // A real string entry (random size 64–4095 B) whose plaintext starts with
      // the marker: on disk it is a normal record with a normal type; every
      // decrypt-all path skips it after decryption. Rotation and WAL replay
      // need no special case. (Legacy files may still carry the old '_decoy'
      // dataType sentinel; readers keep skipping those too.)
      const body = SPD.DECOY_VALUE_MARKER + bytesToHex(crypto.randomBytes(32 + (crypto.randomBytes(2)[0] << 3)));
      await this.addData(name, body);
    }
  }

  /**
   * Removes an entry by name. Throws if not found.
   * Does NOT re-save to disk — call saveToFile/saveToFileStreaming after.
   *
   * Also clears any `restrictEntry()` role restriction recorded under this
   * name — otherwise a later `addData()` reusing the same name would
   * silently inherit a stale ACL from the deleted entry.
   */
  deleteEntry(name: string): void {
    const sanitized = this.sanitizeName(name);
    const idx = this.data.findIndex((e) => e.dataName === sanitized);
    if (idx === -1) throw new Error(`Entry not found: "${sanitized}"`);
    this.data.splice(idx, 1);
    this.entryRoles.delete(sanitized);
  }

  /**
   * Renames an entry. Re-encrypts the blob under the new name's derived key + AAD.
   * Throws if `oldName` is not found or `newName` already exists.
   * Does NOT re-save to disk — call saveToFile/saveToFileStreaming after.
   */
  async renameEntry(oldName: string, newName: string): Promise<void> {
    this.assertReady();
    const oldSan = this.sanitizeName(oldName);
    const newSan = this.sanitizeName(newName);
    if (oldSan === newSan) return;

    const idx = this.data.findIndex((e) => e.dataName === oldSan);
    if (idx === -1) throw new Error(`Entry not found: "${oldSan}"`);
    if (this.data.some((e) => e.dataName === newSan)) {
      throw new Error(`Entry already exists: "${newSan}"`);
    }

    const item = this.data[idx];
    // Decrypt with old name's key + AAD
    const oldEKey = SPD.deriveEntryKey(this.userKey!, oldSan);
    const decrypted = this.fileVersion >= 29
      ? SPD.aeadDecrypt(item.data, utf8ToBytes(oldSan), new Uint8Array(item.nonce), oldEKey)
      : plainAeadDecrypt(item.data, utf8ToBytes(oldSan), new Uint8Array(item.nonce), oldEKey);
    (oldEKey).fill(0);

    // Re-encrypt under new name's key + AAD (always write v29 format)
    const newEKey    = SPD.deriveEntryKey(this.userKey!, newSan);
    const newNonce   = crypto.randomBytes(24);
    const reEncrypted = SPD.aeadEncrypt(decrypted, utf8ToBytes(newSan), newNonce, newEKey);
    (newEKey).fill(0);

    const newHash = crypto.createHash(this.hash).update(reEncrypted).digest('hex');
    this.data[idx] = {
      dataName: newSan,
      nonce:    newNonce,
      data:     reEncrypted,
      hash:     newHash,
      dataType: item.dataType,
    };

    // Migrate any role restriction to the new name — otherwise it's silently
    // dropped (leaving the renamed entry unexpectedly unrestricted) rather
    // than following the entry it was meant to protect.
    const oldRoles = this.entryRoles.get(oldSan);
    if (oldRoles) {
      this.entryRoles.delete(oldSan);
      this.entryRoles.set(newSan, oldRoles);
    }
  }

  /**
   * Replaces an entry's value in place. Equivalent to deleteEntry + addData
   * but preserves insertion order.
   * Throws if the entry is not found.
   * Does NOT re-save to disk — call saveToFile/saveToFileStreaming after.
   */
  async updateEntry(name: string, value: unknown): Promise<void> {
    this.assertReady();
    const sanitized = this.sanitizeName(name);
    const idx = this.data.findIndex((e) => e.dataName === sanitized);
    if (idx === -1) throw new Error(`Entry not found: "${sanitized}"`);
    this.applySchema(sanitized, value);

    const [serialized, dataType] = this.convertInputToString(value);
    const padded      = SPD.padForCompression(utf8ToBytes(serialized));
    const compressed  = await zlib.deflate(padded, { level: this.compressionLevel });
    const entryKey    = SPD.deriveEntryKey(this.userKey!, sanitized);
    const nonce       = crypto.randomBytes(24);
    const encrypted   = SPD.aeadEncrypt(compressed, utf8ToBytes(sanitized), nonce, entryKey);
    (entryKey).fill(0);
    const hash = crypto.createHash(this.hash).update(encrypted).digest('hex');

    this.data[idx] = {
      dataName: sanitized,
      nonce:    nonce,
      data:     encrypted,
      hash,
      dataType,
    };
  }

  /**
   * Returns a new SPD instance (with the same key material) containing only the
   * entries whose sanitized names match `pattern`.  The returned instance is
   * ready for `saveToFile` / `saveToFileStreaming` — it shares no mutable state
   * with the original.
   *
   * @param pattern  RegExp tested against each sanitized entry name.
   * @returns        A new SPD instance carrying the matching encrypted entries.
   */
  exportEntries(pattern: RegExp): SPD {
    this.assertReady();
    const out = new SPD();
    out.userKey  = this.userKey  ? new Uint8Array(this.userKey)  : undefined;
    out.macKey   = this.macKey   ? new Uint8Array(this.macKey)   : undefined;
    out.salt     = this.salt     ? new Uint8Array(this.salt)     : undefined;
    out.hash     = this.hash;
    out.compressionLevel = this.compressionLevel;
    out.fileVersion      = this.fileVersion;
    out.keyProfile       = this.keyProfile;

    for (const e of this.data) {
      if (pattern.test(e.dataName)) {
        // Exporting copies the key: the ACL must gate it like every other read,
        // and the restriction must travel with the entry.
        if (!this.canReadEntry(e.dataName)) {
          throw new Error(`Access denied: entry "${e.dataName}" requires role "${(this.entryRoles.get(e.dataName) ?? []).join('|')}".`);
        }
        out.data.push({
          dataName: e.dataName,
          nonce:    e.nonce,
          data:     e.data,
          hash:     e.hash,
          dataType: e.dataType,
        });
        const roles = this.entryRoles.get(e.dataName);
        if (roles) out.entryRoles.set(e.dataName, [...roles]);
      }
    }
    out.currentRole = this.currentRole;
    return out;
  }

  /**
   * Copies all entries from `source` into this instance.
   * - Both instances must use the same passcode / key material.
   * - If an entry name already exists it is overwritten.
   * - Does NOT re-save to disk.
   *
   * @param source  Another SPD instance (must share the same AEAD / HMAC keys).
   */
  importEntries(source: SPD): void {
    this.assertReady();
    if (!source.userKey || !this.userKey) {
      throw new Error('Both instances must have key material set before importing entries.');
    }
    // Keys must match — a simple length + content check catches accidental misuse.
    if (
      source.userKey.length !== this.userKey.length ||
      !crypto.timingSafeEqual(source.userKey, this.userKey)
    ) {
      throw new Error(
        'importEntries: source and target instances have different AEAD keys. ' +
        'Both must have been created with the same passcode.'
      );
    }

    // Local name->index map instead of a per-entry findIndex against
    // this.data — merging two large SPD instances was O(n*m).
    const nameToIdx = new Map(this.data.map((x, i) => [x.dataName, i] as const));
    for (const e of source.data) {
      const copy: EncryptedDataEntry = {
        dataName: e.dataName,
        nonce:    e.nonce,
        data:     e.data,
        hash:     e.hash,
        dataType: e.dataType,
      };
      const idx = nameToIdx.get(e.dataName);
      if (idx !== undefined) {
        this.data[idx] = copy;
      } else {
        nameToIdx.set(e.dataName, this.data.length);
        this.data.push(copy);
        this.appendToWal(copy);
      }
    }
  }

  /** Returns the number of stored entries. */
  count(): number {
    return this.data.length;
  }

  /**
   * Streaming extraction: decrypts one entry at a time and invokes `callback`
   * for each, instead of `extractData()`'s "decrypt everything, return one
   * object" — useful when you want to start acting on the first entries
   * before the rest have even been decrypted, or when iterating without
   * needing every value held in memory simultaneously (`this.data` itself
   * — the encrypted entries — still lives in memory regardless; only the
   * DECRYPTED plaintext is processed one entry at a time here).
   *
   * Entirely in-memory — no temp files. (Previously wrote each entry's
   * decrypted plaintext to a `.ssf` temp file and read it back before
   * deleting it, purely to reuse `convertStringToInput`'s string-based
   * signature; that function only ever needed a string, not a file path,
   * so the disk round-trip was pure overhead with no functional purpose —
   * `extractData()`'s in-memory sibling already converts the same
   * decrypted bytes to a string directly, with zero disk I/O, and produces
   * identical results.) Removing it also closes a real, if narrow, class of
   * risk a disk-touching decrypt path always carries: temp-file leakage,
   * backup/snapshot exposure, and crash-recovery residue if the process
   * dies between the write and the cleanup unlink.
   *
   * `tmpDir` has been removed from the signature (breaking change) since
   * it served no purpose other than naming the now-eliminated temp files.
   *
   * @param callback Called once per entry in order. Await is respected — the next
   *                 entry won't be processed until your callback resolves.
   *
   * @example
   * await spd.extractDataStreaming(async (name, value) => {
   *   console.log(name, value);
   * });
   */
  async extractDataStreaming(
    callback: (name: string, value: unknown) => Promise<void> | void
  ): Promise<void> {
    this.assertReady();

    for (const item of this.data) {
      if (item.dataType === ('_decoy' as unknown as typeof item.dataType)) continue;
      if (!this.canReadEntry(item.dataName)) {
        throw new Error(`Access denied: entry "${item.dataName}" requires role "${(this.entryRoles.get(item.dataName) ?? []).join('|')}".`);
      }
      let value: unknown;
      const aad  = this.fileVersion >= 27 ? utf8ToBytes(item.dataName) : null;
      const dKey = this.fileVersion >= 27 ? SPD.deriveEntryKey(this.userKey!, item.dataName) : this.userKey!;
      try {
        const decrypted = this.fileVersion >= 29
          ? SPD.aeadDecrypt(item.data, aad, new Uint8Array(item.nonce), dKey)
          : plainAeadDecrypt(item.data, aad, new Uint8Array(item.nonce), dKey);
        const rawInflated = await zlib.inflate(decrypted);
        const decryptedBuf = this.fileVersion >= 29
          ? SPD.unpadAfterDecompression(rawInflated)
          : rawInflated;
        value = this.convertStringToInput(bytesToUtf8(decryptedBuf), item.dataType);
      } catch {
        throw new Error('Authentication failed.');
      } finally {
        if (this.fileVersion >= 27) (dKey as Uint8Array).fill(0);
      }
      if (SPD.isDecoyValue(item.dataType, value)) continue;

      await callback(item.dataName, value);
    }
  }

  // ─── WAL (Write-Ahead Log) ──────────────────────────────────────────────────

  /**
   * Enables the write-ahead log. Once enabled, every `addData` / `addMany` call
   * appends the encrypted entry to `walPath` atomically. On the next
   * `loadFromFile` / `loadFromFileStreaming`, any existing WAL is replayed
   * automatically before returning. `saveToFile` / `saveToFileStreaming` merges
   * and then deletes the WAL.
   *
   * WAL record format (binary, appended):
   *   [4B magic "SPDW"][1B version][1B nameLen][nameLen B name]
   *   [1B typeLen][typeLen B type][2B hashLen][hashLen B hash]
   *   [3B nonceLen][nonceLen B nonce][8B dataLen][dataLen B encData]
   */
  enableWal(walPath: string): void {
    const fs = getFs();
    this.walPath = walPath;
    // Write WAL header if file doesn't exist yet
    if (!fs.existsSync(walPath)) {
      fs.writeFileSync(walPath, walHeader(), { mode: 0o600 });
    }
  }

  /** Disable WAL without deleting the file. */
  disableWal(): void {
    this.walPath = undefined;
  }

  /** Append a single encrypted entry to the WAL file. Auto-compacts when thresholds are exceeded. */
  private appendToWal(entry: EncryptedDataEntry): void {
    if (!this.walPath || this._rotating) return;
    const fs = getFs();
    const record = encodeWalRecord(entry);
    fs.appendFileSync(this.walPath, record);
    this.walRecordCount++;

    // Auto-compaction: schedule but do not block the synchronous caller.
    // Use setImmediate so the current addData/addMany call returns first.
    if (this.walRecordCount >= SPD.WAL_COMPACT_RECORDS) {
      this.walRecordCount = 0;
      setImmediate(() => { this._walAutoCompact(); });
      return;
    }
    try {
      const walSize = fs.statSync(this.walPath).size;
      if (walSize >= SPD.WAL_COMPACT_BYTES) {
        this.walRecordCount = 0;
        setImmediate(() => { this._walAutoCompact(); });
      }
    } catch { /* ignore stat errors */ }
  }

  /**
   * Internal: called by setImmediate when WAL thresholds are exceeded.
   * Requires a `walCompactPath` to be set; does nothing otherwise.
   * Users should call `flushDelta(outputPath, passcode)` explicitly —
   * auto-compaction only fires when `walCompactPath` is configured via `enableWal`.
   */
  private _walAutoCompact(): void {
    if (!this._walCompactPath || !this._walCompactPasscode) return;
    // Fire-and-forget; errors are swallowed (user can check WAL state manually)
    this.flushDelta(this._walCompactPath, this._walCompactPasscode).catch(() => {});
  }

  private _walCompactPath?: string;
  private _walCompactPasscode?: string;

  /**
   * Configures the output path and passcode used for WAL auto-compaction.
   * Must be called after `enableWal()` for auto-compaction to fire.
   */
  setWalCompactTarget(outputPath: string, passcode: string): void {
    this._walCompactPath    = outputPath;
    this._walCompactPasscode = passcode;
  }

  /**
   * Reads and replays all entries from an existing WAL file into `this.data`.
   * Skips duplicate names (WAL entry wins over existing). Returns entry count replayed.
   *
   * A WAL is append-only and gets fsync'd per-record (see `appendToWal`), but
   * the OS can still hand back a torn/incomplete final record after a real
   * crash or power loss mid-append — this is the exact scenario a WAL exists
   * to make recoverable, so replay must tolerate it rather than propagate an
   * exception. Every field is bounds-checked against the remaining buffer
   * BEFORE being read (both the fixed-width length-prefix fields and the
   * variable-length payload each length describes); the first record found
   * to be incomplete stops replay and returns what was successfully replayed
   * so far, exactly like a real database/journal WAL reader would. Malformed
   * *complete* records (e.g. a name containing bytes `assertSafeDecryptedName`
   * rejects) are treated the same way — indistinguishable from truncation
   * without deeper validation, and "stop before this record" is the safe
   * behavior either way.
   */
  static replayWal(walPath: string, target: SPD): number {
    const fs = getFs();
    if (!fs.existsSync(walPath)) return 0;
    return replayWalRecords(new Uint8Array(fs.readFileSync(walPath)), target.data, assertSafeDecryptedName);
  }

  /**
   * Merges any pending WAL entries, saves the full file, then deletes the WAL.
   * Use this instead of `saveToFile` when WAL is enabled to ensure the WAL
   * is atomically cleared only after a successful save.
   */
  async flushDelta(outputPath: string, passcode: string, streaming = false): Promise<void> {
    const fs = getFs();
    this.assertReady();
    if (this.walPath && fs.existsSync(this.walPath)) {
      SPD.replayWal(this.walPath, this);
    }
    if (streaming) {
      await this.saveToFileStreaming(outputPath, passcode);
    } else {
      await this.saveToFile(outputPath, passcode);
    }
    // Only delete WAL after successful save
    if (this.walPath && fs.existsSync(this.walPath)) {
      fs.unlinkSync(this.walPath);
      // Re-create empty WAL header so the WAL path stays enabled
      fs.writeFileSync(this.walPath, walHeader(), { mode: 0o600 });
      this.walRecordCount = 0;
    }
  }

  // ─── Lifecycle ─────────────────────────────────────────────────────────────

  destroy(): void {
    if (this._antiForensicMode) { this._antiForensicMode = false; antiForensic.count--; }
    // Zero key material in place before releasing references so the bytes
    // are scrubbed from the heap rather than just dereferenced.
    const hadKeys = !!this.userKey;
    if (this.userKey) { (this.userKey).fill(0); this.userKey = undefined; }
    if (this.macKey)  { (this.macKey).fill(0);  this.macKey  = undefined; }
    if (this.salt)    { (this.salt).fill(0);     this.salt    = undefined; }
    if (hadKeys) SPD.log('key_destroyed');
    // Zero blinded key material
    if (this._blindedKey)    { this._blindedKey.fill(0);    this._blindedKey = undefined; }
    if (this._blindedMacKey) { this._blindedMacKey.fill(0); this._blindedMacKey = undefined; }
    if (this._keyMask)       { this._keyMask.fill(0);       this._keyMask = undefined; }
    // Zero signing key
    if (this._signingKey)    { this._signingKey.fill(0);    this._signingKey = undefined; }
    // _walCompactPasscode holds a raw passcode string for the lifetime of
    // the instance (used by _walAutoCompact's fire-and-forget flushDelta
    // call) — it's the one long-lived secret field with no cleanup path.
    // Strings can't be zeroed, but the reference is dropped here like
    // every other field, consistent with the rest of this method.
    this._walCompactPath     = undefined;
    this._walCompactPasscode = undefined;
    this.data    = [];
    this.keyPair = undefined;
  }

  clearCache(): void {
    this.destroy();
  }

  /**
   * Sets a global pepper mixed into all Argon2id key derivations.
   * Never stored in the file — both save and load sides must set the same pepper.
   * Must be set before setPassKey / loadFromFile / loadFromString / getEntry.
   *
   * A `Buffer`/binary pepper is mixed into key derivation as raw bytes, not
   * decoded back to a UTF-8 string first — decoding non-UTF-8-valid bytes to
   * a string is lossy and non-injective (distinct binary peppers could
   * collide to the same effective string, silently losing entropy). String
   * peppers are unaffected either way: valid UTF-8 always round-trips
   * losslessly.
   *
   * Pass `''` / an empty `Uint8Array` to clear/disable the pepper — that
   * special case always succeeds regardless of the checks below, matching
   * this codebase's existing "empty pepper = no pepper" convention.
   *
   * Any NON-empty pepper is validated: minimum length (16 bytes / 128 bits)
   * and rejection of obviously degenerate values (a single byte value
   * repeated throughout, e.g. all-zero) — found via direct audit: this
   * method previously accepted literally anything, including a single
   * character, which would silently defeat the whole point of a pepper (an
   * attacker who somehow learns or guesses it back would need only a
   * trivial extra guess, not a meaningfully harder one). Deliberately NOT
   * reusing the human-passphrase entropy heuristics from
   * `checkPassphraseStrength` (common-phrase deny list, keyboard-walk
   * patterns, bigram penalty) — a pepper is meant to be an
   * application-level secret (e.g. `SPD.generateRandomKey()` output, or a
   * value from a secrets manager), not something a human memorizes and
   * types, so those passphrase-specific checks don't fit and could reject
   * a perfectly good random binary pepper that happens to look weak when
   * mis-interpreted as text.
   */
  static setPepper(pepper: string | Uint8Array): void {
    keyMaterial.setPepper(pepper);
    // Key cache entries were derived without this pepper — evict them.
    SPD.clearKeyCache();
  }

  // ─── Keyfile support ─────────────────────────────────────────────────────────

  /**
   * Generate a cryptographically random 64-byte (512-bit) keyfile and write it
   * to `filePath`.  The keyfile should be stored separately from the SPD file
   * (e.g. USB drive, password manager, or HSM) so that an attacker who obtains
   * the SPD file alone cannot attempt password guessing — the keyfile bytes are
   * required as a second factor and are mixed into every Argon2id derivation.
   *
   * Never store the keyfile in the same directory as the SPD file.
   *
   * @example
   * await SPD.generateKeyfile('/mnt/usb/my.key');
   * SPD.loadKeyfile('/mnt/usb/my.key');
   * const spd = new SPD();
   * await spd.setPassKey('anything'); // passcode quality no longer matters
   */
  static generateKeyfile(filePath: string): void {
    keyMaterial.generateKeyfile(filePath);
    SPD.log('keyfile_generated', { path: filePath });
  }

  /**
   * Load a keyfile previously created with `generateKeyfile()`.
   * Must be called before `setPassKey()`, `loadFromFile()`, and any other
   * operation that derives key material.
   *
   * The keyfile bytes are mixed into every Argon2id derivation via
   * HMAC-SHA3-512(keyfileBytes, fileSalt || passcode), so:
   *  - The same keyfile + any passcode ≠ the same keyfile + different passcode
   *  - The same keyfile + same passcode on a different SPD file (different salt) ≠ same key
   *  - Without the keyfile, no amount of passcode guessing succeeds
   *
   * @param filePath  Path to the keyfile (64 bytes of random data).
   */
  static loadKeyfile(filePath: string): void {
    const bytes = keyMaterial.loadKeyfile(filePath);
    SPD.clearKeyCache(); // cached keys don't include keyfile material
    SPD.log('keyfile_loaded', { path: filePath, bytes });
  }

  /**
   * Unload the current keyfile so subsequent operations use passcode-only derivation.
   * Call this when you are done with the SPD instance and want to remove the
   * keyfile material from memory.
   */
  static unloadKeyfile(): void {
    keyMaterial.unloadKeyfile();
    SPD.clearKeyCache();
  }

  // ─── Passphrase generation ────────────────────────────────────────────────────

  /**
   * Generate a cryptographically random passphrase from a built-in 240-word
   * list (~7.9 bits of entropy per word, uniform via rejection sampling).
   *
   * Default: 9 words → ~71 bits of entropy — resistant
   * Argon2id-capable ASICs, and **centuries** at the `high` or `paranoid` profile.
   *
   * With a keyfile loaded alongside, the passphrase entropy is irrelevant — the
   * keyfile provides 512 bits regardless. The passphrase then acts only as a
   * second authentication factor.
   *
   * @param words  Number of words (minimum 5 = ~40 bits; default 9 = ~71 bits).
   * @returns      A space-separated passphrase string, e.g. "apple cargo drum fence grain helm iris"
   *
   * @example
   * const pass = SPD.generatePassphrase();
   * // → "timber rivet angle plumb comet drift spark"
   * const spd = new SPD();
   * await spd.setPassKey(pass);
   */
  static generatePassphrase(words = 9): string {
    return generatePassphrase(words);
  }

  // ─── File locking ───────────────────────────────────────────────────────────

  /**
   * Acquires an advisory lock for `filePath` by creating `filePath.lock`.
   * The lock file contains JSON with PID and timestamp so stale locks
   * (process dead or >30 s old) are automatically broken.
   *
   * If the lock is held by a live process, retries every 50 ms until
   * `lockTimeoutMs` has elapsed (default 5 000 ms) before throwing `ESPD_LOCKED`.
   *
   * Returns this lock's own token (the exact bytes written to the lock
   * file) — pass it to `releaseLock` so release only deletes the lock if
   * it's still the SAME one this call created. Without that check: process
   * A holds a lock past STALE_MS (e.g. a slow save under I/O contention) ->
   * process B considers it stale, deletes it, and re-acquires with its own
   * token -> A's original (still in-flight) call eventually reaches its
   * `finally { releaseLock() }` and deletes B's live lock, letting a third
   * process acquire concurrently with B — defeating the mutual exclusion
   * the lock exists to provide. Verifying the token closes that window.
   */
  static acquireLock(filePath: string, lockTimeoutMs = 5_000): string {
    const token = acquireLock(filePath, lockTimeoutMs);
    SPD.log('lock_acquired', { path: filePath });
    return token;
  }

  /**
   * Releases the advisory lock for `filePath` (deletes `filePath.lock`).
   * If `token` (the string returned by `acquireLock`) is passed, the lock
   * file is only deleted if it still contains that exact token — closing
   * the TOCTOU window described in `acquireLock`'s doc comment, where a
   * lock broken as "stale" by another process and re-acquired could
   * otherwise be deleted out from under that other process by this call.
   * `token` is optional (not required) so this stays callable the same way
   * for any caller that genuinely just wants best-effort cleanup.
   */
  static releaseLock(filePath: string, token?: string): void {
    releaseLock(filePath, token);
  }

  // ─── Serialization ─────────────────────────────────────────────────────────

  async saveToFile(
    outputPath: string,
    passcode: string,
    options?: { errorCorrection?: boolean } & EccOptions
  ): Promise<void> {
    const fs = getFs();
    if (typeof outputPath !== 'string' || !outputPath.trim()) {
      throw new Error('Invalid output path.');
    }
    this.assertReady();
    const effectivePasscode = this._keylessMode ? this._keylessSecretEncoded! : passcode;
    SPD.log('save_start', { path: outputPath, format: 'json' });
    const lockToken = SPD.acquireLock(outputPath);
    try {
      this.writeCounter++;
      const compressed = await this.buildSerializedPayload(effectivePasscode);
      const tmpPath = outputPath + '.tmp';
      const wfd = fs.openSync(tmpPath, 'w', 0o600);
      try {
        fs.writeSync(wfd, compressed);
        fs.fsyncSync(wfd); // flush to disk before the rename is visible
      } finally {
        fs.closeSync(wfd);
      }
      fs.renameSync(tmpPath, outputPath);
      writeSeqCounter(outputPath, this.writeCounter);
    } finally {
      SPD.releaseLock(outputPath, lockToken);
    }
    SPD.log('save_end', { path: outputPath, format: 'json', writeCounter: this.writeCounter });

    if (options?.errorCorrection) {
      await SPD.writeParityFile(outputPath, options);
    }
  }

  /**
   * Saves to file using streaming I/O — supports files larger than 2 GB.
   * Format: [8B LE uint64 plaintext length][64B HMAC-SHA3-512][zlib(plaintext)]
   *
   * Embeds a tail index (SPDx) for fast on-demand `getEntry()` lookups.
   * Acquires an advisory lock on `outputPath` and releases it after save.
   *
   * @param onProgress  Optional callback — called with (bytesWritten, totalBytes)
   *                    as plaintext bytes are fed through the deflate pipeline.
   * @param options.errorCorrection  If true, also writes a `<outputPath>.ecc`
   *   Reed-Solomon parity sidecar after the save completes (sugar over
   *   calling `SPD.writeParityFile(outputPath)` yourself) — see that method's
   *   docs for what it protects against and its tunable parameters, which
   *   can be passed here too via the same option object.
   */
  async saveToFileStreaming(
    outputPath: string,
    passcode: string,
    onProgress?: (bytesWritten: number, totalBytes: number) => void,
    options?: { errorCorrection?: boolean } & EccOptions
  ): Promise<void> {
    const fs = getFs();
    if (typeof outputPath !== 'string' || !outputPath.trim()) {
      throw new Error('Invalid output path.');
    }
    this.assertReady();
    // Keyless mode: this instance has no human passcode at all — use the
    // stored sentinel-wrapped secret instead of whatever the caller passed
    // (which is ignored; pass '' for clarity). See setRandomKey()'s docs.
    const effectivePasscode = this._keylessMode ? this._keylessSecretEncoded! : passcode;
    const lockToken = SPD.acquireLock(outputPath);
    try {
      this.writeCounter++;
      const { plaintext, mac } = await this.buildBinaryPayload(effectivePasscode);

      const tmpSpdPath = outputPath + '.tmp';
      await new Promise<void>((resolve, reject) => {
        const sizeBuf = u8Alloc(8);
        writeBigUInt64LE(sizeBuf, BigInt(plaintext.length));

        const out = fs.createWriteStream(tmpSpdPath, { mode: 0o600 });
        out.once('error', reject);
        out.write(sizeBuf);
        out.write(mac); // always 64 bytes

        const deflate = zlib.createDeflate({ level: this.compressionLevel });
        deflate.on('data', (chunk: Uint8Array) => out.write(chunk));
        deflate.once('end', () => {
          // fsync the underlying fd before closing so data is durable before rename
          const fd = (out as any).fd as number | undefined;
          out.end(() => {
            if (typeof fd === 'number') {
              try { fs.fsyncSync(fd); } catch { /* best-effort on platforms that don't support it */ }
            }
            resolve();
          });
        });
        deflate.once('error', reject);
        // out.once('finish', resolve); — replaced by the end callback above

        const CHUNK = 64 * 1024 * 1024;
        let offset = 0;
        while (offset < plaintext.length) {
          const end = Math.min(offset + CHUNK, plaintext.length);
          deflate.write(plaintext.subarray(offset, end));
          offset = end;
          onProgress?.(offset, plaintext.length);
        }
        deflate.end();
      });

      fs.renameSync(tmpSpdPath, outputPath);
      writeSeqCounter(outputPath, this.writeCounter);

      // Embed index in the file tail for self-contained lookup (no sidecar needed).
      // buildOffsetIndex decrypts every entry's name — an O(n) pass — so it's
      // computed ONCE here and reused for both the embedded tail index and the
      // .spdi sidecar below, instead of each independently re-decrypting every
      // name (previously a full duplicate decrypt pass on every single save).
      const nameKeyForIndex = SPD.deriveNameKey(this.userKey!);
      const indexEntries = SPD.buildOffsetIndex(plaintext, nameKeyForIndex);
      SPD.embedIndexInFile(outputPath, indexEntries, this.macKey!);

    } finally {
      SPD.releaseLock(outputPath, lockToken);
    }
    SPD.log('save_end', { path: outputPath, format: 'binary', writeCounter: this.writeCounter });

    if (options?.errorCorrection) {
      await SPD.writeParityFile(outputPath, options);
    }
  }

  /**
   * Computes the decompressed byte offset of each entry within a binary plaintext buffer.
   * The offset points to the start of that entry's nameLen byte.
   */
  private static buildOffsetIndex(plaintext: Uint8Array, nameKey: Uint8Array): SPDIndexEntry[] {
    const metaLen = readUInt32LE(plaintext, 0);
    let offset = 4 + metaLen;
    const entries: SPDIndexEntry[] = [];
    while (offset < plaintext.length) {
      if (offset + 2 > plaintext.length) break;
      const entryStart = offset;
      // v29+ interleaved format: [2B encNameLen][encName][1B typeLen][type][2B hashLen][hash][3B nonceLen][nonce][8B dataLen][data]
      const encNameLen = readUInt16LE(plaintext, offset); offset += 2;
      const encNameBuf = plaintext.subarray(offset, offset + encNameLen); offset += encNameLen;
      const name = SPD._decryptEntryName(encNameBuf, nameKey);
      const typeLen  = readUInt8(plaintext, offset);              offset += 1 + typeLen;
      const hashLen  = readUInt16LE(plaintext, offset);           offset += 2 + hashLen;
      const nonceLen = readUIntLE3(plaintext, offset);          offset += 3 + nonceLen;
      const dataLen  = Number(readBigUInt64LE(plaintext, offset)); offset += 8 + dataLen;
      entries.push({ name, decompressedOffset: BigInt(entryStart) });
    }
    return entries;
  }

  /**
   * Appends the entry offset index to the end of an already-written .spd file.
   * Tail format: [32B HMAC-SHA3-256 of body][body: N×(1B nameLen + name + 8B offset)][8B indexStart][4B "SPDx"]
   * The indexStart is the byte offset from the start of the file to the 32B HMAC.
   */
  /**
   * @internal 16-byte keyed tag standing in for an entry name inside the tail
   * index. v29 encrypts entry names in every record; the old tail index stored
   * them in clear next to those records, undoing that. A reader derives the
   * tag for the name it wants and looks it up; nothing about other names leaks.
   */
  static indexNameTag(macKey: Uint8Array, name: string): Uint8Array {
    return crypto.createHmac('sha3-256', macKey.subarray(0, 32))
      .update(INDEX_TAG_LABEL).update(utf8ToBytes(name)).digest().subarray(0, INDEX_TAG_BYTES);
  }

  /** @internal Tail index v2 bytes: HMAC ‖ (tag16 ‖ offset8)* ‖ indexStart ‖ "SPDy". Shared with SPDWriter. */
  static buildIndexTail(entries: SPDIndexEntry[], macKey: Uint8Array, indexStart: bigint): Uint8Array {
    const bodyParts: Uint8Array[] = [];
    for (const e of entries) {
      const offBuf = u8Alloc(8); writeBigUInt64LE(offBuf, e.decompressedOffset);
      bodyParts.push(SPD.indexNameTag(macKey, e.name), offBuf);
    }
    const body = u8Concat(bodyParts);
    const hmac = crypto.createHmac('sha3-256', macKey.subarray(0, 32)).update(body).digest();
    const startBuf = u8Alloc(8); writeBigUInt64LE(startBuf, indexStart);
    return u8Concat([hmac, body, startBuf, SPDY_MAGIC]);
  }

  private static embedIndexInFile(
    filePath: string,
    entries: SPDIndexEntry[],
    macKey: Uint8Array
  ): void {
    const fs = getFs();
    const indexStart = BigInt(fs.statSync(filePath).size);
    fs.appendFileSync(filePath, SPD.buildIndexTail(entries, macKey, indexStart));
  }


  /**
   * Reads and validates the embedded tail index from a `.spd` file.
   * Returns null if the file doesn't exist, has no embedded index, or the HMAC fails (falls back to scan).
   */
  private static readIndexFile(
    filePath: string,
    macKey: Uint8Array
  ): { map: Map<string, bigint>; tagged: boolean } | null {
    const fs = getFs();
    let stat: fs.Stats;
    try { stat = fs.statSync(filePath); } catch { return null; }

    if (stat.size < 12) return null;

    const fd = fs.openSync(filePath, 'r');
    try {
      // Read last 12 bytes: [8B indexStart][4B magic]
      const trailer = u8Alloc(12);
      fs.readSync(fd, trailer, 0, 12, stat.size - 12);

      const magic = trailer.subarray(8, 12);
      const tagged = u8Equals(magic, SPDY_MAGIC);
      if (!tagged && !u8Equals(magic, SPDX_MAGIC)) return null;

      const indexStart = Number(readBigUInt64LE(trailer, 0));
      const tailLen = stat.size - indexStart - 12; // excludes trailer
      if (tailLen < 32) return null;

      // Read [32B hmac][body]
      const tailBuf = u8Alloc(tailLen);
      fs.readSync(fd, tailBuf, 0, tailLen, indexStart);

      const storedHmac = tailBuf.subarray(0, 32);
      const body       = tailBuf.subarray(32);

      const computedHmac = crypto.createHmac('sha3-256', macKey.subarray(0, 32)).update(body).digest();
      if (!crypto.timingSafeEqual(storedHmac, computedHmac)) return null;

      const map = new Map<string, bigint>();
      let pos = 0;
      if (tagged) {
        if (body.length % (INDEX_TAG_BYTES + 8) !== 0) return null;
        while (pos < body.length) {
          const tag = bytesToHex(body.subarray(pos, pos + INDEX_TAG_BYTES)); pos += INDEX_TAG_BYTES;
          map.set(tag, readBigUInt64LE(body, pos)); pos += 8;
        }
      } else {
        // Legacy "SPDx" tail: plaintext names (files written before this version).
        while (pos < body.length) {
          const nameLen = readUInt8(body, pos); pos += 1;
          const name    = bytesToUtf8(body.subarray(pos, pos + nameLen)); pos += nameLen;
          const offset  = readBigUInt64LE(body, pos); pos += 8;
          map.set(name, offset);
        }
      }
      return { map, tagged };
    } catch {
      return null;
    } finally {
      try { fs.closeSync(fd); } catch {}
    }
  }

  async saveData(passcode: string = ''): Promise<string> {
    this.assertReady();
    const compressed = await this.buildSerializedPayload(this._keylessMode ? this._keylessSecretEncoded! : passcode);
    return bytesToBase64(compressed);
  }

  /**
   * Splits the payload into base64 chunks for chunked internet transfer.
   * The manifest (last element) records totalChunks/totalBytes for validation.
   * Reassemble with `SPD.loadFromChunks(chunks, passcode)`.
   *
   * If `chunkSize` is omitted (or 0), a size is computed automatically:
   *   - Targets ~32 chunks so the manifest stays small
   *   - Clamped between 64 KB (min) and 8 MB (max)
   *   - Rounded up to the nearest 64 KB boundary for alignment
   */
  async saveDataChunked(passcode: string, chunkSize: number = 0): Promise<string[]> {
    this.assertReady();
    const raw = await this.buildSerializedPayload(this._keylessMode ? this._keylessSecretEncoded! : passcode);

    // Auto-select chunk size when caller passes 0 or omits it
    if (!chunkSize || chunkSize <= 0) {
      const TARGET_CHUNKS = 32;
      const MIN_CHUNK     = 64  * 1024;       //  64 KB
      const MAX_CHUNK     = 8   * 1024 * 1024; //   8 MB
      const ALIGN         = 64  * 1024;        //  64 KB boundary
      const ideal = Math.ceil(raw.length / TARGET_CHUNKS);
      const clamped = Math.max(MIN_CHUNK, Math.min(MAX_CHUNK, ideal));
      chunkSize = Math.ceil(clamped / ALIGN) * ALIGN;
    }

    const chunks: string[] = [];

    for (let offset = 0; offset < raw.length; offset += chunkSize) {
      chunks.push(bytesToBase64(raw.subarray(offset, offset + chunkSize)));
    }

    const manifest: SPDChunkManifest = {
      totalChunks: chunks.length,
      chunkSize,
      totalBytes: raw.length,
      version: SPD_VERSION,
    };

    chunks.push(JSON.stringify(manifest));
    return chunks;
  }

  // ─── Static loaders ────────────────────────────────────────────────────────

  /**
   * Loads a `.spd` file that was saved by an instance unlocked with
   * `setRandomKey()`/`setKeyfileOnly()` — no human passcode anywhere in the
   * flow. `masterSecret` must be the exact same 96-byte secret used to save
   * the file (from `SPD.generateRandomKey()`, or read back from wherever you
   * stored it / from a `setKeyfileOnly()`-format keyfile via
   * `fs.readFileSync`).
   *
   * @example
   * const secret = await getFromSecretsManager('my-app/spd-key'); // your own storage
   * const spd = await SPD.loadWithRandomKey('./data.spd', secret);
   */
  static async loadWithRandomKey(
    filePath: string,
    masterSecret: Uint8Array,
    verifyKey?: Uint8Array,
    options?: { autoRepair?: boolean; streaming?: boolean; onProgress?: (bytesRead: number, totalBytes: number) => void }
  ): Promise<SPD> {
    if (!(masterSecret instanceof Uint8Array) || masterSecret.length !== KEYLESS_MASTER_SECRET_LEN) {
      throw new Error(
        `loadWithRandomKey: expected a ${KEYLESS_MASTER_SECRET_LEN}-byte Uint8Array (got ${masterSecret?.length ?? typeof masterSecret}).`
      );
    }
    const encoded = SPD._encodeKeylessSecret(masterSecret);
    // Both loaders sniff the header and hand off to the other format; `streaming`
    // only chooses which entry point (and whether onProgress applies).
    const spd = options?.streaming === false
      ? await SPD.loadFromFile(filePath, encoded, verifyKey, options)
      : await SPD.loadFromFileStreaming(filePath, encoded, options?.onProgress, verifyKey, options);
    spd._keylessMode = true;
    spd._keylessSecretEncoded = encoded;
    return spd;
  }

  private static _startsWithZlibHeader(filePath: string): boolean {
    const fs = getFs();
    const head = u8Alloc(2);
    const fd = fs.openSync(filePath, 'r');
    try {
      if (fs.readSync(fd, head, 0, 2, 0) < 2) return false;
    } finally {
      fs.closeSync(fd);
    }
    return (head[0] & 0x0f) === 8 && ((head[0] << 8) | head[1]) % 31 === 0;
  }

  /**
   * Convenience wrapper: reads a `setKeyfileOnly()`-format keyfile from
   * `keyfilePath` and loads `filePath` with it in one call.
   *
   * @example
   * const spd = await SPD.loadWithKeyfileOnly('./data.spd', '/secure/vault/my.key');
   */
  static async loadWithKeyfileOnly(
    filePath: string,
    keyfilePath: string,
    verifyKey?: Uint8Array,
    options?: { autoRepair?: boolean; streaming?: boolean; onProgress?: (bytesRead: number, totalBytes: number) => void }
  ): Promise<SPD> {
    const fs = getFs();
    const bytes = fs.readFileSync(keyfilePath);
    if (bytes.length !== KEYLESS_MASTER_SECRET_LEN) {
      throw new Error(
        `loadWithKeyfileOnly: keyfile at ${keyfilePath} must be exactly ${KEYLESS_MASTER_SECRET_LEN} bytes (got ${bytes.length}).`
      );
    }
    return SPD.loadWithRandomKey(filePath, new Uint8Array(bytes), verifyKey, options);
  }

  /**
   * SECURITY CHECKLIST — every method that reads an entry's value from a
   * real `.spd` file on disk (this method, `loadFromFileStreaming`, and
   * `getEntry`) must apply ALL of the following, not a subset:
   *   1. Whole-file MAC verification before trusting anything (never skip
   *      or shortcut based on file size/claimed length — see the
   *      decompression-bomb early-abort fixes on the streaming paths).
   *   2. Rollback protection (`checkRollback`) — a stale/rolled-back file
   *      must not silently succeed.
   *   3. Auto-destruct / open-count (`checkAndIncrementOpenCount`) — a
   *      file configured via `setFileMaxOpenCount` must have its budget
   *      enforced by EVERY read path, or the limit is meaningless.
   *   4. Entry-level ACL (`restrictEntry`/`entryRoles`) — a restricted
   *      entry must not be returned without the right role, from ANY
   *      method that can return its value.
   *   5. File signature verification (`verifyKey`/`fileSignature`) when a
   *      pinned public key is supplied.
   *
   * This checklist exists because `getEntry` is architecturally a
   * SEPARATE, independently-maintained implementation (static, no
   * persistent instance, built as an optimized single-entry lookup) rather
   * than a code path shared with `loadFromFile`/`loadFromFileStreaming` —
   * and it has, in practice, missed #3 and #4 above at different points
   * (both found via direct audit and fixed with regression tests; see
   * `getEntry`'s own doc comment for the specifics). Adding a new
   * security-relevant check to ONE of these three methods without also
   * adding it to the other two recreates that same class of bug. If you
   * add a fourth item to this list, update all three methods' bodies, not
   * just this comment.
   */
  static async loadFromFile(
    filePath: string,
    passcode: string,
    verifyKey?: Uint8Array,
    options?: { autoRepair?: boolean }
  ): Promise<SPD> {
    const fs = getFs();
    if (!filePath?.trim() || !passcode?.trim()) {
      throw new Error('Authentication failed.');
    }

    if (options?.autoRepair && fs.existsSync(filePath + '.ecc')) {
      try {
        await SPD.repairBitRot(filePath, passcode);
      } catch { /* no sidecar, sidecar itself corrupt, unrecoverable, or unauthenticated repair — fall through, the real error will surface below */ }
    }

    // A binary-format file (`saveToFileStreaming`, SPDWriter, the Rust crate)
    // has no zlib header at offset 0 — hand it to the streaming reader instead
    // of failing with zlib's "incorrect header check".
    if (!SPD._startsWithZlibHeader(filePath)) {
      return SPD._loadFromFileStreamingInner(filePath, passcode, undefined, verifyKey);
    }

    SPD.log('load_start', { path: filePath, format: 'json' });
    const fileContent = fs.readFileSync(filePath);
    const spd = await SPD.parseSerializedPayload(fileContent, passcode, filePath, verifyKey);
    SPD.checkAndIncrementOpenCount(filePath, spd);
    SPD.log('load_end', { path: filePath, format: 'json' });
    return spd;
  }

  /** See the SECURITY CHECKLIST on `loadFromFile`'s doc comment — this
   * method must apply the same set of checks (MAC, rollback, auto-destruct,
   * ACL, file signature); it already does, this note is just so a future
   * change to one doesn't drift from the others.
   */
  static async loadFromFileStreaming(
    filePath: string,
    passcode: string,
    onProgress?: ((bytesRead: number, totalBytes: number) => void) | Uint8Array,
    verifyKey?: Uint8Array,
    options?: { autoRepair?: boolean }
  ): Promise<SPD> {
    // Tolerate the common slip of passing the verify key where `loadFromFile`
    // takes it (3rd position): a Uint8Array can only be a key, never a callback.
    if (onProgress instanceof Uint8Array) {
      if (verifyKey !== undefined) throw new Error('loadFromFileStreaming: verifyKey passed twice (positions 3 and 4)');
      verifyKey = onProgress;
      onProgress = undefined;
    }
    const fs = getFs();
    if (!filePath?.trim() || !passcode?.trim()) {
      throw new Error('Authentication failed.');
    }

    if (options?.autoRepair && fs.existsSync(filePath + '.ecc')) {
      // Attempt a bit-rot repair pass BEFORE the real read, rather than only
      // retrying after a failure: a flipped byte inside the zlib stream can
      // corrupt everything downstream of it (inflate desyncs), not just fail
      // a checksum — repairing proactively is more reliable than "read,
      // catch, repair, retry" for this class of corruption.
      try {
        await SPD.repairBitRot(filePath, passcode);
      } catch { /* no sidecar, sidecar itself corrupt, unrecoverable, or unauthenticated repair — fall through to the normal read, which will surface the real error */ }
    }

    if (SPD._startsWithZlibHeader(filePath)) {
      return SPD.loadFromFile(filePath, passcode, verifyKey);
    }
    return SPD._loadFromFileStreamingInner(filePath, passcode, onProgress, verifyKey);
  }

  private static async _loadFromFileStreamingInner(
    filePath: string,
    passcode: string,
    onProgress?: (bytesRead: number, totalBytes: number) => void,
    verifyKey?: Uint8Array
  ): Promise<SPD> {
    const fs = getFs();
    SPD.log('load_start', { path: filePath, format: 'binary' });

    const headerBuf = u8Alloc(72);
    const fd = fs.openSync(filePath, 'r');
    try {
      fs.readSync(fd, headerBuf, 0, 72, 0);
    } finally {
      fs.closeSync(fd);
    }

    const expectedPlaintextLen = Number(readBigUInt64LE(headerBuf, 0));
    const mac = headerBuf.subarray(8, 72);

    // expectedPlaintextLen comes from the file's own 8-byte header — read
    // before the MAC (at the very end of this function) has verified
    // anything, so it is itself attacker-controlled, not a trustworthy
    // bound on its own. The real protection is checking accumulated
    // decompressed bytes AS THEY STREAM IN and aborting the instant they
    // exceed the claimed length, rather than fully inflating an arbitrarily
    // large payload into `chunks[]` first and only comparing lengths
    // afterward — a small, deliberately crafted ciphertext can inflate to
    // an enormous plaintext (zlib's ratio can exceed 1000:1 on repetitive
    // input) and exhaust memory well before this function ever reaches its
    // authentication check. Bounding accumulation to expectedPlaintextLen
    // (plus one chunk of slack, since the overshoot is only detected after
    // a chunk already arrived) keeps peak memory proportional to what the
    // header claims, matching every other load path's "authenticate before
    // trusting size" discipline instead of being the one exception.
    const plaintext = await new Promise<Uint8Array>((resolve, reject) => {
      const chunks: Uint8Array[] = [];
      let bytesRead = 0;
      let aborted = false;
      const readStream = fs.createReadStream(filePath, { start: 72 });
      const inflate = zlib.createInflate();
      const abort = (err: Error): void => {
        aborted = true;
        readStream.destroy();
        inflate.destroy();
        reject(err);
      };
      inflate.on('data', (chunk: Uint8Array) => {
        if (aborted) return;
        chunks.push(chunk);
        bytesRead += chunk.length;
        if (bytesRead > expectedPlaintextLen) {
          abort(new Error('Authentication failed.'));
          return;
        }
        // A throw here (e.g. from a caller's onProgress) would otherwise escape
        // the stream callback as an uncaught exception and leave this promise
        // pending forever.
        try {
          onProgress?.(bytesRead, expectedPlaintextLen);
        } catch (err) {
          abort(err instanceof Error ? err : new Error(String(err)));
        }
      });
      inflate.once('end', () => { if (!aborted) resolve(u8Concat(chunks)); });
      inflate.once('error', (err) => { if (!aborted) reject(err); });
      readStream.once('error', (err) => { if (!aborted) reject(err); });
      onBinaryData(readStream, (chunk) => inflate.write(chunk));
      readStream.once('end', () => inflate.end());
    });

    if (plaintext.length !== expectedPlaintextLen) {
      throw new Error('Authentication failed.');
    }

    const spd = await SPD.parseBinaryPayload(plaintext, mac, passcode, verifyKey);
    // Rollback check — uses writeCounter embedded in the binary meta block
    checkRollback(filePath, spd.writeCounter);
    SPD.checkAndIncrementOpenCount(filePath, spd);
    SPD.log('load_end', { path: filePath, format: 'binary' });
    return spd;
  }

  /**
   * Auto-destruct helper: reads/increments the open count sidecar (.ocount).
   * If `maxOpenCount` is set and the new count exceeds it, wipes the file and throws.
   */
  private static checkAndIncrementOpenCount(filePath: string, spd: SPD): void {
    const fs = getFs();
    // Read limit from .maxcount sidecar (set by setFileMaxOpenCount) or instance field
    let maxCount = spd.maxOpenCount;
    try {
      const sidecaMax = parseInt(fs.readFileSync(filePath + '.maxcount', 'utf8').trim(), 10);
      if (!isNaN(sidecaMax) && sidecaMax > 0) maxCount = sidecaMax;
    } catch { /* no sidecar */ }
    if (maxCount === 0) return;
    const ocPath = filePath + '.ocount';
    let current = 0;
    try {
      current = parseInt(fs.readFileSync(ocPath, 'utf8').trim(), 10) || 0;
    } catch { /* first open */ }
    current++;
    if (current > maxCount) {
      // Wipe the file before throwing
      try {
        const stat = fs.statSync(filePath);
        const zeros = u8Alloc(Math.min(stat.size, 1024 * 1024));
        const wfd = fs.openSync(filePath, 'r+');
        try {
          for (let off = 0; off < stat.size; off += zeros.length) {
            fs.writeSync(wfd, zeros, 0, Math.min(zeros.length, stat.size - off), off);
          }
        } finally { fs.closeSync(wfd); }
        fs.unlinkSync(filePath);
      } catch { /* best effort */ }
      try { fs.unlinkSync(ocPath); } catch { /* best effort */ }
      SPD.log('auto_destruct', { path: filePath, openCount: current });
      throw Object.assign(new Error('Auto-destruct: maximum open count exceeded. File has been wiped.'), { code: 'ESPD_AUTODESTRUCT' });
    }
    try { fs.writeFileSync(ocPath, String(current), { mode: 0o600 }); } catch { /* best effort */ }
    spd.openCount = current;
  }

  /**
   * True constant-memory streaming extract from a binary SPD file.
   *
   * Unlike `loadFromFileStreaming` (which buffers the entire plaintext into RAM),
   * this method pipes the inflate stream through a byte-by-byte parser that:
   *   1. Reads and verifies the file header + MAC (the full decompressed
   *      plaintext DOES touch disk here — written to a `_spd_plaintext.ssf`
   *      temp file in `tmpDir` — because verifying the whole-file MAC
   *      before trusting anything requires the complete plaintext, and
   *      holding that in RAM simultaneously for an arbitrarily large file
   *      is exactly what this method exists to avoid. This is the one
   *      genuinely load-bearing disk touch left in this method.)
   *   2. Parses the metadata block to derive keys
   *   3. Processes one entry at a time, entirely in-memory (no per-entry
   *      temp files — removed: each entry's encrypted blob and decrypted
   *      plaintext were previously round-tripped through their own
   *      `<name>_enc.ssf`/`<name>_dec.ssf` temp files despite already
   *      being plain in-memory buffers at that point, serving no
   *      functional purpose beyond reusing a string-based helper that
   *      never actually needed a file path)
   *
   * Peak RAM usage is proportional to the largest single entry, not the file size.
   * Files of any size are supported as long as individual entries fit in memory.
   *
   * @param filePath Path to the `.spd` file written by `saveToFileStreaming`
   * @param passcode Passcode used when the file was saved
   * @param tmpDir   Scratch directory for the one remaining whole-plaintext temp
   *                 file (must exist, mode 0700 recommended)
   * @param callback Called once per entry in order. Next entry waits for this to resolve.
   *
   * @example
   * await SPD.extractFromFileStreaming('./huge.spd', 'MyPass!', '/tmp/spd', async (name, value) => {
   *   console.log(name, typeof value);
   * });
   */
  static async extractFromFileStreaming(
    filePath: string,
    passcode: string,
    tmpDir: string,
    callback: (name: string, value: unknown) => Promise<void> | void,
    onProgress?: (bytesRead: number, totalBytes: number) => void,
    verifyKey?: Uint8Array
  ): Promise<void> {
    const fs = getFs();
    const path = getPath();
    if (!filePath?.trim() || !passcode?.trim()) {
      throw new Error('Authentication failed.');
    }

    // ── 1. Read the 72-byte file header ──────────────────────────────────────
    const headerBuf = u8Alloc(72);
    const fd = fs.openSync(filePath, 'r');
    try {
      fs.readSync(fd, headerBuf, 0, 72, 0);
    } finally {
      fs.closeSync(fd);
    }
    const expectedPlaintextLen = Number(readBigUInt64LE(headerBuf, 0));
    const fileMac = headerBuf.subarray(8, 72);

    // ── 2. Decompress the entire plaintext for MAC verification ──────────────
    // We must verify the MAC over the whole plaintext before processing any
    // entry — otherwise an attacker could feed us crafted entries.
    // We stream into a temp file so the plaintext never fully lives in a JS Buffer.
    const plaintextTmp = path.join(tmpDir, '_spd_plaintext.ssf');
    let plaintextLen = 0;

    // expectedPlaintextLen is read from the file's own (not-yet-authenticated)
    // header, so it's attacker-controlled, not a trustworthy bound by itself —
    // check accumulated bytes AS THEY STREAM IN rather than only after the
    // fact, same reasoning as _loadFromFileStreamingInner's equivalent fix.
    // Writing to a temp file (not RAM) already makes this a disk- rather than
    // memory-exhaustion concern, but a tiny crafted ciphertext could still
    // force writing an arbitrarily large temp file before the post-hoc
    // length check below ever runs without this early-abort.
    await new Promise<void>((resolve, reject) => {
      let aborted = false;
      const out = fs.createWriteStream(plaintextTmp, { mode: 0o600 });
      const readStream = fs.createReadStream(filePath, { start: 72 });
      const inflate = zlib.createInflate();
      inflate.on('data', (chunk: Uint8Array) => {
        if (aborted) return;
        plaintextLen += chunk.length;
        if (plaintextLen > expectedPlaintextLen) {
          aborted = true;
          readStream.destroy();
          inflate.destroy();
          out.destroy();
          reject(new Error('Authentication failed.'));
          return;
        }
        out.write(chunk);
        try {
          onProgress?.(plaintextLen, expectedPlaintextLen);
        } catch (err) {
          aborted = true;
          readStream.destroy();
          inflate.destroy();
          out.destroy();
          reject(err instanceof Error ? err : new Error(String(err)));
        }
      });
      inflate.once('end', () => { if (!aborted) out.end(); });
      inflate.once('error', (err) => { if (!aborted) reject(err); });
      readStream.once('error', (err) => { if (!aborted) reject(err); });
      out.once('finish', () => { if (!aborted) resolve(); });
      out.once('error', (err) => { if (!aborted) reject(err); });
      onBinaryData(readStream, (chunk) => inflate.write(chunk));
      readStream.once('end', () => inflate.end());
    });

    if (plaintextLen !== expectedPlaintextLen) {
      try { fs.unlinkSync(plaintextTmp); } catch { /* ignore */ }
      throw new Error('Authentication failed.');
    }

    // ── 3. Read just the meta block to derive keys ───────────────────────────
    const metaLenBuf = u8Alloc(4);
    const ptFd = fs.openSync(plaintextTmp, 'r');
    let ptOffset = 0;
    try {
      fs.readSync(ptFd, metaLenBuf, 0, 4, ptOffset);
      ptOffset += 4;
      const metaLen = readUInt32LE(metaLenBuf, 0);
      const metaBuf = u8Alloc(metaLen);
      fs.readSync(ptFd, metaBuf, 0, metaLen, ptOffset);
      ptOffset += metaLen;

      const meta = JSON.parse(bytesToUtf8(metaBuf));
      const { encryptedSalt, saltNonce, wrapSalt, version, entryCount } = meta;
      const writeCounter: number         = meta.writeCounter  ?? 0;
      const hashAlgorithm: HashAlgorithm = meta.hashAlgorithm ?? 'sha3-512';
      const argon2Memory: number         = meta.argon2Memory  ?? ARGON2_MEMORY;
      const argon2Time: number           = meta.argon2Time    ?? ARGON2_TIME;

      if (typeof version !== 'number' || version < SPD_VERSION_MIN || version > SPD_VERSION) {
        throw new Error(`Unsupported SPD version: ${version}`);
      }

      const { argon2HashLen, macKeyLen } = legacyKeyLengthsForVersion(version);

      // KDF chain params (v29+)
      const kdfChainSE: boolean = meta.kdfChain ?? false;
      const scryptNSE: number   = meta.scryptN ?? SCRYPT_N_DEFAULT;
      const scryptRSE: number   = meta.scryptR ?? SCRYPT_R_DEFAULT;
      const scryptPSE: number   = meta.scryptP ?? SCRYPT_P_DEFAULT;
      const a2ParallelSE: number = meta.argon2Parallelism ?? 1;
      validateArgon2Params(argon2Memory, argon2Time, a2ParallelSE);
      if (kdfChainSE) validateScryptParams(scryptNSE, scryptRSE, scryptPSE);

      const { aeadKey, macKey, salt: decryptedSalt } = await SPD.unlockKeys(passcode, {
        encryptedSalt, saltNonce, wrapSalt,
        wrapMemory: meta.wrapArgon2Memory ?? ARGON2_MEMORY_STANDARD,
        wrapTime: meta.wrapArgon2Time ?? ARGON2_TIME_STANDARD,
        wrapParallelism: meta.wrapArgon2Parallelism ?? 1,
        argon2Memory, argon2Time, argon2HashLen, macKeyLen,
        kdfChain: kdfChainSE, scryptN: scryptNSE, scryptR: scryptRSE, scryptP: scryptPSE, argon2Parallelism: a2ParallelSE,
      });

      // ── 4. Verify MAC over the whole plaintext file ───────────────────────
      // Stream the temp file through HMAC without loading it into a Buffer.
      // computeMAC appends contentType to the data, so we replicate that here.
      const macCorrect = await new Promise<Uint8Array>((resolve, reject) => {
        const hmac = crypto.createHmac('sha3-512', macKey);
        const rs = fs.createReadStream(plaintextTmp);
        onBinaryData(rs, (chunk) => hmac.update(chunk));
        rs.once('end', () => {
          hmac.update(utf8ToBytes('application/spd-binary'));
          resolve(hmac.digest());
        });
        rs.once('error', reject);
      });

      if (!crypto.timingSafeEqual(fileMac, macCorrect)) {
        throw new Error('Authentication failed.');
      }

      // ML-DSA-65 signature verification — mirrors parseBinaryPayload's
      // logic (see that function's comment). Kept optional/opt-in via the
      // `verifyKey` param (same as loadFromFile/loadFromFileStreaming) —
      // extractFromFileStreaming previously had no way to enforce a pinned
      // signer at all, an inconsistency with the other load paths.
      const storedSigStream: number[] | undefined = meta.fileSignature;
      if (verifyKey && storedSigStream) {
        const sigBuf = new Uint8Array(storedSigStream);
        const metaNoSig = { ...meta } as Record<string, unknown>;
        delete (metaNoSig as any).fileSignature;
        const metaNoSigPayload = utf8ToBytes(JSON.stringify(metaNoSig));
        const metaNoSigLenBuf  = u8Alloc(4);
        writeUInt32LE(metaNoSigLenBuf, metaNoSigPayload.length);
        const macNoSig = await new Promise<Uint8Array>((resolve, reject) => {
          const hmacNoSig = crypto.createHmac('sha3-512', macKey);
          hmacNoSig.update(metaNoSigLenBuf).update(metaNoSigPayload);
          const rsBody = fs.createReadStream(plaintextTmp, { start: 4 + metaLen });
          onBinaryData(rsBody, (chunk) => hmacNoSig.update(chunk));
          rsBody.once('end', () => {
            hmacNoSig.update(utf8ToBytes('application/spd-binary'));
            resolve(hmacNoSig.digest());
          });
          rsBody.once('error', reject);
        });
        if (!verifyFileMac(sigBuf, macNoSig, verifyKey)) {
          throw new Error('Authentication failed.');
        }
      } else if (verifyKey && !storedSigStream) {
        throw new Error('Authentication failed.');
      }

      // Rollback check — only after the MAC (and signature) have authenticated
      // `writeCounter`. Doing it earlier let an unauthenticated crafted file
      // advance the `.seq` sidecar and lock out the genuine file.
      checkRollback(filePath, writeCounter);

      // ── 5. Parse + decrypt entries one at a time ──────────────────────────
      const tempSpd = new SPD();
      tempSpd.userKey = aeadKey;
      tempSpd.macKey  = macKey;
      tempSpd.salt    = decryptedSalt;
      tempSpd.setHash(hashAlgorithm);

      // entryCount=0 is a sentinel meaning "scan to EOF"
      const scanToEof = (entryCount === 0);
      const nameKeySE = version >= 29 ? SPD.deriveNameKey(aeadKey) : null;
      // Bounds-check a length field against the remaining bytes in the
      // (already MAC-verified, at this point) plaintext before allocating —
      // a corrupted/truncated stream could otherwise drive Buffer.alloc
      // with an inflated length, causing an uncontrolled allocation attempt
      // deep in a per-entry parse loop instead of a clean, early error.
      const checkLen = (len: number, remaining: number, field: string): number => {
        if (len < 0 || len > remaining) {
          throw new Error(`Authentication failed. (malformed ${field} length: ${len})`);
        }
        return len;
      };

      for (let i = 0; scanToEof ? ptOffset < plaintextLen : i < entryCount; i++) {
        // Read entry header fields from the plaintext temp file
        let dataName: string;
        if (version >= 29) {
          const encNameLenBuf = u8Alloc(2);
          fs.readSync(ptFd, encNameLenBuf, 0, 2, ptOffset); ptOffset += 2;
          const encNameLen = checkLen(readUInt16LE(encNameLenBuf, 0), plaintextLen - ptOffset, 'encNameLen');
          const encNameBuf = u8Alloc(encNameLen);
          fs.readSync(ptFd, encNameBuf, 0, encNameLen, ptOffset); ptOffset += encNameLen;
          dataName = SPD._decryptEntryName(encNameBuf, nameKeySE!);
        } else {
          const nameLenBuf2 = u8Alloc(1);
          fs.readSync(ptFd, nameLenBuf2, 0, 1, ptOffset); ptOffset += 1;
          const nameLen = checkLen(readUInt8(nameLenBuf2, 0), plaintextLen - ptOffset, 'nameLen');
          const nameBuf = u8Alloc(nameLen);
          fs.readSync(ptFd, nameBuf, 0, nameLen, ptOffset); ptOffset += nameLen;
          // Pre-v29 names are stored in plaintext (no AEAD layer) — validate
          // the same way as decrypted v29+ names before it's used to build
          // a temp-file path below (see assertSafeDecryptedName's comment).
          dataName = assertSafeDecryptedName(bytesToUtf8(nameBuf));
        }

        const typeLenBuf = u8Alloc(1);
        fs.readSync(ptFd, typeLenBuf, 0, 1, ptOffset); ptOffset += 1;
        const typeLen = checkLen(readUInt8(typeLenBuf, 0), plaintextLen - ptOffset, 'typeLen');
        const typeBuf = u8Alloc(typeLen);
        fs.readSync(ptFd, typeBuf, 0, typeLen, ptOffset); ptOffset += typeLen;
        const dataType = bytesToUtf8(typeBuf) as SupportedDataType;

        const hashLenBuf2 = u8Alloc(2);
        fs.readSync(ptFd, hashLenBuf2, 0, 2, ptOffset); ptOffset += 2;
        const hashLen = checkLen(readUInt16LE(hashLenBuf2, 0), plaintextLen - ptOffset, 'hashLen');
        const hashBuf = u8Alloc(hashLen);
        fs.readSync(ptFd, hashBuf, 0, hashLen, ptOffset); ptOffset += hashLen;
        const entryHash = bytesToUtf8(hashBuf);

        const nonceLenBuf2 = u8Alloc(3);
        fs.readSync(ptFd, nonceLenBuf2, 0, 3, ptOffset); ptOffset += 3;
        const nonceLen = checkLen(readUIntLE3(nonceLenBuf2, 0), plaintextLen - ptOffset, 'nonceLen');
        const nonce = u8Alloc(nonceLen);
        fs.readSync(ptFd, nonce, 0, nonceLen, ptOffset); ptOffset += nonceLen;

        const dataLenBuf2 = u8Alloc(8);
        fs.readSync(ptFd, dataLenBuf2, 0, 8, ptOffset); ptOffset += 8;
        const dataLen = checkLen(Number(readBigUInt64LE(dataLenBuf2, 0)), plaintextLen - ptOffset, 'dataLen');

        // Read the encrypted entry blob into memory (no temp file — see
        // below; encBuf/decompressed never need to leave memory at all,
        // since each is already a plain in-memory Uint8Array by the time
        // it existed here, and convertStringToInput only ever needed a
        // string, not a file path).
        const encBuf = u8Alloc(dataLen);
        fs.readSync(ptFd, encBuf, 0, dataLen, ptOffset); ptOffset += dataLen;

        // Integrity check on the encrypted blob
        const computedHash = crypto.createHash(hashAlgorithm).update(encBuf).digest('hex');
        if (computedHash !== entryHash) {
          throw new Error('Authentication failed.');
        }

        // Decrypt + decompress entirely in-memory — no temp files.
        // (Previously wrote encBuf to an `_enc.ssf` temp file, read it
        // straight back unchanged, then wrote the decrypted plaintext to a
        // second `_dec.ssf` temp file and read THAT back too, purely to
        // reuse convertStringToInput's string-based signature. Neither
        // round-trip served any functional purpose — a real, if narrow,
        // source of temp-file-leakage/crash-residue risk for no benefit —
        // and both are eliminated the same way extractDataStreaming's
        // equivalent temp files were.)
        let value: unknown;
        const aad  = version >= 27 ? utf8ToBytes(dataName) : null;
        const eKey = version >= 27 ? SPD.deriveEntryKey(aeadKey, dataName) : aeadKey;
        try {
          const decrypted = version >= 29
            ? SPD.aeadDecrypt(encBuf, aad, new Uint8Array(nonce), eKey)
            : plainAeadDecrypt(encBuf, aad, new Uint8Array(nonce), eKey);
          const rawDec = await zlib.inflate(decrypted);
          const decompressed = version >= 29
            ? SPD.unpadAfterDecompression(rawDec)
            : rawDec;
          value = tempSpd['convertStringToInput'](bytesToUtf8(decompressed), dataType);
        } finally {
          if (version >= 27) (eKey as Uint8Array).fill(0);
        }

        await callback(dataName, value);
      }

      // Zero key material
      if (nameKeySE) (nameKeySE).fill(0);
      (aeadKey).fill(0);
      (macKey).fill(0);

    } finally {
      try { fs.closeSync(ptFd); } catch { /* ignore */ }
      try { fs.unlinkSync(plaintextTmp); } catch { /* ignore */ }
    }
  }

  /**
   * On-demand disk lookup — decrypts and returns a single named entry from a
   * binary `.spd` file (written by `saveToFileStreaming`) without loading the
   * whole file into RAM.
   *
   * Uses a `.spdi` index sidecar (written alongside by `saveToFileStreaming`)
   * for fast offset lookup when present. Falls back to a sequential scan if
   * the sidecar is missing or its HMAC fails.
   *
   * The full plaintext MAC is always verified before any entry is decrypted —
   * unauthenticated reads are never returned.
   *
   * RAM usage is bounded to ~one entry's worth of bytes at any time.
   *
   * See `loadFromFile`'s SECURITY CHECKLIST doc comment: this method is a
   * separately-maintained implementation from `loadFromFile`/
   * `loadFromFileStreaming` and has, in practice, been the one to miss a
   * security check added to those two (ACL enforcement, then
   * auto-destruct/open-count — both found via direct audit and fixed
   * below/nearby). Check that list before assuming this method already
   * covers something new added elsewhere.
   *
   * @param role  Optional role to check against `restrictEntry()`'s ACL for
   *   this entry, same semantics as `extractData()`/`entries()`'s
   *   `this.currentRole` check. Found via direct audit + a real cross-check
   *   (a role-restricted entry saved, then fetched via `getEntry` with no
   *   role at all) that this method previously never checked ACLs — the
   *   entry's value was returned unconditionally regardless of any
   *   restriction. Since `getEntry` is `static` (a one-shot file lookup,
   *   not a persistent instance with `setRole()` called on it beforehand),
   *   there was no way to express a caller's role here at all until this
   *   parameter was added. Omitting it behaves like `setRole(undefined)` —
   *   only unrestricted entries are accessible.
   */
  static async getEntry(
    filePath: string,
    passcode: string,
    name: string,
    verifyKey?: Uint8Array,
    role?: string
  ): Promise<SPDGetEntryResult> {
    const fs = getFs();
    if (!filePath?.trim() || !passcode?.trim() || !name?.trim()) {
      throw new Error('filePath, passcode, and name are required.');
    }

    // ── 1. Read the 72-byte file header ──────────────────────────────────────
    const headerBuf = u8Alloc(72);
    const fd = fs.openSync(filePath, 'r');
    try { fs.readSync(fd, headerBuf, 0, 72, 0); }
    finally { fs.closeSync(fd); }
    const expectedLen = Number(readBigUInt64LE(headerBuf, 0));
    const fileMac = headerBuf.subarray(8, 72);

    // ── 2. Try the embedded tail index first to get the entry's decompressed offset.
    //     If we know the offset, we only need to decompress up to offset+entrySize bytes.
    //     Full MAC is always verified — we never return data without it.
    const sanitized = new SPD().sanitizeName(name);

    // Phase A: decompress the full plaintext (needed for MAC).
    // Optimisation: if we discover the entry offset early via the index, we set
    // `earlyStopAfter` and destroy the inflate stream once that many bytes are buffered.
    // We still need the full plaintext for MAC so we decompress it all, but we skip
    // buffering bytes beyond the entry's end, reducing peak memory for large files.
    // expectedLen is read from the file's own (not-yet-authenticated) header,
    // so it's attacker-controlled — check accumulated bytes as they stream
    // in rather than only after fully inflating, same fix and reasoning as
    // _loadFromFileStreamingInner/extractFromFileStreaming's equivalent
    // early-abort: a tiny crafted ciphertext could otherwise force
    // unbounded RAM growth here well before this function's MAC check ever
    // runs, which especially undercuts getEntry's own stated goal of
    // keeping peak memory low for a single-entry lookup on a large file.
    const plaintext = await new Promise<Uint8Array>((resolve, reject) => {
      const chunks: Uint8Array[] = [];
      let bytesRead = 0;
      let aborted = false;
      const rs = fs.createReadStream(filePath, { start: 72 });
      const inflate = zlib.createInflate();
      inflate.on('data', (c: Uint8Array) => {
        if (aborted) return;
        chunks.push(c);
        bytesRead += c.length;
        if (bytesRead > expectedLen) {
          aborted = true;
          rs.destroy();
          inflate.destroy();
          reject(new Error('Authentication failed.'));
        }
      });
      inflate.once('end', () => { if (!aborted) resolve(u8Concat(chunks)); });
      inflate.once('error', (err) => { if (!aborted) reject(err); });
      rs.once('error', (err) => { if (!aborted) reject(err); });
      onBinaryData(rs, (chunk) => inflate.write(chunk));
      rs.once('end', () => inflate.end());
    });

    if (plaintext.length !== expectedLen) {
      throw new Error('Authentication failed.');
    }

    // ── 3. Read meta block to derive keys ─────────────────────────────────────
    const metaLenVal = readUInt32LE(plaintext, 0);
    const meta       = JSON.parse(bytesToUtf8(plaintext.subarray(4, 4 + metaLenVal)));
    const { encryptedSalt, saltNonce, wrapSalt, version } = meta;
    const hashAlgorithm: HashAlgorithm = meta.hashAlgorithm ?? 'sha3-512';
    const argon2Memory: number         = meta.argon2Memory  ?? ARGON2_MEMORY;
    const argon2Time: number           = meta.argon2Time    ?? ARGON2_TIME;

    if (typeof version !== 'number' || version < SPD_VERSION_MIN || version > SPD_VERSION) {
      throw new Error(`Unsupported SPD version: ${version}`);
    }

    const { argon2HashLen, macKeyLen } = legacyKeyLengthsForVersion(version);

    // KDF chain params (v29+)
    const kdfChainGE: boolean  = meta.kdfChain ?? false;
    const scryptNGE: number    = meta.scryptN ?? SCRYPT_N_DEFAULT;
    const scryptRGE: number    = meta.scryptR ?? SCRYPT_R_DEFAULT;
    const scryptPGE: number    = meta.scryptP ?? SCRYPT_P_DEFAULT;
    const a2ParallelGE: number = meta.argon2Parallelism ?? 1;
    validateArgon2Params(argon2Memory, argon2Time, a2ParallelGE);
    if (kdfChainGE) validateScryptParams(scryptNGE, scryptRGE, scryptPGE);

    const { aeadKey, macKey, salt: decryptedSalt } = await SPD.unlockKeys(passcode, {
      encryptedSalt, saltNonce, wrapSalt,
      wrapMemory: meta.wrapArgon2Memory ?? ARGON2_MEMORY_STANDARD,
      wrapTime: meta.wrapArgon2Time ?? ARGON2_TIME_STANDARD,
      wrapParallelism: meta.wrapArgon2Parallelism ?? 1,
      argon2Memory, argon2Time, argon2HashLen, macKeyLen,
      kdfChain: kdfChainGE, scryptN: scryptNGE, scryptR: scryptRGE, scryptP: scryptPGE, argon2Parallelism: a2ParallelGE,
    });
    const keysFromCache = false; // unlockKeys returns caller-owned copies, safe to zero

    // ── 4. Verify MAC over the entire plaintext (always — no shortcuts) ──────
    const expectedMac = SPD.computeMAC(plaintext, macKey, 'application/spd-binary');
    if (!crypto.timingSafeEqual(fileMac, expectedMac)) {
      (aeadKey).fill(0); (macKey).fill(0);
      throw new Error('Authentication failed.');
    }

    // ML-DSA-65 signature verification — mirrors parseBinaryPayload's logic.
    // Kept optional/opt-in via `verifyKey` (same as loadFromFile) —
    // getEntry previously had no way to enforce a pinned signer at all, an
    // inconsistency with loadFromFile/loadFromFileStreaming.
    const storedSigGE: number[] | undefined = meta.fileSignature;
    if (verifyKey && storedSigGE) {
      const sigBuf = new Uint8Array(storedSigGE);
      const metaNoSig = { ...meta } as Record<string, unknown>;
      delete (metaNoSig as any).fileSignature;
      const metaNoSigPayload = utf8ToBytes(JSON.stringify(metaNoSig));
      const metaNoSigLenBuf  = u8Alloc(4);
      writeUInt32LE(metaNoSigLenBuf, metaNoSigPayload.length);
      const plaintextNoSig = u8Concat([metaNoSigLenBuf, metaNoSigPayload, plaintext.subarray(4 + metaLenVal)]);
      const macNoSig = SPD.computeMAC(plaintextNoSig, macKey, 'application/spd-binary');
      if (!verifyFileMac(sigBuf, macNoSig, verifyKey)) {
        (aeadKey).fill(0); (macKey).fill(0);
        throw new Error('Authentication failed.');
      }
    } else if (verifyKey && !storedSigGE) {
      (aeadKey).fill(0); (macKey).fill(0);
      throw new Error('Authentication failed.');
    }

    // ── 5. Locate the entry via embedded index or sequential scan ─────────────
    const index = SPD.readIndexFile(filePath, macKey);
    const indexMap = index?.map ?? null;
    const indexKey = index?.tagged ? bytesToHex(SPD.indexNameTag(macKey, sanitized)) : sanitized;

    let entryOffset: number | undefined;
    if (indexMap !== null && indexMap.has(indexKey)) {
      entryOffset = Number(indexMap.get(indexKey)!);
    } else {
      const nameKeyGE = version >= 29 ? SPD.deriveNameKey(aeadKey) : null;
      let pos = 4 + metaLenVal;
      while (pos < plaintext.length) {
        const start = pos;
        let candidate: string;
        if (version >= 29) {
          const encNameLen2 = readUInt16LE(plaintext, pos); pos += 2;
          const encNameBuf2 = plaintext.subarray(pos, pos + encNameLen2); pos += encNameLen2;
          candidate = SPD._decryptEntryName(encNameBuf2, nameKeyGE!);
        } else {
          const nameLen2 = readUInt8(plaintext, pos); pos += 1;
          candidate = bytesToUtf8(plaintext.subarray(pos, pos + nameLen2)); pos += nameLen2;
        }
        if (candidate === sanitized) { entryOffset = start; break; }
        const typeLen  = readUInt8(plaintext, pos);               pos += 1 + typeLen;
        const hashLen  = readUInt16LE(plaintext, pos);            pos += 2 + hashLen;
        const nonceLen = readUIntLE3(plaintext, pos);           pos += 3 + nonceLen;
        const dataLen  = Number(readBigUInt64LE(plaintext, pos)); pos += 8 + dataLen;
      }
      if (nameKeyGE) (nameKeyGE).fill(0);
    }

    if (entryOffset === undefined) {
      if (!keysFromCache) { (aeadKey).fill(0); (macKey).fill(0); }
      throw new Error(`Entry not found: "${sanitized}"`);
    }

    // ── 6. Parse and decrypt the entry ────────────────────────────────────────
    let pos = entryOffset;
    if (version >= 29) {
      const encNameLen2 = readUInt16LE(plaintext, pos); pos += 2 + encNameLen2;
    } else {
      const nameLen2 = readUInt8(plaintext, pos); pos += 1 + nameLen2;
    }
    const typeLen   = readUInt8(plaintext, pos);  pos += 1;
    const dataType  = bytesToUtf8(plaintext.subarray(pos, pos + typeLen)) as SupportedDataType; pos += typeLen;
    const hashLen   = readUInt16LE(plaintext, pos); pos += 2;
    const entryHash = bytesToUtf8(plaintext.subarray(pos, pos + hashLen)); pos += hashLen;
    const nonceLen  = readUIntLE3(plaintext, pos); pos += 3;
    const nonce     = plaintext.subarray(pos, pos + nonceLen); pos += nonceLen;
    const dataLen   = Number(readBigUInt64LE(plaintext, pos)); pos += 8;
    const encData   = plaintext.subarray(pos, pos + dataLen);

    const computedHash = crypto.createHash(hashAlgorithm).update(encData).digest('hex');
    if (computedHash !== entryHash) {
      if (!keysFromCache) { (aeadKey).fill(0); (macKey).fill(0); }
      throw new Error('Authentication failed.');
    }

    const aad   = version >= 27 ? utf8ToBytes(sanitized) : null;
    const eKey  = version >= 27 ? SPD.deriveEntryKey(aeadKey, sanitized) : aeadKey;
    let decompressed: string;
    try {
      const decrypted = version >= 29
        ? SPD.aeadDecrypt(encData, aad, new Uint8Array(nonce), eKey)
        : plainAeadDecrypt(encData, aad, new Uint8Array(nonce), eKey);
      const inflated2 = await zlib.inflate(decrypted);
      decompressed = bytesToUtf8(version >= 29
        ? SPD.unpadAfterDecompression(inflated2)
        : inflated2);
    } catch {
      throw new Error('Authentication failed.');
    } finally {
      if (version >= 27) (eKey as Uint8Array).fill(0);
      if (!keysFromCache) { (aeadKey).fill(0); (macKey).fill(0); }
    }

    // ACL check — mirrors canReadEntry()'s logic (an instance method that
    // reads this.entryRoles/this.currentRole), reimplemented here against
    // meta.entryRoles/the `role` parameter since getEntry is static with no
    // persistent instance. See this method's own doc comment on `role` for
    // the bug this closes.
    const entryRolesGE = (meta.entryRoles as Record<string, string[]> | undefined) ?? {};
    const allowedRoles = entryRolesGE[sanitized];
    if (allowedRoles && allowedRoles.length > 0) {
      const normalizedRole = role?.trim().toLowerCase();
      if (!normalizedRole || !allowedRoles.includes(normalizedRole)) {
        throw new Error(`Access denied: entry "${sanitized}" requires role "${allowedRoles.join('|')}".`);
      }
    }

    const tmp = new SPD();
    const value = tmp['convertStringToInput'](decompressed, dataType);

    // Auto-destruct open-count check — found via direct audit: getEntry
    // never called this at all, meaning a "burn-after-N-reads" file
    // protected via setFileMaxOpenCount() could be read an UNLIMITED
    // number of times through getEntry specifically, even though
    // loadFromFile/loadFromFileStreaming correctly enforce and wipe on the
    // same limit. Confirmed directly: 5 consecutive getEntry calls all
    // succeeded against a file configured for maxOpenCount=1. Runs only
    // after the entry has been fully authenticated and decrypted (same
    // "never destructive-act on unauthenticated input" placement as
    // checkRollback in the other load paths) — tmp has no maxOpenCount of
    // its own set (defaults to 0/disabled), but the check reads the
    // authoritative `.maxcount` sidecar file regardless of instance state,
    // so this still correctly enforces a limit set via
    // SPD.setFileMaxOpenCount().
    SPD.checkAndIncrementOpenCount(filePath, tmp);

    return { name: sanitized, value, dataType };
  }

  /**
   * Reads file metadata without any key derivation or decryption.
   *
   * For binary `.spd` files (written by `saveToFileStreaming` / `SPDWriter`):
   *   reads the 72-byte header + decompresses just the meta block.
   * For JSON `.spd` files (written by `saveToFile`):
   *   decompresses and parses the outer JSON + payload JSON.
   *
   * No passcode required. Returns format, version, entry count, Argon2 params,
   * file size, and whether a tail index (SPDx) is embedded.
   */
  static async inspect(filePath: string): Promise<SPDInspectResult> {
    const fs = getFs();
    if (!filePath?.trim()) throw new Error('filePath is required.');
    const stat = fs.statSync(filePath);
    const fileSize = stat.size;

    // Detect format by trying to read as binary first (72-byte header)
    const headerBuf = u8Alloc(Math.min(72, fileSize));
    const fd = fs.openSync(filePath, 'r');
    try { fs.readSync(fd, headerBuf, 0, headerBuf.length, 0); }
    finally { fs.closeSync(fd); }

    // Binary format: header[0..8) = plaintext length (uint64 LE), usually > 0 and sane
    const binaryCandidate = headerBuf.length >= 72
      ? Number(readBigUInt64LE(headerBuf, 0))
      : 0;
    const looksLikeBinary = binaryCandidate > 0 && binaryCandidate < 1024 * 1024 * 1024 * 4; // < 4 GB sane

    if (looksLikeBinary) {
      // Decompress just enough to read the meta block (first 4 + metaLen bytes)
      const metaRaw = await new Promise<Uint8Array>((resolve, reject) => {
        const chunks: Uint8Array[] = [];
        let total = 0;
        const rs = fs.createReadStream(filePath, { start: 72 });
        const inflate = zlib.createInflate();
        inflate.on('data', (chunk: Uint8Array) => {
          chunks.push(chunk);
          total += chunk.length;
          // Once we have enough data to read the meta block, destroy the stream
          const combined = u8Concat(chunks);
          if (combined.length >= 4) {
            const needed = 4 + readUInt32LE(combined, 0);
            if (combined.length >= needed) {
              inflate.destroy();
              rs.destroy();
              resolve(combined.subarray(0, needed));
            }
          }
        });
        inflate.once('error', reject);
        inflate.once('end', () => resolve(u8Concat(chunks)));
        rs.once('error', reject);
        onBinaryData(rs, (chunk) => inflate.write(chunk));
        rs.once('end', () => inflate.end());
      });

      const metaLen = readUInt32LE(metaRaw, 0);
      const meta    = JSON.parse(bytesToUtf8(metaRaw.subarray(4, 4 + metaLen)));

      // Detect embedded tail index: last 4 bytes = "SPDx"
      const tailBuf = u8Alloc(Math.min(4, fileSize));
      const fd2 = fs.openSync(filePath, 'r');
      try { fs.readSync(fd2, tailBuf, 0, 4, fileSize - 4); }
      finally { fs.closeSync(fd2); }
      const hasIndex = u8Equals(tailBuf, SPDX_MAGIC) || u8Equals(tailBuf, SPDY_MAGIC);

      return {
        format:        'binary',
        version:       meta.version       ?? 0,
        entryCount:    meta.entryCount    ?? 0,
        writeCounter:  meta.writeCounter  ?? 0,
        hashAlgorithm: meta.hashAlgorithm ?? 'sha3-512',
        argon2Memory:  meta.argon2Memory  ?? ARGON2_MEMORY,
        argon2Time:    meta.argon2Time    ?? ARGON2_TIME,
        fileSize,
        hasIndex,
      };
    }

    // JSON format: zlib(JSON({ payload: number[], mac: number[] }))
    const compressed = fs.readFileSync(filePath);
    const decompressed = bytesToUtf8(await zlib.inflate(compressed, { maxOutputLength: SPD.maxJsonInflateBytes }));
    const { payload } = JSON.parse(decompressed);
    const parsed = JSON.parse(bytesToUtf8(decodeWrappedPayload(payload))) as SPDPayload;

    return {
      format:        'json',
      version:       parsed.version       ?? 0,
      entryCount:    parsed.data?.length  ?? 0,
      writeCounter:  parsed.writeCounter  ?? 0,
      hashAlgorithm: parsed.hashAlgorithm ?? 'sha3-512',
      argon2Memory:  parsed.argon2Memory  ?? ARGON2_MEMORY,
      argon2Time:    parsed.argon2Time    ?? ARGON2_TIME,
      fileSize,
      hasIndex:      false,
    };
  }

  /**
   * Verifies file integrity (MAC check) without decrypting any entry values.
   * Derives keys from passcode, verifies the HMAC over the entire plaintext,
   * and returns a result object. Does not call any decrypt operation on entries.
   *
   * Useful for backup health checks: fast, safe, no plaintext produced.
   */
  static async verify(
    filePath: string,
    passcode: string
  ): Promise<SPDVerifyResult> {
    const fs = getFs();
    if (!filePath?.trim() || !passcode?.trim()) {
      throw new Error('filePath and passcode are required.');
    }

    try {
      const stat = fs.statSync(filePath);
      const fileSize = stat.size;

      // Read the 72-byte binary header
      const headerBuf = u8Alloc(Math.min(72, fileSize));
      const fd = fs.openSync(filePath, 'r');
      try { fs.readSync(fd, headerBuf, 0, headerBuf.length, 0); }
      finally { fs.closeSync(fd); }

      const binaryCandidate = headerBuf.length >= 72
        ? Number(readBigUInt64LE(headerBuf, 0))
        : 0;
      const isBinary = binaryCandidate > 0 && binaryCandidate < 4 * 1024 * 1024 * 1024;

      if (isBinary) {
        // Binary format
        const expectedLen = binaryCandidate;
        const fileMac     = headerBuf.subarray(8, 72);

        const plaintext = await new Promise<Uint8Array>((resolve, reject) => {
          const chunks: Uint8Array[] = [];
          const rs = fs.createReadStream(filePath, { start: 72 });
          const inflate = zlib.createInflate();
          inflate.on('data', (c: Uint8Array) => chunks.push(c));
          inflate.once('end', () => resolve(u8Concat(chunks)));
          inflate.once('error', reject);
          rs.once('error', reject);
          onBinaryData(rs, (chunk) => inflate.write(chunk));
          rs.once('end', () => inflate.end());
        });

        if (plaintext.length !== expectedLen) {
          return { valid: false, entryCount: 0, indexPresent: false, writeCounter: 0 };
        }

        const metaLen = readUInt32LE(plaintext, 0);
        const meta    = JSON.parse(bytesToUtf8(plaintext.subarray(4, 4 + metaLen)));
        const { encryptedSalt, saltNonce, wrapSalt, version, entryCount, writeCounter = 0 } = meta;
        const argon2Memory: number = meta.argon2Memory ?? ARGON2_MEMORY;
        const argon2Time: number   = meta.argon2Time   ?? ARGON2_TIME;
        const { argon2HashLen, macKeyLen } = legacyKeyLengthsForVersion(version);
        const a2ParallelV: number  = meta.argon2Parallelism ?? 1;
        validateArgon2Params(argon2Memory, argon2Time, a2ParallelV);

        // Wrap key uses the file's wrapArgon2* params, not the main profile —
        // this path passed argon2Memory/Time here, which failed verification
        // of every file whose main profile differs from the wrap default.
        const { macKey } = await SPD.unlockKeys(passcode, {
          encryptedSalt, saltNonce, wrapSalt,
          wrapMemory: meta.wrapArgon2Memory ?? ARGON2_MEMORY_STANDARD,
          wrapTime: meta.wrapArgon2Time ?? ARGON2_TIME_STANDARD,
          wrapParallelism: meta.wrapArgon2Parallelism ?? 1,
          argon2Memory, argon2Time, argon2HashLen, macKeyLen,
          kdfChain: meta.kdfChain ?? false, scryptN: meta.scryptN ?? SCRYPT_N_DEFAULT,
          scryptR: meta.scryptR ?? SCRYPT_R_DEFAULT, scryptP: meta.scryptP ?? SCRYPT_P_DEFAULT,
          argon2Parallelism: a2ParallelV,
        });

        const expectedMac = SPD.computeMAC(plaintext, macKey, 'application/spd-binary');
        const valid = crypto.timingSafeEqual(fileMac, expectedMac);

        const tailBuf = u8Alloc(4);
        const fd2 = fs.openSync(filePath, 'r');
        try { fs.readSync(fd2, tailBuf, 0, 4, fileSize - 4); }
        finally { fs.closeSync(fd2); }
        const indexPresent = u8Equals(tailBuf, SPDX_MAGIC) || u8Equals(tailBuf, SPDY_MAGIC);

        return { valid, entryCount: entryCount ?? 0, indexPresent, writeCounter };
      }

      // JSON format
      const compressed = fs.readFileSync(filePath);
      const decompressed = bytesToUtf8(await zlib.inflate(compressed, { maxOutputLength: SPD.maxJsonInflateBytes }));
      const { payload, mac } = JSON.parse(decompressed);
      const payloadBuffer = decodeWrappedPayload(payload);
      const parsed = JSON.parse(bytesToUtf8(payloadBuffer)) as SPDPayload;
      const { encryptedSalt, saltNonce, wrapSalt, version } = parsed;
      const argon2Memory: number = parsed.argon2Memory ?? ARGON2_MEMORY;
      const argon2Time: number   = parsed.argon2Time   ?? ARGON2_TIME;
      const { argon2HashLen, macKeyLen } = legacyKeyLengthsForVersion(version);

      const pj = parsed as any;
      const { macKey } = await SPD.unlockKeys(passcode, {
        encryptedSalt: encryptedSalt!, saltNonce: saltNonce!, wrapSalt: wrapSalt!,
        wrapMemory: pj.wrapArgon2Memory ?? ARGON2_MEMORY_STANDARD,
        wrapTime: pj.wrapArgon2Time ?? ARGON2_TIME_STANDARD,
        wrapParallelism: pj.wrapArgon2Parallelism ?? 1,
        argon2Memory, argon2Time, argon2HashLen, macKeyLen,
        kdfChain: pj.kdfChain ?? false, scryptN: pj.scryptN ?? SCRYPT_N_DEFAULT,
        scryptR: pj.scryptR ?? SCRYPT_R_DEFAULT, scryptP: pj.scryptP ?? SCRYPT_P_DEFAULT,
        argon2Parallelism: pj.argon2Parallelism ?? 1,
      });

      const expectedMac = SPD.computeMAC(payloadBuffer, macKey, 'application/json');
      const valid = crypto.timingSafeEqual(new Uint8Array(mac), expectedMac);

      return {
        valid,
        entryCount:   parsed.data?.length ?? 0,
        indexPresent: false,
        writeCounter: parsed.writeCounter ?? 0,
      };
    } catch {
      return { valid: false, entryCount: 0, indexPresent: false, writeCounter: 0 };
    }
  }

  static async loadFromString(
    data: string,
    passcode: string,
    verifyKey?: Uint8Array
  ): Promise<SPD> {
    if (typeof passcode === 'string' && !passcode.trim()) {
      throw new Error('loadFromString: a passcode is required — for keyless data use SPD.loadStringWithRandomKey().');
    }
    if (!data?.trim() || !passcode?.trim()) {
      throw new Error('Authentication failed.');
    }
    const decoded = base64ToBytes(data);
    return SPD.parseSerializedPayload(decoded, passcode, undefined, verifyKey);
  }

  /** In-memory counterpart of `loadWithRandomKey()`: open a `saveData()` string produced by a keyless instance. */
  static async loadStringWithRandomKey(data: string, masterSecret: Uint8Array, verifyKey?: Uint8Array): Promise<SPD> {
    const encoded = SPD._encodeKeylessSecretChecked(masterSecret, 'loadStringWithRandomKey');
    if (!data?.trim()) throw new Error('Authentication failed.');
    const spd = await SPD.parseSerializedPayload(base64ToBytes(data), encoded, undefined, verifyKey);
    spd._keylessMode = true;
    spd._keylessSecretEncoded = encoded;
    return spd;
  }

  /** In-memory counterpart of `loadWithRandomKey()` for `saveDataChunked()` output. */
  static async loadChunksWithRandomKey(chunks: string[], masterSecret: Uint8Array, verifyKey?: Uint8Array): Promise<SPD> {
    const encoded = SPD._encodeKeylessSecretChecked(masterSecret, 'loadChunksWithRandomKey');
    const spd = await SPD.parseSerializedPayload(SPD.reassembleChunks(chunks), encoded, undefined, verifyKey);
    spd._keylessMode = true;
    spd._keylessSecretEncoded = encoded;
    return spd;
  }

  private static _encodeKeylessSecretChecked(masterSecret: Uint8Array, caller: string): string {
    if (!(masterSecret instanceof Uint8Array) || masterSecret.length !== KEYLESS_MASTER_SECRET_LEN) {
      throw new Error(
        `${caller}: expected a ${KEYLESS_MASTER_SECRET_LEN}-byte Uint8Array (got ${masterSecret?.length ?? typeof masterSecret}).`
      );
    }
    return SPD._encodeKeylessSecret(masterSecret);
  }

  static async loadFromChunks(
    chunks: string[],
    passcode: string,
    verifyKey?: Uint8Array
  ): Promise<SPD> {
    return SPD.parseSerializedPayload(SPD.reassembleChunks(chunks), passcode, undefined, verifyKey);
  }

  /** Validates the trailing manifest and reassembles `saveDataChunked()` output into the serialized payload bytes. */
  private static reassembleChunks(chunks: string[]): Uint8Array {
    if (!chunks || chunks.length < 2) {
      throw new Error('Invalid chunks array — must contain at least one data chunk and a manifest.');
    }

    let manifest: SPDChunkManifest;
    try {
      manifest = JSON.parse(chunks[chunks.length - 1]);
    } catch {
      throw new Error('Last element of chunks must be a valid JSON manifest.');
    }

    if (manifest.totalChunks !== chunks.length - 1) {
      throw new Error(
        `Chunk count mismatch: manifest expects ${manifest.totalChunks} but received ${chunks.length - 1}.`
      );
    }

    const parts = chunks.slice(0, manifest.totalChunks).map((c) => base64ToBytes(c));
    const reassembled = u8Concat(parts);

    if (reassembled.length !== manifest.totalBytes) {
      throw new Error(
        `Byte count mismatch: expected ${manifest.totalBytes} but got ${reassembled.length}.`
      );
    }

    return reassembled;
  }

  // ─── Key derivation ────────────────────────────────────────────────────────

  /** See `internal/spd-kdf.ts` — derivePBK (moved; behaviour unchanged). */
  static derivePBK = derivePBK;


  /** See `internal/spd-kdf.ts` — _encodeKeylessSecret (moved; behaviour unchanged). */
  private static _encodeKeylessSecret = _encodeKeylessSecret;


  /** See `internal/spd-kdf.ts` — _decodeKeylessSecret (moved; behaviour unchanged). */
  private static _decodeKeylessSecret = _decodeKeylessSecret;


  /** See `internal/spd-kdf.ts` — decryptSalt (moved; behaviour unchanged). */
  static decryptSalt = decryptSalt;


  /** See `internal/spd-kdf.ts` — encryptSalt (moved; behaviour unchanged). */
  static encryptSalt = encryptSalt;


  static toBase64(data: Uint8Array): string {
    return bytesToBase64(data);
  }

  static fromBase64(data: string): Uint8Array {
    return base64ToBytes(data);
  }

  // ─── Merkle tree helper ────────────────────────────────────────────────────

  /** See `internal/spd-kdf.ts` — buildMerkleRoot (moved; behaviour unchanged). */
  private static buildMerkleRoot = buildMerkleRoot;


  // ─── Signed write counter helper ─────────────────────────────────────────

  /** See `internal/spd-kdf.ts` — computeCounterHMAC (moved; behaviour unchanged). */
  static computeCounterHMAC = computeCounterHMAC;


  // ─── Ratchet helper ──────────────────────────────────────────────────────

  private _applyRatchet(): void {
    // Ratchet: derive the NEXT in-memory key from the current one so the
    // current key cannot be recovered after this save.  The file is always
    // saved with a fresh salt (generated in buildSerializedPayload /
    // buildBinaryPayload when ratchet is enabled) so each file is
    // independently loadable from passcode+salt.  The in-memory ratchet
    // ensures that once a save is written, the in-memory key advances and
    // can no longer be used to re-derive previous file keys.
    if (!this._ratchetEnabled || !this.userKey) return;
    const counterBuf = u8Alloc(8);
    writeBigUInt64BE(counterBuf, BigInt(this.writeCounter));
    const next = crypto.createHmac('sha3-512', this.userKey)
      .update('ratchet-v1')
      .update(counterBuf)
      .digest();
    const newKey = new Uint8Array(next.buffer.slice(next.byteOffset, next.byteOffset + AEAD_KEY_LEN));
    this.userKey.fill(0);
    this.userKey = newKey;
  }

  /** When ratchet is enabled, rotate to a fresh salt+keys before each save,
   * re-encrypting all entries under the new key.
   * NOTE: this is NOT forward secrecy. Each save re-salts and re-encrypts
   * under keys derived from the SAME passcode, so every earlier file remains
   * decryptable with the passcode plus its own embedded salt. It only ensures
   * no two saved files share key material (and costs one Argon2id per save).
   */
  private async _maybeRatchetSalt(passcode: string): Promise<void> {
    if (!this._ratchetEnabled) return;
    const oldAeadKey = this.userKey!;
    const newSalt = crypto.getRandomValues(new Uint8Array(ARGON2_SALT_LEN));
    // Use this instance's ACTUAL current params, not profileParams(keyProfile)
    // — see _argon2Memory/_argon2Time's doc comment for why those can differ.
    const memory = this._argon2Memory;
    const time = this._argon2Time;
    const { aeadKey: newAeadKey, macKey: newMacKey } = await SPD.deriveKeys(
      passcode, newSalt, memory, time, ARGON2_HASH_LEN, HMAC_KEY_LEN,
      this._kdfChain, this._scryptN, this._scryptR, this._scryptP, this._argon2Parallelism
    );
    // Re-encrypt all entries: decrypt with old key, re-encrypt with new key
    for (const item of this.data) {
      const oldEntryKey = SPD.deriveEntryKey(oldAeadKey, item.dataName);
      let plaintext: Uint8Array;
      try {
        plaintext = SPD.aeadDecrypt(
          item.data, utf8ToBytes(item.dataName),
          new Uint8Array(item.nonce), oldEntryKey
        );
      } finally {
        (oldEntryKey).fill(0);
      }
      const newEntryKey = SPD.deriveEntryKey(newAeadKey, item.dataName);
      const nonce = crypto.randomBytes(24);
      const newCt = SPD.aeadEncrypt(plaintext, utf8ToBytes(item.dataName), nonce, newEntryKey);
      (newEntryKey).fill(0);
      (plaintext).fill(0);
      item.data  = newCt;
      item.nonce = nonce;
      item.hash  = crypto.createHash(this.hash).update(item.data).digest('hex');
    }
    if (this.userKey) this.userKey.fill(0);
    if (this.macKey)  this.macKey.fill(0);
    this.salt    = newSalt;
    this.userKey = newAeadKey;
    this.macKey  = newMacKey;
  }

  // ─── Epoch rotation helper ────────────────────────────────────────────────

  private async _maybeRotateEpoch(passcode: string): Promise<void> {
    if (this._epochSize <= 0) return;
    if (this.writeCounter > 0 && this.writeCounter % this._epochSize === 0) {
      // Re-derive with a fresh salt, at this instance's ACTUAL current
      // params (not profileParams(keyProfile) — see _argon2Memory's doc
      // comment for why those can differ).
      const newSalt = crypto.getRandomValues(new Uint8Array(ARGON2_SALT_LEN));
      const memory = this._argon2Memory;
      const time = this._argon2Time;
      const { aeadKey, macKey } = await SPD.deriveKeys(
        passcode, newSalt, memory, time, ARGON2_HASH_LEN, HMAC_KEY_LEN,
        this._kdfChain, this._scryptN, this._scryptR, this._scryptP, this._argon2Parallelism
      );
      const oldAeadKeyEpoch = this.userKey!;
      this.salt    = newSalt;
      this.userKey = aeadKey;
      this.macKey  = macKey;
      this._epochNumber++;
      // Re-encrypt all existing entries: decrypt with old key, re-encrypt with new key
      for (const item of this.data) {
        const oldEntryKey = SPD.deriveEntryKey(oldAeadKeyEpoch, item.dataName);
        let plaintext: Uint8Array;
        try {
          plaintext = SPD.aeadDecrypt(
            item.data, utf8ToBytes(item.dataName),
            new Uint8Array(item.nonce), oldEntryKey
          );
        } finally {
          (oldEntryKey).fill(0);
        }
        const newEntryKey = SPD.deriveEntryKey(aeadKey, item.dataName);
        const nonce = crypto.randomBytes(24);
        const newData = SPD.aeadEncrypt(plaintext, utf8ToBytes(item.dataName), nonce, newEntryKey);
        (newEntryKey).fill(0);
        (plaintext).fill(0);
        item.data  = newData;
        item.nonce = nonce;
        item.hash  = crypto.createHash(this.hash).update(item.data).digest('hex');
      }
      oldAeadKeyEpoch.fill(0);
    }
  }

  // ─── Private payload helpers ───────────────────────────────────────────────

  /** Get the effective AEAD and MAC keys (handles blinding). */
  private _getKeys(): { aeadKey: Uint8Array; macKey: Uint8Array } {
    if (this._keyBlindingEnabled && this._blindedKey) {
      const keyLen  = this._blindedKey.length;
      const mask    = this._keyMask!;
      return {
        aeadKey: SPD._xorBufs(this._blindedKey, mask.subarray(0, keyLen)),
        macKey:  SPD._xorBufs(this._blindedMacKey!, mask.subarray(keyLen)),
      };
    }
    return { aeadKey: this.userKey!, macKey: this.macKey! };
  }

  private async buildSerializedPayload(passcode: string): Promise<Uint8Array> {
    // Epoch rotation before building
    await this._maybeRotateEpoch(passcode);

    // Ratchet: rotate to fresh salt+keys before this save (so each file is independently loadable)
    await this._maybeRatchetSalt(passcode);

    const { aeadKey, macKey } = this._getKeys();

    const { encryptedSalt, saltNonce, wrapSalt } = await SPD.encryptSalt(
      this.salt!, passcode, this._wrapArgon2Memory, this._wrapArgon2Time, this._wrapArgon2Parallelism
    );

    // Write this instance's ACTUAL current params into the meta block, not
    // profileParams(keyProfile) — see _argon2Memory/_argon2Time's doc
    // comment for why those can differ (and why writing the wrong ones here
    // would poison the very field changePasscode/upgradeKdfParams rely on
    // when this file is loaded again later).
    const a2mem = this._argon2Memory;
    const a2time = this._argon2Time;

    // Merkle tree over encrypted entry data
    const leafHashes = this.data.map(item =>
      crypto.createHash('sha3-256').update(item.data).digest('hex')
    );
    const merkleRoot = SPD.buildMerkleRoot(leafHashes);

    // Signed write counter
    const counterHMAC = SPD.computeCounterHMAC(macKey, this.writeCounter);

    const payload: SPDPayload = {
      data: this.data.map((item) => ({
        dataName: item.dataName,
        nonce: bytesToBase64(item.nonce),
        data: bytesToBase64(item.data),
        hash: item.hash,
        dataType: item.dataType,
      })),
      encryptedSalt,
      saltNonce,
      wrapSalt,
      version: SPD_VERSION,
      writeCounter: this.writeCounter,
      hashAlgorithm: this.hash,
      argon2Memory: a2mem,
      argon2Time: a2time,
      argon2HashLen: ARGON2_HASH_LEN,
      hashKeyLen: HMAC_KEY_LEN,
      argon2Parallelism: this._argon2Parallelism,
      keyProfile: this.keyProfile,
      keyCommitment: SPD.computeKeyCommitment(aeadKey),
      merkleRoot,
      counterHMAC,
      kdfChain: this._kdfChain || undefined,
      scryptN: this._kdfChain ? this._scryptN : undefined,
      scryptR: this._kdfChain ? this._scryptR : undefined,
      scryptP: this._kdfChain ? this._scryptP : undefined,
      wrapArgon2Memory: this._wrapArgon2Memory !== ARGON2_MEMORY_STANDARD ? this._wrapArgon2Memory : undefined,
      wrapArgon2Time:   this._wrapArgon2Time   !== ARGON2_TIME_STANDARD   ? this._wrapArgon2Time   : undefined,
      wrapArgon2Parallelism: this._wrapArgon2Parallelism !== 1 ? this._wrapArgon2Parallelism : undefined,
      ratchetEnabled: this._ratchetEnabled || undefined,
      ratchetCounter: this._ratchetEnabled ? this.writeCounter : undefined,
      epochNumber: this._epochSize > 0 ? this._epochNumber : undefined,
      epochSize:   this._epochSize > 0 ? this._epochSize   : undefined,
      keylessMode: this._keylessMode || undefined,
      // Found via direct audit: this field existed in SPDPayload's type
      // (and restrictEntry()/setRole() have worked correctly in-memory
      // this whole time) but was never actually written here — meaning
      // restrictEntry()'s ACL was silently discarded on every save, and a
      // reloaded file had ZERO access restrictions regardless of what was
      // set before saving. Confirmed directly: a role-restricted entry
      // saved, then reloaded with no role set at all, was fully readable.
      // Real, serious access-control bypass, not cosmetic.
      entryRoles: this.entryRoles.size > 0
        ? Object.fromEntries(this.entryRoles)
        : undefined,
    };

    const payloadBuffer = utf8ToBytes(JSON.stringify(payload));
    const mac = SPD.computeMAC(payloadBuffer, macKey, 'application/json');

    // ML-DSA-65 file signature over the MAC bytes
    if (this._signingKey) {
      const sig = signFileMac(mac, this._signingKey);
      (payload as any).fileSignature  = Array.from(sig);
      // Re-serialize with signature included
      const payloadBuffer2 = utf8ToBytes(JSON.stringify(payload));
      const mac2 = SPD.computeMAC(payloadBuffer2, macKey, 'application/json');
      // payload is base64-encoded (not Array.from — see decodeEntryBytes's
      // doc comment: an array of one number per byte hit the same
      // array-length ceiling and slowness at the outer layer too, once
      // this whole already-JSON-stringified buffer got large). mac stays
      // a plain number[] — always a small, fixed-size hash, never the
      // bottleneck, so changing it would add format-compat risk for
      // no real gain.
      const wrapped2 = { payload: bytesToBase64(payloadBuffer2), mac: Array.from(mac2) };
      // Zero temp keys if blinding
      if (this._keyBlindingEnabled) { aeadKey.fill(0); macKey.fill(0); }
      return await zlib.deflate(utf8ToBytes(JSON.stringify(wrapped2)), { level: this.compressionLevel });
    }

    const wrapped = { payload: bytesToBase64(payloadBuffer), mac: Array.from(mac) };
    if (this._keyBlindingEnabled) { aeadKey.fill(0); macKey.fill(0); }
    return await zlib.deflate(utf8ToBytes(JSON.stringify(wrapped)), { level: this.compressionLevel });
  }

  private static async parseSerializedPayload(
    compressed: Uint8Array,
    passcode: string,
    filePath?: string,
    verifyKey?: Uint8Array
  ): Promise<SPD> {

    const decompressed = bytesToUtf8(await zlib.inflate(compressed, { maxOutputLength: SPD.maxJsonInflateBytes }));
    const { payload, mac } = JSON.parse(decompressed);

    const payloadBuffer = decodeWrappedPayload(payload);
    const parsed = JSON.parse(bytesToUtf8(payloadBuffer)) as SPDPayload;
    const { data, encryptedSalt, saltNonce, wrapSalt, version } = parsed;
    const writeCounter: number         = parsed.writeCounter ?? 0;

    // Read embedded params with safe fallbacks for files saved before v26
    const hashAlgorithm: HashAlgorithm = (parsed as any).hashAlgorithm ?? 'sha3-512';
    const argon2Memory: number         = (parsed as any).argon2Memory   ?? ARGON2_MEMORY;
    const argon2Time: number           = (parsed as any).argon2Time     ?? ARGON2_TIME;

    if (typeof version !== 'number' || version < SPD_VERSION_MIN || version > SPD_VERSION) {
      throw new Error(`Unsupported SPD version: ${version}`);
    }

    // v26 used 64-byte hash / 32-byte macKey; v27+ uses 96-byte hash / 64-byte macKey
    const { argon2HashLen, macKeyLen } = legacyKeyLengthsForVersion(version);

    // Wrap key params — read from file if present (v29+), else use standard defaults
    const wrapMemory = (parsed as any).wrapArgon2Memory ?? ARGON2_MEMORY_STANDARD;
    const wrapTime   = (parsed as any).wrapArgon2Time   ?? ARGON2_TIME_STANDARD;
    const wrapParallelism: number = (parsed as any).wrapArgon2Parallelism ?? 1;
    // Validate BEFORE decryptSalt — this runs pre-authentication (the file's
    // HMAC isn't checked yet at this point), so an unvalidated file-supplied
    // wrapMemory/wrapTime would let a crafted file force a huge allocation
    // attempt on load, before the file's authenticity is ever confirmed.
    validateArgon2Params(wrapMemory, wrapTime, wrapParallelism);

    // KDF chain params from file
    const kdfChain: boolean   = (parsed as any).kdfChain ?? false;
    const scryptN: number     = (parsed as any).scryptN ?? SCRYPT_N_DEFAULT;
    const scryptR: number     = (parsed as any).scryptR ?? SCRYPT_R_DEFAULT;
    const scryptP: number     = (parsed as any).scryptP ?? SCRYPT_P_DEFAULT;
    const argon2Parallelism   = (parsed as any).argon2Parallelism ?? 1;
    validateArgon2Params(argon2Memory, argon2Time, argon2Parallelism);
    if (kdfChain) validateScryptParams(scryptN, scryptR, scryptP);

    const { aeadKey, macKey, salt: decryptedSalt } = await SPD.unlockKeys(passcode, {
      encryptedSalt, saltNonce, wrapSalt,
      wrapMemory, wrapTime, wrapParallelism,
      argon2Memory, argon2Time, argon2HashLen, macKeyLen,
      kdfChain, scryptN, scryptR, scryptP, argon2Parallelism,
    });

    const expectedMac = SPD.computeMAC(payloadBuffer, macKey, 'application/json');
    if (!crypto.timingSafeEqual(new Uint8Array(mac), expectedMac)) {
      throw new Error('Authentication failed.');
    }

    // ML-DSA-65 file signature verification
    // The signature covers the MAC of the payload WITHOUT the fileSignature field.
    // Reconstruct that MAC by stripping fileSignature and re-computing.
    const storedSig: number[] | undefined = (parsed as any).fileSignature;
    const vk = verifyKey;
    if (vk && storedSig) {
      const sigBuf = new Uint8Array(storedSig);
      // Strip fileSignature from parsed payload, reserialize, recompute mac
      const parsedNoSig = { ...parsed } as Record<string, unknown>;
      delete (parsedNoSig as any).fileSignature;
      const payloadNoSigBuf = utf8ToBytes(JSON.stringify(parsedNoSig));
      const macNoSig = SPD.computeMAC(payloadNoSigBuf, macKey, 'application/json');
      if (!verifyFileMac(sigBuf, macNoSig, vk)) {
        throw new Error('Authentication failed.');
      }
    } else if (vk && !storedSig) {
      throw new Error('Authentication failed.');
    }

    // Key commitment check
    const storedCommitment: string | undefined = (parsed as any).keyCommitment;
    if (storedCommitment) {
      const actualCommitment = SPD.computeKeyCommitment(aeadKey);
      if (!crypto.timingSafeEqual(
        hexToBytes(storedCommitment),
        hexToBytes(actualCommitment)
      )) {
        throw new Error('Authentication failed.');
      }
    }

    // Signed write counter verification (v29+)
    const storedCounterHMAC: string | undefined = (parsed as any).counterHMAC;
    if (storedCounterHMAC) {
      const expectedCounterHMAC = SPD.computeCounterHMAC(macKey, writeCounter);
      if (!crypto.timingSafeEqual(
        hexToBytes(storedCounterHMAC),
        hexToBytes(expectedCounterHMAC)
      )) {
        throw new Error('Authentication failed.');
      }
    }

    const spd = new SPD();
    spd.setHash(hashAlgorithm);
    spd.fileVersion  = version;
    spd.writeCounter = writeCounter;
    spd.userKey      = aeadKey;
    spd.macKey       = macKey;
    spd.keyPair      = { publicKey: aeadKey };
    spd.salt         = decryptedSalt;
    spd.keyProfile   = ((parsed as any).keyProfile as SPDKeyProfile) ?? 'high';
    spd._kdfChain    = kdfChain;
    spd._scryptN     = scryptN;
    spd._scryptR     = scryptR;
    spd._scryptP     = scryptP;
    spd._argon2Parallelism = argon2Parallelism;
    spd._argon2Memory = argon2Memory;
    spd._argon2Time   = argon2Time;
    spd._wrapArgon2Memory = wrapMemory;
    spd._wrapArgon2Time   = wrapTime;
    spd._wrapArgon2Parallelism = wrapParallelism;
    spd._ratchetEnabled   = (parsed as any).ratchetEnabled ?? false;
    spd._epochSize        = (parsed as any).epochSize ?? 0;
    spd._epochNumber      = (parsed as any).epochNumber ?? 0;
    // Keyless mode: preserve it on the loaded instance so a subsequent
    // saveToFile/saveToFileStreaming call on THIS instance keeps using the
    // sentinel-encoded secret (via _keylessSecretEncoded) instead of
    // whatever raw string the caller passed as "passcode" to load it —
    // which is the sentinel string itself here, so this is just recording
    // what already worked.
    spd._keylessMode = (parsed as any).keylessMode ?? false;
    if (spd._keylessMode) spd._keylessSecretEncoded = passcode;
    // Restore entry ACL roles — see buildSerializedPayload's comment on
    // this same field for why this matters (previously never written,
    // meaning restrictEntry()'s restriction was silently lost on save).
    const storedEntryRoles = (parsed as any).entryRoles as Record<string, string[]> | undefined;
    if (storedEntryRoles) {
      spd.entryRoles = new Map(Object.entries(storedEntryRoles));
    }
    spd.data = data.map((item) => ({
      dataName: item.dataName,
      nonce: decodeEntryBytes(item.nonce),
      data: decodeEntryBytes(item.data),
      hash: item.hash,
      dataType: item.dataType,
    }));

    // Merkle tree verification (v29+)
    const storedMerkleRoot: string | undefined = (parsed as any).merkleRoot;
    if (storedMerkleRoot) {
      const leafHashes = spd.data.map(item =>
        crypto.createHash('sha3-256').update(item.data).digest('hex')
      );
      const computedRoot = SPD.buildMerkleRoot(leafHashes);
      if (computedRoot !== storedMerkleRoot) {
        throw new Error('Authentication failed.');
      }
    }

    // Per-entry hash verification
    // synchronous — no real parallelism to gain from Promise.all here
    for (const item of spd.data) {
      const computedHash = crypto.createHash(hashAlgorithm).update(item.data).digest('hex');
      if (computedHash !== item.hash) {
        throw new Error('Authentication failed.');
      }
    }

    // Rollback protection
    if (filePath) checkRollback(filePath, writeCounter);

    return spd;
  }

  private async buildBinaryPayload(
    passcode: string
  ): Promise<{ plaintext: Uint8Array; mac: Uint8Array }> {
    // Epoch rotation before building
    await this._maybeRotateEpoch(passcode);

    // Ratchet: rotate to fresh salt+keys before this save
    await this._maybeRatchetSalt(passcode);

    const { aeadKey, macKey } = this._getKeys();

    const { encryptedSalt, saltNonce, wrapSalt } = await SPD.encryptSalt(
      this.salt!, passcode, this._wrapArgon2Memory, this._wrapArgon2Time, this._wrapArgon2Parallelism
    );

    // Write this instance's ACTUAL current params into the meta block, not
    // profileParams(keyProfile) — see _argon2Memory/_argon2Time's doc
    // comment for why those can differ (and why writing the wrong ones here
    // would poison the very field changePasscode/upgradeKdfParams rely on
    // when this file is loaded again later).
    const a2mem = this._argon2Memory;
    const a2time = this._argon2Time;

    // Compute Merkle root over encrypted entry data
    const leafHashes = this.data.map(item =>
      crypto.createHash('sha3-256').update(item.data).digest('hex')
    );
    const merkleRoot = SPD.buildMerkleRoot(leafHashes);

    // Signed write counter
    const counterHMAC = SPD.computeCounterHMAC(macKey, this.writeCounter);

    const metaObj: Record<string, unknown> = {
      encryptedSalt,
      saltNonce,
      wrapSalt,
      version: SPD_VERSION,
      entryCount: this.data.length,
      writeCounter: this.writeCounter,
      hashAlgorithm: this.hash,
      argon2Memory: a2mem,
      argon2Time: a2time,
      argon2HashLen: ARGON2_HASH_LEN,
      hashKeyLen: HMAC_KEY_LEN,
      argon2Parallelism: this._argon2Parallelism,
      keyProfile: this.keyProfile,
      keyCommitment: SPD.computeKeyCommitment(aeadKey),
      merkleRoot,
      counterHMAC,
    };
    if (this._kdfChain) {
      metaObj.kdfChain = true;
      metaObj.scryptN  = this._scryptN;
      metaObj.scryptR  = this._scryptR;
      metaObj.scryptP  = this._scryptP;
    }
    if (this._wrapArgon2Memory !== ARGON2_MEMORY_STANDARD) metaObj.wrapArgon2Memory = this._wrapArgon2Memory;
    if (this._wrapArgon2Time   !== ARGON2_TIME_STANDARD)   metaObj.wrapArgon2Time   = this._wrapArgon2Time;
    if (this._wrapArgon2Parallelism !== 1) metaObj.wrapArgon2Parallelism = this._wrapArgon2Parallelism;
    if (this._ratchetEnabled)  { metaObj.ratchetEnabled = true; metaObj.ratchetCounter = this.writeCounter; }
    if (this._epochSize > 0)   { metaObj.epochNumber = this._epochNumber; metaObj.epochSize = this._epochSize; }
    if (this._keylessMode)     { metaObj.keylessMode = true; }
    // Same fix as buildSerializedPayload's identical addition — see that
    // comment for why this matters (previously never written in either
    // format, silently discarding restrictEntry()'s ACL on every save).
    if (this.entryRoles.size > 0) metaObj.entryRoles = Object.fromEntries(this.entryRoles);

    const metaPayload = utf8ToBytes(JSON.stringify(metaObj));
    const metaLenBuf = u8Alloc(4);
    writeUInt32LE(metaLenBuf, metaPayload.length);

    // Derive name-encryption key for v29+ index name encryption
    const nameKey = SPD.deriveNameKey(aeadKey);

    // Interleaved format (v29+): [2B encNameLen][encName][1B typeLen][type][2B hashLen][hash][3B nonceLen][nonce][8B dataLen][data]
    // encName = 24-byte nonce || CMT-4 ciphertext of UTF-8 name
    // (v26-28 used [1B nameLen][name] — handled in parseBinaryPayload)
    const parts: Uint8Array[] = [metaLenBuf, metaPayload];
    for (const item of this.data) {
      const encNameBytes = SPD._encryptEntryName(item.dataName, nameKey);
      const typeBytes = utf8ToBytes(item.dataType);
      const hashBytes = utf8ToBytes(item.hash);
      const enlBuf = u8Alloc(2);  writeUInt16LE(enlBuf, encNameBytes.length);
      const tlBuf  = u8Alloc(1);  writeUInt8(tlBuf, typeBytes.length);
      const hlBuf  = u8Alloc(2);  writeUInt16LE(hlBuf, hashBytes.length);
      const nolBuf = u8Alloc(3);  writeUIntLE3(nolBuf, item.nonce.length);
      const dlBuf  = u8Alloc(8);  writeBigUInt64LE(dlBuf, BigInt(item.data.length));
      parts.push(enlBuf, encNameBytes, tlBuf, typeBytes, hlBuf, hashBytes, nolBuf, item.nonce, dlBuf, item.data);
    }
    (nameKey).fill(0);

    const plaintext = u8Concat(parts);
    const mac = SPD.computeMAC(plaintext, macKey, 'application/spd-binary');

    // ML-DSA-65 signature: sign the MAC bytes, embed in meta
    if (this._signingKey) {
      const sig = signFileMac(mac, this._signingKey);
      metaObj.fileSignature = Array.from(sig);
      // Rebuild meta and plaintext with signature
      const metaPayload2 = utf8ToBytes(JSON.stringify(metaObj));
      const metaLenBuf2  = u8Alloc(4);
      writeUInt32LE(metaLenBuf2, metaPayload2.length);
      parts[0] = metaLenBuf2;
      parts[1] = metaPayload2;
      const plaintext2 = u8Concat(parts);
      const mac2 = SPD.computeMAC(plaintext2, macKey, 'application/spd-binary');
      if (this._keyBlindingEnabled) { aeadKey.fill(0); macKey.fill(0); }
      return { plaintext: plaintext2, mac: mac2 };
    }

    if (this._keyBlindingEnabled) { aeadKey.fill(0); macKey.fill(0); }
    return { plaintext, mac };
  }

  private static async parseBinaryPayload(
    plaintext: Uint8Array,
    mac: Uint8Array,
    passcode: string,
    verifyKey?: Uint8Array
  ): Promise<SPD> {
    const metaLen     = readUInt32LE(plaintext, 0);
    const metaPayload = plaintext.subarray(4, 4 + metaLen);
    const meta        = JSON.parse(bytesToUtf8(metaPayload));

    const { encryptedSalt, saltNonce, wrapSalt, version, entryCount } = meta;
    const writeCounter: number         = meta.writeCounter   ?? 0;
    const hashAlgorithm: HashAlgorithm = meta.hashAlgorithm ?? 'sha3-512';
    const argon2Memory: number         = meta.argon2Memory  ?? ARGON2_MEMORY;
    const argon2Time: number           = meta.argon2Time    ?? ARGON2_TIME;

    if (typeof version !== 'number' || version < SPD_VERSION_MIN || version > SPD_VERSION) {
      throw new Error(`Unsupported SPD version: ${version}`);
    }

    const { argon2HashLen, macKeyLen } = legacyKeyLengthsForVersion(version);

    // Wrap key params (v29+)
    const wrapMemory: number = meta.wrapArgon2Memory ?? ARGON2_MEMORY_STANDARD;
    const wrapTime: number   = meta.wrapArgon2Time   ?? ARGON2_TIME_STANDARD;
    const wrapParallelism: number = meta.wrapArgon2Parallelism ?? 1;
    // Validate BEFORE decryptSalt — see parseSerializedPayload's identical
    // comment; this runs pre-authentication (HMAC not yet checked).
    validateArgon2Params(wrapMemory, wrapTime, wrapParallelism);

    // KDF chain params
    const kdfChain: boolean = meta.kdfChain ?? false;
    const scryptN: number   = meta.scryptN ?? SCRYPT_N_DEFAULT;
    const scryptR: number   = meta.scryptR ?? SCRYPT_R_DEFAULT;
    const scryptP: number   = meta.scryptP ?? SCRYPT_P_DEFAULT;
    const argon2Parallelism = meta.argon2Parallelism ?? 1;
    validateArgon2Params(argon2Memory, argon2Time, argon2Parallelism);
    if (kdfChain) validateScryptParams(scryptN, scryptR, scryptP);

    const { aeadKey, macKey, salt: decryptedSalt } = await SPD.unlockKeys(passcode, {
      encryptedSalt, saltNonce, wrapSalt,
      wrapMemory, wrapTime, wrapParallelism,
      argon2Memory, argon2Time, argon2HashLen, macKeyLen,
      kdfChain, scryptN, scryptR, scryptP, argon2Parallelism,
    });

    const expectedMac = SPD.computeMAC(plaintext, macKey, 'application/spd-binary');
    if (!crypto.timingSafeEqual(mac, expectedMac)) {
      throw new Error('Authentication failed.');
    }

    // ML-DSA-65 signature verification
    // The signature covers the MAC of plaintext WITHOUT the fileSignature in the meta block.
    const storedSigBin: number[] | undefined = meta.fileSignature;
    if (verifyKey && storedSigBin) {
      const sigBuf = new Uint8Array(storedSigBin);
      // Rebuild plaintext without fileSignature to get the mac that was signed
      const metaNoSig = { ...meta } as Record<string, unknown>;
      delete (metaNoSig as any).fileSignature;
      const metaNoSigPayload = utf8ToBytes(JSON.stringify(metaNoSig));
      const metaNoSigLenBuf  = u8Alloc(4);
      writeUInt32LE(metaNoSigLenBuf, metaNoSigPayload.length);
      const plaintextNoSig = u8Concat([metaNoSigLenBuf, metaNoSigPayload, plaintext.subarray(4 + metaLen)]);
      const macNoSig = SPD.computeMAC(plaintextNoSig, macKey, 'application/spd-binary');
      if (!verifyFileMac(sigBuf, macNoSig, verifyKey)) {
        throw new Error('Authentication failed.');
      }
    } else if (verifyKey && !storedSigBin) {
      throw new Error('Authentication failed.');
    }

    // Key commitment verification
    const storedCommitmentBin: string | undefined = meta.keyCommitment;
    if (storedCommitmentBin) {
      const actualCommitmentBin = SPD.computeKeyCommitment(aeadKey);
      if (!crypto.timingSafeEqual(
        hexToBytes(storedCommitmentBin),
        hexToBytes(actualCommitmentBin)
      )) {
        throw new Error('Authentication failed.');
      }
    }

    // Signed write counter verification
    const storedCounterHMAC: string | undefined = meta.counterHMAC;
    if (storedCounterHMAC) {
      const expectedCounterHMAC = SPD.computeCounterHMAC(macKey, writeCounter);
      if (!crypto.timingSafeEqual(
        hexToBytes(storedCounterHMAC),
        hexToBytes(expectedCounterHMAC)
      )) {
        throw new Error('Authentication failed.');
      }
    }

    // Derive name-decryption key (v29+)
    const nameKey = version >= 29 ? SPD.deriveNameKey(aeadKey) : null;

    const entries: EncryptedDataEntry[] = [];
    let offset = 4 + metaLen;
    const scanToEof = (entryCount === 0);
    for (let i = 0; scanToEof ? offset < plaintext.length : i < entryCount; i++) {
      let dataName: string;
      if (version >= 29) {
        // v29+: [2B encNameLen][encName]
        const encNameLen = readUInt16LE(plaintext, offset); offset += 2;
        const encNameBuf = plaintext.subarray(offset, offset + encNameLen); offset += encNameLen;
        dataName = SPD._decryptEntryName(encNameBuf, nameKey!);
      } else {
        // v26-28: [1B nameLen][name] — stored in plaintext (no AEAD layer);
        // validate before it's later used to build a temp-file path (see
        // assertSafeDecryptedName's comment).
        const nameLen = readUInt8(plaintext, offset); offset += 1;
        dataName = assertSafeDecryptedName(bytesToUtf8(plaintext.subarray(offset, offset + nameLen))); offset += nameLen;
      }
      const typeLen   = readUInt8(plaintext, offset);    offset += 1;
      const dataType  = bytesToUtf8(plaintext.subarray(offset, offset + typeLen)) as SupportedDataType; offset += typeLen;
      const hashLen   = readUInt16LE(plaintext, offset); offset += 2;
      const entryHash = bytesToUtf8(plaintext.subarray(offset, offset + hashLen)); offset += hashLen;
      const nonceLen  = readUIntLE3(plaintext, offset); offset += 3;
      const nonce     = plaintext.subarray(offset, offset + nonceLen); offset += nonceLen;
      const dataLen   = Number(readBigUInt64LE(plaintext, offset)); offset += 8;
      const data      = plaintext.subarray(offset, offset + dataLen); offset += dataLen;

      const computedHash = crypto.createHash(hashAlgorithm).update(data).digest('hex');
      if (computedHash !== entryHash) {
        throw new Error('Authentication failed.');
      }

      entries.push({ dataName, nonce, data, hash: entryHash, dataType });
    }
    if (nameKey) (nameKey).fill(0);

    // Merkle root verification
    const storedMerkleRoot: string | undefined = meta.merkleRoot;
    if (storedMerkleRoot) {
      const leafHashes = entries.map(e => crypto.createHash('sha3-256').update(e.data).digest('hex'));
      const computedRoot = SPD.buildMerkleRoot(leafHashes);
      if (computedRoot !== storedMerkleRoot) {
        throw new Error('Authentication failed.');
      }
    }

    const spd = new SPD();
    spd.setHash(hashAlgorithm);
    spd.fileVersion   = version;
    spd.writeCounter  = writeCounter;
    spd.userKey       = aeadKey;
    spd.macKey        = macKey;
    spd.keyPair       = { publicKey: aeadKey };
    spd.salt          = decryptedSalt;
    spd.data          = entries;
    spd.keyProfile    = (meta.keyProfile as SPDKeyProfile) ?? 'high';
    spd._kdfChain     = kdfChain;
    spd._scryptN      = scryptN;
    spd._scryptR      = scryptR;
    spd._scryptP      = scryptP;
    spd._argon2Parallelism = argon2Parallelism;
    spd._argon2Memory = argon2Memory;
    spd._argon2Time   = argon2Time;
    spd._wrapArgon2Memory = wrapMemory;
    spd._wrapArgon2Time   = wrapTime;
    spd._wrapArgon2Parallelism = wrapParallelism;
    spd._ratchetEnabled   = meta.ratchetEnabled ?? false;
    spd._epochSize        = meta.epochSize ?? 0;
    spd._epochNumber      = meta.epochNumber ?? 0;
    // Keyless mode: preserve it on the loaded instance — see the identical
    // comment in parseSerializedPayload for why.
    spd._keylessMode = meta.keylessMode ?? false;
    if (spd._keylessMode) spd._keylessSecretEncoded = passcode;
    // Restore entry ACL roles — see buildBinaryPayload/buildSerializedPayload's
    // comment on this same field for why this matters (previously never
    // written in either format, silently discarding restrictEntry()'s
    // restriction on every save).
    const storedEntryRoles = meta.entryRoles as Record<string, string[]> | undefined;
    if (storedEntryRoles) {
      spd.entryRoles = new Map(Object.entries(storedEntryRoles));
    }
    return spd;
  }

  // ─── Type serialization (see internal/spd-serialize.ts) ────────────────────

  private convertInputToString(value: unknown): [string, SupportedDataType] {
    return serializeValue(value);
  }

  private convertStringToInput(value: string, type: SupportedDataType): unknown {
    return deserializeValue(value, type);
  }

  // ─── SPD.diff ──────────────────────────────────────────────────────────────

  /**
   * Compares two SPD files by entry name and hash — no entry decryption.
   * Only key derivation is performed (to verify MACs before trusting hashes).
   *
   * @returns `{added, removed, modified}` arrays of sanitized entry names.
   *   `added`    — names present in `fileB` but not `fileA`
   *   `removed`  — names present in `fileA` but not `fileB`
   *   `modified` — names present in both but with different ciphertext hashes
   */
  static async diff(
    fileA: string,
    fileB: string,
    passcode: string
  ): Promise<SPDDiffResult> {
    const [a, b] = await Promise.all([
      SPD.loadFromFile(fileA, passcode).catch(() => SPD.loadFromFileStreaming(fileA, passcode)),
      SPD.loadFromFile(fileB, passcode).catch(() => SPD.loadFromFileStreaming(fileB, passcode)),
    ]);

    const mapA = new Map(a['data'].map((e) => [e.dataName, e.hash]));
    const mapB = new Map(b['data'].map((e) => [e.dataName, e.hash]));

    const added: string[]    = [];
    const removed: string[]  = [];
    const modified: string[] = [];

    for (const [name, hash] of mapB) {
      if (!mapA.has(name))           added.push(name);
      else if (mapA.get(name) !== hash) modified.push(name);
    }
    for (const name of mapA.keys()) {
      if (!mapB.has(name)) removed.push(name);
    }

    a.destroy(); b.destroy();
    return { added, removed, modified };
  }

  // ─── SPD.merge ─────────────────────────────────────────────────────────────

  /**
   * Merges two SPD files into a new in-memory instance.
   * - `'a-wins'` : conflicting entries keep file A's version.
   * - `'b-wins'` : conflicting entries keep file B's version.
   * - `'newer'`  : keeps the version from the file with the higher `writeCounter`
   *                (file-level granularity, not per-entry).
   *
   * Returns `{ merged, conflicts }` — `merged` uses the winning file's key
   * material and is ready for `saveToFile`/`saveToFileStreaming`; `conflicts`
   * lists every entry name present in BOTH files with differing (ciphertext)
   * content, i.e. names where the losing side's value was discarded. Check
   * this if silently dropping one side's value on a real conflict matters
   * for your use case — previously this information was computed internally
   * (to decide what to skip) but never surfaced to the caller at all.
   */
  static async merge(
    fileA: string,
    fileB: string,
    passcode: string,
    options: SPDMergeOptions = { strategy: 'a-wins' }
  ): Promise<SPDMergeResult> {
    const [a, b] = await Promise.all([
      SPD.loadFromFile(fileA, passcode).catch(() => SPD.loadFromFileStreaming(fileA, passcode)),
      SPD.loadFromFile(fileB, passcode).catch(() => SPD.loadFromFileStreaming(fileB, passcode)),
    ]);

    // Determine which file's entries win on conflict
    let winner: SPD, loser: SPD;
    if (options.strategy === 'newer') {
      winner = a.writeCounter >= b.writeCounter ? a : b;
      loser  = winner === a ? b : a;
    } else if (options.strategy === 'b-wins') {
      winner = b; loser = a;
    } else {
      winner = a; loser = b;
    }

    // Build merged instance using winner's key material.
    // The loser may have a different Argon2 salt (different AEAD key), so we
    // must decrypt each loser entry and re-encrypt it under the winner's key.
    const merged = winner.exportEntries(/.*/);

    const winnerHashByName = new Map(winner['data'].map((e) => [e.dataName, e.hash] as const));
    const conflicts: string[] = [];
    for (const entry of loser['data']) {
      if (winnerHashByName.has(entry.dataName)) {
        // Same name on both sides — a real conflict only if the content
        // actually differs (same hash-comparison basis as SPD.diff()'s
        // `modified` list). Report it before skipping, so the caller can
        // tell "the winner already had this, unchanged" apart from
        // "the winner's value silently overwrote a different one."
        if (winnerHashByName.get(entry.dataName) !== entry.hash) {
          conflicts.push(entry.dataName);
        }
        continue; // winner already has this name
      }

      // Decrypt with loser's key + AAD
      const loserEKey = SPD.deriveEntryKey(loser['userKey']!, entry.dataName);
      let decrypted: Uint8Array;
      try {
        const aad = loser['fileVersion'] >= 27 ? utf8ToBytes(entry.dataName) : null;
        decrypted = loser['fileVersion'] >= 29
          ? SPD.aeadDecrypt(entry.data, aad, new Uint8Array(entry.nonce), loserEKey)
          : plainAeadDecrypt(entry.data, aad, new Uint8Array(entry.nonce), loserEKey);
      } finally {
        (loserEKey).fill(0);
      }

      // Re-encrypt under winner's (= merged's) key
      const winnerEKey = SPD.deriveEntryKey(merged['userKey']!, entry.dataName);
      let reEncrypted: Uint8Array;
      let nonce: Uint8Array;
      try {
        nonce = crypto.randomBytes(24);
        reEncrypted = SPD.aeadEncrypt(decrypted, utf8ToBytes(entry.dataName), nonce, winnerEKey);
      } finally {
        (winnerEKey).fill(0);
      }

      const hash = crypto.createHash(merged['hash']).update(reEncrypted).digest('hex');
      merged['data'].push({
        dataName: entry.dataName,
        nonce:    nonce,
        data:     reEncrypted,
        hash,
        dataType: entry.dataType,
      });
    }

    a.destroy(); b.destroy();
    return { merged, conflicts };
  }

  // ─── SPD.repair ────────────────────────────────────────────────────────────

  /**
   * Attempts partial recovery of a corrupt SPD file.
   * Reads entries sequentially until the first parse/decrypt failure, then saves
   * whatever was recovered to `outputPath`.
   *
   * Returns `{recovered, skipped}` counts.  If the file is a valid JSON payload
   * it uses the JSON loader; otherwise it attempts binary streaming entry-by-entry.
   */
  static async repair(
    filePath: string,
    passcode: string,
    outputPath: string
  ): Promise<SPDRepairResult> {
    const fs = getFs();
    SPD.log('load_start', { path: filePath, reason: 'repair' });

    let recovered = 0;
    let skipped = 0;

    // Try full load first
    try {
      const spd = await SPD.loadFromFile(filePath, passcode)
        .catch(() => SPD.loadFromFileStreaming(filePath, passcode));
      await spd.saveToFileStreaming(outputPath, passcode);
      recovered = spd.count();
      spd.destroy();
      SPD.log('repair_complete', { recovered, skipped });
      return { recovered, skipped };
    } catch { /* fall through to partial recovery */ }

    // Partial binary recovery: load binary plaintext, skip malformed entries
    let plaintext: Uint8Array;
    try {
      plaintext = await new Promise<Uint8Array>((resolve, reject) => {
        const chunks: Uint8Array[] = [];
        const rs = fs.createReadStream(filePath, { start: 72 });
        const inflate = zlib.createInflate();
        inflate.on('data', (c: Uint8Array) => chunks.push(c));
        inflate.once('end', () => resolve(u8Concat(chunks)));
        inflate.once('error', reject);
        rs.once('error', reject);
        onBinaryData(rs, (chunk) => inflate.write(chunk));
        rs.once('end', () => inflate.end());
      });
    } catch {
      return { recovered: 0, skipped: 0 };
    }

    // Parse meta block to get keys
    let aeadKey: Uint8Array | undefined;
    let macKey: Uint8Array | undefined;
    let hashAlgo: HashAlgorithm = 'sha3-512';
    let fileVersion = SPD_VERSION;
    try {
      const metaLen = readUInt32LE(plaintext, 0);
      const meta = JSON.parse(bytesToUtf8(plaintext.subarray(4, 4 + metaLen)));
      const { encryptedSalt, saltNonce, wrapSalt, version } = meta;
      hashAlgo = meta.hashAlgorithm ?? 'sha3-512';
      fileVersion = version ?? SPD_VERSION;
      const argon2Memory: number = meta.argon2Memory ?? ARGON2_MEMORY;
      const argon2Time: number   = meta.argon2Time   ?? ARGON2_TIME;
      const { argon2HashLen, macKeyLen } = legacyKeyLengthsForVersion(version);
      const unlockedRep = await SPD.unlockKeys(passcode, {
        encryptedSalt, saltNonce, wrapSalt,
        wrapMemory: meta.wrapArgon2Memory ?? ARGON2_MEMORY_STANDARD,
        wrapTime: meta.wrapArgon2Time ?? ARGON2_TIME_STANDARD,
        wrapParallelism: meta.wrapArgon2Parallelism ?? 1,
        argon2Memory, argon2Time, argon2HashLen, macKeyLen,
        kdfChain: meta.kdfChain ?? false, scryptN: meta.scryptN ?? SCRYPT_N_DEFAULT,
        scryptR: meta.scryptR ?? SCRYPT_R_DEFAULT, scryptP: meta.scryptP ?? SCRYPT_P_DEFAULT,
        argon2Parallelism: meta.argon2Parallelism ?? 1,
      });
      aeadKey = unlockedRep.aeadKey; macKey = unlockedRep.macKey;
    } catch { return { recovered: 0, skipped: 0 }; }

    // Scan entries
    const out = new SPD();
    out['userKey']      = new Uint8Array(aeadKey!);
    out['macKey']       = new Uint8Array(macKey!);
    out['salt']         = crypto.getRandomValues(new Uint8Array(ARGON2_SALT_LEN));
    out['hash']         = hashAlgo;
    out['fileVersion']  = fileVersion;

    const metaLen2 = readUInt32LE(plaintext, 0);
    let pos = 4 + metaLen2;
    const nameKeyRep = fileVersion >= 29 ? SPD.deriveNameKey(aeadKey!) : null;
    while (pos < plaintext.length) {
      try {
        const entryStart = pos;
        let dataName: string;
        if (fileVersion >= 29) {
          const encNameLen = readUInt16LE(plaintext, pos); pos += 2;
          const encNameBuf = plaintext.subarray(pos, pos + encNameLen); pos += encNameLen;
          dataName = SPD._decryptEntryName(encNameBuf, nameKeyRep!);
        } else {
          const nameLen = readUInt8(plaintext, pos); pos += 1;
          // Stored in plaintext (pre-v29) — validate so a corrupted/crafted
          // name doesn't propagate into the repaired output file (which
          // would then be readable via extractFromFileStreaming later).
          dataName = assertSafeDecryptedName(bytesToUtf8(plaintext.subarray(pos, pos + nameLen))); pos += nameLen;
        }
        const typeLen  = readUInt8(plaintext, pos);                 pos += 1;
        const dataType = bytesToUtf8(plaintext.subarray(pos, pos + typeLen)) as typeof out['data'][0]['dataType']; pos += typeLen;
        const hashLen  = readUInt16LE(plaintext, pos);              pos += 2;
        const hash     = bytesToUtf8(plaintext.subarray(pos, pos + hashLen)); pos += hashLen;
        const nonceLen = readUIntLE3(plaintext, pos);             pos += 3;
        const nonce    = plaintext.subarray(pos, pos + nonceLen); pos += nonceLen;
        const dataLen  = Number(readBigUInt64LE(plaintext, pos));   pos += 8;
        const data     = plaintext.subarray(pos, pos + dataLen); pos += dataLen;

        // Attempt decryption to verify the entry is intact
        const aad  = utf8ToBytes(dataName);
        const eKey = SPD.deriveEntryKey(aeadKey!, dataName);
        SPD.aeadDecrypt(data, aad, new Uint8Array(nonce), eKey);
        (eKey).fill(0);

        out['data'].push({ dataName, nonce, data, hash, dataType });
        recovered++;
      } catch {
        skipped++;
        break; // stop at first corrupt entry — further entries are likely corrupt too
      }
    }

    if (nameKeyRep) (nameKeyRep).fill(0);

    if (recovered > 0) {
      await out.saveToFileStreaming(outputPath, passcode);
    }
    out.destroy();
    SPD.log('repair_complete', { recovered, skipped });
    return { recovered, skipped };
  }

  // ─── SPD.writeParityFile / repairBitRot ────────────────────────────────────
  // Bit-rot / silent-corruption resilience for long-term archival storage.
  // Reed-Solomon parity is computed over the `.spd` file's raw on-disk bytes
  // AFTER encryption — never over plaintext (see internal/spd-ecc.ts's header
  // comment for why) — and stored in a separate `<path>.ecc` sidecar. The
  // `.spd` file's own format, offset index, and every existing read/write
  // path are completely unmodified: this is 100% additive and opt-in. No
  // passcode is needed for either method — the sidecar carries no secrets,
  // only parity over already-opaque ciphertext bytes.

  /**
   * Computes and writes a `<filePath>.ecc` Reed-Solomon parity sidecar for an
   * existing `.spd` file (or any file, in principle — this operates on raw
   * bytes and knows nothing about the SPD format itself).
   *
   * With the default parameters (64 KiB blocks, 16 data + 4 parity shards
   * per block), up to ~20% of the bytes in any given 64 KiB block can be
   * corrupted and still be fully recovered via `repairBitRot()`.
   *
   * @param filePath Path to the file to protect.
   * @param options  Tune block size / shard counts. Larger `parityShards`
   *                 relative to `dataShards` tolerates more corruption per
   *                 block at the cost of a larger `.ecc` file.
   */
  static async writeParityFile(filePath: string, options?: EccOptions): Promise<void> {
    const fs = getFs();
    const fileBytes = fs.readFileSync(filePath);
    const { sidecar } = buildEccSidecar(fileBytes, options);
    const tmpPath = filePath + '.ecc.tmp';
    fs.writeFileSync(tmpPath, sidecar, { mode: 0o600 });
    fs.renameSync(tmpPath, filePath + '.ecc');
    SPD.log('repair_complete', { path: filePath, reason: 'writeParityFile' });
  }

  /**
   * Checks `filePath` against its `<filePath>.ecc` parity sidecar (written
   * earlier by `writeParityFile`) and, if any blocks are corrupted but still
   * within the parity budget, repairs them and writes the fixed bytes back
   * to `filePath` in place (via the same atomic write-tmp-then-rename pattern
   * used elsewhere in this library). No-op (returns `repaired: false`,
   * `blocksCorrupted: 0`) if the file was already intact.
   *
   * @throws if no `.ecc` sidecar exists for `filePath`, if the sidecar's own
   *         integrity check fails, or if `filePath`'s size no longer matches
   *         what the sidecar was built for (the file was replaced, not just
   *         bit-rotted — repair is meaningless in that case).
   */
  static async repairBitRot(filePath: string, passcode?: string): Promise<SPDEccRepairResult> {
    const lockToken = acquireLock(filePath);
    try {
      return await SPD._repairBitRotLocked(filePath, passcode);
    } finally {
      releaseLock(filePath, lockToken);
    }
  }

  private static async _repairBitRotLocked(filePath: string, passcode?: string): Promise<SPDEccRepairResult> {
    const fs = getFs();
    const eccPath = filePath + '.ecc';
    if (!fs.existsSync(eccPath)) {
      throw new Error(`repairBitRot: no parity sidecar found at ${eccPath} — call writeParityFile() first.`);
    }
    const fileBytes = fs.readFileSync(filePath);
    const sidecar = fs.readFileSync(eccPath);

    const check = verifyWithEccSidecar(fileBytes, sidecar);
    if (check.sizeMismatch) {
      throw new Error(
        `repairBitRot: ${filePath} size no longer matches its .ecc sidecar — the file was replaced, not just bit-rotted. Cannot repair.`
      );
    }
    if (check.ok) {
      SPD.log('repair_complete', { path: filePath, reason: 'repairBitRot', blocksCorrupted: 0 });
      return { repaired: false, blocksChecked: 0, blocksCorrupted: 0, blocksRepaired: 0, unrecoverableBlocks: [] };
    }

    const result = repairWithEccSidecar(fileBytes, sidecar);
    let repairedPath: string | undefined;
    let verified = false;
    if (result.repaired && result.repairedBytes) {
      // The .ecc sidecar is integrity-protected but NOT authenticated (its HMAC
      // key is stored inside it), so a forged sidecar can "repair" a file into
      // attacker-chosen bytes. The original is therefore never overwritten
      // unless the repaired bytes pass the file's own MAC (needs the passcode);
      // without one, the repair is written next to the original as `.repaired`.
      const tmpPath = `${filePath}.repair-${process.pid}-${bytesToHex(crypto.randomBytes(6))}.tmp`;
      const wfd = fs.openSync(tmpPath, 'w', 0o600);
      try {
        fs.writeSync(wfd, result.repairedBytes);
        fs.fsyncSync(wfd);
      } finally {
        fs.closeSync(wfd);
      }
      if (passcode) {
        let ok = false;
        try { ok = (await SPD.verify(tmpPath, passcode)).valid; } catch { ok = false; }
        for (const side of ['.seq', '.ocount']) { try { fs.unlinkSync(tmpPath + side); } catch { /* none */ } }
        if (!ok) {
          try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
          throw new Error('repairBitRot: repaired bytes failed authentication — the .ecc sidecar is not trusted; original left untouched.');
        }
        fs.renameSync(tmpPath, filePath);
        repairedPath = filePath;
        verified = true;
      } else {
        repairedPath = filePath + '.repaired';
        fs.renameSync(tmpPath, repairedPath);
      }
    }
    SPD.log('repair_complete', {
      path: filePath, reason: 'repairBitRot',
      blocksCorrupted: result.blocksCorrupted, blocksRepaired: result.blocksRepaired,
      unrecoverable: result.unrecoverableBlocks.length,
    });
    return {
      repairedPath,
      verified,
      repaired: result.repaired,
      blocksChecked: result.blocksChecked,
      blocksCorrupted: result.blocksCorrupted,
      blocksRepaired: result.blocksRepaired,
      unrecoverableBlocks: result.unrecoverableBlocks,
    };
  }

  // ─── SPD.benchmark ─────────────────────────────────────────────────────────

  /**
   * Runs an in-memory self-test and returns timing/throughput numbers.
   * Useful for choosing `argon2Memory`/`argon2Time` on the target hardware.
   *
   * Does NOT write any files or use any persistent state.
   */
  static async benchmark(): Promise<SPDBenchmarkResult> {
    const SAMPLES = 10;
    const passcode = 'BenchmarkPass!1A';
    const salt = crypto.getRandomValues(new Uint8Array(ARGON2_SALT_LEN));

    // Argon2id
    const t0 = Date.now();
    await SPD.deriveKeys(passcode, salt);
    const argon2Ms = Date.now() - t0;

    // Encrypt SAMPLES entries
    const spd = new SPD();
    await spd.setPassKey(passcode);
    const t1 = Date.now();
    for (let i = 0; i < SAMPLES; i++) {
      await spd.addData(`bench_key_${i}`, `benchmark value ${i} `.repeat(100));
    }
    const encryptMs = (Date.now() - t1) / SAMPLES;

    // Decrypt (extractData)
    const t2 = Date.now();
    await spd.extractData();
    const decryptMs = (Date.now() - t2) / SAMPLES;

    // MAC (compute over a 1 MiB buffer)
    const buf = crypto.randomBytes(1024 * 1024);
    const t3 = Date.now();
    const macKey = spd['macKey']!;
    for (let i = 0; i < 10; i++) SPD.computeMAC(buf, macKey, 'application/spd-binary');
    const macMs = (Date.now() - t3) / 10;

    const entriesPerSecond = encryptMs > 0 ? Math.round(1000 / encryptMs) : Infinity;

    spd.destroy();
    SPD.log('benchmark_complete', { argon2Ms, encryptMs, decryptMs, macMs, entriesPerSecond });
    return { argon2Ms, encryptMs, decryptMs, macMs, entriesPerSecond };
  }

  // ─── SPD.watch ─────────────────────────────────────────────────────────────

  /**
   * Watches `filePath` for external changes and calls `cb` with the freshly
   * loaded SPD instance and a diff report each time the file is modified.
   *
   * ```ts
   * const stop = SPD.watch('/data/secrets.spd', 'pass', (spd, diff) => {
   *   console.log('added:', diff.added);
   * });
   * // … later:
   * stop();
   * ```
   *
   * - Uses `fs.watchFile` (stat polling, 1 s interval) so it works on NFS /
   *   Docker volumes where `fs.watch` inotify events are unreliable.
   * - Re-loads via `SPD.loadFromFile` (JSON) with a `SPD.loadFromFileStreaming`
   *   fallback for binary files.
   * - If the reload throws, the error is swallowed and `cb` is **not** called
   *   (avoids crashing the host process on transient FS errors).
   * - Returns a `stop()` function; call it to un-watch and stop polling.
   */
  static watch(
    filePath: string,
    passcode: string,
    cb: (spd: SPD, diff: SPDDiffResult) => void
  ): () => void {
    const fs = getFs();
    let prev: SPD | undefined;

    const reload = async () => {
      let next: SPD;
      try {
        next = await SPD.loadFromFile(filePath, passcode).catch(() =>
          SPD.loadFromFileStreaming(filePath, passcode)
        );
      } catch {
        return; // transient error — skip this tick
      }

      if (!prev) {
        // First load: fire cb with all entries as "added"
        const names = next['data'].map((e) => e.dataName);
        const diff: SPDDiffResult = { added: names, removed: [], modified: [] };
        prev = next;
        try { cb(next, diff); } catch { /* swallow handler errors */ }
        return;
      }

      // Compute diff without a second file load
      const prevMap = new Map(prev['data'].map((e) => [e.dataName, e.hash]));
      const nextMap = new Map(next['data'].map((e) => [e.dataName, e.hash]));

      const added: string[]    = [];
      const removed: string[]  = [];
      const modified: string[] = [];

      for (const [name, hash] of nextMap) {
        if (!prevMap.has(name))          added.push(name);
        else if (prevMap.get(name) !== hash) modified.push(name);
      }
      for (const name of prevMap.keys()) {
        if (!nextMap.has(name)) removed.push(name);
      }

      const diff: SPDDiffResult = { added, removed, modified };
      prev.destroy();
      prev = next;

      if (added.length || removed.length || modified.length) {
        try { cb(next, diff); } catch { /* swallow handler errors */ }
      }
    };

    // Perform an initial load synchronously in the next tick so callers can
    // attach event handlers before the first callback fires.
    setImmediate(() => { reload().catch(() => {}); });

    const listener = (_curr: fs.Stats, _prev: fs.Stats) => { reload().catch(() => {}); };
    fs.watchFile(filePath, { interval: 1000, persistent: false }, listener);

    return () => {
      fs.unwatchFile(filePath, listener);
      prev?.destroy();
      prev = undefined;
    };
  }

  // ─── Rule 1: True One-Time Pad (OTP) mode ──────────────────────────────────

  /** See `SPDUtils.otpEncrypt` (moved out of this class; behaviour unchanged). */
  static otpEncrypt = otpEncrypt;


  /** See `SPDUtils.otpDecrypt` (moved out of this class; behaviour unchanged). */
  static otpDecrypt = otpDecrypt;


  /** See `SPDUtils.generateSalt` (moved out of this class; behaviour unchanged). */
  static generateSalt = generateSalt;


  /** See `SPDUtils.generateOtpKey` (moved out of this class; behaviour unchanged). */
  static generateOtpKey = generateOtpKey;


  // ─── Rule 2: Physical key distribution ─────────────────────────────────────

  /**
   * Key delivery mode for Rule 2 compliance.
   *
   * Keys must never travel over the same digital channel as the ciphertext.
   * Use one of:
   *   - 'QKD'      — Quantum Key Distribution channel
   *   - 'courier'  — Human courier (physical delivery)
   *   - 'hardware' — Tamper-proof hardware token (HSM, smart card, FIDO2 key)
   *
   * `PHYSICAL_KEY_CHANNEL` documents which out-of-band delivery method was
   * used for a given key exchange session.
   */
  static readonly PHYSICAL_KEY_CHANNEL = PHYSICAL_KEY_CHANNEL;

  /** See `SPDUtils.assertPhysicalKeyDistrib` (moved out of this class; behaviour unchanged). */
  static assertPhysicalKeyDistrib = assertPhysicalKeyDistrib;


  // ─── Rule 8: Air-gapped decryption ─────────────────────────────────────────

  /** See `SPDUtils.requiresAirGap` (moved out of this class; behaviour unchanged). */
  static requiresAirGap = requiresAirGap;


  /** See `SPDUtils.isAirGapped` (moved out of this class; behaviour unchanged). */
  static isAirGapped = isAirGapped;


  // ─── Rule 12 (rules2 R11): Destruction assurance ───────────────────────────

  /**
   * Produce a signed cryptographic proof-of-destruction for key material.
   *
   * `DESTRUCTION_PROOF` receipts let auditors verify that key material was
   * actually destroyed, not just zeroed in a way that could be faked.
   *
   * The receipt is an HMAC-SHA3-512 of `key || timestamp` signed with a
   * destruction signing key, then the key is immediately zeroed.
   *
   * @param key             Key material being destroyed.
   * @param signingKey      32-byte HMAC signing key held by an auditor.
   * @returns               Hex-encoded `DESTRUCTION_PROOF` receipt string.
   */
  static destroyWithProof(key: Uint8Array, signingKey: Uint8Array): string {
    const ts  = u8Alloc(8);
    writeBigUInt64BE(ts, BigInt(Date.now()));
    const receipt = crypto.createHmac('sha3-512', signingKey)
      .update(key).update(ts).digest('hex');
    (key).fill(0);  // immediate destruction after signing
    const destructionProof = `DESTRUCTION_PROOF:${receipt}:${readBigUInt64BE(ts)}`;
    SPD.log('key_derived', { event: 'destroyWithProof', destructionProof });
    return destructionProof;
  }

  // ─── Rule 13 (rules2 R12): Temporal keys ───────────────────────────────────

  /**
   * Temporal key validity window (rules2.txt Rule 12).
   *
   * `TIME_WINDOW_MS` defines the maximum absolute wall-clock duration a key
   * may exist.  After `absoluteExpiry`, key fragments auto-erase and decryption
   * becomes physically impossible — even infinite computation cannot recover
   * information that was never stored beyond the window.
   *
   * Default: 5 minutes.
   */
  static readonly TIME_WINDOW_MS = TIME_WINDOW_MS;

  /** See `SPDUtils.wrapTemporalKey` (moved out of this class; behaviour unchanged). */
  static wrapTemporalKey = wrapTemporalKey;


  // ─── Rule 14 (rules2 R13): Physical channel noise injection ─────────────────

  /**
   * Channel noise injection parameters (rules2.txt Rule 13).
   *
   * `CHANNEL_NOISE` / `noiseInjection`: inject randomized transmission delays
   * and padding so a passive observer cannot distinguish signal from background.
   *
   * Prevents traffic analysis — the communication pattern becomes indistinguishable
   * from noise even to an observer recording every packet.
   */
  static readonly CHANNEL_NOISE = CHANNEL_NOISE;

  /** See `SPDUtils.noiseInjection` (moved out of this class; behaviour unchanged). */
  static noiseInjection = noiseInjection;


  /** See `SPDUtils.secureRandomInt`. */
  private static _secureRandomInt = secureRandomInt;


  // ─── Rule 15 (rules2 R14): Human separation of knowledge ────────────────────

  /**
   * Human separation of knowledge (rules2.txt Rule 14).
   *
   * No single person may know the full key, full message, and full process.
   * Roles are separated: `entropyOperator`, `fragmentKeeper`, `courierRole`,
   * `decryptOperator`.  Compromise requires multiple independent insiders.
   *
   * `knowledgeSeparation` is enforced by requiring separate acknowledgement
   * tokens from each role before a decryption session may proceed.
   */
  static readonly KNOWLEDGE_SEP = KNOWLEDGE_SEP;

  /** See `SPDUtils.assertKnowledgeSeparation` (moved out of this class; behaviour unchanged). */
  static assertKnowledgeSeparation = assertKnowledgeSeparation;


  // ─── Rule 16 (rules2 R15): Anti-forensic protocol ───────────────────────────

  /**
   * Anti-forensic protocol flag (rules2.txt Rule 15).
   *
   * `ANTI_FORENSIC` / `volatileOnly`: all key computation must occur in volatile
   * memory only.  No swap, no logging of key material, no persistent cache,
   * no cloud sync.  Power loss = total wipe.
   *
   * This flag is set when the SPD instance is operating in anti-forensic mode.
   */
  private _antiForensicMode = false;

  /**
   * Enable anti-forensic protocol (`VOLATILE_ONLY` / `ANTI_FORENSIC` mode).
   *
   * In this mode:
   *   - Key caching is disabled (`SPD.setKeyCacheTtl(0)` enforced)
   *   - WAL / persistent log writes are suppressed for key events
   *   - `volatileMemory.*key` / `ramOnly.*key` patterns are activated
   *   - `noPersistentCache` is enforced
   *
   * @param enable  `true` to enable anti-forensic mode.
   */
  enableAntiForensic(enable = true): void {
    if (enable && !this._antiForensicMode) antiForensic.count++;
    if (!enable && this._antiForensicMode) antiForensic.count--;
    this._antiForensicMode = enable;
    if (enable) {
      // No key cache allowed: disable it process-wide and drop anything cached;
      // setKeyCacheTtl refuses to re-enable it while any such instance is live.
      SPD.setKeyCacheTtl(0);
    }
  }


  /** Returns `true` if anti-forensic (`volatileOnly`) mode is active. */
  isAntiForensicMode(): boolean {
    return this._antiForensicMode;
  }

  // ─── Rule 17 (rules2 R2): Multi-pad obfuscation ──────────────────────────────

  /** See `SPDUtils.multiPadEncrypt` (moved out of this class; behaviour unchanged). */
  static multiPadEncrypt = multiPadEncrypt;


  /** See `SPDUtils.multiPadDecrypt` (moved out of this class; behaviour unchanged). */
  static multiPadDecrypt = multiPadDecrypt;


  // ─── Rule 18 (rules2 R6): Traffic camouflage / steganography ─────────────────

  /** See `SPDUtils.embedInCarrier` (moved out of this class; behaviour unchanged). */
  static embedInCarrier = embedInCarrier;


  /** See `SPDUtils.extractFromCarrier` (moved out of this class; behaviour unchanged). */
  static extractFromCarrier = extractFromCarrier;


  // ─── Deniable/hidden-volume entries ─────────────────────────────────────────

  /** Entries whose sanitized name starts with this prefix are the "hidden volume" — real content, revealed only via `deniableDecryptView()`. */
  static readonly DECOY_NAME_PREFIX = '_decoy_';

  private _deniableMode = false;

  /**
   * Enable/disable deniable-view bookkeeping for this instance (currently
   * informational only — `deniableDecryptView()` works regardless of this
   * flag, since the actual mechanism is purely name-prefix-based and needs
   * no per-instance state; kept for API stability and as a place to hang
   * future per-instance behavior).
   */
  enableDeniableEncryption(enable = true): void {
    this._deniableMode = enable;
  }

  /** Returns `true` if `enableDeniableEncryption(true)` was called. */
  isDeniableMode(): boolean {
    return this._deniableMode;
  }

  /**
   * Returns only the decrypted values of entries added via `addData()`
   * whose name starts with `SPD.DECOY_NAME_PREFIX` ("_decoy_") — a
   * "hidden volume"-style pattern (same idea as VeraCrypt hidden volumes,
   * which this doc previously and correctly cited as the real precedent):
   * store real, readable content under decoy-prefixed names alongside your
   * genuinely sensitive entries, then under duress present only this view
   * (or a whole separate file built via `exportEntries(/^_decoy_/)`) —
   * whoever sees it has no way to know further, real entries exist in the
   * same vault.
   *
   * Regression note: this method previously looked for `dataType ===
   * '_decoy'`, a sentinel only ever set by the unrelated `addDecoy()`
   * method (which fills entries with meaningless random noise, by design
   * never meant to be decrypted at all — see its own doc comment). Calling
   * `addData('_decoy_message', 'innocent content')` as this method's own
   * documented example showed never set that sentinel, so
   * `deniableDecryptView()` always returned an empty array — confirmed
   * directly by running that exact example. Fixed to match by NAME prefix
   * instead, against entries added the normal way via `addData()`, which
   * is what the documented usage actually needs.
   *
   * @returns  Array of `{ name, value }` pairs — real, decrypted content
   *           for every decoy-prefixed entry.
   */
  async deniableDecryptView(): Promise<{ name: string; value: unknown }[]> {
    this.assertReady();
    const result: { name: string; value: unknown }[] = [];
    for (const item of this.data) {
      if (item.dataType === ('_decoy' as unknown as typeof item.dataType)) continue;
      if (!item.dataName.startsWith(SPD.DECOY_NAME_PREFIX)) continue;
      if (!this.canReadEntry(item.dataName)) {
        throw new Error(`Access denied: entry "${item.dataName}" requires role "${(this.entryRoles.get(item.dataName) ?? []).join('|')}".`);
      }

      const aad  = this.fileVersion >= 27 ? utf8ToBytes(item.dataName) : null;
      const dKey = this.fileVersion >= 27 ? SPD.deriveEntryKey(this.userKey!, item.dataName) : this.userKey!;
      try {
        const decrypted = this.fileVersion >= 29
          ? SPD.aeadDecrypt(item.data, aad, new Uint8Array(item.nonce), dKey)
          : plainAeadDecrypt(item.data, aad, new Uint8Array(item.nonce), dKey);
        const inflated = await zlib.inflate(decrypted);
        const decompressed = bytesToUtf8(this.fileVersion >= 29
          ? SPD.unpadAfterDecompression(inflated)
          : inflated);
        const value = this.convertStringToInput(decompressed, item.dataType);
        result.push({ name: item.dataName, value });
      } catch {
        throw new Error('Authentication failed.');
      } finally {
        if (this.fileVersion >= 27) (dKey as Uint8Array).fill(0);
      }
    }
    return result;
  }

  // ─── rules3.txt utilities ────────────────────────────────────────────────────

  /** See `SPDUtils.startNoiseBaseline` (moved out of this class; behaviour unchanged). */
  static startNoiseBaseline = startNoiseBaseline;


  /** See `SPDUtils.timeSmear` (moved out of this class; behaviour unchanged). */
  static timeSmear = timeSmear;


  /** See `SPDUtils.generateQuantumKey` (moved out of this class; behaviour unchanged). */
  static generateQuantumKey = generateQuantumKey;


  /** See `SPDUtils.inflateEntropy` (moved out of this class; behaviour unchanged). */
  static inflateEntropy = inflateEntropy;


}
