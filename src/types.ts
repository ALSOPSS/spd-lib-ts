import type { SPD } from './SPD.js';

export type HashAlgorithm = 'sha3-512' | 'sha256' | 'sha512';

export type SupportedDataType =
  | 'string'
  | 'number'
  | 'boolean'
  | 'object'
  | 'Array'
  | 'Uint8Array'
  | 'Uint16Array'
  | 'Uint32Array'
  | 'BigInt64Array'
  | 'BigUint64Array'
  | 'Float32Array'
  | 'Float64Array'
  | 'Map'
  | 'Set'
  | 'Date'
  | 'RegExp'
  | 'Error';

export interface EncryptedDataEntry {
  dataName: string;
  nonce: Uint8Array;
  data: Uint8Array;
  hash: string;
  dataType: SupportedDataType;
}

export interface SerializedDataEntry {
  dataName: string;
  // v2.0.1+: written as base64 strings — a number[] with one element per
  // byte made buildSerializedPayload() explode every entry's ciphertext
  // into a JS array of numbers before JSON.stringify, which hit V8's
  // array-length ceiling (a real, reproducible RangeError: Invalid array
  // length) around 50MB of real entry data, and was severely slow well
  // before that (tens of seconds for a 25MB entry) — one array element
  // per byte has far more per-element overhead than a packed Uint8Array,
  // and Array.from() over millions of elements is not cheap. Base64
  // strings avoid both: no per-byte JS object overhead, and no array at
  // all. Still accepts the legacy number[] shape for reading files
  // written by older versions — see readEntryBytes().
  nonce: number[] | string;
  data: number[] | string;
  hash: string;
  dataType: SupportedDataType;
}

export interface SPDPayload {
  data: SerializedDataEntry[];
  encryptedSalt: number[];
  saltNonce: number[];
  wrapSalt: number[];
  version: number;
  writeCounter?: number;  // v27.1+: monotonically incremented on each save for rollback detection
  // v26+: embedded so loads are fully self-contained
  hashAlgorithm?: string;
  argon2Memory?: number;
  argon2Time?: number;
  // v27+: wider master secret and HMAC key
  argon2HashLen?: number;
  hashKeyLen?: number;
  // v29+: Argon2id parallelism (default 1 for backward compat, 2 for new files)
  argon2Parallelism?: number;
  // v27.2+: entry ACL roles map { entryName -> string[] }
  entryRoles?: Record<string, string[]>;
  // v27.2+: max open count for auto-destruct
  maxOpenCount?: number;
  openCount?: number;
  // v27.3+: key stretching profile + key commitment
  keyProfile?: string;
  keyCommitment?: string;
  // v29+: KDF chaining
  kdfChain?: boolean;
  scryptN?: number;
  scryptR?: number;
  scryptP?: number;
  // v29+: configurable wrap key params
  wrapArgon2Memory?: number;
  wrapArgon2Time?: number;
  wrapArgon2Parallelism?: number; // lanes for the salt-wrap KDF (absent = 1)
  // v29+: post-quantum file signature (ML-DSA-65)
  fileSignature?: number[];
  signingPubKey?: number[];
  // v29+: forward secrecy ratchet
  ratchetEnabled?: boolean;
  ratchetCounter?: number;
  // v29+: epoch key rotation
  epochNumber?: number;
  epochSize?: number;
  // v29+: per-entry Merkle tree root
  merkleRoot?: string;
  // v29+: signed write counter
  counterHMAC?: string;
  // v29+: keyless mode (SPD.setRandomKey()/setKeyfileOnly()) — when true,
  // argon2Memory/argon2Time are meaningless placeholders (always 1), not a
  // real KDF cost, since this file's master secret skipped Argon2id entirely.
  keylessMode?: boolean;
}

/** PKCS#11 / HSM key provider abstraction. Implement this interface to use hardware keys. */
export interface SPDKeyProvider {
  /** Derive the 96-byte master secret from a passcode and salt (replaces Argon2id). */
  deriveKey(passcode: string, salt: Uint8Array, memory: number, time: number): Promise<Uint8Array>;
  /** Optional: wrap (encrypt) a key for storage — used when exporting key material. */
  wrapKey?(key: Uint8Array): Promise<Uint8Array>;
  /** Optional: unwrap (decrypt) a key retrieved from storage. */
  unwrapKey?(wrapped: Uint8Array): Promise<Uint8Array>;
}

/** ML-DSA-65 signing key pair for file authentication. Signatures are 3309 bytes. */
export interface SPDSigningKeyPair {
  privateKey: Uint8Array; // 4032 bytes (ML-DSA-65) or 4064 (ML-DSA-65 + Ed25519 composite)
  publicKey:  Uint8Array; // 1952 bytes (ML-DSA-65) or 1984 (composite)
}


export interface WrappedPayload {
  payload: Uint8Array;
  mac: Uint8Array;
}

export interface SerializedWrappedPayload {
  payload: number[];
  mac: number[];
}

export interface PBKResult {
  pbk: Uint8Array;
  salt: Uint8Array;
}

export interface EncryptedSaltResult {
  encryptedSalt: number[];
  saltNonce: number[];
  wrapSalt: number[];
}

export interface DataInput {
  name: string;
  data: unknown;
}

export interface SPDChunkManifest {
  totalChunks: number;
  chunkSize: number;
  totalBytes: number;
  version: number;
}

export interface SPDIndexEntry {
  name: string;
  decompressedOffset: bigint;
}

export interface SPDWriterOptions {
  compressionLevel?: number;
  hashAlgorithm?: HashAlgorithm;
  argon2Memory?: number;
  argon2Time?: number;
}

export interface SPDGetEntryResult {
  value: unknown;
  dataType: SupportedDataType;
  name: string;
}

export interface SPDInspectResult {
  version: number;
  entryCount: number;
  writeCounter: number;
  hashAlgorithm: string;
  argon2Memory: number;
  argon2Time: number;
  fileSize: number;
  hasIndex: boolean;
  format: 'binary' | 'json';
}

export interface SPDVerifyResult {
  valid: boolean;
  entryCount: number;
  indexPresent: boolean;
  writeCounter: number;
}

export interface SPDDiffResult {
  added: string[];
  removed: string[];
  modified: string[];
}

export interface SPDMergeOptions {
  strategy: 'a-wins' | 'b-wins' | 'newer';
}

export interface SPDMergeResult {
  /** The merged instance, ready for saveToFile/saveToFileStreaming. */
  merged: SPD;
  /**
   * Names present in BOTH input files where the encrypted content differs —
   * i.e. a genuine conflict the chosen strategy resolved by picking one
   * side and silently discarding the other's value for that name. Empty
   * when the two files had no overlapping entries with differing content.
   * Uses the same ciphertext-hash comparison as `SPD.diff()`'s `modified`
   * list, so (as with `diff()`) two saves of identical plaintext will still
   * appear here if re-encrypted with a fresh nonce — this is a conservative
   * "these might differ" signal, not a guaranteed plaintext inequality.
   */
  conflicts: string[];
}

export interface SPDSnapshot {
  /** Encrypted entries captured at snapshot time (deep copies). */
  data: EncryptedDataEntry[];
  writeCounter: number;
  ts: number;
  /** Entry ACL at snapshot time; restored with the entries. */
  entryRoles?: Record<string, string[]>;
}

export interface SPDLogEvent {
  event:
    | 'key_derived'
    | 'key_destroyed'
    | 'key_cache_hit'
    | 'entry_added'
    | 'entry_updated'
    | 'entry_deleted'
    | 'save_start'
    | 'save_end'
    | 'load_start'
    | 'load_end'
    | 'rollback_detected'
    | 'lock_acquired'
    | 'lock_released'
    | 'wal_flushed'
    | 'auto_destruct'
    | 'repair_complete'
    | 'benchmark_complete'
    | 'keyfile_generated'
    | 'keyfile_loaded';
  ts: number;
  detail?: Record<string, unknown>;
}

export interface SPDBenchmarkResult {
  argon2Ms: number;
  encryptMs: number;
  decryptMs: number;
  macMs: number;
  entriesPerSecond: number;
}

export interface SPDRepairResult {
  recovered: number;
  skipped: number;
}

/**
 * Result of `SPD.repairBitRot()` — byte-level Reed-Solomon repair using a
 * `.ecc` parity sidecar (see internal/spd-ecc.ts). Distinct from
 * `SPDRepairResult` (`SPD.repair()`), which is an application-level, passcode-
 * requiring recovery of a corrupt file's readable entries — this one operates
 * on raw bytes with no passcode, before any entry is ever parsed.
 */
export interface SPDEccRepairResult {
  /** Where the repaired bytes went: the original path (only when a passcode was given and the result authenticated) or `<file>.repaired`. */
  repairedPath?: string;
  /** True when the repaired bytes passed the file's own MAC before replacing the original. */
  verified?: boolean;
  /** True if every corrupted block found was successfully repaired. False if nothing needed repair OR something was unrecoverable. */
  repaired: boolean;
  blocksChecked: number;
  blocksCorrupted: number;
  blocksRepaired: number;
  /** Block indices where corruption exceeded the parity budget — those bytes are permanently lost. */
  unrecoverableBlocks: number[];
}

export type TypedArray =
  | Uint8Array
  | Uint16Array
  | Uint32Array
  | BigInt64Array
  | BigUint64Array
  | Float32Array
  | Float64Array;

export type SupportedValue =
  | string
  | number
  | boolean
  | unknown[]
  | TypedArray
  | Map<unknown, unknown>
  | Set<unknown>
  | Date
  | RegExp
  | Error
  | Record<string, unknown>;
