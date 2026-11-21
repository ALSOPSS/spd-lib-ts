/**
 * Key derivation, salt wrapping, the opt-in unlock cache and the small
 * cryptographic helpers of the SPD file format (SPEC.md §2–§4), extracted
 * from SPD.ts. `SPD` keeps static aliases to every function here, so the
 * public surface is unchanged. No function in this module touches SPD
 * instance state.
 */
import * as crypto from './portable-crypto.js';
import { utf8ToBytes, bytesToUtf8, concatBytes, bytesToHex, bytesToBase64, base64ToBytes } from './portable-crypto.js';
import { u8Alloc, writeBigUInt64BE } from './portable-binary.js';
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
} from './spd-crypto.js';
import * as keyMaterial from './spd-key-material.js';
import type { SPDKeyProvider, EncryptedSaltResult, PBKResult } from '../types.js';

// ─── Constants (SPEC.md §1–§3) ──────────────────────────────────────────────
export const SCRYPT_N_DEFAULT = 1048576;
export const SCRYPT_R_DEFAULT = 8;
export const SCRYPT_P_DEFAULT = 4;
export const ARGON2_MEMORY = 524288;
export const ARGON2_TIME = 8;
export const ARGON2_MEMORY_STANDARD = 131072;
export const ARGON2_TIME_STANDARD = 6;
export const ARGON2_HASH_LEN = 96;
export const ARGON2_SALT_LEN = 32;
export const AEAD_KEY_LEN = 32;
export const HMAC_KEY_LEN = 64;
export const ARGON2_MEMORY_HIGH = 524288;
export const ARGON2_TIME_HIGH = 8;
export const ARGON2_MEMORY_PARANOID = 2097152;
export const ARGON2_TIME_PARANOID = 16;
export const KEYLESS_SENTINEL = '\0SPD-KEYLESS-V1\0';
export const KEYLESS_MASTER_SECRET_LEN = ARGON2_HASH_LEN;
export const ARGON2_MEMORY_MAX_KIB = ARGON2_MEMORY_PARANOID * 4;
export const ARGON2_TIME_MAX = ARGON2_TIME_PARANOID * 4;
export const ARGON2_PARALLELISM_MAX = 16;
export const SCRYPT_N_MAX = SCRYPT_N_DEFAULT * 8;
export const SCRYPT_R_MAX = 32;
export const SCRYPT_P_MAX = 16;

// ─── Parameter validation (runs BEFORE authentication on file-supplied values) ──
/**
 * Validates a KDF parameter read from (untrusted) file metadata is a
 * positive integer within a sane ceiling. Throws — callers should let this
 * propagate as a load failure, same as any other malformed-file error.
 */
export function validateKdfParam(name: string, value: number, max: number): number {
  if (!Number.isInteger(value) || value < 1 || value > max) {
    throw new Error(`Invalid or out-of-range KDF parameter "${name}": ${value} (expected an integer in [1, ${max}]).`);
  }
  return value;
}
export function validateArgon2Params(memory: number, time: number, parallelism: number): void {
  validateKdfParam('argon2Memory', memory, ARGON2_MEMORY_MAX_KIB);
  validateKdfParam('argon2Time', time, ARGON2_TIME_MAX);
  validateKdfParam('argon2Parallelism', parallelism, ARGON2_PARALLELISM_MAX);
}
export function validateScryptParams(n: number, r: number, p: number): void {
  validateKdfParam('scryptN', n, SCRYPT_N_MAX);
  validateKdfParam('scryptR', r, SCRYPT_R_MAX);
  validateKdfParam('scryptP', p, SCRYPT_P_MAX);
}

export const SANITIZED_NAME_RE = /^[a-z0-9_-]{1,255}$/;
/**
 * Validates a decrypted entry name is safe to use in a filesystem path —
 * i.e. it matches exactly what `sanitizeName()` would have produced at
 * write time. Throws (as "Authentication failed.", matching every other
 * decrypt-path error in this file) rather than silently re-sanitizing,
 * since a name that doesn't already match indicates the entry was never
 * legitimately written by this library.
 */
export function assertSafeDecryptedName(name: string): string {
  if (!SANITIZED_NAME_RE.test(name)) {
    throw new Error('Authentication failed.');
  }
  return name;
}

// ─── Process-wide state ─────────────────────────────────────────────────────
/** Installed HSM/PKCS#11 provider, if any (see SPD.setKeyProvider). */
export const keyProvider: { current: SPDKeyProvider | undefined } = { current: undefined };
/** Live anti-forensic instances pin the unlock cache off (see SPD.enableAntiForensic). */
export const antiForensic = { count: 0 };
/** Unlock-cache TTL in ms; 0 = disabled (default). See setKeyCacheTtl(). */
export const keyCacheTtlMsRef = { value: 0 };
// Per-process random HMAC key for cache lookups: the cache key is then not an
// offline-usable passcode verifier (unlike a plain SHA-256 of the passcode).
const keyCacheHmacKey = crypto.randomBytes(32);
interface KeyCacheEntry {
  aeadKey: Uint8Array;
  macKey: Uint8Array;
  salt: Uint8Array;
  expiresAt: number;
}
export const keyCache = new Map<string, KeyCacheEntry>();

// ─── Functions ──────────────────────────────────────────────────────────────
export async function derivePBK(
  passcode: string,
  salt: Uint8Array,
  memory: number = ARGON2_MEMORY_STANDARD,
  time: number = ARGON2_TIME_STANDARD,
  hashLen: number = ARGON2_HASH_LEN,
  parallelism: number = 1
): Promise<PBKResult> {
  if (!salt || !(salt instanceof Uint8Array)) {
    throw new Error('Invalid salt: expected a Uint8Array.');
  }
  if (salt.length < 16) {
    throw new Error(`Invalid salt: must be at least 16 bytes (got ${salt.length}).`);
  }
  if (!passcode || typeof passcode !== 'string') {
    throw new Error('Authentication failed.');
  }

  // ── Keyless mode: skip Argon2id entirely for a raw high-entropy secret ──
  // See KEYLESS_SENTINEL's doc comment for why this dispatch is safe. A
  // 96-byte CSPRNG secret has no brute-force surface to slow down — running
  // it through Argon2id/scrypt would cost real wall-clock time for zero
  // security benefit, which is exactly the "no human keys, no wasted time"
  // property generateRandomKey()/setRandomKey() are for. Pepper and
  // keyfile mixing are also skipped here deliberately: both exist to
  // strengthen a weak HUMAN passphrase, which does not apply to an
  // already-maximum-entropy secret, and mixing them in would only add
  // coupling between two independent security mechanisms for no benefit.
  const keylessSecret = _decodeKeylessSecret(passcode);
  if (keylessSecret) {
    // HKDF-Expand only (no Extract) — the secret already has full entropy,
    // exactly the same reasoning already used for aeadKey/macKey expansion
    // in deriveKeys(). Bind the salt into the info string so the same
    // master secret still produces different output per file/per-call,
    // matching Argon2id's own salt-dependence.
    const pbk = sharedHkdfExpand(keylessSecret, `spd-keyless-pbk-v1:${bytesToHex(salt)}`, hashLen);
    keylessSecret.fill(0);
    return { pbk, salt };
  }

  // Pepper + keyfile mixing — see keyMaterial.mixPasscode.
  const effectivePasscode = keyMaterial.mixPasscode(passcode, salt);

  const pbk = await argon2idRaw(effectivePasscode, salt, {
    memory,
    time,
    parallelism,
    hashLen,
  });
  if (effectivePasscode instanceof Uint8Array) effectivePasscode.fill(0); // pepper || passcode copy

  return { pbk, salt };
}

/**
 * Derives a master secret via Argon2id and splits it into:
 *   aeadKey (32 B)     — XChaCha20-Poly1305 encryption key
 *   macKey  (32/64 B)  — HMAC-SHA3-512 authentication key (domain-separated)
 *
 * v27+: hashLen=96, macKeyLen=64 (full SHA3-512 output width = 128-bit PQ forgery resistance)
 * v26:  hashLen=64, macKeyLen=32 (legacy — pass these explicitly when reading old files)
 */
export async function deriveKeys(
  passcode: string,
  salt: Uint8Array,
  memory: number = ARGON2_MEMORY,
  time: number = ARGON2_TIME,
  hashLen: number = ARGON2_HASH_LEN,
  macKeyLen: number = HMAC_KEY_LEN,
  kdfChain = false,
  scryptN = SCRYPT_N_DEFAULT,
  scryptR = SCRYPT_R_DEFAULT,
  scryptP = SCRYPT_P_DEFAULT,
  parallelism = 1
): Promise<{ aeadKey: Uint8Array; macKey: Uint8Array }> {
  // If an HSM provider is installed, delegate to it; then apply HKDF domain separation.
  if (keyProvider.current) {
    const masterHsm = await keyProvider.current.deriveKey(passcode, salt, memory, time);
    const aeadKey = sharedHkdfExpand(masterHsm, 'spd-aead-key-v1', AEAD_KEY_LEN);
    const macKey  = sharedHkdfExpand(masterHsm, 'spd-mac-key-v1',  macKeyLen);
    return { aeadKey, macKey };
  }

  const master = await derivePBK(passcode, salt, memory, time, hashLen, parallelism);
  // Slice into independent contiguous Uint8Arrays (not views) so memzero on
  // the master doesn't corrupt the returned keys before they are used.
  let masterBytes = new Uint8Array(master.pbk.buffer.slice(
    master.pbk.byteOffset,
    master.pbk.byteOffset + hashLen
  ));
  // Zero the original master buffer
  master.pbk.fill(0);

  // ── KDF chaining: pipe Argon2id output through scrypt ──────────────────
  // This means an attacker must break BOTH Argon2id AND scrypt to derive keys.
  if (kdfChain) {
    const scryptOut = await crypto.scrypt(
      masterBytes,           // password = Argon2id output
      concatBytes(salt, utf8ToBytes('spd-kdf-chain-v1')),  // salt
      hashLen,               // output length = same as Argon2id output
      { N: scryptN, r: scryptR, p: scryptP, maxmem: 256 * scryptN * scryptR }
    );
    masterBytes.fill(0);
    masterBytes = new Uint8Array(scryptOut.buffer.slice(scryptOut.byteOffset, scryptOut.byteOffset + hashLen));
  }

  // HKDF domain separation: derive AEAD and HMAC keys from the master via
  // independent HKDF-SHA3-512 expansions with distinct info strings.
  // This eliminates the related-key attack surface from adjacent-slice splitting:
  // aeadKey = HKDF-Expand(PRK=master, info="spd-aead-key-v1", L=32)
  // macKey  = HKDF-Expand(PRK=master, info="spd-mac-key-v1",  L=64)
  // where HKDF-Extract is skipped because the master already has full entropy
  // (Argon2id/scrypt output is indistinguishable from random).
  let aeadKey = sharedHkdfExpand(masterBytes, 'spd-aead-key-v1', AEAD_KEY_LEN);
  let macKey  = sharedHkdfExpand(masterBytes, 'spd-mac-key-v1',  macKeyLen);
  masterBytes.fill(0);

  // Apply machine binding if enabled
  if (keyMaterial.isMachineBindingEnabled()) {
    aeadKey = keyMaterial.applyMachineBinding(aeadKey);
    macKey  = keyMaterial.applyMachineBinding(macKey);
  }
  return { aeadKey, macKey };
}

export async function encryptSalt(
  salt: Uint8Array,
  passcode: string,
  memory = ARGON2_MEMORY_STANDARD,
  time   = ARGON2_TIME_STANDARD,
  parallelism = 1
): Promise<EncryptedSaltResult> {
  const wrapSalt = crypto.getRandomValues(new Uint8Array(ARGON2_SALT_LEN));
  const { pbk } = await derivePBK(passcode, wrapSalt, memory, time, ARGON2_HASH_LEN, parallelism);

  const wrapKey = new Uint8Array(pbk.buffer.slice(pbk.byteOffset, pbk.byteOffset + AEAD_KEY_LEN));
  pbk.fill(0);

  const nonce = crypto.randomBytes(24);
  const encrypted = plainAeadEncrypt(salt, null, nonce, wrapKey);

  (wrapKey).fill(0);

  return {
    encryptedSalt: Array.from(encrypted),
    saltNonce: Array.from(nonce),
    wrapSalt: Array.from(wrapSalt),
  };
}

export async function decryptSalt(
  encryptedSalt: number[],
  saltNonce: number[],
  wrapSalt: number[],
  passcode: string,
  memory: number = ARGON2_MEMORY_STANDARD,
  time: number = ARGON2_TIME_STANDARD,
  parallelism = 1
): Promise<Uint8Array> {
  const { pbk } = await derivePBK(passcode, new Uint8Array(wrapSalt), memory, time, ARGON2_HASH_LEN, parallelism);

  const wrapKey = new Uint8Array(pbk.buffer.slice(pbk.byteOffset, pbk.byteOffset + AEAD_KEY_LEN));
  pbk.fill(0);

  let decrypted: Uint8Array;
  try {
    decrypted = plainAeadDecrypt(new Uint8Array(encryptedSalt), null, new Uint8Array(saltNonce), wrapKey);
  } finally {
    (wrapKey).fill(0);
  }

  if (!decrypted) {
    throw new Error('Authentication failed.');
  }

  return decrypted;
}

/**
 * Single unlock path for every file reader: validates the file-supplied KDF
 * parameters (pre-authentication, so before any allocation they control),
 * consults the opt-in cache FIRST (a hit skips both Argon2id runs, the salt
 * unwrap included), otherwise unwraps the salt with the file's wrap params
 * and derives the AEAD/MAC keys. Returns caller-owned buffers.
 */
export async function unlockKeys(passcode: string, p: {
  encryptedSalt: number[]; saltNonce: number[]; wrapSalt: number[];
  wrapMemory: number; wrapTime: number; wrapParallelism: number;
  argon2Memory: number; argon2Time: number; argon2HashLen: number; macKeyLen: number;
  kdfChain: boolean; scryptN: number; scryptR: number; scryptP: number; argon2Parallelism: number;
}): Promise<{ aeadKey: Uint8Array; macKey: Uint8Array; salt: Uint8Array; fromCache: boolean }> {
  validateArgon2Params(p.wrapMemory, p.wrapTime, p.wrapParallelism);
  validateArgon2Params(p.argon2Memory, p.argon2Time, p.argon2Parallelism);
  if (p.kdfChain) validateScryptParams(p.scryptN, p.scryptR, p.scryptP);
  const cacheKey = buildCacheKey(
    passcode, p.wrapSalt, p.kdfChain, p.scryptN, p.scryptR, p.scryptP,
    `:${p.wrapMemory}:${p.wrapTime}:${p.wrapParallelism}:${p.argon2Memory}:${p.argon2Time}:${p.argon2Parallelism}:${p.argon2HashLen}:${p.macKeyLen}`
  );
  const hit = keyCacheGet(cacheKey);
  if (hit) return { ...hit, fromCache: true };
  const salt = await decryptSalt(p.encryptedSalt, p.saltNonce, p.wrapSalt, passcode, p.wrapMemory, p.wrapTime, p.wrapParallelism);
  const { aeadKey, macKey } = await deriveKeys(
    passcode, salt, p.argon2Memory, p.argon2Time, p.argon2HashLen, p.macKeyLen,
    p.kdfChain, p.scryptN, p.scryptR, p.scryptP, p.argon2Parallelism
  );
  keyCacheSet(cacheKey, new Uint8Array(aeadKey), new Uint8Array(macKey), new Uint8Array(salt));
  return { aeadKey, macKey, salt, fromCache: false };
}

export function keyCacheGet(cacheKey: string): { aeadKey: Uint8Array; macKey: Uint8Array; salt: Uint8Array } | undefined {
  const entry = keyCache.get(cacheKey);
  if (!entry) return undefined;
  if (Date.now() > entry.expiresAt) { keyCacheEvict(cacheKey); return undefined; }
  // Copies: callers zero their keys on destroy(), which must not corrupt the cache.
  return { aeadKey: new Uint8Array(entry.aeadKey), macKey: new Uint8Array(entry.macKey), salt: new Uint8Array(entry.salt) };
}

export function keyCacheEvict(cacheKey: string): void {
  const v = keyCache.get(cacheKey);
  if (v) { v.aeadKey.fill(0); v.macKey.fill(0); v.salt.fill(0); keyCache.delete(cacheKey); }
}

export function keyCacheSet(cacheKey: string, aeadKey: Uint8Array, macKey: Uint8Array, salt: Uint8Array): void {
  // TTL 0 means caching is disabled: never park key copies in this static
  // map (they would otherwise outlive destroy() until the next cache call).
  if (keyCacheTtlMsRef.value <= 0) {
    aeadKey.fill(0);
    macKey.fill(0);
    salt.fill(0);
    return;
  }
  const now = Date.now();
  for (const [k, v] of keyCache) { if (now > v.expiresAt) keyCacheEvict(k); }
  keyCache.set(cacheKey, { aeadKey, macKey, salt, expiresAt: now + keyCacheTtlMsRef.value });
}

/** Build a non-secret cache key from the passcode and wrapSalt bytes. */
export function buildCacheKey(passcode: string, wrapSalt: number[], kdfChain = false, scryptN = 0, scryptR = 0, scryptP = 0, extra = ''): string {
  // Caching disabled: don't materialize a fast-hash passcode verifier
  // (SHA-256 of passcode + public salt) as an unzeroable heap string.
  if (keyCacheTtlMsRef.value <= 0) return '';
  const kdfSuffix = (kdfChain ? `:kdf:${scryptN}:${scryptR}:${scryptP}` : '') + extra;
  return crypto.createHmac('sha3-256', keyCacheHmacKey)
    .update(passcode + kdfSuffix)
    .update(new Uint8Array(wrapSalt))
    .digest('hex');
}

/**
 * Opt-in unlock cache. Every file open (`loadFromFile`, `getEntry`, ...)
 * re-runs two Argon2id derivations (~0.5–1.5 s at the default profiles).
 * With a TTL set, derived keys for a given (passcode, file salt) are kept in
 * memory for `ms` milliseconds, so repeated reads of the same file are
 * ~1000× faster. Trade-off: live AEAD/MAC keys sit in process memory for
 * the TTL; keep it short (seconds to a few minutes) and never enable it
 * where a memory dump is in the threat model. `enableAntiForensic()` forces
 * it off. Default: 0 (disabled).
 */
export function setKeyCacheTtl(ms: number): void {
  if (!Number.isFinite(ms) || ms < 0) throw new Error('setKeyCacheTtl: ms must be a non-negative number');
  if (ms > 0 && antiForensic.count > 0) {
    throw new Error('setKeyCacheTtl: an anti-forensic instance is active; the key cache stays disabled until it is destroyed or disabled.');
  }
  keyCacheTtlMsRef.value = ms;
  if (ms === 0) clearKeyCache();
}

/** Evict all cached key material immediately (e.g. on pepper change). */
export function clearKeyCache(): void {
  for (const v of keyCache.values()) { v.aeadKey.fill(0); v.macKey.fill(0); v.salt.fill(0); }
  keyCache.clear();
}

/**
 * Compute a key commitment token: HMAC-SHA3-256(aeadKey, "spd-key-commit-v1").
 * Stored in the file meta and verified on load before decryption begins.
 * Closes key-commitment attacks where an adversary crafts a ciphertext that
 * "decrypts" under two different keys.
 */
export function computeKeyCommitment(aeadKey: Uint8Array): string {
  return crypto
    .createHmac('sha3-256', aeadKey)
    .update('spd-key-commit-v1')
    .digest('hex');
}

/** @internal Shared with SPDWriter so its meta carries the same signed write counter. */
export function computeCounterHMAC(macKey: Uint8Array, counter: number): string {
  const counterBuf = u8Alloc(8);
  writeBigUInt64BE(counterBuf, BigInt(counter));
  return crypto.createHmac('sha3-256', macKey)
    .update('counter-v1')
    .update(counterBuf)
    .digest('hex');
}

/**
 * Build a SHA3-256 Merkle tree over an array of leaf hashes (hex strings).
 * Returns the root hash as a hex string. Empty input returns the hash of "".
 */
export function buildMerkleRoot(leafHashes: string[]): string {
  if (leafHashes.length === 0) {
    return crypto.createHash('sha3-256').update('').digest('hex');
  }
  let level: string[] = leafHashes.slice();
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left  = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left; // duplicate last if odd
      next.push(
        crypto.createHash('sha3-256').update(left + right).digest('hex')
      );
    }
    level = next;
  }
  return level[0];
}

export function computeMAC(data: Uint8Array, key: Uint8Array, contentType: string): Uint8Array {
  return crypto
    .createHmac('sha3-512', key)
    .update(concatBytes(data, utf8ToBytes(contentType)))
    .digest();
}

/**
 * Install a global PKCS#11 / HSM key provider. When set, SPD delegates
 * all key derivation to `provider.deriveKey()` instead of Argon2id+scrypt.
 * Pass `undefined` to revert to the built-in KDF.
 */
export function setKeyProvider(provider: SPDKeyProvider | undefined): void {
  keyProvider.current = provider;
  clearKeyCache();
}

/**
 * Derives a per-entry 32-byte AEAD key from the master AEAD key using HKDF-SHA3-512.
 *
 * Each entry is encrypted under a unique key = HKDF(masterKey, salt=entryName, info="spd-entry-v27").
 * This means:
 *   - Compromise of one entry's ciphertext reveals nothing about other entries' keys
 *   - The master key never touches AEAD directly
 *   - Zero performance impact: HKDF is ~microseconds vs ~1s for Argon2id
 */
export function deriveEntryKey(masterAeadKey: Uint8Array, entryName: string): Uint8Array {
  return sharedDeriveEntryKey(masterAeadKey, entryName);
}

/**
 * Derive a dedicated 32-byte name-encryption key from the master AEAD key.
 * Domain-separated from entry data keys via a distinct info string.
 * Used to encrypt entry names in the binary index so the plaintext index
 * does not leak entry names to an attacker who has the file but not the passcode.
 */
export function deriveNameKey(masterAeadKey: Uint8Array): Uint8Array {
  const prk = crypto.createHmac('sha3-512', masterAeadKey)
    .update('spd-name-key-v1')
    .digest();
  const okm = crypto.createHmac('sha3-512', prk)
    .update(concatBytes(utf8ToBytes('expand'), new Uint8Array([0x01])))
    .digest();
  return new Uint8Array(okm.buffer, okm.byteOffset, AEAD_KEY_LEN);
}

/**
 * Encrypt an entry name.
 * Returns [24-byte nonce || XChaCha20-Poly1305+CMT ciphertext].
 */
export function _encryptEntryName(name: string, nameKey: Uint8Array): Uint8Array {
  const nonce = crypto.randomBytes(24);
  const ct    = aeadEncrypt(utf8ToBytes(name), null, nonce, nameKey);
  return concatBytes(nonce, ct);
}

/**
 * Decrypt an entry name.
 * Expects [24-byte nonce || ciphertext] as produced by _encryptEntryName.
 */
export function _decryptEntryName(encName: Uint8Array, nameKey: Uint8Array): string {
  const NONCE_LEN = 24; // XChaCha20-Poly1305 nonce length
  if (encName.length <= NONCE_LEN) throw new Error('Authentication failed.');
  const nonce = new Uint8Array(encName.subarray(0, NONCE_LEN));
  const ct    = encName.subarray(NONCE_LEN);
  const plain = aeadDecrypt(ct, null, nonce, nameKey);
  const name  = bytesToUtf8(plain);
  // Every entry name is run through sanitizeName() (charset [a-z0-9_-]
  // only) before _encryptEntryName() is ever called — so a legitimately-
  // written name always matches. A decrypted name that doesn't match was
  // never written by this library and must not be trusted with a
  // filesystem path (extractFromFileStreaming/extractDataStreaming build
  // temp-file paths directly from this return value).
  return assertSafeDecryptedName(name);
}

export function padForCompression(data: Uint8Array): Uint8Array {
  return sharedPadForCompression(data);
}

export function unpadAfterDecompression(data: Uint8Array): Uint8Array {
  return sharedUnpadAfterDecompression(data);
}

/**
 * CMT-4 encrypt: encrypt plaintext with XChaCha20-Poly1305, then prepend
 * H(key || nonce) so that the correct key is the *only* key that can produce
 * a valid commitment.  Closes the USENIX 2022 partitioning oracle attack.
 *
 * Stored layout: [ 32-byte cmt | xchacha20-poly1305 ciphertext ]
 */
export function aeadEncrypt(
  plaintext: Uint8Array,
  aad: Uint8Array | null,
  nonce: Uint8Array,
  key: Uint8Array
): Uint8Array {
  return sharedAeadEncrypt(plaintext, aad, nonce, key);
}

/**
 * CMT-4 decrypt: verify the prepended commitment block, then decrypt.
 * Throws on commitment mismatch or AEAD authentication failure.
 */
export function aeadDecrypt(
  ciphertextWithCmt: Uint8Array,
  aad: Uint8Array | null,
  nonce: Uint8Array,
  key: Uint8Array
): Uint8Array {
  return sharedAeadDecrypt(ciphertextWithCmt, aad, nonce, key);
}

/**
 * Encodes a raw keyless master secret into the sentinel-wrapped string
 * format every passcode-shaped parameter in this codebase already accepts
 * (SPDKeyProvider.deriveKey, changePasscode, upgradeKdfParams, ratchet,
 * epoch rotation, etc. all take a `passcode: string` — this lets a keyless
 * secret flow through every one of them completely unmodified).
 */
export function _encodeKeylessSecret(masterSecret: Uint8Array): string {
  if (masterSecret.length !== KEYLESS_MASTER_SECRET_LEN) {
    throw new Error(
      `Keyless master secret must be exactly ${KEYLESS_MASTER_SECRET_LEN} bytes (got ${masterSecret.length}). ` +
      'Generate one with generateRandomKey() — do not construct this manually.'
    );
  }
  return KEYLESS_SENTINEL + bytesToBase64(masterSecret);
}

/**
 * Detects and decodes a keyless-mode "passcode" string produced by
 * `_encodeKeylessSecret`. Returns null (not a keyless value — treat as an
 * ordinary passphrase) or the decoded 96-byte master secret.
 */
export function _decodeKeylessSecret(passcode: string): Uint8Array | null {
  if (!passcode.startsWith(KEYLESS_SENTINEL)) return null;
  try {
    const decoded = base64ToBytes(passcode.slice(KEYLESS_SENTINEL.length));
    if (decoded.length !== KEYLESS_MASTER_SECRET_LEN) return null;
    return decoded;
  } catch {
    return null; // malformed base64 — not actually a keyless value, fall through to normal Argon2id
  }
}

/**
 * Generates a fresh 96-byte (768-bit) CSPRNG master secret suitable for
 * `setRandomKey()` — true random bytes, no human input, no passphrase
 * entropy considerations. Store the result yourself (OS keychain, secrets
 * manager, HSM, or `SPD.generateKeyfileOnly()`'s keyfile format).
 */
export function generateRandomKey(): Uint8Array {
  return crypto.randomBytes(KEYLESS_MASTER_SECRET_LEN);
}
