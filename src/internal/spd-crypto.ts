/**
 * Shared crypto primitives for the SPD binary format.
 *
 * Single source of truth for the security-critical building blocks that were
 * previously duplicated (with drift risk) across SPD.ts, SPDWriter.ts,
 * spd-encrypt-worker.ts, and spd-inspect.ts. All four now import from here.
 *
 * Scope note: this module intentionally does NOT wrap @noble/post-quantum's
 * ML-KEM/ML-DSA — that dependency is pure-JS/WASM already, portable, and
 * load-bearing for the documented security model, retained as direct calls
 * at its existing call sites. XChaCha20-Poly1305 (see aeadEncrypt/aeadDecrypt
 * below) comes from @noble/ciphers via `portable-aead.ts`, verified against
 * RFC 8439 / draft-irtf-cfrg-xchacha-03's official test vectors AND 300
 * random (including unaligned-buffer) cross-checks against real libsodium
 * (byte-identical both directions), plus Poly1305 carry/reduction edge cases
 * against a literal RFC-formula oracle — see test/portable-aead-vectors.test.ts.
 *
 * NOTE: SPDHandshake.ts's `hkdf()` is a *different*, RFC 5869-correct
 * Extract+Expand function used for session/handshake key derivation — a
 * different purpose from the Expand-only `hkdfExpand` below (which expands
 * an already-high-entropy Argon2id/scrypt master secret). Do not merge them.
 */

import { argon2idAsync } from '@noble/hashes/argon2.js';
import { argon2id as argon2idWasm } from 'hash-wasm';
import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';
import { hmac } from '@noble/hashes/hmac.js';
import { xchacha20poly1305Encrypt, xchacha20poly1305Decrypt } from './portable-aead.js';
import { utf8ToBytes, concatBytes } from './portable-crypto.js';
import { u8Alloc, writeUInt32LE, readUInt32LE } from './portable-binary.js';

// Replaces Node's `crypto` module (createHash/createHmac/timingSafeEqual/
// randomBytes) with @noble/hashes — pure JS, no native bindings, works
// identically in Node and browsers. Verified byte-identical to Node's
// crypto.createHash('sha3-256'/'sha3-512') and crypto.createHmac output for
// the same inputs (including chained .update() calls) before this swap.
function sha3_256Concat(...parts: Uint8Array[]): Uint8Array {
  const h = sha3_256.create();
  for (const p of parts) h.update(p);
  return h.digest();
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function randomBytes(len: number): Uint8Array {
  const buf = new Uint8Array(len);
  globalThis.crypto.getRandomValues(buf);
  return buf;
}

// Native `argon2` (N-API addon) is loaded lazily and defensively: it's fast
// (native) but only installable/loadable where a matching prebuilt binary
// exists (Node, not browsers/edge/Deno Deploy/etc). Loaded once and cached;
// if it ever throws (missing binary, wrong platform, no build toolchain, or
// no `module` built-in at all), every subsequent call falls back to the
// pure-JS path below instead of retrying the failing load on every key
// derivation.
//
// Uses a dynamic `await import('module')` (not a static top-level import,
// and not a bare `require('argon2')`) for two reasons:
// 1. A static `import { createRequire } from 'module'` forces every bundler
//    — including ones targeting browsers, which don't have Node's `module`
//    built-in at all — to resolve it eagerly, breaking non-Node builds of
//    this codebase even though this path never actually runs there.
// 2. esbuild (tsup) rewrites EVERY bare `require` identifier in ESM bundle
//    output — including inside a `typeof require` check — into its own
//    `__require` shim, whose fallback (used when the real `require` global
//    genuinely doesn't exist, i.e. real ESM Node) unconditionally throws
//    "Dynamic require of ... is not supported" for any non-literal specifier.
//    That made a `typeof require` check always true and always wrong in the
//    ESM build, silently forcing the ~15-20x-slower pure-JS Argon2id fallback
//    on every call instead of loading the native addon (this exact bug shipped
//    once, caught via a ~160s vs ~20s timing regression).
type NativeArgon2Module = typeof import('argon2');
let _nativeArgon2: NativeArgon2Module | null | undefined; // undefined = not yet probed

async function loadNativeArgon2(): Promise<NativeArgon2Module | null> {
  if (_nativeArgon2 !== undefined) return _nativeArgon2;
  try {
    const { createRequire } = await import('module');
    _nativeArgon2 = createRequire(import.meta.url)('argon2') as NativeArgon2Module;
  } catch {
    _nativeArgon2 = null;
  }
  return _nativeArgon2;
}

// Node >= 24.7 ships a built-in `crypto.argon2` (OpenSSL-backed, runs on the
// libuv threadpool). Same speed as the `argon2` addon and byte-identical
// output, with no third-party native code or install scripts. Probed once via
// the same createRequire pattern as the addon (never resolves in browsers);
// absent on older Node or builds linked against OpenSSL < 3.2.
type NodeArgon2 = (
  algorithm: 'argon2id',
  params: { message: string | Uint8Array; nonce: Uint8Array; parallelism: number; tagLength: number; memory: number; passes: number },
  cb: (err: Error | null, derivedKey: Uint8Array) => void
) => void;
let _nodeArgon2: NodeArgon2 | null | undefined; // undefined = not yet probed

async function loadNodeArgon2(): Promise<NodeArgon2 | null> {
  if (_nodeArgon2 !== undefined) return _nodeArgon2;
  try {
    const { createRequire } = await import('module');
    const fn = (createRequire(import.meta.url)('node:crypto') as { argon2?: NodeArgon2 }).argon2;
    _nodeArgon2 = typeof fn === 'function' ? fn : null;
  } catch {
    _nodeArgon2 = null;
  }
  return _nodeArgon2;
}

/**
 * Argon2id via Node's built-in `crypto.argon2` (Node >= 24.7). Returns null
 * when unavailable. Exported separately so the golden-vector test can compare
 * it directly against the other tiers.
 */
export async function argon2idNodeBuiltin(
  password: string | Uint8Array,
  salt: Uint8Array,
  opts: Argon2idOpts
): Promise<Uint8Array | null> {
  const fn = await loadNodeArgon2();
  if (!fn) return null;
  return new Promise((resolve, reject) => {
    fn('argon2id', {
      message: password,
      nonce: salt,
      parallelism: opts.parallelism,
      tagLength: opts.hashLen,
      memory: opts.memory,
      passes: opts.time,
    }, (err, key) => (err ? reject(err) : resolve(key)));
  });
}

// ─── Constants shared by every call site ──────────────────────────────────

export const AEAD_KEY_LEN = 32;     // bytes -> XChaCha20-Poly1305 key
export const CMT_BLOCK_BYTES = 32;  // SHA3-256(key || nonce) commitment prefix
export const COMPRESS_PAD_BLOCK = 256;

// ─── Argon2id (pure JS via @noble/hashes) ─────────────────────────────────

export interface Argon2idOpts {
  memory: number;       // KiB
  time: number;         // iterations
  parallelism: number;
  hashLen: number;      // output length in bytes
}

/**
 * Pure-JS Argon2id via @noble/hashes. ~15-20x slower than the native addon
 * (measured: 128 MiB/6-iter "standard" profile took ~13-17s pure-JS vs
 * ~0.8s native) — used only as a portability fallback, never as the default
 * path in Node. Exported separately so the golden-vector test can compare
 * it directly against the native package's output.
 *
 * `version: 0x13` is passed explicitly (it's also @noble/hashes' default)
 * so the compatibility guarantee is visible in code, not incidental.
 */
export async function argon2idPureJs(
  password: string | Uint8Array,
  salt: Uint8Array,
  opts: Argon2idOpts
): Promise<Uint8Array> {
  return argon2idAsync(password, salt, {
    t: opts.time,
    m: opts.memory,
    p: opts.parallelism,
    dkLen: opts.hashLen,
    version: 0x13,
  });
}

/**
 * Argon2id via hash-wasm — hand-tuned WebAssembly, not pure JS. ~6x faster
 * than @noble/hashes' pure-JS path (measured: 128 MiB/6-iter "standard"
 * profile: ~840ms WASM vs ~5060ms pure-JS), with byte-identical output for
 * SPD's parameter shape (no `secret`/associated-data — hash-wasm's Argon2id
 * doesn't expose an `ad` param at all, unlike RFC 9106's optional one; SPD
 * never uses either, so this is a complete match, not a partial one) —
 * cross-checked directly against argon2idPureJs's output, not assumed from
 * hash-wasm's own claims. WASM modules are inlined as base64 (hash-wasm's
 * own design), so this needs no bundler configuration and works in the
 * browser build exactly like every other already-portable dependency here.
 */
export async function argon2idWasmTier(
  password: string | Uint8Array,
  salt: Uint8Array,
  opts: Argon2idOpts
): Promise<Uint8Array> {
  return argon2idWasm({
    password,
    salt,
    parallelism: opts.parallelism,
    iterations: opts.time,
    memorySize: opts.memory,
    hashLength: opts.hashLen,
    outputType: 'binary',
  });
}

/**
 * Argon2id key derivation — four-tier fallback:
 *   0. Node's built-in `crypto.argon2` (Node >= 24.7; native, no addon).
 *   1. Native `argon2` addon (older Node only — same speed as tier 0).
 *   2. hash-wasm's WASM Argon2id (~6x faster than pure JS; the default path
 *      everywhere the native addon can't load — browsers, Deno Deploy,
 *      Cloudflare Workers, restricted sandboxes).
 *   3. @noble/hashes' pure-JS Argon2id (final fallback — only reached if
 *      WASM itself can't instantiate, e.g. a CSP blocking `wasm-unsafe-eval`).
 * All tiers are byte-identical for the same inputs (RFC 9106 Argon2id is
 * deterministic given the same params) — verified in
 * test/argon2-golden-vector.test.ts — so callers never need to know which
 * path actually ran.
 */
/** Call counter for Argon2id runs — lets tests pin "exactly N KDF runs per operation" so regressions in unlock latency are caught. */
export const argon2Stats = { calls: 0 };

export async function argon2idRaw(
  password: string | Uint8Array,
  salt: Uint8Array,
  opts: Argon2idOpts
): Promise<Uint8Array> {
  argon2Stats.calls++;
  const builtin = await argon2idNodeBuiltin(password, salt, opts);
  if (builtin) return builtin;
  const native = await loadNativeArgon2();
  if (native) {
    // NOTE for anyone grepping this codebase for "no Buffer anywhere": these
    // are the only two intentional exceptions, and they're dead code in the
    // spd-lib/browser build. The real `argon2` package is a Node native
    // addon with a Buffer-typed API — this branch only ever runs after
    // loadNativeArgon2() succeeds, which requires the dynamic
    // `await import('module')` above to resolve, which never happens outside
    // Node (browsers have no `module` built-in) — so `Buffer` is guaranteed
    // to exist whenever this line actually executes, and this line never
    // executes in a browser bundle at all. The public return type stays
    // Uint8Array (Buffer *is* a Uint8Array subclass, so no copy is needed)
    // to keep this module's own API portable.
    const passwordBuf = typeof password === 'string' ? password : Buffer.from(password);
    return native.hash(passwordBuf, {
      salt: Buffer.from(salt),
      type: native.argon2id,
      raw: true,
      memoryCost: opts.memory,
      timeCost: opts.time,
      parallelism: opts.parallelism,
      hashLength: opts.hashLen,
    });
  }
  try {
    return await argon2idWasmTier(password, salt, opts);
  } catch {
    // WASM instantiation itself failed (e.g. a CSP without
    // 'wasm-unsafe-eval') — fall through to the pure-JS tier rather than
    // surface the failure, matching the native-tier's own silent-fallback
    // behavior above.
    return argon2idPureJs(password, salt, opts);
  }
}

// ─── HKDF-Expand (HMAC-SHA3-512), master-secret domain separation ─────────

/**
 * HKDF-Expand only (no Extract) — the master secret (Argon2id/scrypt output)
 * already has full entropy, so Extract is skipped, per RFC 5869 §3.3.
 */
export function hkdfExpand(prk: Uint8Array, info: string, len: number): Uint8Array {
  const infoBytes = utf8ToBytes(info);
  const out: Uint8Array[] = [];
  let prev: Uint8Array = new Uint8Array(0);
  let pos = 0;
  let ctr = 1;
  while (pos < len) {
    const h = hmac.create(sha3_512, prk);
    h.update(prev).update(infoBytes).update(Uint8Array.of(ctr++));
    const block = h.digest();
    out.push(block);
    prev = block;
    pos += block.length;
  }
  return concatBytes(...out).subarray(0, len);
}

// ─── CMT-4 AEAD (commitment-prepended XChaCha20-Poly1305) ─────────────────

/**
 * CMT-4 encrypt: encrypt with XChaCha20-Poly1305, then prepend
 * H(key || nonce) so the correct key is the only key that can produce a
 * valid commitment. Closes the USENIX 2022 partitioning oracle attack.
 *
 * Stored layout: [ 32-byte cmt | xchacha20-poly1305 ciphertext ]
 */
export function aeadEncrypt(
  plaintext: Uint8Array,
  aad: Uint8Array | null,
  nonce: Uint8Array,
  key: Uint8Array
): Uint8Array {
  const cmt = sha3_256Concat(key, nonce);
  const ct = xchacha20poly1305Encrypt(key, nonce, plaintext, aad ?? new Uint8Array(0));
  const out = new Uint8Array(CMT_BLOCK_BYTES + ct.length);
  out.set(cmt, 0);
  out.set(ct, CMT_BLOCK_BYTES);
  return out;
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
  if (ciphertextWithCmt.length < CMT_BLOCK_BYTES) {
    throw new Error('Authentication failed.');
  }
  const storedCmt = ciphertextWithCmt.subarray(0, CMT_BLOCK_BYTES);
  const ct = ciphertextWithCmt.subarray(CMT_BLOCK_BYTES);
  const expectedCmt = sha3_256Concat(key, nonce);
  if (!timingSafeEqual(storedCmt, expectedCmt)) {
    throw new Error('Authentication failed.');
  }
  try {
    return xchacha20poly1305Decrypt(key, nonce, ct, aad ?? new Uint8Array(0));
  } catch {
    throw new Error('Authentication failed.');
  }
}

// ─── Plain XChaCha20-Poly1305 (no CMT-4 prefix) ───────────────────────────

/**
 * Plain XChaCha20-Poly1305 encrypt/decrypt — no CMT-4 commitment prefix.
 * Used for: (1) reading/writing pre-v29 entries (v27/v28 files predate the
 * CMT-4 commitment scheme, so their on-disk format has no 32-byte cmt
 * block to check), and (2) salt wrapping (encryptSalt/decryptSalt), which
 * has never used CMT-4 — the salt isn't attacker-influenced ciphertext an
 * oracle attack would target the way entry data is.
 */
export function plainAeadEncrypt(
  plaintext: Uint8Array,
  aad: Uint8Array | null,
  nonce: Uint8Array,
  key: Uint8Array
): Uint8Array {
  return xchacha20poly1305Encrypt(key, nonce, plaintext, aad ?? new Uint8Array(0));
}

export function plainAeadDecrypt(
  ciphertext: Uint8Array,
  aad: Uint8Array | null,
  nonce: Uint8Array,
  key: Uint8Array
): Uint8Array {
  try {
    return xchacha20poly1305Decrypt(key, nonce, ciphertext, aad ?? new Uint8Array(0));
  } catch {
    throw new Error('Authentication failed.');
  }
}

// ─── Compression padding (CRIME/BREACH mitigation) ────────────────────────

/**
 * Pad `data` to a multiple of `COMPRESS_PAD_BLOCK` bytes before compression.
 * A 4-byte LE prefix records the original length so the receiver can strip
 * padding. Random pad bytes ensure the padding itself doesn't compress,
 * quantising ciphertext length regardless of plaintext content.
 */
export function padForCompression(data: Uint8Array): Uint8Array {
  const origLen = data.length;
  const lenBuf = u8Alloc(4);
  writeUInt32LE(lenBuf, origLen, 0);
  const combined = concatBytes(lenBuf, data);
  const rem = combined.length % COMPRESS_PAD_BLOCK;
  if (rem === 0) return combined;
  const pad = randomBytes(COMPRESS_PAD_BLOCK - rem);
  return concatBytes(combined, pad);
}

export function unpadAfterDecompression(data: Uint8Array): Uint8Array {
  if (data.length < 4) throw new Error('Authentication failed.');
  const origLen = readUInt32LE(data, 0);
  if (origLen > data.length - 4) throw new Error('Authentication failed.');
  return data.subarray(4, 4 + origLen);
}

// ─── Per-entry key derivation ──────────────────────────────────────────────

/**
 * Derives a per-entry 32-byte AEAD key from the master AEAD key via
 * HKDF-SHA3-512: PRK = HMAC-SHA3-512(salt=entryName, IKM=masterAeadKey),
 * OKM = HMAC-SHA3-512(PRK, info || 0x01)[0..32).
 */
export function deriveEntryKey(masterAeadKey: Uint8Array, entryName: string): Uint8Array {
  const prk = hmac(sha3_512, utf8ToBytes(entryName), masterAeadKey);

  const info = utf8ToBytes('spd-entry-v27');
  const okm = hmac(sha3_512, prk, concatBytes(info, new Uint8Array([0x01])));

  return okm.subarray(0, AEAD_KEY_LEN);
}

// ─── Passphrase strength estimation ────────────────────────────────────────

/**
 * Normalizes common leet-speak substitutions before pattern/phrase checks
 * (so "p4ssw0rd" is caught the same as "password").
 */
function normalizeLeet(s: string): string {
  return s
    .replace(/@/g, 'a').replace(/0/g, 'o').replace(/3/g, 'e')
    .replace(/1/g, 'i').replace(/5/g, 's').replace(/\$/g, 's')
    .replace(/!/g, 'i').replace(/4/g, 'a').replace(/7/g, 't');
}

/**
 * Compute a bigram-frequency penalty factor [0, 0.5].
 * Returns higher values for text heavy in common English bigrams.
 * A factor of 0.3 means the entropy estimate is reduced by 30%.
 */
function bigramPenalty(s: string): number {
  // 20 most common English bigrams by frequency
  const COMMON_BIGRAMS = new Set([
    'th', 'he', 'in', 'er', 'an', 're', 'on', 'at', 'en', 'nd',
    'ti', 'es', 'or', 'te', 'of', 'ed', 'is', 'it', 'al', 'ar',
  ]);
  if (s.length < 2) return 0;
  let hits = 0;
  for (let i = 0; i < s.length - 1; i++) {
    if (COMMON_BIGRAMS.has(s[i] + s[i + 1])) hits++;
  }
  const ratio = hits / (s.length - 1); // 0..1
  // Map to penalty: up to 0.5 (cap so we don't zero out entropy entirely)
  return Math.min(ratio * 1.5, 0.5);
}

/**
 * Estimates a passphrase's real (not just length-based) entropy and throws
 * a descriptive error if it falls below a safe floor — the same check used
 * by `SPD.checkPasscodeStrength()`, extracted here so every passcode-based
 * key-derivation entry point in this codebase can share one implementation
 * rather than some paths (e.g. SPDWriter, previously) silently skipping
 * validation entirely. Argon2id's cost already makes a properly-random
 * 60+ bit passphrase infeasible to brute-force (comfortably beyond OWASP's
 * own minimum Argon2id recommendation even at this library's lightest
 * profile) — the actual weak link in any password-based scheme is always
 * a guessable human-chosen passphrase, not the KDF, so this check is what
 * actually matters for "hardest to brute-force."
 *
 * Does NOT implement `SPD`'s keyfile-bypass escape hatch (a loaded keyfile
 * supplies 512 bits of true random entropy regardless of passphrase
 * quality) — that's SPD-specific instance state with no equivalent concept
 * in a keyfile-less caller like SPDWriter; `SPD.checkPasscodeStrength`
 * checks for that itself before delegating here.
 */
export function checkPassphraseStrength(passcode: string): boolean {
  if (typeof passcode !== 'string' || passcode.length < 12) {
    throw new Error('Passcode must be at least 12 characters long.');
  }

  // ── L33t-normalized form — used for pattern and phrase checks ────────────
  const normalized = normalizeLeet(passcode.toLowerCase());

  // ── Common-phrase deny list (checked on normalized form) ────────────────
  const COMMON_PHRASES = [
    'password', 'letmein', 'iloveyou', 'welcome',
    'monkey', 'dragon', 'sunshine', 'princess', 'superman',
    'trustno', 'qwerty', 'secret',
  ];
  for (const phrase of COMMON_PHRASES) {
    if (normalized.includes(phrase)) {
      throw new Error(
        `Passcode contains a common phrase ("${phrase}"). Use SPD.generatePassphrase() for a strong passphrase.`
      );
    }
  }

  // ── Real entropy estimation ────────────────────────────────────────────
  // Special case: space-separated word passphrases use word-count entropy
  // (avoids bigram penalty mis-firing on short random-wordlist passphrases).
  // Detect: 5+ tokens separated by single spaces, each token 2-8 lowercase letters.
  const passphraseWords = passcode.split(' ');
  const isWordPassphrase = passphraseWords.length >= 5 &&
    passphraseWords.every((w) => /^[a-z]{2,8}$/.test(w));

  let effectiveBits: number;
  let passphraseBitsThreshold = 60;
  if (isWordPassphrase) {
    // EFF short wordlist (256 words) = 8 bits/word. Conservative lower bound.
    // Accept 7+ words (≥56 bits) — Argon2id makes even 56-bit passphrases infeasible.
    effectiveBits = passphraseWords.length * 8;
    passphraseBitsThreshold = 55;
  } else {
    // Estimate Shannon entropy via character pool size, then apply a
    // diversity penalty so repeated/low-variety strings fail even when
    // they technically contain all character classes.
    let pool = 0;
    if (/[a-z]/.test(passcode)) pool += 26;
    if (/[A-Z]/.test(passcode)) pool += 26;
    if (/[0-9]/.test(passcode)) pool += 10;
    if (/[^A-Za-z0-9]/.test(passcode)) pool += 32;
    const rawBits = passcode.length * Math.log2(pool || 1);

    // Penalty: low character diversity reduces effective entropy
    const uniqueChars = new Set(passcode).size;
    const diversityRatio = uniqueChars / passcode.length; // 0..1
    const penalty = bigramPenalty(passcode.toLowerCase());
    effectiveBits = rawBits * diversityRatio * (1 - penalty);
  }

  // Block known-bad patterns regardless of computed entropy score (on normalized form)
  const WEAK_PATTERNS = [
    new RegExp('^(.+)\\1{2,}$'),        // gross repetition (abcabcabc)
    /^[a-zA-Z]+[0-9]{1,4}[^a-zA-Z0-9]?$/, // Word+digits (Password1!)
    /01234|12345|23456|34567|45678|56789|qwert|asdfg|zxcvb/i, // keyboard walks
  ];
  if (WEAK_PATTERNS.some((p) => p.test(normalized))) {
    throw new Error(
      'Passcode matches a common weak pattern. Use SPD.generatePassphrase() for a cryptographically strong passphrase.'
    );
  }

  // Require at least 60 bits of effective entropy (55 for word passphrases)
  if (effectiveBits < passphraseBitsThreshold) {
    throw new Error(
      `Passcode has insufficient entropy (~${Math.round(effectiveBits)} bits effective). ` +
      `Use SPD.generatePassphrase() to generate a strong passphrase.`
    );
  }

  return true;
}
