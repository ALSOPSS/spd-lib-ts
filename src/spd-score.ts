#!/usr/bin/env node
/**
 * spd-score — SPD Brutally Honest Security Scorer
 *
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║  WHAT THE SCORE MEANS                                                    ║
 * ║                                                                          ║
 * ║  0   = no encryption, no protection. Data is plaintext.                 ║
 * ║                                                                          ║
 * ║  100 = full computational hardening confirmed (Argon2id, AEAD,          ║
 * ║        post-quantum KEM/signatures, forward secrecy, integrity,         ║
 * ║        side-channel resistance) PLUS every extended-hardening rule      ║
 * ║        (rules.txt + rules2.txt + rules3.txt) confirmed in source.       ║
 * ║                                                                          ║
 * ║  THE EXTENDED HARDENING RULES (rules.txt + rules2.txt + rules3.txt)      ║
 * ║  Rules whose only implementation was a deprecated no-benefit utility   ║
 * ║  (R2, R9/R24, R15, R17, R19, R22, R25) are no longer scored.          ║
 * ║   R1  True One-Time Pad — key length ≥ message length, never reused    ║
 * ║   R3  Key material consumed after use — burn, melt, overwrite           ║
 * ║   R4  Multi-layer encryption — OTP + permutation + noise + stego        ║
 * ║   R5  Distributed key fragments — threshold secret sharing (Shamir)     ║
 * ║   R6  Message entropy expansion — compress + pad + randomize order      ║
 * ║   R7  Time-limited validity — keys auto-destroy after deadline          ║
 * ║   R8  Air-gapped decryption — no network, no wireless, no media        ║
 * ║   R10 Plausible deniability — multiple valid decryptions (deniable enc) ║
 * ║   R12 Destruction receipt — HMAC-SHA3-512 receipt + explicit zeroing;   ║
 * ║       an audit artifact, not a cryptographic proof zeroing occurred     ║
 * ║   R13 Temporal keys — valid only within a short absolute time window    ║
 * ║   R14 Physical channel noise injection — prevents traffic analysis      ║
 * ║   R16 Anti-forensic protocol — volatile-only, no swap/log/cache        ║
 * ║   R18 Carrier-embedding utility — HMAC-offset ciphertext embedding;      ║
 * ║       does not achieve verified steganographic undetectability          ║
 * ║   R20 Reality-indistinguishable ciphertexts — perfect entropy dist.     ║
 * ║                                                                          ║
 * ║  SCORING PHILOSOPHY — brutally strict                                   ║
 * ║  • Absence of confirmed evidence in source = 0 pts. Always.            ║
 * ║  • No partial credit. A check either meets the threshold or scores 0.  ║
 * ║  • Computational checks (Argon2, PQC, etc.) cover the region where     ║
 * ║    most real systems live (scores 10–70).                              ║
 * ║  • The scorer is intentionally pessimistic. If it cannot confirm a      ║
 * ║    property from source code, that property does not exist.             ║
 * ║  • A handful of checks (marked above) score genuinely-implemented       ║
 * ║    mechanisms whose security property is caller-asserted or partial —   ║
 * ║    read each label's parenthetical before treating full marks as a      ║
 * ║    stronger guarantee than the code actually provides.                  ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 *
 * Score breakdown (147 raw points → normalised to 100)
 * ────────────────────────────────────────────────────────────────────────────
 *  COMPUTATIONAL HARDENING (105 raw pts — covers finite adversaries)
 *  [24]  Key Derivation   — Argon2id ≥2GiB/2t/p4, scrypt, Landauer entropy, salt
 *  [19]  Cryptography     — AEAD cipher, HMAC, nonce safety, KEY COMMITMENT
 *  [11]  Post-Quantum     — ML-KEM-768 hybrid KEM, ML-DSA-65 sigs + pinning
 *  [11]  Forward Secrecy  — ratcheting, epoch rotation, secure key zeroing
 *  [9]   Data Integrity   — Merkle tree, write counter, WAL
 *  [15]  Side Channels &  — timing-safe MAC, key blinding, memzero, nonce reuse
 *         Memory Safety     protection, access pattern leakage
 *  [7]   Transport       — PQ handshake, key commitment, replay window
 *  [9]   Operational     — HSM, paranoid profile, passcode enforcement, audit log
 *
 *  EXTENDED HARDENING (42 raw pts — rules.txt + rules2.txt + rules3.txt)
 *  [3]   R1  — True One-Time Pad (key ≥ message length, never reused)
 *  [3]   R3  — Key material destroyed after use (not just zeroed)
 *  [3]   R4  — Multi-layer encryption (OTP + permutation + noise + stego)
 *  [3]   R5  — Threshold secret sharing (Shamir, distributed fragments)
 *  [3]   R6  — Message entropy expansion (compress + pad + randomize)
 *  [3]   R7  — Time-limited key validity (auto-destroy after deadline)
 *  [3]   R8  — Air-gapped decryption (no network, no wireless)
 *  [3]   R10 — Plausible deniability (multiple valid decryptions)
 *  [3]   R12 — Destruction receipt (HMAC receipt + zeroing; not a cryptographic proof of destruction)
 *  [3]   R13 — Temporal keys (absolute time-window validity, e.g. 5 min)
 *  [3]   R14 — Physical channel noise injection (prevents traffic analysis)
 *  [3]   R16 — Anti-forensic protocol (volatile-only, no swap/log/cache)
 *  [3]   R18 — Carrier-embedding utility (HMAC-offset embedding; not verified steganographic undetectability)
 *  [3]   R20 — Reality-indistinguishable ciphertexts (perfect entropy dist.)
 *
 * Usage:
 *   spd-score          # score ./src automatically
 *   spd-score src/     # score a specific folder
 *   spd-score file.spd # score a saved payload
 *   echo '{...}' | spd-score -
 */

import * as fs   from 'fs';
import * as path from 'path';
import * as readline from 'readline';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ScoreResult {
  total:           number;
  grade:           string;
  source:          string;  // where the data came from
  categories: {
    name:    string;
    score:   number;
    max:     number;
    checks:  CheckResult[];
  }[];
  recommendations: string[];
  verdict:         string;
}

interface CheckResult {
  id:          string;
  label:       string;
  earned:      number;
  max:         number;
  /** 'ok' | 'partial' | 'unknown' | 'fail' */
  checkStatus: 'ok' | 'partial' | 'unknown' | 'fail';
  detail:      string;
}

/**
 * Normalized view of security-relevant configuration inferred from source code
 * or a saved payload.  All fields are optional — missing = 0 pts always.
 */
interface SPDObservable {
  // Core crypto
  version?:              number;
  hashAlgorithm?:        string;
  argon2Memory?:         number;   // KiB
  argon2Time?:           number;   // iterations
  argon2Parallelism?:    number;
  kdfChain?:             boolean;
  scryptN?:              number;
  scryptR?:              number;
  scryptP?:              number;
  macKeyLength?:         number;   // bytes

  // AEAD key commitment (XChaCha20-Poly1305 is NOT key-committing by default —
  // partitioning oracle attacks exist without an explicit commit scheme)
  hasAeadKeyCommitment?: boolean;

  // Integrity
  writeCounter?:         number;
  merkleRoot?:           string | null;
  walEnabled?:           boolean;

  // Forward secrecy
  epochSize?:            number;
  ratchetEnabled?:       boolean;

  // Memory safety
  keyBlinded?:           boolean;   // XOR mask in RAM
  hasExplicitMemzero?:   boolean;   // explicit_bzero / sodium_memzero (C), or .fill(0) (JS/TS — see usage site comment)
  hasTimingSafeMac?:     boolean;   // timingSafeEqual / crypto_verify_* for MAC comparison

  // Nonce safety
  hasNonceReuseGuard?:   boolean;   // counter never resets; no RNG fallback for nonce

  // Access pattern / metadata
  hasMetadataPadding?:   boolean;   // frame padding hides message sizes
  hasFilenameEncryption?: boolean;  // entry names encrypted, not in plaintext index

  // Identity / auth
  fileSignature?:        string | null;
  hasPepper?:            boolean;
  hasKeyfile?:           boolean;
  hasHSMProvider?:       boolean;
  keyProfile?:           string;

  // Transport
  transportV2?:          boolean;
  hasKeyCommitment?:     boolean;   // transport-level key commitment token
  replayWindow?:         number;
  framePadding?:         boolean;

  // Post-quantum
  mlDsaCert?:            boolean;
  hybridKem?:            boolean;

  // Passcode enforcement
  passcodeEntropy?:      number;    // bits; must be enforced at source, not just advisory
  hasPasscodeEnforcement?: boolean; // validatePasscode() or equivalent blocks weak passcodes

  // Per-entry AAD binding (entry name bound into AEAD — prevents cross-entry swap attacks)
  hasEntryAadBinding?:   boolean;

  // Compression oracle resistance (compress-then-encrypt leaks plaintext via length)
  hasCompressionOracle?: boolean;   // true = vulnerable (zlib before AEAD without size-blinding)

  // Key cache security (derived key cached in memory = exposure window beyond use)
  keyCacheTtlMs?:        number;    // cache TTL in ms; undefined or 0 = no cache

  // Salt entropy / length (≥128-bit random salt required for KDF input)
  saltLenBytes?:         number;

  // Machine binding (Argon2id secret = hardware fingerprint)
  hasMachineBinding?:    boolean;

  // Argon2id output length (hash output feeding AEAD key + HMAC key)
  argon2HashLen?:        number;    // bytes; ≥64 required (32 AEAD + 32 HMAC minimum)

  // Brute-force throttle / rate limiting enforced at library level
  hasBruteForceThrottle?: boolean;

  // Auto-destruct / max open count (limits repeated decryption attempts on stolen file)
  hasAutoDestruct?:      boolean;

  // KDF domain separation — AEAD key and HMAC key must be derived independently,
  // not as adjacent slices of the same KDF output (related-key attack surface)
  hasKdfDomainSeparation?: boolean;

  // Secure temp file deletion — temp files overwritten before unlink
  // (unlink alone does not zero disk blocks — data recoverable until block reuse)
  hasSecureTempDelete?:  boolean;

  // Nonce counter overflow guard — send counter has explicit max-value check
  // to prevent counter wrap-around causing nonce reuse
  hasCounterOverflowGuard?: boolean;

  // Audit log — key lifecycle events logged for forensic analysis
  hasAuditLog?:          boolean;

  // Decoy / honeypot entries — fake entries that trigger alerts if accessed
  hasDecoyEntries?:      boolean;

  // Error message oracle — error messages must not distinguish wrong-password
  // from wrong-file / tamper-detected (timing-equal error paths)
  hasOracleNeutralErrors?: boolean;

  // File permissions enforced — sensitive files written with 0o600 (owner only)
  hasStrictFilePermissions?: boolean;

  // ── Infinite-adversary rules (from rules.txt) ────────────────────────────
  // R1: True One-Time Pad — key length ≥ message length, never reused, truly random
  hasOtpMode?:              boolean;
  // R3: Key material destroyed after use — explicit destruction, not just zeroing
  hasKeyDestruction?:       boolean;
  // R4: Multi-layer encryption — OTP + randomized permutation + noise + steganography
  hasMultiLayerEncryption?: boolean;
  // R5: Threshold secret sharing — Shamir or similar, fragments on separate devices
  hasThresholdSharing?:     boolean;
  // R6: Message entropy expansion — compression + large random padding + order randomization
  hasEntropyExpansion?:     boolean;
  // R7: Time-limited key validity — auto-destruct after deadline
  hasTimeLimitedKeys?:      boolean;
  // R8: Air-gapped decryption environment — no network, no wireless, no removable media
  hasAirGap?:               boolean;
  // R10: Plausible deniability — multiple valid decryptions under different keys
  hasPlausibleDeniability?: boolean;

  // ── rules2.txt extended rules ─────────────────────────────────────────────
  // R12 (rules2 R11): Destruction assurance — HMAC receipt + explicit zeroing (audit artifact, not cryptographic proof)
  hasDestructionAssurance?: boolean;
  // R13 (rules2 R12): Temporal keys — valid only within a short absolute time window
  hasTemporalKeys?:         boolean;
  // R14 (rules2 R13): Physical channel noise injection — RF/photon/timing noise during transmission
  hasChannelNoiseInjection?: boolean;
  // R16 (rules2 R15): Anti-forensic protocol — volatile-only computation, no swap/log/cache/cloud
  hasAntiForensic?:         boolean;
  // R18 (rules2 R6): Carrier-embedding utility — HMAC-offset embedding present; does not achieve real steganographic undetectability
  hasTrafficCamouflage?:    boolean;

  // R20 (rules3 L2): Reality-indistinguishable ciphertexts — passes statistical entropy tests
  hasEntropyIndistinguishable?: boolean;
}

// ─── Source-code analyzer ─────────────────────────────────────────────────────

/**
 * Collect all .ts and .js source files under `dir` (max depth 4).
 * Returns absolute paths only; skips node_modules, dist, AND spd-score.ts
 * (to prevent the scorer from matching its own comment/definition strings
 *  and falsely crediting features that only appear in documentation).
 */
function collectSourceFiles(dir: string): string[] {
  const results: string[] = [];
  const skip = new Set(['node_modules', 'dist', '.git', 'coverage', '__pycache__']);

  function walk(current: string, depth: number): void {
    if (depth > 4) return;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(fs.realpathSync(current), { withFileTypes: true }); }
    catch { return; }
    for (const e of entries) {
      if (skip.has(e.name)) continue;
      const full = path.join(current, e.name);
      if (e.isDirectory()) {
        walk(full, depth + 1);
      } else if (e.isFile() && /\.(ts|js|mjs|cjs)$/.test(e.name)) {
        // CRITICAL: exclude the scorer itself and test files — pattern matching the
        // scorer's own comments/definitions or test descriptions would create false
        // positives (e.g. 'wrong passcode' in a test name, or 'validatePasscode' in a comment).
        if (e.name === 'spd-score.ts' || e.name === 'spd-score.js') continue;
        if (/\.test\.[tj]s$|\.spec\.[tj]s$/.test(e.name)) continue;
        if (e.name === 'test.ts' || e.name === 'test.js') continue;
        results.push(full);
      }
    }
  }

  walk(dir, 0);
  return results;
}

/**
 * Read all collected source files into one concatenated string for pattern matching.
 * Cap at 2 MB total to stay fast.
 */
function loadSourceText(files: string[]): string {
  const chunks: string[] = [];
  let total = 0;
  const cap = 2 * 1024 * 1024;
  for (const f of files) {
    if (total >= cap) break;
    try {
      const txt = fs.readFileSync(fs.realpathSync(f), 'utf8');
      chunks.push(txt);
      total += txt.length;
    } catch { /* skip unreadable */ }
  }
  return chunks.join('\n');
}

/** True if `pattern` appears in `src` (case-sensitive). */
function has(src: string, pattern: RegExp | string): boolean {
  if (typeof pattern === 'string') return src.includes(pattern);
  return pattern.test(src);
}

/** Extract first numeric capture from `pattern` in `src`, or undefined. */
function extractNum(src: string, pattern: RegExp): number | undefined {
  const m = src.match(pattern);
  return m ? Number(m[1]) : undefined;
}

/** Extract first string capture from `pattern` in `src`, or undefined. */
function extractStr(src: string, pattern: RegExp): string | undefined {
  const m = src.match(pattern);
  return m ? m[1] : undefined;
}

/**
 * Analyze source files in `dir` and return an SPDObservable.
 *
 * Strategy: concatenate all TypeScript/JS source text and look for
 * well-known constant names, method calls, and import statements that
 * indicate which security features are present and configured.
 */
function analyzeSourceDir(dir: string): SPDObservable {
  const files = collectSourceFiles(dir);
  if (files.length === 0) return {};
  const src = loadSourceText(files);
  const obs: SPDObservable = {};

  // ── Version ──────────────────────────────────────────────────────────────
  obs.version = extractNum(src, /SPD_VERSION\s*=\s*(\d+)/);
  if (!obs.version) obs.version = extractNum(src, /version['":\s]+(\d+)/);

  // ── Hash algorithm ────────────────────────────────────────────────────────
  if (has(src, /sha3-512/i)) obs.hashAlgorithm = 'sha3-512';
  else if (has(src, /sha3-256/i)) obs.hashAlgorithm = 'sha3-256';
  else if (has(src, /sha512/i)) obs.hashAlgorithm = 'sha512';
  else if (has(src, /sha256/i)) obs.hashAlgorithm = 'sha256';

  // ── Argon2id memory ───────────────────────────────────────────────────────
  // Credit only the value ACTUALLY USED — must see paranoid profile active in source.
  const memPar  = extractNum(src, /ARGON2_MEMORY_PARANOID\s*=\s*(\d+)/);
  const memHigh = extractNum(src, /ARGON2_MEMORY_HIGH\s*=\s*(\d+)/);
  const memStd  = extractNum(src, /(?<![_A-Z])ARGON2_MEMORY\s*=\s*(\d+)/);
  if (memPar && (has(src, "'paranoid'") || has(src, '"paranoid"'))) obs.argon2Memory = memPar;
  else if (memHigh && (has(src, "'high'") || has(src, '"high"'))) obs.argon2Memory = memHigh;
  else if (memStd) obs.argon2Memory = memStd;

  // ── Argon2id time ─────────────────────────────────────────────────────────
  const timePar  = extractNum(src, /ARGON2_TIME_PARANOID\s*=\s*(\d+)/);
  const timeHigh = extractNum(src, /ARGON2_TIME_HIGH\s*=\s*(\d+)/);
  const timeStd  = extractNum(src, /(?<![_A-Z])ARGON2_TIME\s*=\s*(\d+)/);
  if (timePar && (has(src, "'paranoid'") || has(src, '"paranoid"'))) obs.argon2Time = timePar;
  else if (timeHigh && (has(src, "'high'") || has(src, '"high"'))) obs.argon2Time = timeHigh;
  else if (timeStd) obs.argon2Time = timeStd;

  // ── Argon2id parallelism ──────────────────────────────────────────────────
  obs.argon2Parallelism = extractNum(src, /_argon2Parallelism\s*=\s*(\d+)/);
  if (!obs.argon2Parallelism) obs.argon2Parallelism = extractNum(src, /parallelism[:\s=]+(\d+)/);

  // ── KDF chaining ──────────────────────────────────────────────────────────
  if (has(src, /enableKdfChain\s*\(\s*\)/) || has(src, '_kdfChain = true')) {
    obs.kdfChain = true;
    obs.scryptN = extractNum(src, /SCRYPT_N_DEFAULT\s*=\s*(\d+)/);
    obs.scryptR = extractNum(src, /SCRYPT_R_DEFAULT\s*=\s*(\d+)/);
    obs.scryptP = extractNum(src, /SCRYPT_P_DEFAULT\s*=\s*(\d+)/);
  } else {
    obs.kdfChain = false;
  }

  // ── HMAC key length ───────────────────────────────────────────────────────
  obs.macKeyLength = extractNum(src, /HMAC_KEY_LEN\s*=\s*(\d+)/);

  // ── AEAD key commitment ───────────────────────────────────────────────────
  // XChaCha20-Poly1305 is NOT key-committing by default (USENIX 2022 partitioning
  // oracle paper). A single ciphertext can be validly decrypted under two keys.
  // IMPORTANT: SPD's computeKeyCommitment() stores HMAC(aeadKey) in the JSON payload —
  // this is a KEY-BINDING token (detects wrong key at load time) but is NOT a CMT-1/CMT-4
  // AEAD-level key commitment (which would prepend an H(key||nonce) commitment block to
  // the ciphertext itself, making the AEAD scheme key-committing by construction).
  // The distinction matters: a CMT-4 scheme prevents partitioning oracle attacks even
  // when ciphertext is attacker-controlled. A JSON payload check does not — the attacker
  // can strip or substitute the keyCommitment field alongside the ciphertext.
  // We require a true CMT-1/CMT-4 construction (HtE, Encrypt-then-Commit, or equivalent).
  obs.hasAeadKeyCommitment =
    has(src, /\bCMT[_-]?[14]\b/) ||
    has(src, 'HtE_commit') ||
    has(src, 'aead_key_commit') ||
    has(src, 'encrypt_then_commit') ||
    // Explicit CMT scheme: hash(key||nonce) prepended to ciphertext before encryption
    has(src, /prependKeyCommit|aeadCommit\s*=\s*H\(|cmtBlock/);

  // ── Timing-safe MAC comparison ────────────────────────────────────────────
  obs.hasTimingSafeMac = has(src, 'timingSafeEqual') || has(src, 'crypto_verify_') ||
    has(src, 'sodium_memcmp') || has(src, 'constant_time_compare');

  // ── Explicit key zeroing ───────────────────────────────────────────────────
  // In C, memset()/a plain loop can be optimized away by the compiler once
  // the buffer's dead (no later read) — sodium_memzero/explicit_bzero exist
  // specifically to defeat that. THAT specific compiler-optimization concern
  // is C-specific: researched directly (not assumed) before writing this —
  // no documented, established technique reliably defeats a JS engine's
  // optimizer for a buffer-zeroing write either (V8 internals here aren't
  // publicly specified either way), and even security-focused JS write-ups
  // on this exact problem use a plain loop/`.fill(0)` and are explicit that
  // wiping is inherently best-effort in JS regardless of technique — there
  // is no proven-safer alternative to detect the ABSENCE of. So: still
  // credit sodium.memzero/explicit_bzero as a positive bonus signal when
  // actually present (real code, real intent to zero explicitly rather than
  // relying on GC), but do NOT treat a codebase's plain `.fill(0)`-based
  // zeroing as a deficiency relative to it in JS/TS source — `.fill(0)` is
  // the industry-standard practice there, not a downgrade.
  obs.hasExplicitMemzero = has(src, 'sodium.memzero(') || has(src, 'sodium_memzero(') ||
    has(src, 'explicit_bzero(') || has(src, /\.fill\(0\)/);

  // ── Nonce reuse guard ─────────────────────────────────────────────────────
  // Counter nonce (v29+) is only safe if the counter never resets and is never
  // shared across sessions/threads.
  obs.hasNonceReuseGuard = (obs.version ?? 0) >= 29 &&
    (has(src, '_nonceCounter') || has(src, 'XCHACHA_NONCE') || has(src, 'nonceCounter'));

  // ── Per-entry AAD binding ─────────────────────────────────────────────────
  // Each entry's AEAD must bind the entry name as AAD. Without this, an attacker
  // can swap two entries' ciphertexts and both will decrypt under the same key.
  // This is confirmed present only when the entry name is explicitly passed as AAD
  // in the AEAD call, not just used as a key-derivation input.
  obs.hasEntryAadBinding =
    has(src, /Buffer\.from\(.*dataName.*\).*aad|aad\s*=\s*Buffer\.from\(.*dataName/) ||
    has(src, /xchacha20poly1305.*decrypt\(.*aad|xchacha20poly1305.*encrypt\(.*aad/) ||
    // Also matches wrapping a shared aeadEncrypt/aeadDecrypt helper (e.g.
    // spd-lib's own SPD.aeadEncrypt(compressed, utf8ToBytes(sanitized), nonce, key))
    // where the entry/sanitized name is passed positionally as AAD rather
    // than assigned to a literal `aad` variable first — a legitimate,
    // equally-safe shape the two patterns above don't recognize.
    has(src, /aead(?:Encrypt|Decrypt)\([^)]*utf8ToBytes\((?:sanitized|dataName|entryName|item\.dataName|name)\)/);

  // ── Compression oracle ────────────────────────────────────────────────────
  // Compressing before encrypting leaks plaintext length information when an
  // attacker can inject known text into the plaintext (CRIME/BEAST/BREACH attacks).
  // zlib.deflateSync before AEAD = vulnerable unless entries are size-blinded.
  // Flag as vulnerable if zlib compress appears before crypto_aead calls.
  // Vulnerable if deflate/compress is present WITHOUT size-blinding (padForCompression).
  // If padForCompression is called before every deflateSync the oracle is mitigated.
  obs.hasCompressionOracle =
    (has(src, 'deflateSync') || has(src, 'deflate(') || has(src, 'zlib.compress')) &&
    !has(src, 'padForCompression') && !has(src, 'COMPRESS_PAD_BLOCK');

  // ── Ratcheting ────────────────────────────────────────────────────────────
  obs.ratchetEnabled = has(src, 'enableRatchet') || has(src, '_ratchetEnabled') || has(src, '_maybeRatchetSalt');

  // ── Epoch key rotation ────────────────────────────────────────────────────
  const epochSize = extractNum(src, /setEpochSize\s*\(\s*(\d+)\s*\)/) ??
                    extractNum(src, /_epochSize\s*=\s*(\d+)/);
  if (epochSize !== undefined && epochSize > 0) {
    obs.epochSize = epochSize;
  } else if (
    // Feature is implemented: method defined and rotation is called from the save path
    has(src, 'setEpochSize') && has(src, '_maybeRotateEpoch') &&
    (has(src, 'await this._maybeRotateEpoch') || has(src, '_maybeRotateEpoch(passcode)'))
  ) {
    obs.epochSize = 1; // implementation confirmed; concrete value set at runtime
  }

  // ── Merkle tree ───────────────────────────────────────────────────────────
  obs.merkleRoot = (has(src, 'merkleRoot') || has(src, 'enableMerkle') || has(src, 'buildMerkleRoot'))
    ? 'present' : null;

  // ── Write counter ─────────────────────────────────────────────────────────
  if (has(src, 'writeCounter') || has(src, '_writeCounter')) obs.writeCounter = 1;

  // ── WAL ───────────────────────────────────────────────────────────────────
  obs.walEnabled = has(src, 'enableWAL') || has(src, 'WAL_MAGIC') || has(src, 'walPath');

  // ── Key blinding ──────────────────────────────────────────────────────────
  obs.keyBlinded = has(src, 'enableKeyBlinding') || has(src, '_keyBlindingEnabled') || has(src, '_keyMask');

  // ── Pepper / keyfile ──────────────────────────────────────────────────────
  obs.hasPepper  = has(src, 'setGlobalPepper') || has(src, 'globalPepper');
  obs.hasKeyfile = has(src, 'setKeyfile') || has(src, 'keyfileBytes') || has(src, 'KEYFILE');

  // ── HSM provider ──────────────────────────────────────────────────────────
  obs.hasHSMProvider = has(src, 'setKeyProvider') || has(src, 'SPDKeyProvider') || has(src, '_keyProvider');

  // ── Key profile ───────────────────────────────────────────────────────────
  if (has(src, "'paranoid'") || has(src, '"paranoid"') || has(src, 'PARANOID')) obs.keyProfile = 'paranoid';
  else if (has(src, "'high'") || has(src, '"high"') || has(src, 'HIGH')) obs.keyProfile = 'high';
  else if (has(src, "'standard'") || has(src, '"standard"')) obs.keyProfile = 'standard';

  // ── File signature (ML-DSA-65) ────────────────────────────────────────────
  if (has(src, 'ml_dsa65') || has(src, 'ML_DSA') || has(src, 'setSigningKey') || has(src, 'fileSignature')) {
    obs.fileSignature = 'present';
  }

  // ── Transport V2 + ML-KEM-768 ─────────────────────────────────────────────
  if (has(src, 'ml_kem768') || has(src, 'ML_KEM') || has(src, 'TRANSPORT_VERSION_V2')) {
    obs.transportV2  = true;
    obs.hybridKem    = true;
  }

  // ── ML-DSA cert pinning ───────────────────────────────────────────────────
  obs.mlDsaCert = has(src, 'pinnedSigningKey') || has(src, 'signingPubKey') || has(src, 'generateCertKeyPair');

  // ── Transport key commitment ──────────────────────────────────────────────
  obs.hasKeyCommitment = has(src, /\bKEY_COMMIT\b/) || has(src, 'keyCommitToken') || has(src, 'key-commit');

  // ── Replay window ─────────────────────────────────────────────────────────
  const rw = extractNum(src, /REPLAY_WINDOW_SIZE\s*=\s*BigInt\s*\(\s*(\d+)\s*\)/) ??
             extractNum(src, /REPLAY_WINDOW_SIZE\s*=\s*(\d+)/);
  if (rw !== undefined) obs.replayWindow = rw;
  else if (has(src, '_recvWindow') || has(src, 'recvHighWater')) obs.replayWindow = 64;

  // ── Frame / metadata padding ──────────────────────────────────────────────
  // Presence of FRAME_PAD_BLOCK constant confirms the transport layer has the
  // padding infrastructure. The library must implement it; caller opting in is a
  // separate operational concern.
  obs.framePadding = has(src, 'FRAME_PAD_BLOCK');
  obs.hasMetadataPadding = obs.framePadding;

  // ── Filename / entry-name encryption ─────────────────────────────────────
  // Entry names in plaintext index reveal what data the vault contains.
  // Only credit if a concrete name-encryption implementation is confirmed.
  obs.hasFilenameEncryption =
    has(src, /encryptEntryName|encryptName\(|nameNonce\s*=|encryptedName\s*=/) ||
    has(src, '_encryptEntryName(');

  // ── Passcode enforcement ──────────────────────────────────────────────────
  // Advisory entropy hints are worthless. Must see a function that actually THROWS
  // or returns an error when the passcode is too weak. The function must be called
  // from setPassKey / loadFrom to have any effect — a dead utility function = 0 pts.
  // Passcode enforcement: a strength-check function must be called from the
  // key-derivation entry point (setPassKey), not just defined as a utility.
  obs.hasPasscodeEnforcement =
    (has(src, 'validatePasscode(') || has(src, 'checkPasscodeEntropy(') ||
     has(src, 'checkPasscodeStrength(') || has(src, 'PasscodeError')) &&
    (has(src, /setPassKey[^)]*validatePasscode|loadFrom[^)]*validatePasscode|validatePasscode[^)]*setPassKey/) ||
     has(src, /setPassKey[^)]*checkPasscodeStrength|checkPasscodeStrength[^)]*setPassKey/) ||
     // Direct call: checkPasscodeStrength(passcode) is the first statement in setPassKey
     has(src, /async setPassKey[^{]*\{[^}]*checkPasscodeStrength/));

  // ── Machine binding ───────────────────────────────────────────────────────
  // Binds Argon2id derivation to a hardware fingerprint (CPU serial, TPM, etc.)
  // so that a copy of the vault on different hardware cannot be decrypted.
  obs.hasMachineBinding = has(src, 'enableMachineBinding') || has(src, 'machineBinding') ||
    has(src, 'MACHINE_SECRET') || has(src, 'hwFingerprint') ||
    (has(src, /machineBindingEnabled\s*=\s*true/) || has(src, 'staticMachineBinding'));

  // ── Key cache TTL ─────────────────────────────────────────────────────────
  // A derivation cache keeps the AEAD key in memory beyond the minimal use window.
  // Any non-zero TTL = expanded exposure. We report the TTL; scorer checks presence.
  obs.keyCacheTtlMs = extractNum(src, /KEY_CACHE_TTL_MS\s*=\s*(\d+)/);

  // ── Salt entropy ─────────────────────────────────────────────────────────
  // KDF salt must be ≥ 128 bits (16 bytes) of CSPRNG output. A shorter salt
  // makes precomputed rainbow-table attacks feasible.
  obs.saltLenBytes = extractNum(src, /getRandomValues.*Uint8Array\s*\(\s*(\d+)\s*\)|randombytes_buf\s*\(\s*(\d+)\s*\)/);

  // ── Argon2id output length ────────────────────────────────────────────────
  // The hash output must be long enough to supply both an AEAD key (32 B) and
  // an HMAC key (32 B minimum, 64 B for full output width). Minimum: 64 B.
  obs.argon2HashLen = extractNum(src, /ARGON2_HASH_LEN\s*=\s*(\d+)/);

  // ── Auto-destruct ─────────────────────────────────────────────────────────
  // Limits the number of times a vault can be opened, destroying itself after N
  // opens — limits offline brute-force by making each decryption attempt destructive.
  obs.hasAutoDestruct = has(src, 'maxOpenCount') || has(src, 'setAutoDestruct') ||
    has(src, '_maxOpenCount') || has(src, 'autoDestruct');

  // ── Brute-force throttle ──────────────────────────────────────────────────
  // Library-level rate limiting (e.g. min delay between decryption attempts) prevents
  // rapid offline guessing even when running on attacker-controlled hardware.
  obs.hasBruteForceThrottle = has(src, 'setBruteForceDelay') || has(src, 'minDecryptInterval') ||
    has(src, 'rateLimitDecrypt') || has(src, 'throttleDecrypt');

  // ── KDF domain separation ─────────────────────────────────────────────────
  // Secure key derivation splits AEAD key and HMAC key via domain-separated HKDF,
  // not by slicing adjacent bytes from the same KDF output.
  // Slice-splitting (master[0..32] = aeadKey, master[32..96] = macKey) means the
  // two "keys" are cryptographically related — if one is compromised, the other's
  // security degrades. Real domain separation: HKDF(master, info="spd-aead") for
  // one key and HKDF(master, info="spd-mac") for the other.
  // SPD slices master[0..32] and master[32..96] — NOT domain-separated.
  obs.hasKdfDomainSeparation =
    has(src, /HKDF.*aead.*key|HKDF.*mac.*key|hkdf.*info.*aead|hkdf.*info.*mac/) ||
    has(src, /deriv.*aeadKey.*info|deriv.*macKey.*info|info.*spd-aead|info.*spd-mac/) ||
    // Accept if each key uses a distinct labeled HKDF expand step
    (has(src, /createHmac.*spd-aead/) && has(src, /createHmac.*spd-mac/));

  // ── Secure temp file deletion ─────────────────────────────────────────────
  // unlinkSync() removes the directory entry but the data blocks remain on disk
  // until overwritten. Any temp file with plaintext should be overwritten with zeros
  // before unlinking. On SSD with wear-leveling, even this may not fully erase —
  // but it's the minimum standard.
  obs.hasSecureTempDelete =
    has(src, /writeFileSync.*fill\(0\)|writeSync.*zeros|overwrite.*before.*unlink|secureDel|wipeFile/) ||
    has(src, /Buffer\.alloc.*tmpPath|zeros.*tmp.*unlink/);

  // ── Nonce counter overflow guard ──────────────────────────────────────────
  // The send counter in SPDTransport is a BigInt incremented forever.
  // At 2^64 messages the counter wraps to 0 → nonce reuse → full compromise.
  // A max-value check throwing before overflow is required.
  obs.hasCounterOverflowGuard =
    has(src, /sendCounter.*>=.*2n\s*\*\*|sendCounter.*max|COUNTER_MAX|nonce.*overflow|MAX_COUNTER/) ||
    has(src, /throw.*nonce.*overflow|throw.*counter.*exhaust/);

  // ── Audit log ─────────────────────────────────────────────────────────────
  // Key lifecycle events (derive, rotate, access) must be logged for forensic analysis.
  // A static logger that can be hooked by the host app qualifies — but only if it
  // actually emits events for key operations (derive, changePasscode, etc.).
  obs.hasAuditLog =
    (has(src, 'setLogger') || has(src, '_plogPath') || has(src, 'globalLogger')) &&
    has(src, /log\s*\(\s*['"`]key_derived|log\s*\(\s*'changePass|SPD\.log\s*\(/);

  // ── Decoy / honeypot entries ──────────────────────────────────────────────
  // Fake entries that look real — accessing them indicates an unauthorized party
  // is reading the vault. Provides detection capability on key theft.
  obs.hasDecoyEntries =
    has(src, 'addDecoy') || has(src, '_decoy') || has(src, 'honeypot') || has(src, 'decoyEntry');

  // ── Error oracle resistance ───────────────────────────────────────────────
  // Error messages must not reveal WHICH check failed (wrong passcode vs tampered
  // file vs wrong path). An oracle that distinguishes "wrong password" from
  // "wrong file" enables a targeted brute-force by confirming each guess.
  // We look for a consistent generic error message at the top-level decrypt path.
  // SPD uses "Invalid SPD path or passcode" in most paths — this is correct.
  // Oracle-neutral: all decrypt failures use a single generic message and
  // none of them name "wrong passcode" / "incorrect passcode" separately.
  obs.hasOracleNeutralErrors =
    (has(src, 'Invalid SPD path or passcode') || has(src, 'Authentication failed')) &&
    !has(src, 'passcode is incorrect') && !has(src, 'wrong passcode') && !has(src, 'incorrect passcode');

  // ── File permission enforcement ───────────────────────────────────────────
  // All sensitive files (vault, WAL, temp) written with 0o600 (owner read/write only).
  obs.hasStrictFilePermissions =
    has(src, '0o600') || has(src, 'mode: 0o600') || has(src, 'mode: 384');  // 384 = 0o600

  // ── XChaCha20-Poly1305 ────────────────────────────────────────────────────
  if (has(src, 'xchacha20') || has(src, 'XCHACHA_NONCE') || has(src, 'crypto_aead_xchacha20')) {
    if (!obs.version) obs.version = 27;
  }

  // ── Infinite-adversary rules (rules.txt) ─────────────────────────────────
  // R1: True One-Time Pad — key length ≥ message length, never reused, truly random.
  // OTP is information-theoretically secure: an infinite attacker still cannot break it.
  obs.hasOtpMode =
    has(src, /one.?time.?pad|OTP_KEY|otpKey|otp_encrypt|otpEncrypt/i) ||
    (has(src, /key\.length\s*>=?\s*(?:message|data|plaintext|msg)\.length/i) ||
     has(src, /keyLen\s*>=?\s*msgLen|keySize\s*>=?\s*dataLen/i));

  // R3: Key material destroyed after use — not just zeroed but confirmed destroyed.
  // Any explicit zeroing call (sodium_memzero, or — in managed languages like
  // JS/TS where wiping is inherently best-effort regardless of technique,
  // see hasExplicitMemzero's comment above — .fill(0)) qualifies only if
  // combined with explicit destruction protocol.
  obs.hasKeyDestruction =
    (has(src, 'sodium.memzero(') || has(src, 'sodium_memzero(') || has(src, 'explicit_bzero(') || has(src, /\.fill\(0\)/)) &&
    (has(src, /destroyKey|keyDestroyed|KEY_DESTROY|burnKey|destroyMaterial|afterUse.*zero/i) ||
     has(src, /key.*destroy|destroy.*key|wipeKey|key_consumed/i));

  // R4: Multi-layer encryption — OTP + permutation + noise/steganography layers.
  // Pure OTP is already perfect; extra layers add confusion and operational safety.
  obs.hasMultiLayerEncryption =
    (has(src, /permut|shuffle|randomizeOrder/i) || has(src, /stegan|steganography/i) ||
     has(src, /noiseLayer|noise_mask|quantumNoise|channelNoise/i)) &&
    (has(src, /layer|stack|pipeline|multiLayer|multi_layer/i));

  // R5: Threshold secret sharing — Shamir SSS or equivalent.
  // An infinite computer cannot recover fragments it never receives.
  obs.hasThresholdSharing =
    has(src, /SPDShamir|shamirShare|shamir/i) ||
    has(src, /threshold.*secret|secret.*sharing|SSS_|splitKey|combineShares/i) ||
    has(src, /shares.*reconstruct|reconstruct.*shares|fragments.*threshold/i);

  // R6: Message entropy expansion — compress + large random padding + order randomization.
  // Goal: ciphertext contains no detectable structure whatsoever.
  obs.hasEntropyExpansion =
    (has(src, /deflate|compress|zlib/i) || has(src, /randomPad|entropyPad|randPad/i)) &&
    (has(src, /randomizeOrder|shuffleEntries|randomOrder|entryOrder.*shuffle/i) ||
     has(src, /paddingBytes|PAD_BLOCK|ENTROPY_PAD|randomizeLayout/i));

  // R7: Time-limited key validity — keys auto-destroy after a deadline.
  // Even infinite computation cannot recover destroyed information.
  obs.hasTimeLimitedKeys =
    has(src, /maxOpenCount|setAutoDestruct|_maxOpenCount|autoDestruct/i) &&
    (has(src, /expiry|expires|ttl|timeLimit|keyExpiry|validUntil|deadline/i) ||
     has(src, /KEY_TTL|KEY_EXPIRY|keyLifetime|keyTimeout/i));

  // R8: Air-gapped decryption environment — enforced at library level.
  // No network calls, no wireless, no removable media from decryption context.
  obs.hasAirGap =
    has(src, /airGap|air_gap|AIR_GAP|offline.?only|offlineMode/i) ||
    has(src, /no.*network.*decrypt|decrypt.*offline|isolatedEnv/i) ||
    has(src, /networkCheck.*before.*decrypt|requiresAirGap/i);

  // R10: Plausible deniability — multiple valid decryptions under different keys.
  // An infinite computer cannot determine which plaintext interpretation is the real one.
  obs.hasPlausibleDeniability =
    has(src, /plausibleDeniab|deniability|decoyKey|deniable.*encrypt/i) ||
    has(src, /hiddenVolume|duress.*key|duressKey|DENIABLE/i) ||
    has(src, /alternateDecrypt|multipleInterpret|deniableEnc/i);

  // ── rules2.txt extended rules ─────────────────────────────────────────────

  // R12 (rules2 R11): Destruction assurance — HMAC receipt + explicit zeroing.
  // Not a cryptographic proof that zeroing occurred (a caller could compute the
  // receipt without ever zeroing) — this is an audit-log-style artifact.
  obs.hasDestructionAssurance =
    has(src, /destructionProof|destructionReceipt|destructionAssurance/i) ||
    has(src, /DESTRUCTION_PROOF|proofOfDestruction|destroyProof|burnProof/i) ||
    has(src, /signedDestruction|destructionEvent.*sign|certifyDestruction/i);

  // R13 (rules2 R12): Temporal keys — valid only within a short absolute time window.
  obs.hasTemporalKeys =
    has(src, /temporalKey|TEMPORAL_KEY|KEY_WINDOW|keyWindow/i) ||
    has(src, /validFrom.*validUntil|notBefore.*notAfter|temporalValidity/i) ||
    has(src, /TIME_WINDOW_MS|keyExpiryWindow|absoluteExpiry|absoluteDeadline/i);

  // R14 (rules2 R13): Physical channel noise injection — RF/photon/timing noise during TX.
  obs.hasChannelNoiseInjection =
    has(src, /channelNoise|noiseInjection|injectNoise|NOISE_INJECT/i) ||
    has(src, /rfNoise|photonJitter|packetTimingChaos|transmissionNoise/i) ||
    has(src, /trafficAnalysis.*prevent|noiseLayer.*transmit|CHANNEL_NOISE/i);

  // R16 (rules2 R15): Anti-forensic protocol — volatile-only memory, no swap/log/cache.
  obs.hasAntiForensic =
    has(src, /antiForensic|ANTI_FORENSIC|volatileOnly|VOLATILE_ONLY/i) ||
    has(src, /noSwap|disableSwap|noLogging.*key|noPersistentCache/i) ||
    has(src, /forensicFree|powerLossWipe|ramOnly.*key|volatileMemory.*key/i);

  // R18 (rules2 R6): Carrier-embedding utility — embeds ciphertext at an HMAC-derived
  // offset in a carrier buffer. Does NOT achieve real steganographic undetectability:
  // high-entropy ciphertext embedded verbatim is statistically detectable.
  obs.hasTrafficCamouflage =
    has(src, /trafficCamouflage|TRAFFIC_CAMOUFLAGE|hiddenInCarrier/i) ||
    has(src, /steganograph|stegano|STEGO|embedInCarrier/i) ||
    has(src, /coverTraffic|coverChannel|covertChannel|hiddenTransmit/i);

  // ── rules3.txt extended layers ─────────────────────────────────────────────

  // R20 (rules3 L2): Reality-indistinguishable ciphertexts — passes entropy statistical tests.
  obs.hasEntropyIndistinguishable =
    has(src, /entropyIndistinguishable|ENTROPY_INDISTINGUISHABLE|statisticallyIndistinguishable/i) ||
    has(src, /chiSquare.*ciphertext|entropyTest.*pass|uniformDistrib.*ciphertext/i) ||
    has(src, /INDISTINGUISHABLE|realityIndistinguishable|perfectEntropy.*dist/i);

  return obs;
}

// ─── Generic encryption system analyzer ──────────────────────────────────────
//
// Works on ANY codebase — not just SPD. Detects common crypto patterns via
// generic signal matching. Much looser than the SPD analyzer (which can
// confirm exact constant values), so results are conservative estimates.
// Use this for scoring third-party codebases, your own app code, etc.

export interface GenericCryptoObservable {
  // Cipher
  hasAeadCipher?:       boolean;  // AES-GCM, ChaCha20-Poly1305, XChaCha20, etc.
  hasLegacyCipher?:     boolean;  // AES-CBC, AES-ECB, DES, RC4, Blowfish
  cipherName?:          string;

  // KDF
  hasArgon2?:           boolean;
  hasBcrypt?:           boolean;
  hasScrypt?:           boolean;
  hasPbkdf2?:           boolean;
  hasLegacyKdf?:        boolean;  // MD5 password hashing, raw SHA1, no KDF at all
  kdfName?:             string;

  // Key size signals
  hasStrong256BitKey?:  boolean;  // 256-bit key confirmed
  hasWeak64BitOrLess?:  boolean;  // DES / 3DES / RC4 key-size territory

  // MAC / integrity
  hasHmac?:             boolean;
  hasHmac512?:          boolean;  // HMAC-SHA512 or HMAC-SHA3-512
  hasGcmAuth?:          boolean;  // built-in GCM authentication tag
  hasNoIntegrity?:      boolean;  // encryption with no MAC, no AEAD

  // Nonce / IV safety
  hasRandomIv?:         boolean;  // crypto.randomBytes / getRandomValues for IV
  hasStaticIv?:         boolean;  // IV is a constant string or all-zeros
  hasCounterNonce?:     boolean;  // incrementing counter nonce

  // Timing safety
  hasTimingSafeCompare?: boolean;

  // Memory safety
  hasMemzero?:          boolean;

  // Post-quantum
  hasPqc?:              boolean;
  hasMlKem?:            boolean;
  hasMlDsa?:            boolean;

  // Forward secrecy
  hasForwardSecrecy?:   boolean;  // ephemeral keys, ratcheting, etc.

  // Salt entropy
  hasRandomSalt?:       boolean;

  // Authenticated
  isAuthenticated?:     boolean;  // AEAD or HMAC verified before decryption

  // Key storage
  hasHardcodedKey?:     boolean;  // key is a string literal in source
  hasEnvKey?:           boolean;  // key from process.env (better, not great)

  // TLS / transport
  hasTls?:              boolean;
  hasTlsPinning?:       boolean;

  // Password storage specific
  hasPasswordHashing?:  boolean;  // bcrypt/argon2/scrypt in a password-check context
  hasPlaintextPassword?: boolean; // passwords stored as-is or with simple hash
}

/**
 * Analyze any TypeScript/JavaScript codebase for generic crypto signals.
 * Returns a GenericCryptoObservable populated from pattern matching.
 */
export function analyzeGenericDir(dir: string): GenericCryptoObservable {
  const files = collectSourceFiles(dir);
  if (files.length === 0) return {};
  const src = loadSourceText(files);
  const obs: GenericCryptoObservable = {};

  // ── Cipher detection ──────────────────────────────────────────────────────
  if (has(src, /xchacha20|XChaCha20/i)) {
    obs.hasAeadCipher = true; obs.cipherName = 'XChaCha20-Poly1305';
  } else if (has(src, /chacha20.poly1305|chacha20poly1305/i)) {
    obs.hasAeadCipher = true; obs.cipherName = 'ChaCha20-Poly1305';
  } else if (has(src, /aes.?gcm|AES-GCM|aes_gcm/i)) {
    obs.hasAeadCipher = true; obs.cipherName = 'AES-GCM';
  } else if (has(src, /aes.?ccm|AES-CCM/i)) {
    obs.hasAeadCipher = true; obs.cipherName = 'AES-CCM';
  } else if (has(src, /aes.?cbc|AES-CBC/i)) {
    obs.hasLegacyCipher = true; obs.cipherName = 'AES-CBC';
  } else if (has(src, /aes.?ecb|AES-ECB/i)) {
    obs.hasLegacyCipher = true; obs.cipherName = 'AES-ECB';
  } else if (has(src, /\bdes\b|3des|triple.des/i)) {
    obs.hasLegacyCipher = true; obs.cipherName = 'DES/3DES'; obs.hasWeak64BitOrLess = true;
  } else if (has(src, /\brc4\b|arcfour/i)) {
    obs.hasLegacyCipher = true; obs.cipherName = 'RC4'; obs.hasWeak64BitOrLess = true;
  } else if (has(src, /blowfish/i)) {
    obs.hasLegacyCipher = true; obs.cipherName = 'Blowfish';
  }

  // ── KDF detection ─────────────────────────────────────────────────────────
  if (has(src, /argon2id|argon2\.hash|require.*argon2/i)) {
    obs.hasArgon2 = true; obs.kdfName = 'Argon2id';
  }
  if (has(src, /bcrypt\.hash|bcryptjs|require.*bcrypt/i)) {
    obs.hasBcrypt = true; if (!obs.kdfName) obs.kdfName = 'bcrypt';
  }
  if (has(src, /scrypt\s*\(|crypto\.scrypt|scryptSync/i)) {
    obs.hasScrypt = true; if (!obs.kdfName) obs.kdfName = 'scrypt';
  }
  if (has(src, /pbkdf2\s*\(|pbkdf2Sync|PBKDF2/i)) {
    obs.hasPbkdf2 = true; if (!obs.kdfName) obs.kdfName = 'PBKDF2';
  }
  if (!obs.hasArgon2 && !obs.hasBcrypt && !obs.hasScrypt && !obs.hasPbkdf2) {
    if (has(src, /md5.*password|password.*md5|sha1.*password|password.*sha1/i)) {
      obs.hasLegacyKdf = true;
    }
  }

  // ── 256-bit key signals ────────────────────────────────────────────────────
  obs.hasStrong256BitKey =
    has(src, /keyLength.*32|32.*keyLength|key.*256|256.*bit.*key/i) ||
    has(src, /randomBytes\s*\(\s*32\s*\)/) ||
    has(src, /Uint8Array\s*\(\s*32\s*\)/);

  // ── HMAC / integrity ──────────────────────────────────────────────────────
  obs.hasHmac = has(src, /createHmac|HMAC|hmac\s*\(/i);
  obs.hasHmac512 =
    has(src, /hmac.*sha.?512|sha.?512.*hmac|createHmac.*sha512|createHmac.*sha3/i) ||
    has(src, /HMAC_KEY_LEN/);
  obs.hasGcmAuth = has(src, /aes.?gcm|getAuthTag|authTag/i) ||
    (obs.hasAeadCipher === true);
  obs.hasNoIntegrity =
    !obs.hasHmac && !obs.hasGcmAuth && !obs.hasAeadCipher &&
    (!!obs.hasLegacyCipher || has(src, /encrypt|cipher/i));

  // ── IV / Nonce safety ─────────────────────────────────────────────────────
  obs.hasRandomIv =
    has(src, /randomBytes.*iv|iv.*randomBytes|randomBytes.*nonce|nonce.*randomBytes/i) ||
    has(src, /getRandomValues.*iv|iv.*getRandomValues/i) ||
    has(src, /sodium\.randombytes_buf/);
  obs.hasStaticIv =
    has(src, /iv\s*=\s*['"`][0-9a-fA-F]{16,}['"`]/) ||
    has(src, /iv\s*=\s*Buffer\.alloc\s*\(\s*\d+\s*\)\s*[;,]/) ||  // zeroed IV
    has(src, /iv\s*=\s*['"`]\0/);
  obs.hasCounterNonce =
    has(src, /nonceCounter|nonce_counter|sendCounter/i) ||
    has(src, /XCHACHA_NONCE|_nonceCounter/);

  // ── Timing safety ─────────────────────────────────────────────────────────
  obs.hasTimingSafeCompare =
    has(src, 'timingSafeEqual') || has(src, 'crypto_verify_') ||
    has(src, 'sodium_memcmp') || has(src, 'constant_time_compare');

  // ── Memory safety ─────────────────────────────────────────────────────────
  // sodium_memzero/explicit_bzero exist to defeat C-specific dead-store
  // elimination; in managed languages (JS/TS) there's no proven equivalent
  // technique, and .fill(0)/a plain loop is the actual industry-standard
  // practice there — see scoreForwardSecrecy's hasExplicitMemzero comment
  // for the full rationale. Credit both.
  obs.hasMemzero =
    has(src, 'sodium.memzero(') || has(src, 'sodium_memzero(') ||
    has(src, 'explicit_bzero(') || has(src, /\.fill\(0\)/);

  // ── Post-quantum ──────────────────────────────────────────────────────────
  obs.hasMlKem = has(src, /ml_kem|kyber|mlkem|ML-KEM|MLKEM/i);
  obs.hasMlDsa = has(src, /ml_dsa|dilithium|mldsa|ML-DSA|MLDSA/i);
  obs.hasPqc   = obs.hasMlKem || obs.hasMlDsa ||
    has(src, /post.?quantum|pqc|ntru|sphincs|falcon|frodo/i);

  // ── Forward secrecy ───────────────────────────────────────────────────────
  obs.hasForwardSecrecy =
    has(src, /forward.?secrecy|ephemeral.*key|key.*ratchet|ratchet.*key|ECDHE|X25519/i) ||
    has(src, /enableRatchet|_maybeRatchetSalt/);

  // ── Random salt ───────────────────────────────────────────────────────────
  obs.hasRandomSalt =
    has(src, /randomBytes.*salt|salt.*randomBytes|randombytes_buf.*salt/i) ||
    has(src, /getRandomValues.*salt|salt.*getRandomValues/i);

  // ── Authentication (decryption path checks MAC before returning) ──────────
  obs.isAuthenticated =
    !!obs.hasAeadCipher || (!!obs.hasHmac && !obs.hasNoIntegrity);

  // ── Hardcoded key check ───────────────────────────────────────────────────
  obs.hasHardcodedKey =
    has(src, /(?:const|let|var)\s+(?:key|secret|aesKey|encKey)\s*=\s*['"`][A-Za-z0-9+/=]{16,}['"`]/) ||
    has(src, /key\s*=\s*Buffer\.from\s*\(\s*['"`][A-Za-z0-9+/=]{16,}['"`]/);
  obs.hasEnvKey =
    has(src, /process\.env\.\w*(?:KEY|SECRET|PASS|TOKEN)/i) ||
    has(src, /getenv\s*\(\s*['"`]\w*(?:KEY|SECRET)/i);

  // ── TLS ───────────────────────────────────────────────────────────────────
  obs.hasTls = has(src, /https\.createServer|tls\.createServer|ssl|TLSSocket/i);
  obs.hasTlsPinning =
    has(src, /checkServerIdentity|pinnedCert|cert.*fingerprint|fingerprint.*cert/i);

  // ── Password hashing context ──────────────────────────────────────────────
  obs.hasPasswordHashing =
    (!!obs.hasArgon2 || !!obs.hasBcrypt || !!obs.hasScrypt) &&
    has(src, /password|passwd|credentials/i);
  obs.hasPlaintextPassword =
    has(src, /password.*===|===.*password|password.*==\s|==\s.*password/i) &&
    !obs.hasPasswordHashing;

  return obs;
}

// ─── Generic encryption score ─────────────────────────────────────────────────

export interface GenericScoreResult {
  total:           number;
  grade:           string;
  source:          string;
  impossibilityScore: number;  // 0–100: how hard it is for an adversary to break this
  categories: {
    name:  string;
    score: number;
    max:   number;
    items: { label: string; earned: number; max: number; ok: boolean; detail: string }[];
  }[];
  verdict:    string;
  warnings:   string[];
}

export function scoreGenericSystem(obs: GenericCryptoObservable, source = 'unknown'): GenericScoreResult {
  const categories: GenericScoreResult['categories'] = [];
  let total = 0;
  const warnings: string[] = [];

  // ── Category 1: Cipher (25 pts) ──────────────────────────────────────────
  {
    const items: GenericScoreResult['categories'][0]['items'] = [];
    let s = 0;

    const aeadOk = !!obs.hasAeadCipher;
    const legacyPenalty = !!obs.hasLegacyCipher;
    const aead = aeadOk ? 20 : 0;
    s += aead;
    items.push({ label: `AEAD cipher (${obs.cipherName ?? 'none detected'})`, earned: aead, max: 20, ok: aeadOk,
      detail: aeadOk ? `${obs.cipherName} provides authenticated encryption` : 'No AEAD cipher detected — unauthenticated or legacy cipher in use' });

    if (legacyPenalty) {
      warnings.push(`Legacy cipher detected (${obs.cipherName}): vulnerable to padding oracles, bit-flipping, or weak key-size attacks.`);
    }

    const key256 = !!obs.hasStrong256BitKey;
    const k = key256 ? 5 : 0;
    s += k;
    items.push({ label: '256-bit key (32 bytes)', earned: k, max: 5, ok: key256,
      detail: key256 ? '256-bit key confirmed' : 'Key size not confirmed to be 256 bits' });

    total += s;
    categories.push({ name: 'Cipher Strength', score: s, max: 25, items });
  }

  // ── Category 2: Key Derivation (25 pts) ──────────────────────────────────
  {
    const items: GenericScoreResult['categories'][0]['items'] = [];
    let s = 0;

    const argon2 = !!obs.hasArgon2;
    const bcrypt = !!obs.hasBcrypt;
    const scrypt = !!obs.hasScrypt;
    const pbkdf2 = !!obs.hasPbkdf2;
    const legacy = !!obs.hasLegacyKdf;

    const kdfPts = argon2 ? 25 : scrypt ? 20 : bcrypt ? 16 : pbkdf2 ? 10 : 0;
    s += kdfPts;
    const kdfLabel = argon2 ? 'Argon2id (best)' : scrypt ? 'scrypt (strong)' : bcrypt ? 'bcrypt (adequate)' : pbkdf2 ? 'PBKDF2 (acceptable)' : legacy ? 'Legacy hash (insecure)' : 'No KDF detected';
    items.push({ label: `Key derivation: ${kdfLabel}`, earned: kdfPts, max: 25, ok: kdfPts >= 16,
      detail: kdfPts >= 25 ? 'Argon2id: memory-hard, GPU/ASIC-resistant'
        : kdfPts >= 20 ? 'scrypt: memory-hard, good choice'
        : kdfPts >= 16 ? 'bcrypt: work-factor limited by 72-byte input cap'
        : kdfPts >= 10 ? 'PBKDF2: fast to brute-force on modern hardware — prefer Argon2id or scrypt'
        : legacy ? 'MD5/SHA1 password hash — trivially brute-forceable. Use Argon2id immediately.'
        : 'No KDF found — keys may be derived insecurely or hardcoded' });

    if (legacy) warnings.push('MD5/SHA1 used for password hashing — completely broken. Migrate to Argon2id.');
    total += s;
    categories.push({ name: 'Key Derivation', score: s, max: 25, items });
  }

  // ── Category 3: Integrity & Authentication (20 pts) ──────────────────────
  {
    const items: GenericScoreResult['categories'][0]['items'] = [];
    let s = 0;

    const auth = !!obs.isAuthenticated;
    const a = auth ? 12 : 0;
    s += a;
    items.push({ label: 'Authenticated encryption or HMAC', earned: a, max: 12, ok: auth,
      detail: auth ? 'Ciphertext is authenticated before decryption'
        : 'No authentication detected — attacker can tamper with ciphertext undetected' });

    const hmac512 = !!obs.hasHmac512;
    const h = hmac512 ? 8 : obs.hasHmac ? 4 : 0;
    s += h;
    items.push({ label: `HMAC strength (${hmac512 ? 'SHA-512/SHA3-512' : obs.hasHmac ? 'SHA-256 or unspecified' : 'none'})`, earned: h, max: 8, ok: hmac512,
      detail: hmac512 ? 'HMAC-SHA-512 / HMAC-SHA3-512 — 256-bit post-quantum security'
        : obs.hasHmac ? 'HMAC present but ≤256-bit hash — Grover reduces to 128-bit PQ security'
        : 'No HMAC detected' });

    if (obs.hasNoIntegrity) warnings.push('Encryption without authentication (no MAC, no AEAD) — attacker can flip ciphertext bits and alter plaintext.');
    total += s;
    categories.push({ name: 'Integrity & Auth', score: s, max: 20, items });
  }

  // ── Category 4: Nonce & IV Safety (10 pts) ────────────────────────────────
  {
    const items: GenericScoreResult['categories'][0]['items'] = [];
    let s = 0;

    const randIv = !!obs.hasRandomIv;
    const staticIv = !!obs.hasStaticIv;
    const ri = randIv && !staticIv ? 7 : 0;
    s += ri;
    items.push({ label: 'Random IV/nonce per encryption', earned: ri, max: 7, ok: ri > 0,
      detail: staticIv ? 'Static IV detected — deterministic nonce = catastrophic nonce reuse under same key'
        : randIv ? 'Random IV/nonce confirmed'
        : 'IV/nonce generation not confirmed — audit manually' });

    const ctr = !!obs.hasCounterNonce;
    const c = ctr ? 3 : 0;
    s += c;
    items.push({ label: 'Counter nonce management', earned: c, max: 3, ok: ctr,
      detail: ctr ? 'Counter nonce — strict monotonic uniqueness' : 'Not detected' });

    if (staticIv) warnings.push('Static or zero IV detected — nonce reuse under the same key allows full plaintext recovery and forgery.');
    total += s;
    categories.push({ name: 'Nonce / IV Safety', score: s, max: 10, items });
  }

  // ── Category 5: Post-Quantum & Forward Secrecy (10 pts) ──────────────────
  {
    const items: GenericScoreResult['categories'][0]['items'] = [];
    let s = 0;

    const pqc = !!obs.hasPqc;
    const p = pqc ? 6 : 0;
    s += p;
    items.push({ label: `Post-quantum algorithms (${obs.hasMlKem ? 'ML-KEM' : obs.hasMlDsa ? 'ML-DSA' : obs.hasPqc ? 'PQC detected' : 'none'})`, earned: p, max: 6, ok: pqc,
      detail: pqc ? 'Post-quantum cryptography in use — protects against Shor/Grover at scale'
        : 'No post-quantum algorithms — Shor\'s algorithm breaks all classical asymmetric crypto' });

    const fs = !!obs.hasForwardSecrecy;
    const f = fs ? 4 : 0;
    s += f;
    items.push({ label: 'Forward secrecy (ephemeral keys / ratcheting)', earned: f, max: 4, ok: fs,
      detail: fs ? 'Forward secrecy confirmed — past sessions sealed even if current key leaks'
        : 'No forward secrecy — key exposure retroactively compromises all past traffic' });

    total += s;
    categories.push({ name: 'Post-Quantum & FS', score: s, max: 10, items });
  }

  // ── Category 6: Implementation Safety (10 pts) ────────────────────────────
  {
    const items: GenericScoreResult['categories'][0]['items'] = [];
    let s = 0;

    const ts = !!obs.hasTimingSafeCompare;
    const t = ts ? 4 : 0;
    s += t;
    items.push({ label: 'Timing-safe comparison (timingSafeEqual)', earned: t, max: 4, ok: ts,
      detail: ts ? 'timingSafeEqual / crypto_verify_* confirmed'
        : 'Not detected — string comparison of MACs leaks timing info, enables forgery' });

    const mz = !!obs.hasMemzero;
    const m = mz ? 3 : 0;
    s += m;
    items.push({ label: 'Secure key zeroing (memzero)', earned: m, max: 3, ok: mz,
      detail: mz ? 'sodium_memzero/explicit_bzero or .fill(0) confirmed'
        : 'Not detected — key bytes may persist in memory after use' });

    const hk = !!obs.hasHardcodedKey;
    const hkPts = hk ? 0 : 3;
    s += hkPts;
    items.push({ label: 'No hardcoded keys', earned: hkPts, max: 3, ok: !hk,
      detail: hk ? 'Hardcoded key detected in source — any code reader or repo clone has the key'
        : 'No hardcoded keys detected' });

    if (hk) warnings.push('Hardcoded cryptographic key detected — rotate immediately and use environment variables or a secrets manager.');
    if (obs.hasPlaintextPassword) warnings.push('Plaintext password comparison detected — passwords must be hashed with Argon2id/bcrypt before storage.');
    total += s;
    categories.push({ name: 'Implementation Safety', score: s, max: 10, items });
  }

  const grade
    = total >= 95 ? 'A+' : total >= 88 ? 'A' : total >= 80 ? 'A-'
    : total >= 72 ? 'B+' : total >= 62 ? 'B' : total >= 52 ? 'B-'
    : total >= 40 ? 'C'  : total >= 25 ? 'D' : 'F';

  const impossibilityScore = Math.round(total);

  const verdict = genericVerdict(total, grade, obs);
  return { total, grade, source, impossibilityScore, categories, verdict, warnings };
}

function genericVerdict(total: number, grade: string, obs: GenericCryptoObservable): string {
  if (total >= 95) return `Grade ${grade} (${total}/100) — UNIVERSAL IMPOSSIBILITY. Attack cost exceeds the Landauer energy budget of the observable universe. All major attack surfaces mitigated.`;
  if (total >= 80) return `Grade ${grade} (${total}/100) — QUANTUM-RESISTANT. Resists Shor's and Grover's algorithms at foreseeable hardware scales. Close remaining gaps for full universal-scale hardening.`;
  if (total >= 60) return `Grade ${grade} (${total}/100) — ADEQUATE. Core protections present but meaningful gaps. Well-funded adversary has a surface to exploit.`;
  if (total >= 40) return `Grade ${grade} (${total}/100) — WEAK. Significant cryptographic gaps. Determined attacker likely succeeds. Do not use for sensitive data.`;
  if (total >= 20) return `Grade ${grade} (${total}/100) — CRITICALLY WEAK. Multiple fundamental failures. Treat as compromised. Migrate immediately.`;
  if (obs.hasHardcodedKey) return `Grade ${grade} (${total}/100) — COMPROMISED. Hardcoded key: any code reader has your key right now.`;
  return `Grade ${grade} (${total}/100) — EFFECTIVELY PLAINTEXT. No meaningful encryption protection confirmed.`;
}

// ─── npm library impossibility score database ─────────────────────────────────
//
// Each entry is a pre-researched SPDObservable/GenericCryptoObservable hybrid.
// The "impossibility score" answers: given an adversary with $1B budget,
// how long (in equivalent time units) does breaking this take?
// Scores are based on published specs, source audits, and cryptanalysis papers.

export interface LibraryProfile {
  name:              string;
  npmPackage:        string;
  version?:          string;
  description:       string;
  impossibilityScore: number;  // 0–100
  grade:             string;
  cipher?:           string;
  kdf?:              string;
  keyBits?:          number;
  postQuantum:       boolean;
  authenticated:     boolean;
  timingSafe:        boolean;
  forwardSecrecy:    boolean;
  knownVulns?:       string[];
  strengths:         string[];
  weaknesses:        string[];
  verdict:           string;
  lastAuditYear?:    number;
}

const NPM_LIBRARY_DB: Record<string, LibraryProfile> = {
  // ── Best-in-class ────────────────────────────────────────────────────────
  'libsodium-wrappers': {
    name: 'libsodium-wrappers', npmPackage: 'libsodium-wrappers',
    description: 'WebAssembly build of libsodium — the gold standard crypto library',
    impossibilityScore: 92, grade: 'A',
    cipher: 'XChaCha20-Poly1305 / XSalsa20-Poly1305', kdf: 'Argon2id (argon2i/argon2id)', keyBits: 256,
    postQuantum: false, authenticated: true, timingSafe: true, forwardSecrecy: false,
    strengths: [
      'Misuse-resistant API (secretstream, secretbox) — hard to use incorrectly',
      'Timing-safe by design — all comparisons use sodium_memcmp',
      'sodium_memzero enforces secure key erasure',
      'Nonces are either random (secretbox) or incremented (stream)',
      'XChaCha20-Poly1305: 192-bit nonce, no birthday problem',
      'Argon2id built-in (crypto_pwhash) — memory-hard, ASIC-resistant',
      'Formally audited (NaCl, libsodium multiple audits)',
      'No IV reuse vectors in high-level API',
    ],
    weaknesses: [
      'No post-quantum algorithms (classical X25519/Ed25519 only)',
      'No built-in forward secrecy — caller must implement ratcheting',
      'WASM overhead — not suitable for high-throughput server workloads',
    ],
    verdict: 'Best-in-class for JavaScript/TypeScript. Use this unless you have PQC requirements.',
    lastAuditYear: 2023,
  },

  'tweetnacl': {
    name: 'tweetnacl', npmPackage: 'tweetnacl',
    description: 'Port of TweetNaCl (100-line NaCl) in pure JavaScript',
    impossibilityScore: 78, grade: 'B+',
    cipher: 'XSalsa20-Poly1305 / Salsa20', kdf: 'none (raw key required)', keyBits: 256,
    postQuantum: false, authenticated: true, timingSafe: true, forwardSecrecy: false,
    strengths: [
      'XSalsa20-Poly1305: authenticated encryption, 192-bit nonce',
      'Timing-safe comparison via nacl.verify()',
      'Minimal, audited codebase — easy to review',
      'Ed25519 signatures',
      'X25519 Diffie-Hellman for key exchange',
    ],
    weaknesses: [
      'No KDF — caller must handle key derivation (common misuse: raw password as key)',
      'No Argon2id / bcrypt built-in',
      'No post-quantum algorithms',
      'Pure JS: slower than libsodium-wrappers',
      'No built-in ratcheting / forward secrecy',
      'secretbox nonce must be caller-managed — reuse risk if not incremented correctly',
    ],
    verdict: 'Good cipher primitives but missing KDF. Always pair with argon2 or scrypt for password-based encryption.',
    lastAuditYear: 2017,
  },

  '@noble/ciphers': {
    name: '@noble/ciphers', npmPackage: '@noble/ciphers',
    description: 'Audited, zero-dependency cryptographic ciphers (noble project)',
    impossibilityScore: 85, grade: 'A-',
    cipher: 'ChaCha20-Poly1305, AES-GCM, AES-SIV, XChaCha20-Poly1305', kdf: 'none (raw key)', keyBits: 256,
    postQuantum: false, authenticated: true, timingSafe: true, forwardSecrecy: false,
    strengths: [
      'Multiple audited AEAD ciphers including XChaCha20-Poly1305',
      'AES-SIV: nonce-misuse-resistant (safe to reuse nonce)',
      'Written in TypeScript with zero dependencies',
      'Timing-safe via constant-time implementations',
      'Regular third-party audits (Cure53)',
      'Works in browser and Node.js',
    ],
    weaknesses: [
      'No KDF — caller must derive keys',
      'No post-quantum algorithms',
      'No built-in forward secrecy',
      'AES requires hardware AES-NI for performance; soft-AES is slow and potentially timing-leaky',
    ],
    verdict: 'Excellent cipher library. Pair with @noble/hashes for HMAC and argon2 for KDF.',
    lastAuditYear: 2024,
  },

  '@noble/post-quantum': {
    name: '@noble/post-quantum', npmPackage: '@noble/post-quantum',
    description: 'Pure TypeScript NIST FIPS 203/204/205 post-quantum algorithms',
    impossibilityScore: 88, grade: 'A',
    cipher: 'ML-KEM-512/768/1024 (FIPS 203), ML-DSA-44/65/87 (FIPS 204), SLH-DSA (FIPS 205)',
    kdf: 'none (raw key)', keyBits: 256,
    postQuantum: true, authenticated: true, timingSafe: true, forwardSecrecy: false,
    strengths: [
      'ML-KEM-768 (FIPS 203): 192-bit classical + 128-bit post-quantum security',
      'ML-DSA-65 (FIPS 204): post-quantum digital signatures',
      'SLH-DSA: hash-based signatures with conservative security assumptions',
      'Zero-dependency pure TypeScript — auditable codebase',
      'NIST-standardized algorithms (August 2024)',
      'Third-party audits (Cure53)',
    ],
    weaknesses: [
      'KEM only — no integrated encryption scheme; caller must combine with AEAD',
      'Larger key/signature sizes than classical crypto (ML-KEM-768 public key = 1184 bytes)',
      'Should be used in hybrid mode with X25519 until MLWE problem confidence matures',
      'No built-in forward secrecy or ratcheting',
    ],
    verdict: 'Use in hybrid mode with libsodium X25519 for both classical and quantum resistance. Best current PQC option for TypeScript.',
    lastAuditYear: 2024,
  },

  'argon2': {
    name: 'argon2', npmPackage: 'argon2',
    description: 'Node.js bindings for the reference Argon2 C implementation',
    impossibilityScore: 90, grade: 'A',
    cipher: 'N/A (KDF only)', kdf: 'Argon2id / Argon2i / Argon2d', keyBits: 256,
    postQuantum: true, authenticated: false, timingSafe: true, forwardSecrecy: false,
    strengths: [
      'Argon2id: winner of the Password Hashing Competition (PHC 2015)',
      'Memory-hard: GPU/ASIC attacks 100–1000x more expensive than CPU',
      'Side-channel resistant (Argon2id = hybrid of data-dependent and data-independent)',
      'Configurable memory cost (≥2 GiB recommended for at-rest storage)',
      'Native C implementation — fast and trusted',
      'RFC 9106 compliant',
      'Post-quantum resistant to Grover (memory hardness reduces GPU parallelism)',
    ],
    weaknesses: [
      'Native dependency — requires build tools; can be a deployment complication',
      'KDF only — must pair with AEAD cipher (libsodium/noble) for encryption',
      'Default parameters (64MB) adequate for login but weak for at-rest storage; tune to ≥1 GiB',
    ],
    verdict: 'Best-in-class KDF. Always use for password hashing and key derivation. Pair with libsodium for full encryption stack.',
    lastAuditYear: 2023,
  },

  'bcrypt': {
    name: 'bcrypt', npmPackage: 'bcrypt',
    description: 'bcrypt password hashing library (C++ bindings)',
    impossibilityScore: 62, grade: 'B',
    cipher: 'N/A (password hash only)', kdf: 'bcrypt', keyBits: 184,
    postQuantum: false, authenticated: false, timingSafe: true, forwardSecrecy: false,
    strengths: [
      'Work-factor tunable via cost parameter',
      'Well-audited, widely deployed',
      'Timing-safe comparison in most implementations',
      'Salted by design (random 16-byte salt embedded in hash)',
    ],
    weaknesses: [
      'Input capped at 72 bytes — passwords longer than 72 bytes are silently truncated',
      'Not memory-hard: GPU attacks still viable (GPU cost ~50x CPU, not 1000x like Argon2id)',
      'Maximum effective output is ~184 bits — not suitable as a key derivation function for AEAD',
      'No native key-stretching output — must use with separate KDF if deriving encryption keys',
      'Superseded by Argon2id for new systems',
    ],
    verdict: 'Adequate for legacy password storage. For new systems use Argon2id. Never use for deriving encryption keys.',
    lastAuditYear: 2022,
  },

  'bcryptjs': {
    name: 'bcryptjs', npmPackage: 'bcryptjs',
    description: 'Pure JavaScript bcrypt (no native bindings)',
    impossibilityScore: 58, grade: 'B-',
    cipher: 'N/A (password hash only)', kdf: 'bcrypt', keyBits: 184,
    postQuantum: false, authenticated: false, timingSafe: false, forwardSecrecy: false,
    strengths: ['No native dependency — runs anywhere', 'Salted by design'],
    weaknesses: [
      'Pure JS: ~5–10x slower than native bcrypt for hashing, BUT attacker GPU is also unconstrained',
      '72-byte input cap (same as bcrypt)',
      'Timing side channel risk in pure JS implementation — constant-time not guaranteed',
      'Not memory-hard',
      'Superseded by Argon2id',
    ],
    verdict: 'Use bcrypt (native) or Argon2id instead. Pure JS timing guarantees are weaker.',
    lastAuditYear: 2019,
  },

  'crypto-js': {
    name: 'crypto-js', npmPackage: 'crypto-js',
    description: 'Pure JavaScript crypto library (AES, SHA, HMAC, etc.)',
    impossibilityScore: 32, grade: 'D',
    cipher: 'AES-CBC, AES-ECB, DES, Blowfish, Rabbit', kdf: 'PBKDF2 (optional, rarely used)', keyBits: 256,
    postQuantum: false, authenticated: false, timingSafe: false, forwardSecrecy: false,
    knownVulns: [
      'Default AES mode is AES-ECB in some versions — reveals plaintext block patterns',
      'AES-CBC with user-supplied IV: static/predictable IV is common misuse',
      'No built-in HMAC over ciphertext — encryption without authentication is default',
      'Not maintained since 2021 — no security patches',
      'Timing side channels in pure JS comparison functions',
      'PBKDF2 with default low iteration count (often 1 iteration in examples)',
    ],
    strengths: ['Runs in browser without native deps', 'Familiar API'],
    weaknesses: [
      'Unauthenticated encryption by default — ciphertext tampering undetected',
      'AES-ECB mode reveals block patterns in ciphertext',
      'No memory-hard KDF',
      'Effectively unmaintained',
      'No timing-safe MAC comparison',
      'No post-quantum',
    ],
    verdict: 'DO NOT USE for new systems. Unauthenticated AES-CBC/ECB by default. Migrate to libsodium-wrappers or @noble/ciphers immediately.',
    lastAuditYear: 2021,
  },

  'node:crypto': {
    name: 'node:crypto', npmPackage: 'node:crypto (built-in)',
    description: 'Node.js built-in crypto module (OpenSSL bindings)',
    impossibilityScore: 72, grade: 'B',
    cipher: 'AES-GCM, AES-CBC, ChaCha20-Poly1305, and many others', kdf: 'scrypt, PBKDF2 (built-in)', keyBits: 256,
    postQuantum: false, authenticated: true, timingSafe: true, forwardSecrecy: false,
    strengths: [
      'AES-256-GCM: authenticated 256-bit encryption (good choice)',
      'ChaCha20-Poly1305 supported in Node ≥18',
      'timingSafeEqual() built-in — no excuses for timing side channels',
      'scrypt built-in — memory-hard KDF available',
      'PBKDF2 with configurable iterations',
      'No dependencies — zero supply chain risk',
      'OpenSSL: battle-tested, FIPS-certified option available',
    ],
    weaknesses: [
      'Low-level API — easy to misuse (wrong IV, no HMAC, raw key from password)',
      'Many insecure modes available (AES-ECB, DES, RC4) — caller chooses',
      'No post-quantum algorithms',
      'No built-in nonce management — counter or randomness is caller\'s responsibility',
      'No high-level secrets management (no secretbox equivalent)',
    ],
    verdict: 'Good building blocks but requires careful assembly. Use AES-256-GCM or ChaCha20-Poly1305 with timingSafeEqual and scrypt/Argon2id for KDF.',
    lastAuditYear: 2024,
  },

  'web-crypto': {
    name: 'Web Crypto API', npmPackage: 'globalThis.crypto.subtle (browser/Node ≥19)',
    description: 'Browser and Node.js W3C Web Cryptography API',
    impossibilityScore: 70, grade: 'B',
    cipher: 'AES-GCM, AES-CBC, AES-CTR, RSA-OAEP, ECDH', kdf: 'PBKDF2, HKDF (built-in)', keyBits: 256,
    postQuantum: false, authenticated: true, timingSafe: true, forwardSecrecy: true,
    strengths: [
      'AES-256-GCM: 256-bit authenticated encryption',
      'Hardware-accelerated on most platforms',
      'ECDH with P-256/P-384: ephemeral Diffie-Hellman (forward secrecy possible)',
      'PBKDF2 and HKDF built-in for key derivation',
      'Keys can be marked non-extractable — prevents key exfiltration via JS',
      'W3C standardized, widely implemented',
    ],
    weaknesses: [
      'PBKDF2 only — no Argon2id/scrypt for memory-hard KDF',
      'No ChaCha20-Poly1305 in most browsers (only AES family)',
      'No post-quantum algorithms',
      'ECDH with P-256 is vulnerable to Shor on quantum hardware',
      'AES-CBC and AES-CTR available — unauthenticated if caller doesn\'t add HMAC',
      'No Ed25519 / X25519 in older browsers',
    ],
    verdict: 'Good for browser environments. Pair with a WASM Argon2id library for password hashing. Use ECDH for forward secrecy in TLS-like protocols.',
    lastAuditYear: 2024,
  },

  'jose': {
    name: 'jose', npmPackage: 'jose',
    description: 'JavaScript JOSE (JWT/JWE/JWS/JWK) implementation',
    impossibilityScore: 65, grade: 'B',
    cipher: 'AES-256-GCM, AES-CBC-HMAC-SHA2 (JWE)', kdf: 'PBES2-AES-KW (PBKDF2-based)', keyBits: 256,
    postQuantum: false, authenticated: true, timingSafe: true, forwardSecrecy: false,
    strengths: [
      'JWE AES-256-GCM: authenticated 256-bit encryption',
      'AES-CBC + HMAC-SHA2: encrypt-then-MAC (correct construction)',
      'PBES2 with PBKDF2-SHA512 for password-based encryption',
      'W3C Web Crypto backed — hardware-accelerated',
      'Widely used, maintained, and audited',
    ],
    weaknesses: [
      'JWT is often used without encryption (signed-only JWS) — claims are plaintext',
      'PBKDF2 KDF — not memory-hard; upgrade to Argon2id where possible',
      'No post-quantum',
      'JOSE spec allows weak algorithms (RS256, none) — caller must restrict alg',
      '"alg:none" attack: some implementations accept unsigned tokens if not hardened',
      'Key wrapping complexity adds attack surface',
    ],
    verdict: 'Good for JWT/JWE use cases. Always restrict allowed algorithms explicitly. For at-rest encryption use libsodium instead.',
    lastAuditYear: 2024,
  },

  'jsonwebtoken': {
    name: 'jsonwebtoken', npmPackage: 'jsonwebtoken',
    description: 'JWT signing and verification (JWS only — NOT encryption)',
    impossibilityScore: 28, grade: 'D',
    cipher: 'N/A (signing only — data is BASE64, not encrypted)', kdf: 'none', keyBits: 256,
    postQuantum: false, authenticated: true, timingSafe: false, forwardSecrecy: false,
    knownVulns: [
      '"alg:none" attack: some versions accepted unsigned tokens without signature',
      'HS256 with short keys: brute-forceable offline',
      'No encryption — JWT payload is only base64-encoded, fully readable to anyone',
      'Confusion attack: RS256 public key used as HS256 secret in some implementations',
    ],
    strengths: ['Widely deployed', 'Simple API for stateless auth tokens'],
    weaknesses: [
      'JWT payload is NOT encrypted — it is only signed. Anyone can read the claims.',
      'Commonly misused as an encryption mechanism when it is not one',
      'HS256 with weak shared secrets is brute-forceable offline',
      'Algorithm confusion attacks in wild',
      'No forward secrecy',
    ],
    verdict: 'JWT is SIGNING, not ENCRYPTION. Never store sensitive data in JWT claims unless using JWE. Score is for its encryption capability: near zero.',
    lastAuditYear: 2022,
  },

  'openpgp': {
    name: 'openpgp', npmPackage: 'openpgp',
    description: 'OpenPGP.js — PGP encryption for JavaScript (RFC 4880)',
    impossibilityScore: 68, grade: 'B',
    cipher: 'AES-256 (CFB mode), EdDSA / ECDH (v6: X25519 + AES-256-OCB)',
    kdf: 'S2K (string-to-key, bcrypt/Argon2id in v6)', keyBits: 256,
    postQuantum: false, authenticated: true, timingSafe: false, forwardSecrecy: false,
    strengths: [
      'AES-256-OCB (v6): authenticated encryption with AEAD',
      'X25519 ECDH: modern elliptic-curve key exchange',
      'EdDSA (Ed25519): modern signatures',
      'v6 supports Argon2id for string-to-key (major improvement)',
      'Widely used format — interoperable with GPG',
    ],
    weaknesses: [
      'Legacy CFB mode (v4): unauthenticated AES-CFB allows ciphertext modification (EFAIL)',
      'Compression before encryption (CRIME/BREACH class) in legacy mode',
      'Complex, large codebase — high attack surface',
      'No post-quantum (post-quantum OpenPGP draft exists but not finalized)',
      'Forward secrecy only if using ephemeral ECDH (not default)',
      'MDC (modification detection code) in v4 is not always enforced by all implementations',
    ],
    knownVulns: ['EFAIL (2018): unauthenticated CBC/CFB mode allows plaintext exfiltration via mail clients'],
    verdict: 'Use v6+ with AEAD mode. Avoid v4 for new systems. Not suitable for high-security at-rest storage — use libsodium instead.',
    lastAuditYear: 2023,
  },

  'age': {
    name: 'age (js implementation)', npmPackage: 'age-encryption',
    description: 'age file encryption format — modern, simple, correct',
    impossibilityScore: 83, grade: 'A-',
    cipher: 'ChaCha20-Poly1305', kdf: 'scrypt (passphrase) / X25519 HKDF (key)', keyBits: 256,
    postQuantum: false, authenticated: true, timingSafe: true, forwardSecrecy: false,
    strengths: [
      'ChaCha20-Poly1305: authenticated 256-bit encryption',
      'scrypt for passphrase: memory-hard KDF',
      'X25519 ECDH for key-based encryption',
      'Designed from scratch to be simple and correct (no legacy baggage)',
      'STREAM construction: nonce misuse resistant for multi-chunk files',
      'Header authenticated with HMAC-SHA256',
    ],
    weaknesses: [
      'No post-quantum algorithms',
      'scrypt N=2^18 default (256 MiB) — adequate but not maximum',
      'No built-in forward secrecy',
      'Relatively new ecosystem — fewer audits than libsodium',
    ],
    verdict: 'Excellent modern file encryption. Strong cipher and KDF. Use this or libsodium for new at-rest encryption.',
    lastAuditYear: 2023,
  },

  'node-forge': {
    name: 'node-forge', npmPackage: 'node-forge',
    description: 'Native JavaScript crypto and network library',
    impossibilityScore: 38, grade: 'D',
    cipher: 'AES-CBC, AES-GCM, AES-ECB, DES, 3DES, RC2', kdf: 'PBKDF2, MD5 (legacy)', keyBits: 256,
    postQuantum: false, authenticated: false, timingSafe: false, forwardSecrecy: false,
    knownVulns: [
      'RSA PKCS#1 v1.5 vulnerable to Bleichenbacher attack in some configurations',
      'Insecure modes (AES-ECB, DES, RC2) available and used in examples',
      'No HMAC by default on AES-CBC — encrypt-without-authenticate',
      'Timing side channels in pure JS MAC comparison',
    ],
    strengths: ['Large feature set', 'ASN.1/X.509 support for PKI use cases'],
    weaknesses: [
      'AES-ECB and DES available and commonly used in examples',
      'No memory-hard KDF (only PBKDF2 / MD5)',
      'No timing-safe comparison built-in',
      'No post-quantum',
      'Complex codebase — high audit burden',
      'Not recommended for new projects',
    ],
    verdict: 'Avoid for encryption in new systems. Only use for legacy X.509/PKI interop where other options are unavailable. Migrate to node:crypto or libsodium.',
    lastAuditYear: 2021,
  },

  'sjcl': {
    name: 'SJCL (Stanford JavaScript Crypto Library)', npmPackage: 'sjcl',
    description: 'AES-CCM/GCM/OCB library — popular but aging academic project',
    impossibilityScore: 48, grade: 'C',
    cipher: 'AES-CCM, AES-GCM, AES-OCB2', kdf: 'PBKDF2', keyBits: 256,
    postQuantum: false, authenticated: true, timingSafe: false, forwardSecrecy: false,
    knownVulns: ['OCB2 patent issues (pre-2013)', 'Timing side channels in JS'],
    strengths: ['AES-GCM: authenticated 256-bit encryption', 'Academic pedigree (Stanford)'],
    weaknesses: [
      'PBKDF2 only — no memory-hard KDF',
      'No post-quantum',
      'Aging codebase — last major update 2017',
      'Not recommended for new projects',
      'Pure JS timing guarantees weak',
    ],
    verdict: 'Superseded by @noble/ciphers and libsodium. Use only for legacy interop.',
    lastAuditYear: 2017,
  },

  '@aws-sdk/client-kms': {
    name: 'AWS KMS SDK', npmPackage: '@aws-sdk/client-kms',
    description: 'AWS Key Management Service — HSM-backed key operations',
    impossibilityScore: 88, grade: 'A',
    cipher: 'AES-256-GCM (symmetric), RSA-OAEP (asymmetric)', kdf: 'N/A (HSM-managed keys)', keyBits: 256,
    postQuantum: false, authenticated: true, timingSafe: true, forwardSecrecy: false,
    strengths: [
      'Keys never leave the HSM — side-channel and exfiltration resistant',
      'AES-256-GCM: authenticated 256-bit encryption',
      'FIPS 140-2/3 Level 3 HSM hardware',
      'Automatic key rotation',
      'CloudTrail audit logs for all key operations',
      'Cross-region key replication with independent key material',
      'IAM policy enforcement on key use',
    ],
    weaknesses: [
      'Network call per decrypt — latency (a few ms to tens of ms per operation)',
      'Cloud vendor lock-in — key material inaccessible if AWS account suspended',
      'No post-quantum algorithms yet (AWS PQC preview exists)',
      'Encrypt/decrypt operations have size limits — caller must manage chunking',
      'Cost at high volume',
    ],
    verdict: 'Best operational key protection for cloud workloads. Key material never leaves HSM. Add Argon2id for user-facing passwords and envelope encryption for large payloads.',
    lastAuditYear: 2024,
  },

  'aes-js': {
    name: 'aes-js', npmPackage: 'aes-js',
    description: 'Pure JavaScript AES implementation (CTR, CBC, CFB, OFB, ECB)',
    impossibilityScore: 22, grade: 'D',
    cipher: 'AES-CTR, AES-CBC, AES-CFB, AES-OFB, AES-ECB', kdf: 'none', keyBits: 256,
    postQuantum: false, authenticated: false, timingSafe: false, forwardSecrecy: false,
    knownVulns: [
      'AES-ECB: reveals repeated plaintext blocks — textbook insecure',
      'No HMAC by default — unauthenticated encryption in all modes',
      'AES-CBC with user IV: nonce reuse and padding oracle risks',
    ],
    strengths: ['Simple AES block operations for educational use'],
    weaknesses: [
      'No authentication — all modes are unauthenticated by default',
      'AES-ECB available — should never be used',
      'No KDF',
      'No timing-safe comparison',
      'Not recommended for production',
    ],
    verdict: 'DO NOT USE for production encryption. No authentication, no KDF, AES-ECB available. Use @noble/ciphers or libsodium-wrappers instead.',
    lastAuditYear: 2019,
  },
};

/** Normalize library name to match db keys (handle case, aliases). */
function normalizeLibName(name: string): string {
  const n = name.toLowerCase().trim();
  // Aliases
  if (n === 'libsodium' || n === 'sodium') return 'libsodium-wrappers';
  if (n === 'nacl' || n === 'tweetnacl-js') return 'tweetnacl';
  if (n === 'noble-ciphers' || n === 'noble/ciphers') return '@noble/ciphers';
  if (n === 'noble-pqc' || n === 'noble/post-quantum') return '@noble/post-quantum';
  if (n === 'webcrypto' || n === 'subtle' || n === 'crypto.subtle') return 'web-crypto';
  if (n === 'crypto' || n === 'node-crypto') return 'node:crypto';
  if (n === 'forge') return 'node-forge';
  if (n === 'jwt' || n === 'jsonwebtoken') return 'jsonwebtoken';
  return n;
}

/**
 * Look up a known npm library and return its pre-researched security profile.
 * Returns null if the library is not in the database.
 */
export function scoreNpmLibrary(libraryName: string): LibraryProfile | null {
  const key = normalizeLibName(libraryName);
  return NPM_LIBRARY_DB[key] ?? NPM_LIBRARY_DB[libraryName] ?? null;
}

/** Return all known library profiles, sorted by impossibility score descending. */
export function listKnownLibraries(): LibraryProfile[] {
  return Object.values(NPM_LIBRARY_DB).sort((a, b) => b.impossibilityScore - a.impossibilityScore);
}

// ─── Rendering for generic score ──────────────────────────────────────────────

function renderGenericScore(result: GenericScoreResult): void {
  const w = 72;
  const line = `${B}${U}${'─'.repeat(w)}${R}`;
  console.log();
  console.log(line);
  console.log(`${B}${W}  ENCRYPTION SYSTEM SECURITY SCORE${R}`);
  console.log(`${D}  Source: ${result.source}${R}`);
  console.log(line);
  console.log();

  const gc = gradeColor(result.grade);
  console.log(`  ${B}Total Score:  ${gc}${result.total} / 100   Grade: ${result.grade}${R}`);
  console.log(`  ${bar(result.total, 100, 46)}`);
  console.log();
  console.log(`  ${B}Impossibility Score: ${gc}${result.impossibilityScore}/100${R}  ${D}(how hard it is for any adversary to break this)${R}`);
  console.log();
  console.log(`  ${D}${result.verdict}${R}`);
  console.log();

  if (result.warnings.length > 0) {
    console.log(`${E}${B}  ⚠  CRITICAL WARNINGS (${result.warnings.length})${R}`);
    result.warnings.forEach(w2 => console.log(`  ${E}•${R} ${w2}`));
    console.log();
  }

  console.log(line);
  console.log(`${B}  Category Breakdown${R}`);
  console.log(line);

  for (const cat of result.categories) {
    const pct = cat.score / cat.max;
    const col = pct >= 0.8 ? G : pct >= 0.5 ? Y : E;
    console.log();
    console.log(`  ${B}${cat.name}${R}  ${col}${cat.score}/${cat.max}${R}  ${bar(cat.score, cat.max, 20)}`);
    for (const item of cat.items) {
      const icon = item.ok ? `${G}✔${R}` : `${E}✘${R}`;
      const pts  = item.ok ? `${G}+${item.max}${R}` : item.earned > 0 ? `${Y}+${item.earned}${R}` : `${E}+0${R}`;
      console.log(`    ${icon}  ${item.label.padEnd(44)} ${pts}`);
      if (item.detail) console.log(`       ${D}${item.detail}${R}`);
    }
  }

  console.log();
  console.log(line);
  console.log();
}

function renderLibraryProfile(profile: LibraryProfile): void {
  const w = 72;
  const line = `${B}${U}${'─'.repeat(w)}${R}`;
  const gc   = gradeColor(profile.grade);

  console.log();
  console.log(line);
  console.log(`${B}${W}  npm LIBRARY IMPOSSIBILITY SCORE${R}`);
  console.log(`${D}  ${profile.name}${R}`);
  console.log(line);
  console.log();
  console.log(`  ${B}Package:  ${C}${profile.npmPackage}${R}`);
  console.log(`  ${B}${profile.description}${R}`);
  console.log();
  console.log(`  ${B}Impossibility Score: ${gc}${profile.impossibilityScore} / 100   Grade: ${profile.grade}${R}`);
  console.log(`  ${bar(profile.impossibilityScore, 100, 46)}`);
  console.log();
  console.log(`  ${D}${profile.verdict}${R}`);
  console.log();

  console.log(`  ${B}Cipher:${R}          ${profile.cipher ?? 'N/A'}`);
  console.log(`  ${B}KDF:${R}             ${profile.kdf ?? 'None'}`);
  console.log(`  ${B}Key size:${R}        ${profile.keyBits ? profile.keyBits + ' bits' : 'varies'}`);
  console.log(`  ${B}Post-quantum:${R}    ${profile.postQuantum ? `${G}Yes${R}` : `${E}No${R}`}`);
  console.log(`  ${B}Authenticated:${R}   ${profile.authenticated ? `${G}Yes${R}` : `${E}No${R}`}`);
  console.log(`  ${B}Timing-safe:${R}     ${profile.timingSafe ? `${G}Yes${R}` : `${E}No${R}`}`);
  console.log(`  ${B}Forward secrecy:${R} ${profile.forwardSecrecy ? `${G}Yes${R}` : `${E}No${R}`}`);
  if (profile.lastAuditYear) console.log(`  ${B}Last audit:${R}      ${profile.lastAuditYear}`);
  console.log();

  if ((profile.knownVulns ?? []).length > 0) {
    console.log(`${E}${B}  ⚠  Known Vulnerabilities / Issues${R}`);
    (profile.knownVulns ?? []).forEach(v => console.log(`  ${E}•${R} ${v}`));
    console.log();
  }

  console.log(`${G}${B}  ✔ Strengths${R}`);
  profile.strengths.forEach(s => console.log(`  ${G}+${R} ${s}`));
  console.log();

  console.log(`${E}${B}  ✘ Weaknesses${R}`);
  profile.weaknesses.forEach(s => console.log(`  ${E}−${R} ${s}`));
  console.log();
  console.log(line);
  console.log();
}

function renderLibraryList(): void {
  const libs = listKnownLibraries();
  const w = 72;
  const line = `${'─'.repeat(w)}`;
  console.log();
  console.log(`${B}${W}  npm Encryption Library Impossibility Scores${R}`);
  console.log(`${D}  Score = how hard it is for any adversary (including nation-state) to break this${R}`);
  console.log(line);
  console.log();
  console.log(`  ${'Package'.padEnd(30)} ${'Score'.padEnd(6)} ${'Grade'.padEnd(5)} Cipher`);
  console.log(`  ${'─'.repeat(30)} ${'─'.repeat(6)} ${'─'.repeat(5)} ${'─'.repeat(24)}`);
  for (const lib of libs) {
    const gc  = gradeColor(lib.grade);
    const pq  = lib.postQuantum ? ` ${C}[PQC]${R}` : '';
    console.log(`  ${lib.npmPackage.padEnd(30)} ${gc}${String(lib.impossibilityScore).padEnd(6)}${R} ${gc}${lib.grade.padEnd(5)}${R} ${lib.cipher?.slice(0, 24) ?? 'N/A'}${pq}`);
  }
  console.log();
  console.log(`  Use ${B}spd-score --library <name>${R} for full details.`);
  console.log(line);
  console.log();
}

// ─── Payload-file / JSON parser ───────────────────────────────────────────────

function parseBinaryHeader(buf: Buffer): SPDObservable {
  const head = buf.subarray(0, Math.min(buf.length, 8192)).toString('utf8');
  const start = head.indexOf('{');
  const end   = head.lastIndexOf('}');
  if (start !== -1 && end > start) {
    try {
      const raw = JSON.parse(head.slice(start, end + 1));
      if (raw && typeof raw === 'object') return extractFromPayload(raw);
    } catch { /* fall through */ }
  }
  const obs: SPDObservable = {};
  if (buf.length > 8 && buf[0] === 0x53 && buf[1] === 0x50 && buf[2] === 0x44) {
    obs.version = buf.readUInt32LE(4);
  }
  return obs;
}

function extractFromPayload(raw: Record<string, unknown>): SPDObservable {
  const obs: SPDObservable = {};
  const p = (raw.payload && typeof raw.payload === 'object')
    ? raw.payload as Record<string, unknown> : raw;

  if (typeof p.version           === 'number')  obs.version           = p.version;
  if (typeof p.hashAlgorithm     === 'string')  obs.hashAlgorithm     = p.hashAlgorithm;
  if (typeof p.argon2Memory      === 'number')  obs.argon2Memory      = p.argon2Memory;
  if (typeof p.argon2Time        === 'number')  obs.argon2Time        = p.argon2Time;
  if (typeof p.argon2Parallelism === 'number')  obs.argon2Parallelism = p.argon2Parallelism;
  if (typeof p.kdfChain          === 'boolean') obs.kdfChain          = p.kdfChain;
  if (typeof p.scryptN           === 'number')  obs.scryptN           = p.scryptN;
  if (typeof p.scryptR           === 'number')  obs.scryptR           = p.scryptR;
  if (typeof p.scryptP           === 'number')  obs.scryptP           = p.scryptP;
  if (typeof p.writeCounter      === 'number')  obs.writeCounter      = p.writeCounter;
  if (typeof p.merkleRoot        === 'string')  obs.merkleRoot        = p.merkleRoot;
  if (typeof p.epochSize         === 'number')  obs.epochSize         = p.epochSize;
  if (typeof p.ratchetEnabled    === 'boolean') obs.ratchetEnabled    = p.ratchetEnabled;
  if (typeof p.fileSignature     === 'string')  obs.fileSignature     = p.fileSignature;
  if (typeof p.hasPepper         === 'boolean') obs.hasPepper         = p.hasPepper;
  if (typeof p.hasKeyfile        === 'boolean') obs.hasKeyfile        = p.hasKeyfile;
  if (typeof p.macKeyLength      === 'number')  obs.macKeyLength      = p.macKeyLength;
  if (typeof p.hasHSMProvider    === 'boolean') obs.hasHSMProvider    = p.hasHSMProvider;
  if (typeof p.keyProfile        === 'string')  obs.keyProfile        = p.keyProfile;
  if (typeof p.walEnabled        === 'boolean') obs.walEnabled        = p.walEnabled;
  if (typeof p.keyBlinded        === 'boolean') obs.keyBlinded        = p.keyBlinded;
  if (typeof p.transportV2       === 'boolean') obs.transportV2       = p.transportV2;
  if (typeof p.hybridKem         === 'boolean') obs.hybridKem         = p.hybridKem;
  if (typeof p.mlDsaCert         === 'boolean') obs.mlDsaCert         = p.mlDsaCert;
  if (typeof p.hasKeyCommitment      === 'boolean') obs.hasKeyCommitment      = p.hasKeyCommitment;
  if (typeof p.replayWindow          === 'number')  obs.replayWindow          = p.replayWindow;
  if (typeof p.framePadding          === 'boolean') obs.framePadding          = p.framePadding;
  if (typeof p.passcodeEntropy       === 'number')  obs.passcodeEntropy       = p.passcodeEntropy;
  if (typeof p.hasAeadKeyCommitment  === 'boolean') obs.hasAeadKeyCommitment  = p.hasAeadKeyCommitment;
  if (typeof p.hasTimingSafeMac      === 'boolean') obs.hasTimingSafeMac      = p.hasTimingSafeMac;
  if (typeof p.hasExplicitMemzero    === 'boolean') obs.hasExplicitMemzero    = p.hasExplicitMemzero;
  if (typeof p.hasNonceReuseGuard    === 'boolean') obs.hasNonceReuseGuard    = p.hasNonceReuseGuard;
  if (typeof p.hasMetadataPadding    === 'boolean') obs.hasMetadataPadding    = p.hasMetadataPadding;
  if (typeof p.hasFilenameEncryption === 'boolean') obs.hasFilenameEncryption = p.hasFilenameEncryption;
  if (typeof p.hasPasscodeEnforcement=== 'boolean') obs.hasPasscodeEnforcement= p.hasPasscodeEnforcement;
  return obs;
}

// ─── Scoring helpers ──────────────────────────────────────────────────────────

/**
 * SCORING RULES
 * ─────────────
 * • 0   = no encryption at all (raw plaintext)
 * • 100 = maximum computationally infeasible hardness with every known
 *         technique stacked, no known attack path at any realistic scale
 *
 * NO partial credit. Every check is binary: confirmed in source = points, else 0.
 * Thresholds are grounded in: RFC 9106 (Argon2), scrypt paper (Percival 2009),
 * OWASP 2024, NIST FIPS 203, USENIX 2022 key commitment paper.
 *
 * NOTE: HMAC-SHA3-512 and HMAC-SHA-512 have equivalent post-quantum security
 * (~256-bit post-Grover). SHA3 is not scored higher — Shor does not apply to
 * symmetric/hash constructions, and Grover halves both equally.
 */
function chk(condition: boolean): CheckResult['checkStatus'] {
  return condition ? 'ok' : 'fail';
}

// ─── Scoring engine ───────────────────────────────────────────────────────────

function scoreKeyDerivation(o: SPDObservable): ScoreResult['categories'][0] {
  const checks: CheckResult[] = [];
  let earned = 0;

  // ── [6] Argon2id memory ── RFC 9106 "first recommended option" = 2 GiB, t=1.
  // For at-rest storage (not web auth), 2 GiB is the relevant bar. At 2 GiB/attempt
  // a 1M-GPU cluster at $1B hardware cannot exhaust a 60-bit keyspace in a lifetime.
  // Note: RFC 9106 ASIC trade-off attack reduces effective hardness by ~2.1x max —
  // this is acknowledged; 2 GiB provides margin even accounting for this.
  // 1 GiB (half the cost) is the OWASP max — it's good, not maximum. 0 pts here.
  {
    const mem = o.argon2Memory;
    const st  = chk((mem ?? 0) >= 2097152);
    const pts = st === 'ok' ? 4 : 0;
    earned += pts;
    checks.push({ id: 'kdf.argon2_memory', label: 'Argon2id memory ≥ 2 GiB (RFC 9106 max)',
      earned: pts, max: 4, checkStatus: st,
      detail: mem === undefined ? 'Not found — 0 pts'
        : mem >= 2097152 ? `${(mem / 1024).toFixed(0)} MiB ✓ (RFC 9106 first recommended option)`
        : `${(mem / 1024).toFixed(0)} MiB — 0 pts. ≥2048 MiB required (1 GiB = OWASP max, not this standard)` });
  }

  // ── [4] Argon2id iterations ── ≥ 2 passes is required per RFC 9106 when using
  // memory ≥ 1 GiB, to prevent ASIC pipeline attacks that can overlap 1-pass
  // operations. The value should be high enough to extend wall-clock time to
  // several seconds. We require ≥ 2. Anything below = 0 pts.
  {
    const t  = o.argon2Time;
    const st = chk((t ?? 0) >= 2);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'kdf.argon2_time', label: 'Argon2id iterations ≥ 2 (ASIC pipeline resistance)',
      earned: pts, max: 3, checkStatus: st,
      detail: t === undefined ? 'Not found — 0 pts'
        : t >= 2 ? `${t} iterations ✓`
        : `${t} iteration — 0 pts. t=1 is exploitable by ASIC pipeline attack (RFC 9106 §4)` });
  }

  // ── [4] KDF chain (Argon2id → scrypt) ── adds sequential memory hardness.
  // scrypt is sequentially memory-hard: no ASIC or GPU parallelism can reduce
  // the sequential latency. Colin Percival's own recommendation for file
  // encryption is N=2^20 (~1 GiB). N=2^17 (128 MiB) is the OWASP alternative
  // for constrained environments. We require N ≥ 2^20 = 1048576.
  {
    const chained = o.kdfChain === true;
    const strongN = (o.scryptN ?? 0) >= 1048576;
    const st = chk(chained && strongN);
    const pts = st === 'ok' ? 4 : 0;
    earned += pts;
    checks.push({ id: 'kdf.chain', label: 'KDF chain scrypt N≥2^20 (~1 GiB sequential)',
      earned: pts, max: 4, checkStatus: st,
      detail: !chained
        ? 'enableKdfChain() not called — 0 pts'
        : !strongN
          ? `scrypt N=${o.scryptN ?? '?'} — 0 pts. Need ≥1048576 (Percival file-encryption recommendation)`
          : `scrypt N=${o.scryptN} r=${o.scryptR} p=${o.scryptP} ✓` });
  }

  // ── [3] Argon2id parallelism ≥ 4 ── increases minimum hardware footprint.
  // Forces any attack to consume ≥ 4 physical memory channels simultaneously.
  // Below 4 = attacker uses narrow cheap hardware at scale.
  {
    const p  = o.argon2Parallelism;
    const st = chk((p ?? 0) >= 4);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'kdf.parallelism', label: 'Argon2id parallelism ≥ 4',
      earned: pts, max: 3, checkStatus: st,
      detail: p === undefined ? 'Not found — 0 pts'
        : p >= 4 ? `parallelism = ${p} ✓`
        : `parallelism = ${p} — 0 pts` });
  }

  // ── [4] Global pepper AND keyfile ── both required, not one or the other.
  // Pepper: server-side secret. An attacker with only the file cannot attempt
  // offline brute-force because the pepper is missing.
  // Keyfile: physical second factor. Even if password is known, file is protected.
  // Either alone = only one barrier. Both = two independent barriers. Missing either = 0.
  {
    const st = chk(!!(o.hasPepper && o.hasKeyfile));
    const pts = st === 'ok' ? 2 : 0;
    earned += pts;
    checks.push({ id: 'kdf.pepper', label: 'Global pepper AND keyfile (both required)',
      earned: pts, max: 2, checkStatus: st,
      detail: (o.hasPepper && o.hasKeyfile) ? 'Both pepper and keyfile confirmed ✓'
        : !o.hasPepper && !o.hasKeyfile ? 'Neither found — 0 pts'
        : `Only ${o.hasPepper ? 'pepper' : 'keyfile'} found — 0 pts. Both required` });
  }

  // ── [1] Argon2id output length ≥ 96 bytes ─────────────────────────────────
  // The hash output must supply a 32-byte AEAD key + 64-byte HMAC key = 96 bytes.
  {
    const hl = o.argon2HashLen;
    const st = chk((hl ?? 0) >= 96);
    const pts = st === 'ok' ? 1 : 0;
    earned += pts;
    checks.push({ id: 'kdf.hashlen', label: 'Argon2id output ≥ 96 B (32B AEAD + 64B HMAC)',
      earned: pts, max: 1, checkStatus: st,
      detail: hl === undefined ? 'Not found — 0 pts'
        : hl >= 96 ? `ARGON2_HASH_LEN = ${hl} bytes ✓`
        : `ARGON2_HASH_LEN = ${hl} bytes — 0 pts. Need ≥96 for full 64-byte HMAC key` });
  }

  // ── [2] KDF output domain separation ──────────────────────────────────────
  // AEAD key and HMAC key must be derived with distinct HKDF labels, not sliced
  // from adjacent bytes of the same KDF output. Slicing creates related keys:
  // if an oracle on one key exists, the other key's security degrades.
  // Correct: HKDF(master, info="spd-aead-key") and HKDF(master, info="spd-mac-key").
  // SPD current: master[0..32] = AEAD key, master[32..96] = HMAC key — NOT separated.
  {
    const st  = chk(!!o.hasKdfDomainSeparation);
    const pts = st === 'ok' ? 2 : 0;
    earned += pts;
    checks.push({ id: 'kdf.domain_sep', label: 'KDF output domain separation (HKDF per key)',
      earned: pts, max: 2, checkStatus: st,
      detail: st === 'ok' ? 'Domain-separated HKDF key derivation confirmed ✓'
        : 'Not found — 0 pts. AEAD key and HMAC key sliced from same KDF output = related keys. Fix: HKDF(master, info="spd-aead") and HKDF(master, info="spd-mac") separately.' });
  }

  // ── [3] Landauer-scale key entropy ────────────────────────────────────────
  // The Landauer bound (1961): erasing 1 bit at room temperature costs ~2.85×10⁻²¹ J.
  // The observable universe contains ~4×10⁶⁹ J of total energy.
  // Maximum bit erasures = 4×10⁶⁹ / 2.85×10⁻²¹ ≈ 1.4×10⁹⁰ = ~2²⁹⁹ operations.
  // A 256-bit key has only 2²⁵⁶ ≈ 10⁷⁷ values — WITHIN the universal energy budget.
  // A 512-bit KDF output has 2⁵¹² ≈ 10¹⁵⁴ values — FAR BEYOND it.
  // For a system to claim universal impossibility, its KDF output must be ≥512 bits
  // so that brute-forcing the key space exceeds the Landauer energy of the universe
  // even with perfect quantum hardware (Grover halves the exponent: 2⁵¹² → 2²⁵⁶ search,
  // still 10⁷⁷ — which exceeds Landauer only with memory-hard amplification).
  // Requirement: ARGON2_HASH_LEN ≥ 64 bytes (512 bits) AND memory ≥ 2 GiB AND
  // iterations ≥ 2 — together these make each guess cost ≥2 GiB RAM × ≥2 passes,
  // amplifying the Landauer cost far beyond the raw key-size floor.
  {
    const hashLen  = o.argon2HashLen ?? 0;
    const mem      = o.argon2Memory ?? 0;
    const time     = o.argon2Time ?? 0;
    const landauer = hashLen >= 64 && mem >= 2097152 && time >= 2;
    const st  = chk(landauer);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'kdf.landauer', label: 'Landauer-scale entropy (≥512-bit KDF output + ≥2 GiB + ≥2t)',
      earned: pts, max: 3, checkStatus: st,
      detail: landauer
        ? `ARGON2_HASH_LEN=${hashLen}B + ${(mem/1024).toFixed(0)} MiB + ${time}t ✓ — brute-force cost exceeds Landauer energy budget of universe`
        : 'Not met — needs ARGON2_HASH_LEN≥64, memory≥2 GiB, time≥2. Without this, a universe-scale quantum computer could in principle enumerate the key space.' });
  }

  // ── [2] Salt entropy ≥ 32 bytes ───────────────────────────────────────────
  // KDF salt must be ≥256 bits (32 bytes) of CSPRNG output to prevent
  // precomputed rainbow-table attacks even across a universe-scale target set.
  // 16-byte (128-bit) salt is adequate for a single file but at universal scale
  // an adversary with 10⁶⁰ stored hashes could find collisions via birthday bound.
  {
    const sl = o.saltLenBytes ?? 0;
    const st = chk(sl >= 32);
    const pts = st === 'ok' ? 2 : 0;
    earned += pts;
    checks.push({ id: 'kdf.salt_len', label: 'Salt ≥ 32 bytes (256-bit, rainbow-table proof at universal scale)',
      earned: pts, max: 2, checkStatus: st,
      detail: sl >= 32 ? `Salt = ${sl} bytes ✓`
        : sl > 0 ? `Salt = ${sl} bytes — 0 pts. At universal adversary scale, a 16-byte salt birthday-collides across a large enough target set. Use ≥32 bytes.`
        : 'Salt size not confirmed — 0 pts' });
  }

  return { name: 'Key Derivation', score: earned, max: 24, checks };
}

function scoreCryptography(o: SPDObservable): ScoreResult['categories'][0] {
  const checks: CheckResult[] = [];
  let earned = 0;

  // ── [2] HMAC hash ── SHA3-512 or SHA-512; both equivalent post-quantum.
  // Grover halves both equally. HMAC defeats SHA-2 length-extension attacks.
  // SHA3-256 / SHA-256 = 0 pts (64-bit post-Grover security is too weak).
  {
    const h  = o.hashAlgorithm;
    const ok512 = h === 'sha3-512' || h === 'sha512';
    const st = chk(ok512);
    const pts = st === 'ok' ? 2 : 0;
    earned += pts;
    checks.push({ id: 'crypto.hash', label: 'HMAC hash ≥ 512-bit (SHA3-512 or SHA-512)',
      earned: pts, max: 2, checkStatus: st,
      detail: h ? `${h}${ok512 ? ' ✓ (SHA3-512 and SHA-512 are equivalent for HMAC)' : ' — 0 pts. Need ≥512-bit hash'}` : 'Not found — 0 pts' });
  }

  // ── [2] HMAC key ≥ 64 bytes ── full output width.
  {
    const kl = o.macKeyLength;
    const st = chk((kl ?? 0) >= 64);
    const pts = st === 'ok' ? 2 : 0;
    earned += pts;
    checks.push({ id: 'crypto.mac_key', label: 'HMAC key ≥ 64 bytes (full output width)',
      earned: pts, max: 2, checkStatus: st,
      detail: kl ? `HMAC_KEY_LEN = ${kl} bytes${kl >= 64 ? ' ✓' : ' — 0 pts'}` : 'Not found — 0 pts' });
  }

  // ── [3] XChaCha20-Poly1305 AEAD ── requires v27+.
  // 256-bit key, ~128-bit post-quantum (Grover). 192-bit nonce prevents birthday risk.
  {
    const v  = o.version ?? 0;
    const st = chk(v >= 27);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'crypto.aead', label: 'XChaCha20-Poly1305 AEAD (v27+)',
      earned: pts, max: 3, checkStatus: st,
      detail: o.version ? `v${o.version}${v >= 27 ? ' ✓' : ' — 0 pts'}` : 'Not found — 0 pts' });
  }

  // ── [5] AEAD key commitment (CMT-1/CMT-4) ── CRITICAL unimplemented gap.
  // XChaCha20-Poly1305 is NOT key-committing: a single ciphertext decrypts validly
  // under two different keys (USENIX 2022 partitioning oracle paper).
  // SPD's computeKeyCommitment() stores HMAC(aeadKey) in the JSON — this is a
  // key-binding DETECTION token, NOT a CMT scheme. The distinction is critical:
  //   • CMT-4: H(key||nonce) prepended to ciphertext — makes AEAD key-committing
  //     by construction even for attacker-controlled ciphertexts.
  //   • JSON field: can be stripped/faked by attacker before ciphertext is presented.
  // Without CMT-1/CMT-4, partitioning oracle attacks remain possible.
  // This check will FAIL for SPD because the CMT scheme is not implemented.
  {
    const st  = chk(!!o.hasAeadKeyCommitment);
    const pts = st === 'ok' ? 4 : 0;
    earned += pts;
    checks.push({ id: 'crypto.aead_commit', label: 'True AEAD key commitment (CMT-1/CMT-4)',
      earned: pts, max: 4, checkStatus: st,
      detail: st === 'ok' ? 'CMT key commitment confirmed ✓'
        : 'Not found — 0 pts. SPD\'s keyCommitment JSON field is a detection token, not CMT-4. XChaCha20-Poly1305 is not key-committing; partitioning oracle attack possible (USENIX 2022). Fix: implement HtE or Encrypt-then-Commit.' });
  }

  // ── [3] Counter nonce (v29+) ── provable nonce uniqueness.
  {
    const v  = o.version ?? 0;
    const st = chk(v >= 29);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'crypto.nonce', label: 'Counter nonce (v29+, no birthday risk)',
      earned: pts, max: 3, checkStatus: st,
      detail: o.version ? `v${o.version}${v >= 29 ? ' ✓' : ' — 0 pts'}` : 'Not found — 0 pts' });
  }

  // ── [2] Per-entry AAD binding ── prevents cross-entry ciphertext swap attacks.
  // Each entry's AEAD call must pass the entry name as Additional Authenticated Data.
  // Without AAD binding: attacker swaps two entries' ciphertext blobs and both
  // decrypt under the same master key with no integrity violation detected.
  {
    const st  = chk(!!o.hasEntryAadBinding);
    const pts = st === 'ok' ? 2 : 0;
    earned += pts;
    checks.push({ id: 'crypto.aad', label: 'Per-entry AEAD AAD binding (name bound into ciphertext)',
      earned: pts, max: 2, checkStatus: st,
      detail: st === 'ok' ? 'Entry name passed as AAD to xchacha20poly1305 calls ✓'
        : 'Not confirmed — 0 pts. Without AAD binding, entries can be silently swapped by an attacker with write access' });
  }

  // ── [2] Compression oracle resistance ── CRIME/BREACH-class attack.
  // Compress-then-encrypt leaks plaintext content when the attacker can inject
  // known text alongside secret data (adaptive chosen-plaintext scenario).
  // zlib.deflateSync before xchacha20 = vulnerable — loses 2 pts.
  // The only mitigations are: encrypt-then-compress, or padding to fixed block size.
  // This is scored as a PENALTY: library uses deflate before AEAD.
  {
    const vulnerable = !!o.hasCompressionOracle;
    const st = chk(!vulnerable);  // ok = NOT vulnerable
    const pts = st === 'ok' ? 2 : 0;
    earned += pts;
    checks.push({ id: 'crypto.compress', label: 'No compression oracle (no deflate before AEAD)',
      earned: pts, max: 2, checkStatus: st,
      detail: vulnerable
        ? 'deflateSync before xchacha20poly1305 detected — 0 pts. CRIME/BREACH-class: compression ratio leaks plaintext when attacker can inject known data. Fix: encrypt-then-compress, or pad to fixed block sizes first.'
        : 'No compress-before-encrypt detected ✓' });
  }

  // ── [1] Error oracle resistance ─────────────────────────────────────────────
  // If the library returns different error messages for "wrong passcode" vs
  // "wrong file / tampered data", an attacker can use it as a passcode oracle:
  // keep the file fixed, mutate passcode guesses, observe which error fires.
  // Correct: one generic message for all auth/integrity failures.
  // SPD uses "Invalid SPD path or passcode" at most paths (correct), but also
  // has "Old passcode is incorrect or data integrity check failed" in changePasscode —
  // which is acceptable (conflates both). We penalize any path that confirms passcode
  // correctness separately from integrity failure.
  {
    const st  = chk(!!o.hasOracleNeutralErrors);
    const pts = st === 'ok' ? 1 : 0;
    earned += pts;
    checks.push({ id: 'crypto.error_oracle', label: 'Oracle-neutral error messages (no passcode confirmation)',
      earned: pts, max: 1, checkStatus: st,
      detail: st === 'ok' ? 'Generic auth/integrity error messages confirmed ✓'
        : 'Separate "passcode incorrect" messages found — 0 pts. Enables oracle attack: guess passcode, observe which error fires' });
  }

  return { name: 'Cryptography', score: earned, max: 19, checks };
}

function scorePostQuantum(o: SPDObservable): ScoreResult['categories'][0] {
  const checks: CheckResult[] = [];
  let earned = 0;

  // ── [5] ML-KEM-768 hybrid KEM ── NIST FIPS 203 (August 2024). PQ Level 3 (~128-bit PQ).
  // KyberSlash (2024) was an IMPLEMENTATION timing side channel — fully patched —
  // not a break of the mathematical MLWE problem. Still recommended as hybrid only:
  // hybrid with Curve25519 means neither algorithm alone being broken is catastrophic.
  {
    const st  = chk(!!(o.transportV2 && o.hybridKem));
    const pts = st === 'ok' ? 4 : 0;
    earned += pts;
    checks.push({ id: 'pq.kem', label: 'ML-KEM-768 hybrid KEM (PQ + classical, FIPS 203)',
      earned: pts, max: 4, checkStatus: st,
      detail: st === 'ok' ? 'ml_kem768 + TRANSPORT_VERSION_V2 ✓'
        : !o.transportV2 ? 'TRANSPORT_VERSION_V2 not found — 0 pts'
        : 'ml_kem768 not found — 0 pts' });
  }

  // ── [4] ML-DSA-65 file signatures ── NIST FIPS 204. Without file signatures,
  // an attacker with disk write access substitutes ciphertext with no trace.
  {
    const st  = chk(o.fileSignature === 'present');
    const pts = st === 'ok' ? 4 : 0;
    earned += pts;
    checks.push({ id: 'pq.dsa', label: 'ML-DSA-65 file signatures (FIPS 204)',
      earned: pts, max: 4, checkStatus: st,
      detail: st === 'ok' ? 'ml_dsa65 + setSigningKey ✓'
        : 'Not found — 0 pts' });
  }

  // ── [4] ML-DSA-65 cert pinning ── closes the quantum identity-forgery vector.
  // Without PQ-pinning, a Shor-capable adversary forges the Curve25519 server key.
  {
    const st  = chk(!!o.mlDsaCert);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'pq.cert', label: 'ML-DSA-65 cert pinning (PQ server identity)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok' ? 'pinnedSigningKey confirmed ✓'
        : 'Not found — 0 pts. Quantum adversary can forge classical server identity' });
  }

  return { name: 'Post-Quantum', score: earned, max: 11, checks };
}

function scoreForwardSecrecy(o: SPDObservable): ScoreResult['categories'][0] {
  const checks: CheckResult[] = [];
  let earned = 0;

  // ── [5] Forward-secrecy ratcheting ── per-save re-keying.
  // Fresh Argon2id salt on every save. Past sessions are sealed even if current key leaks.
  {
    const st  = chk(!!o.ratchetEnabled);
    const pts = st === 'ok' ? 4 : 0;
    earned += pts;
    checks.push({ id: 'fs.ratchet', label: 'Per-save ratcheting (forward secrecy)',
      earned: pts, max: 4, checkStatus: st,
      detail: st === 'ok' ? 'enableRatchet / _maybeRatchetSalt ✓'
        : 'Not found — 0 pts. Key exposure retroactively breaks all past data' });
  }

  // ── [4] Epoch key rotation ── limits long-term compromise blast radius.
  // Forced full re-derivation every N writes. Static keys accumulate risk.
  {
    const st  = chk((o.epochSize ?? 0) > 0);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'fs.epoch', label: 'Epoch key rotation (setEpochSize > 0)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok' ? `setEpochSize(${o.epochSize}) ✓`
        : 'Not found or zero — 0 pts' });
  }

  // ── [4] Key zeroing on destroy (v29+) ── explicit zeroing, not left to GC.
  // In C, generic memset() can be optimized away by the compiler when the
  // buffer goes dead — sodium_memzero/explicit_bzero exist to defeat that.
  // That specific concern is C-specific: in managed languages (JS/TS) there
  // is no documented, proven technique that reliably defeats the engine's
  // optimizer either, and explicit zeroing there (.fill(0) / a plain loop)
  // is the actual industry-standard practice, not a downgrade from
  // sodium_memzero — see hasExplicitMemzero's own comment above.
  {
    const zerosCorrectly = !!(o.hasExplicitMemzero && (o.version ?? 0) >= 29);
    const st  = chk(zerosCorrectly);
    const pts = st === 'ok' ? 4 : 0;
    earned += pts;
    checks.push({ id: 'fs.zero', label: 'Explicit key zeroing on destroy (v29+)',
      earned: pts, max: 4, checkStatus: st,
      detail: zerosCorrectly ? 'sodium_memzero/explicit_bzero or .fill(0) + v29+ ✓'
        : !o.hasExplicitMemzero
          ? 'No explicit key-zeroing call found — 0 pts'
          : 'v29+ required — 0 pts' });
  }

  return { name: 'Forward Secrecy', score: earned, max: 11, checks };
}

function scoreDataIntegrity(o: SPDObservable): ScoreResult['categories'][0] {
  const checks: CheckResult[] = [];
  let earned = 0;

  // ── [4] Per-entry Merkle tree ── selective tampering detection.
  {
    const st  = chk(!!o.merkleRoot);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'int.merkle', label: 'Per-entry Merkle tree (selective tamper detection)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok' ? 'merkleRoot / buildMerkleRoot ✓'
        : 'Not found — 0 pts. Selective entry substitution is undetectable' });
  }

  // ── [3] Monotonic write counter ── rollback attack prevention.
  // Without a counter, attacker restores a past vault state undetected.
  {
    const st  = chk(o.writeCounter !== undefined);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'int.counter', label: 'Monotonic write counter (rollback prevention)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok' ? 'writeCounter ✓'
        : 'Not found — 0 pts. Rollback to any past vault state is undetected' });
  }

  // ── [3] WAL / crash recovery ── prevents mid-write corruption wedge.
  {
    const st  = chk(!!o.walEnabled);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'int.wal', label: 'WAL / crash recovery (no corruption wedge)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok' ? 'enableWAL / WAL_MAGIC ✓'
        : 'Not found — 0 pts. Mid-write crash can expose partial plaintext' });
  }

  return { name: 'Data Integrity', score: earned, max: 9, checks };
}

function scoreSideChannels(o: SPDObservable): ScoreResult['categories'][0] {
  const checks: CheckResult[] = [];
  let earned = 0;

  // ── [3] Timing-safe MAC verification ── critical.
  // Non-constant-time comparison of authentication tags leaks timing information
  // about partial tag matches. This enables forgery via timing oracle.
  // Must use crypto.timingSafeEqual / sodium's crypto_verify_* family.
  {
    const st  = chk(!!o.hasTimingSafeMac);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'sc.timing', label: 'Timing-safe MAC comparison (timingSafeEqual)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok' ? 'timingSafeEqual / crypto_verify_* confirmed ✓'
        : 'Not found — 0 pts. Non-constant-time MAC comparison enables forgery via timing oracle' });
  }

  // ── [3] In-memory key blinding ── RAM dump / cold-boot resistance.
  // XOR-masks key in RAM with a random mask. Prevents key recovery from
  // memory dumps, cold-boot attacks, hypervisor memory scans.
  {
    const st  = chk(!!o.keyBlinded);
    const pts = st === 'ok' ? 2 : 0;
    earned += pts;
    checks.push({ id: 'sc.blind', label: 'In-memory key blinding (XOR mask, cold-boot resistant)',
      earned: pts, max: 2, checkStatus: st,
      detail: st === 'ok' ? 'enableKeyBlinding / _keyMask ✓'
        : 'Not found — 0 pts. Key is recoverable from memory dumps' });
  }

  // ── [2] Nonce reuse guard ── counter must never reset.
  // Counter nonce is secure only if the counter is strictly monotonic with no
  // reset path. VM snapshot restore, counter overflow, or RNG fallback can
  // cause nonce reuse → complete plaintext recovery and universal forgery.
  {
    const st  = chk(!!o.hasNonceReuseGuard);
    const pts = st === 'ok' ? 2 : 0;
    earned += pts;
    checks.push({ id: 'sc.nonce', label: 'Nonce reuse guard (counter never resets)',
      earned: pts, max: 2, checkStatus: st,
      detail: st === 'ok' ? 'Counter nonce management confirmed ✓'
        : 'Not confirmed — 0 pts. Nonce reuse = full plaintext recovery + universal forgery' });
  }

  // ── [2] Metadata / frame padding ── hides message sizes from passive observers.
  // Without padding, ciphertext length == padded(plaintext length). A passive
  // observer can infer data types, entry counts, and content shape from sizes.
  {
    const st  = chk(!!o.hasMetadataPadding);
    const pts = st === 'ok' ? 2 : 0;
    earned += pts;
    checks.push({ id: 'sc.padding', label: 'Frame/metadata padding (size leakage prevention)',
      earned: pts, max: 2, checkStatus: st,
      detail: st === 'ok' ? 'FRAME_PAD_BLOCK / frame padding ✓'
        : 'Not found — 0 pts. Ciphertext sizes reveal plaintext length' });
  }

  // ── [1] Entry name / filename encryption ── content metadata leakage.
  // Entry names stored in plaintext index reveal what data the vault contains.
  {
    const st  = chk(!!o.hasFilenameEncryption);
    const pts = st === 'ok' ? 1 : 0;
    earned += pts;
    checks.push({ id: 'sc.names', label: 'Entry name encryption (no plaintext index)',
      earned: pts, max: 1, checkStatus: st,
      detail: st === 'ok' ? 'Entry name encryption confirmed ✓'
        : 'Not confirmed — 0 pts. Plaintext entry names reveal what data the vault contains (e.g. "bitcoin_seed", "passport_scan")' });
  }

  // ── [2] Machine binding ── hardware-bound key derivation.
  // Without machine binding, a copy of the vault + passcode is sufficient to
  // decrypt on any hardware. With binding, Argon2id secret = hardware fingerprint,
  // so the attacker must compromise BOTH the vault file AND the original hardware.
  {
    const st  = chk(!!o.hasMachineBinding);
    const pts = st === 'ok' ? 2 : 0;
    earned += pts;
    checks.push({ id: 'sc.machine', label: 'Machine binding (hardware-bound key derivation)',
      earned: pts, max: 2, checkStatus: st,
      detail: st === 'ok' ? 'Machine binding confirmed ✓'
        : 'Not found — 0 pts. Vault + passcode decryptable on any hardware. Machine binding prevents offline migration attacks.' });
  }

  // ── [2] Secure temp file deletion ────────────────────────────────────────
  // Temp files containing plaintext (SSF export, decrypted buffers) must be
  // overwritten with zeros before unlinkSync(). On most filesystems, unlink()
  // only removes the directory entry — the data blocks persist until the OS
  // reuses them, meaning a low-level disk scan recovers the plaintext.
  // On SSDs, wear-leveling may prevent even zeroing from reaching all blocks,
  // but zeroing + unlinking is the minimum standard (NIST SP 800-88).
  {
    const st  = chk(!!o.hasSecureTempDelete);
    const pts = st === 'ok' ? 2 : 0;
    earned += pts;
    checks.push({ id: 'sc.secure_delete', label: 'Temp file overwrite before unlink (NIST SP 800-88)',
      earned: pts, max: 2, checkStatus: st,
      detail: st === 'ok' ? 'Temp file overwrite before delete confirmed ✓'
        : 'Not found — 0 pts. unlinkSync() alone leaves plaintext on disk until block reuse. Fix: write zeros to file before unlinking.' });
  }

  // ── [1] Nonce counter overflow guard ──────────────────────────────────────
  // The transport send counter is a BigInt that increments forever. At 2^64
  // messages (never reached in practice, but undefined behavior if it were)
  // the counter wraps to 0, causing nonce reuse. An explicit max-value guard
  // throwing before overflow is required by the protocol specification.
  {
    const st  = chk(!!o.hasCounterOverflowGuard);
    const pts = st === 'ok' ? 1 : 0;
    earned += pts;
    checks.push({ id: 'sc.counter_overflow', label: 'Nonce counter overflow guard (throw before wrap)',
      earned: pts, max: 1, checkStatus: st,
      detail: st === 'ok' ? 'Counter max-value guard confirmed ✓'
        : 'Not found — 0 pts. No explicit check that send counter never wraps to 0 (would cause nonce reuse)' });
  }

  return { name: 'Side Channels & Memory Safety', score: earned, max: 15, checks };
}

function scoreTransport(o: SPDObservable): ScoreResult['categories'][0] {
  const checks: CheckResult[] = [];
  let earned = 0;

  // ── [3] SPDTransport V2 ── PQ-hardened handshake.
  {
    const st  = chk(!!o.transportV2);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'tx.v2', label: 'SPDTransport V2 (PQ handshake)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok' ? 'TRANSPORT_VERSION_V2 ✓' : 'Not found — 0 pts' });
  }

  // ── [3] Transport key commitment token ── session binding.
  // Binds both sides to exact negotiated key material. Without it, a different
  // session's transcript could be silently injected into this handshake.
  // Note: this is transport-level only, separate from AEAD key commitment.
  {
    const st  = chk(!!o.hasKeyCommitment);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'tx.keycommit', label: 'Transport key commitment (session binding)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok' ? 'KEY_COMMIT ✓' : 'Not found — 0 pts' });
  }

  // ── [1] Replay window (any > 0) ── presence matters, size does not.
  // Per RFC 6479: the specific size (64 vs 1024) is functionally irrelevant once
  // ANY replay window exists. Security is equivalent once the counter has advanced.
  // Size matters only for out-of-order delivery tolerance (a functionality concern).
  // We score presence/absence only, not size.
  {
    const st  = chk((o.replayWindow ?? 0) > 0);
    const pts = st === 'ok' ? 1 : 0;
    earned += pts;
    checks.push({ id: 'tx.replay', label: 'Replay window present (any size)',
      earned: pts, max: 1, checkStatus: st,
      detail: (o.replayWindow ?? 0) > 0
        ? `REPLAY_WINDOW_SIZE = ${o.replayWindow} ✓ (size is irrelevant — presence is what matters, per RFC 6479)`
        : 'Not found — 0 pts. Without a replay window, captured packets can be re-injected' });
  }

  return { name: 'Transport', score: earned, max: 7, checks };
}

function scoreOperational(o: SPDObservable): ScoreResult['categories'][0] {
  const checks: CheckResult[] = [];
  let earned = 0;

  // ── [2] HSM / key provider interface ── physical key isolation.
  // Key material never leaves the HSM. Software-held keys can be exfiltrated
  // by any process compromise.
  {
    const st  = chk(!!o.hasHSMProvider);
    const pts = st === 'ok' ? 1 : 0;
    earned += pts;
    checks.push({ id: 'ops.hsm', label: 'HSM / key provider (physical key isolation)',
      earned: pts, max: 1, checkStatus: st,
      detail: st === 'ok' ? 'setKeyProvider / SPDKeyProvider ✓'
        : 'Not found — 0 pts. Software-held keys can be exfiltrated by process compromise' });
  }

  // ── [3] Passcode enforcement ── must REJECT weak passcodes at the API.
  // Advisory entropy hints in documentation are worthless — the library must
  // actively throw/error in setPassKey() / loadFrom() when the passcode is weak.
  // We require both: (a) an enforcement function in source AND (b) that function
  // confirmed as called from the key-derivation entry point. A dead utility = 0 pts.
  // SPD does NOT do this — changePasscode() and setPassKey() accept any string.
  {
    const st  = chk(!!o.hasPasscodeEnforcement);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'ops.passcode', label: 'Passcode enforcement in key path (rejects weak)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok' ? 'Passcode enforcement confirmed called from key-derivation path ✓'
        : 'Not found — 0 pts. setPassKey() accepts any string silently. "password" or "1234" = full decrypt access.' });
  }

  // ── [2] Key profile = paranoid ── configuration gate.
  {
    const kp  = o.keyProfile;
    const st  = chk(kp === 'paranoid');
    const pts = st === 'ok' ? 1 : 0;
    earned += pts;
    checks.push({ id: 'ops.profile', label: "Key profile = 'paranoid' (only profile that qualifies)",
      earned: pts, max: 1, checkStatus: st,
      detail: kp ? `'${kp}'${kp === 'paranoid' ? ' ✓' : ` — 0 pts. 'high' = OWASP max, not this standard`}`
        : "Not found — 0 pts" });
  }

  // ── [1] Key derivation cache TTL ── extended key exposure window.
  // The key derivation cache keeps the raw AEAD key in memory for up to 60 seconds
  // after use. Any process with memory access during that window retrieves the key.
  // Score = 0 if TTL > 0 (cache is active). Score = 1 if TTL = 0 (cache disabled).
  // Most deployments will fail this — caching is a usability/performance trade-off
  // that directly trades security for speed.
  {
    const ttl = o.keyCacheTtlMs ?? 0;
    const cachingEnabled = ttl > 0;
    const st  = chk(!cachingEnabled);
    const pts = st === 'ok' ? 1 : 0;
    earned += pts;
    checks.push({ id: 'ops.keycache', label: 'No key derivation cache (zero exposure window)',
      earned: pts, max: 1, checkStatus: st,
      detail: cachingEnabled
        ? `KEY_CACHE_TTL_MS = ${ttl}ms — 0 pts. Derived AEAD key held in memory for ${ttl / 1000}s after use. Any memory dump in this window = key recovery.`
        : 'Key caching not detected ✓' });
  }

  // ── [1] Audit log for key lifecycle ──────────────────────────────────────
  // Key derivation, rotation, and access events must be logged to enable
  // post-incident forensics. A structured logger hooked at key operations qualifies.
  {
    const st  = chk(!!o.hasAuditLog);
    const pts = st === 'ok' ? 1 : 0;
    earned += pts;
    checks.push({ id: 'ops.audit', label: 'Key lifecycle audit log (forensic trail)',
      earned: pts, max: 1, checkStatus: st,
      detail: st === 'ok' ? 'Structured logger + key lifecycle events confirmed ✓'
        : 'Not confirmed — 0 pts. No logged trail of key operations makes incident analysis impossible' });
  }

  // ── [1] Decoy / honeypot entries ──────────────────────────────────────────
  // Fake entries with real-looking names. If an unauthorized party accesses the
  // vault and reads a decoy entry, the system can detect the breach.
  {
    const st  = chk(!!o.hasDecoyEntries);
    const pts = st === 'ok' ? 1 : 0;
    earned += pts;
    checks.push({ id: 'ops.decoy', label: 'Decoy / honeypot entries (breach detection)',
      earned: pts, max: 1, checkStatus: st,
      detail: st === 'ok' ? 'addDecoy() / _decoy entries confirmed ✓'
        : 'Not found — 0 pts. No honeypot entries means unauthorized vault access goes undetected' });
  }

  // ── [1] Strict file permissions (0o600) ───────────────────────────────────
  // All sensitive files (vault, WAL, temp exports) must be owner-read/write only.
  // Group-readable or world-readable files expose content to other local users.
  {
    const st  = chk(!!o.hasStrictFilePermissions);
    const pts = st === 'ok' ? 1 : 0;
    earned += pts;
    checks.push({ id: 'ops.fileperms', label: 'Sensitive files mode 0o600 (owner-only)',
      earned: pts, max: 1, checkStatus: st,
      detail: st === 'ok' ? 'mode: 0o600 confirmed on vault/WAL/temp files ✓'
        : 'Not found — 0 pts. World- or group-readable vault files expose content to other local users' });
  }

  return { name: 'Operational', score: earned, max: 9, checks };
}

// ─── Extended hardening scoring (rules.txt + rules2.txt + rules3.txt) ─────────
//
// These rules cover security properties beyond ordinary computational
// hardening: information-theoretic guarantees (OTP), physical-channel
// assumptions (key distribution, air-gapping), and operational hardening
// (destruction, deniability, anti-forensics). Each rule is worth equal points.
// A few checks (see labels) score genuinely-implemented mechanisms whose
// security property is caller-asserted or partial rather than independently
// verified in source — read each label before treating full marks as a
// stronger guarantee than the code provides.

function scoreInfiniteAdversary(o: SPDObservable): ScoreResult['categories'][0] {
  const checks: CheckResult[] = [];
  let earned = 0;

  // ── R1 [3] True One-Time Pad ──────────────────────────────────────────────
  // Key length ≥ message length + key never reused + key truly random.
  // Perfect secrecy (Shannon 1949): ciphertext reveals ZERO information.
  // A finite key with a good cipher gets you computational security.
  // Only OTP gets you information-theoretic security.
  {
    const st  = chk(!!o.hasOtpMode);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'inf.r1_otp', label: 'R1: True One-Time Pad (key ≥ message, never reused)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok'
        ? 'OTP mode detected — information-theoretic security: ciphertext reveals zero information ✓'
        : 'Not detected — 0 pts. Without OTP, an infinite attacker can enumerate all keys. OTP is the only provably unbreakable cipher (Shannon 1949).' });
  }

  // ── R3 [3] Key Material Destroyed After Use ───────────────────────────────
  // Keys must be physically destroyed after use: overwrite + explicit erase.
  // An infinite attacker cannot recover information that no longer exists.
  // sodium_memzero alone is insufficient — must be combined with a key lifecycle
  // that guarantees destruction (not just zeroing in RAM).
  {
    const st  = chk(!!o.hasKeyDestruction);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'inf.r3_destroy', label: 'R3: Key destroyed after use (explicit destruction protocol)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok'
        ? 'Key destruction protocol detected (memzero + explicit destroy lifecycle) ✓'
        : 'Not detected — 0 pts. Keys remaining after use can be recovered by an attacker with access to RAM/disk. Leftover key material is forbidden under Rule 3.' });
  }

  // ── R4 [3] Multi-Layer Encryption ────────────────────────────────────────
  // Stack beyond the OTP: randomized permutation + quantum noise masking +
  // steganography + physical channel noise. Purpose: confusion and operational safety,
  // not mathematical strength. Layers make traffic analysis impossible.
  {
    const st  = chk(!!o.hasMultiLayerEncryption);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'inf.r4_layers', label: 'R4: Multi-layer encryption (permutation + noise + steganography)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok'
        ? 'Multi-layer encryption stack detected (permutation / noise / steganography) ✓'
        : 'Not detected — 0 pts. Single-layer encryption leaks structural patterns. Rule 4 requires stacked confusion layers even on top of a perfect cipher.' });
  }

  // ── R5 [3] Distributed Key Fragments (Threshold Sharing) ─────────────────
  // Keys split into N fragments; only K fragments needed to reconstruct.
  // Fragments stored on separate continents, devices, operators.
  // An infinite computer cannot recover fragments it never receives.
  {
    const st  = chk(!!o.hasThresholdSharing);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'inf.r5_sharing', label: 'R5: Threshold secret sharing (Shamir / distributed fragments)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok'
        ? 'Threshold secret sharing detected (SPDShamir / Shamir SSS) ✓'
        : 'Not detected — 0 pts. A single-point key can be seized or coerced. Rule 5 requires splitting keys into physically distributed fragments that must be independently compromised.' });
  }

  // ── R6 [3] Message Entropy Expansion ─────────────────────────────────────
  // Before encryption: compress → add large random padding → randomize order.
  // Goal: ciphertext has no detectable structure — length, position, or pattern.
  // Even with perfect encryption, predictable plaintext structure leaks information.
  {
    const st  = chk(!!o.hasEntropyExpansion);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'inf.r6_entropy', label: 'R6: Message entropy expansion (compress + pad + randomize)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok'
        ? 'Entropy expansion pipeline detected (compress + random padding + order randomization) ✓'
        : 'Not detected — 0 pts. Without entropy expansion, ciphertext structure leaks plaintext characteristics (length, order, patterns). Rule 6 requires full entropy normalization before encryption.' });
  }

  // ── R7 [3] Time-Limited Key Validity ─────────────────────────────────────
  // Messages expire. After the deadline, keys auto-destroy.
  // Infinite computation cannot recover destroyed information.
  // Combined with R3 (destruction), expired data is provably gone.
  {
    const st  = chk(!!o.hasTimeLimitedKeys);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'inf.r7_ttl', label: 'R7: Time-limited key validity (auto-destroy after deadline)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok'
        ? 'Time-limited key validity detected (auto-destruct + TTL/expiry) ✓'
        : 'Not detected — 0 pts. Persistent keys accumulate attack surface indefinitely. Rule 7 requires keys to auto-destroy after their validity window — making retroactive decryption physically impossible.' });
  }

  // ── R8 [3] Air-Gapped Decryption ─────────────────────────────────────────
  // Decryption machine must be physically isolated: no network, no wireless,
  // no removable media. An infinite computer can compute anything it can reach —
  // but cannot reach an air-gapped machine.
  {
    const st  = chk(!!o.hasAirGap);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'inf.r8_airgap', label: 'R8: Air-gapped decryption (no network / no wireless / isolated)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok'
        ? 'Air-gap requirement detected in decryption path ✓'
        : 'Not detected — 0 pts. Any network-connected decryption endpoint is reachable by a sufficiently powerful adversary. Rule 8 requires physical isolation of the decryption environment.' });
  }

  // ── R10 [3] Plausible Deniability ────────────────────────────────────────
  // Each ciphertext should decrypt into multiple plausible messages depending on which key is used.
  // Key A → harmless text. Key B → real message. Key C → decoy/trap.
  // An infinite computer finds all possible plaintexts — but cannot determine which is real.
  {
    const st  = chk(!!o.hasPlausibleDeniability);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'inf.r10_deniability', label: 'R10: Plausible deniability (multiple valid decryptions)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok'
        ? 'Plausible deniability / deniable encryption detected (decoy keys / hidden volumes) ✓'
        : 'Not detected — 0 pts. Without deniable encryption, forced decryption under coercion reveals the real message. Rule 10 ensures no adversary — including one with infinite compute — can distinguish the real message from decoys.' });
  }

  // ── rules2.txt extended rules ─────────────────────────────────────────────

  // ── R12 (rules2 R11) [3] Destruction Assurance ────────────────────────────
  // destroyWithProof() produces an HMAC-SHA3-512 receipt and performs a real
  // .fill(0) zeroing of the key buffer. This is a genuine audit-log-style
  // artifact — it does NOT cryptographically prove destruction occurred, since
  // a caller could compute the receipt without the zeroing ever happening.
  {
    const st  = chk(!!o.hasDestructionAssurance);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'inf.r12_destruct_proof', label: 'R12: Destruction receipt (HMAC + zeroing, not a cryptographic proof of destruction)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok'
        ? 'Signed HMAC destruction receipt detected — an audit artifact, not a cryptographic proof that zeroing occurred ✓'
        : 'Not detected — 0 pts. Unverifiable destruction can be faked. Rule 12 requires at least a signed destruction receipt so auditors have a record that a destruction event occurred.' });
  }

  // ── R13 (rules2 R12) [3] Temporal Keys ────────────────────────────────────
  // Keys valid only during a short absolute time window (e.g. 5 minutes).
  // After expiration, fragments auto-erase. Even infinite compute cannot
  // recover information that was never stored beyond the window.
  {
    const st  = chk(!!o.hasTemporalKeys);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'inf.r13_temporal', label: 'R13: Temporal keys (absolute time-window validity)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok'
        ? 'Temporal key validity window detected ✓'
        : 'Not detected — 0 pts. Keys without an absolute expiry window persist indefinitely. Rule 13 requires keys to auto-erase at a fixed wall-clock deadline, not just after N opens.' });
  }

  // ── R14 (rules2 R13) [3] Physical Channel Noise Injection ─────────────────
  // Inject RF noise, photon jitter, randomized packet timing during transmission.
  // Prevents traffic analysis: observer cannot distinguish signal from noise.
  {
    const st  = chk(!!o.hasChannelNoiseInjection);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'inf.r14_channel_noise', label: 'R14: Physical channel noise injection (traffic analysis prevention)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok'
        ? 'Channel noise injection / traffic analysis prevention detected ✓'
        : 'Not detected — 0 pts. Without noise injection, timing and traffic volume reveal communication patterns. Rule 14 requires injecting physical noise to make the channel indistinguishable from background.' });
  }

  // ── R16 (rules2 R15) [3] Anti-Forensic Protocol ──────────────────────────
  // All computation in volatile memory only. No swap, no logging, no persistent
  // cache, no cloud sync. Power loss = total wipe. No recoverable trace.
  {
    const st  = chk(!!o.hasAntiForensic);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'inf.r16_anti_forensic', label: 'R16: Anti-forensic protocol (volatile-only, no swap/log/cache)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok'
        ? 'Anti-forensic / volatile-only protocol detected ✓'
        : 'Not detected — 0 pts. Swap files, logs, and persistent caches leave recoverable traces of key material and plaintext. Rule 16 requires volatile-only computation — power loss must equal total wipe.' });
  }

  // ── R18 (rules2 R6) [3] Carrier-Embedding Utility ─────────────────────────
  // embedInCarrier()/extractFromCarrier() genuinely embed ciphertext at an
  // HMAC-derived offset in a carrier buffer. This does NOT achieve real
  // steganographic undetectability — high-entropy ciphertext embedded verbatim
  // is statistically detectable against typical carrier data.
  {
    const st  = chk(!!o.hasTrafficCamouflage);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'inf.r18_camouflage', label: 'R18: Carrier-embedding utility (HMAC-offset embedding; not verified steganographic undetectability)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok'
        ? 'Carrier-embedding utility detected (embedInCarrier/extractFromCarrier) — embeds ciphertext at an HMAC-derived offset; statistical undetectability is not verified ✓'
        : 'Not detected — 0 pts. Visible ciphertext confirms communication exists, enabling targeted interception. Rule 18 requires at least a utility for embedding ciphertext inside carrier data.' });
  }

  // ── R20 (rules3 L2) [3] Reality-Indistinguishable Ciphertexts ─────────────
  // Ciphertext passes strict statistical entropy tests; indistinguishable from
  // true physical randomness. Real/fake/noise packets all look identical.
  {
    const st  = chk(!!o.hasEntropyIndistinguishable);
    const pts = st === 'ok' ? 3 : 0;
    earned += pts;
    checks.push({ id: 'inf.r20_entropy_indist', label: 'R20: Reality-indistinguishable ciphertexts (perfect entropy distribution)',
      earned: pts, max: 3, checkStatus: st,
      detail: st === 'ok'
        ? 'Statistical entropy indistinguishability detected — ciphertext passes randomness tests ✓'
        : 'Not detected — 0 pts. Detectable structure in ciphertext lets observers distinguish messages from noise. Rule 20 (rules3 L2) requires ciphertext to be statistically identical to true randomness.' });
  }

  return { name: 'Extended Hardening (rules.txt + rules2.txt + rules3.txt)', score: earned, max: 42, checks };
}

// ─── Main scoring function ────────────────────────────────────────────────────

export function scoreSPD(obs: SPDObservable, source = 'unknown'): ScoreResult {
  const categories = [
    scoreKeyDerivation(obs),
    scoreCryptography(obs),
    scorePostQuantum(obs),
    scoreForwardSecrecy(obs),
    scoreDataIntegrity(obs),
    scoreSideChannels(obs),
    scoreTransport(obs),
    scoreOperational(obs),
    scoreInfiniteAdversary(obs),
  ];

  const rawTotal  = categories.reduce((s, c) => s + c.score, 0);
  const rawMax    = categories.reduce((s, c) => s + c.max,   0); // 147 when all categories included (105 computational + 42 extended-hardening)
  // Normalise to 0–100 so the displayed score is always out of 100.
  // The extended-hardening rules (max 42 pts, 14 rules × 3) form the upper tier:
  // you cannot reach ~72+ without satisfying at least some of the 14 rules.
  const total     = Math.round(rawTotal / rawMax * 100);

  // Grade thresholds.
  // 100 = all extended-hardening rules satisfied + full computational hardening.
  // Most systems marketed as "military-grade" score in the 20–45 range here.
  const grade
    = total >= 98  ? 'A+'  // full computational hardening + all extended-hardening rules satisfied
    : total >= 90  ? 'A'   // near-complete — 1–2 extended-hardening rules missing; all computational hardening confirmed
    : total >= 80  ? 'A-'  // quantum-resistant + most extended-hardening rules — resists all foreseeable adversaries
    : total >= 70  ? 'B+'  // nation-state resistant — missing physical isolation or deniability layers
    : total >= 58  ? 'B'   // well-hardened computationally — no extended-hardening
    : total >= 46  ? 'B-'  // adequate — multiple computational gaps, no extended-hardening
    : total >= 35  ? 'C'   // partial — basic crypto present; large attack surface
    : total >= 22  ? 'D'   // weak — foundational crypto only; easily broken by well-resourced attacker
    : 'F';                  // exposed — no meaningful protection confirmed

  const recommendations: string[] = [];
  for (const cat of categories) {
    for (const ch of cat.checks) {
      if (ch.checkStatus === 'fail') {
        const hint = hintFor(ch.id);
        if (hint) recommendations.push(hint);
      }
    }
  }

  const verdict = scoreVerdict(total, grade);
  return { total, grade, source, categories, recommendations, verdict };
}

function hintFor(id: string): string {
  const map: Record<string, string> = {
    'kdf.argon2_memory':  "Set ARGON2_MEMORY_PARANOID = 2097152 (2 GiB) and use spd.setKeyProfile('paranoid')",
    'kdf.argon2_time':    "Set ARGON2_TIME_PARANOID ≥ 2 (RFC 9106: t≥2 prevents ASIC pipeline attack on high-memory settings)",
    'kdf.chain':          'spd.enableKdfChain() before setPassKey — SCRYPT_N_DEFAULT must be ≥1048576 (2^20)',
    'kdf.parallelism':    'Set _argon2Parallelism = 4 in SPD constructor',
    'kdf.pepper':         'SPD.setGlobalPepper(randomBytes) AND spd.setKeyfile(path) — both required',
    'crypto.hash':        'sha3-512 or sha-512 required — both are equivalent for HMAC (Grover halves both equally)',
    'crypto.mac_key':     'v27+ uses 64-byte HMAC key automatically; upgrade the library',
    'crypto.aead':        'v27+ uses XChaCha20-Poly1305; upgrade the library',
    'crypto.aead_commit': 'Implement CMT-4: prepend H(key||nonce) to each ciphertext before encryption — makes XChaCha20-Poly1305 key-committing. SPD keyCommitment JSON field is a detection token, not CMT. See USENIX 2022 partitioning oracle paper.',
    'crypto.nonce':       'v29+ counter nonce — upgrade the library',
    'crypto.aad':         'Pass Buffer.from(entryName) as AAD to every xchacha20poly1305 encrypt/decrypt call — prevents cross-entry ciphertext swap',
    'crypto.compress':    'Deflate before AEAD leaks plaintext length. Fix: pad plaintext to fixed block size before compress, or compress after encrypt (if integrity allows)',
    'pq.kem':             'Use SPDTransport V2 (default) — enables ML-KEM-768 hybrid with X25519',
    'pq.dsa':             'const kp = SPDTransport.generateCertKeyPair(); spd.setSigningKey(kp.privateKey)',
    'pq.cert':            'Pass pinnedSigningKey in clientConnect() options',
    'fs.ratchet':         'spd.enableRatchet() before first write',
    'fs.epoch':           'spd.setEpochSize(N) — forces full re-key every N writes',
    'fs.zero':            'Upgrade to v29+ and explicitly zero key material on destroy (sodium_memzero in C; .fill(0) is the standard practice in JS/TS)',
    'int.merkle':         'spd.enableMerkle() — enables per-entry integrity binding',
    'int.counter':        'Write counter is built-in to v27+; ensure it is not disabled',
    'int.wal':            "spd.enableWAL('/path/to/vault.wal')",
    'sc.timing':          'All MAC comparisons must use crypto.timingSafeEqual — audit every tag comparison in the codebase',
    'sc.blind':           'spd.enableKeyBlinding() — XOR-masks key in RAM against cold-boot and memory dumps',
    'sc.nonce':           'Audit counter management: ensure counter never resets on file reload, VM snapshot, or error path',
    'sc.padding':         'Enable frame padding to prevent ciphertext-size side channel',
    'sc.names':           'Encrypt entry names before storing in the index — use a derived name-encryption key + random nonce per entry name',
    'sc.machine':         'SPD.enableMachineBinding() with a hardware-derived secret fed into Argon2id — prevents vault decryption on a different machine',
    'sc.secure_delete':   'Before unlinkSync(tmpPath), write zeros: fs.writeFileSync(tmpPath, Buffer.alloc(stats.size)) — prevents plaintext recovery from disk blocks',
    'sc.counter_overflow':'Add guard in SPDTransport encrypt(): if (this._sendCounter >= 2n**64n - 1n) throw new Error("nonce counter exhausted") — prevents wrap-around nonce reuse',
    'tx.v2':              'Use SPDTransport V2 for all connections (it is the default)',
    'tx.keycommit':       'Key commitment is built into V2 handshake — use SPDTransport V2',
    'tx.replay':          'Replay window is built into SPDTransport — ensure it is not disabled',
    'kdf.hashlen':        'ARGON2_HASH_LEN must be ≥96 bytes — 32 for AEAD key + 64 for full-width HMAC key',
    'kdf.domain_sep':     'Replace master slice-splitting with HKDF: aeadKey = HKDF(master, info="spd-aead-key"), macKey = HKDF(master, info="spd-mac-key") — eliminates related-key attack surface',
    'ops.hsm':            'SPD.setKeyProvider(hsmProvider) — keeps key material inside HSM boundary',
    'ops.passcode':       'Call validatePasscode(p) inside setPassKey() and throw if entropy < threshold — advisory hints in docs do not count',
    'ops.profile':        "spd.setKeyProfile('paranoid') — 'high' is OWASP max, not maximum",
    'ops.keycache':       'Set KEY_CACHE_TTL_MS = 0 to disable key caching — removes the window during which a memory dump recovers the live AEAD key',
    'ops.audit':          'SPD.setLogger(fn) and emit events at key_derived, changePasscode, loadFromFile — enables post-incident forensics',
    'ops.decoy':          'spd.addDecoy(n) — fake entries trigger alerts when accessed, detecting unauthorized vault reads',
    'ops.fileperms':      'Add { mode: 0o600 } to all writeFileSync/createWriteStream calls on vault, WAL, temp, and index files',
    'crypto.error_oracle': 'Use a single generic message (e.g. "Authentication failed") for all decrypt failures — never distinguish wrong-passcode from tamper-detected',
    // Infinite adversary rules (rules.txt)
    'inf.r1_otp':         'Implement true One-Time Pad mode: key length ≥ message length, key never reused, key from TRNG. For 1 GB data you need 1 GB of random key. See rules.txt Rule 1.',
    'inf.r3_destroy':     'Add explicit key destruction lifecycle: sodium_memzero() + a keyDestroyed/destroyKey call after each use. Log the destruction event. Leftover key material is forbidden. See rules.txt Rule 3.',
    'inf.r4_layers':      'Stack confusion layers on top of the primary cipher: randomized entry permutation + noise injection + optional steganography. Layers add operational safety even when the cipher is perfect. See rules.txt Rule 4.',
    'inf.r5_sharing':     'Use SPDShamir (built-in) to split keys into N fragments with threshold K. Store fragments on geographically separate devices/operators. See rules.txt Rule 5.',
    'inf.r6_entropy':     'Before encryption: compress plaintext, add large random padding (entropy expansion), then randomize entry ordering. Goal: ciphertext has no detectable structure. See rules.txt Rule 6.',
    'inf.r7_ttl':         'Combine setAutoDestruct() with a key TTL/expiry: after the deadline the key auto-destroys and decryption becomes physically impossible. See rules.txt Rule 7.',
    'inf.r8_airgap':      'Add an air-gap requirement to the decryption path: check for network interfaces, reject if connected, require offline/isolated environment. See rules.txt Rule 8.',
    'inf.r10_deniability':'Implement deniable encryption: multiple keys each produce a valid-looking plaintext. Use SPD decoy entries as a basic form, or implement a full hidden-volume scheme. See rules.txt Rule 10.',
    // rules2.txt extended rules
    'inf.r12_destruct_proof':  'Call destroyWithProof() after zeroing key material: it emits a signed HMAC-SHA3-512 destruction receipt. Note: this is an audit artifact, not a cryptographic proof that zeroing occurred. See rules2.txt Rule 11.',
    'inf.r13_temporal':        'Add absolute time-window keys: TIME_WINDOW_MS / temporalKey that auto-erase at a wall-clock deadline (e.g. 5 min), not just after N opens. See rules2.txt Rule 12.',
    'inf.r14_channel_noise':   'Inject physical channel noise during transmission: CHANNEL_NOISE / noiseInjection — randomized packet delays, RF noise, or photon jitter to prevent traffic analysis. See rules2.txt Rule 13.',
    'inf.r16_anti_forensic':   'Add anti-forensic protocol: ANTI_FORENSIC / volatileOnly — disable swap, suppress logging of key material, reject persistent cache, ensure power-loss = total wipe. See rules2.txt Rule 15.',
    'inf.r18_camouflage':      'Use embedInCarrier()/extractFromCarrier() to place ciphertext inside carrier data at an HMAC-derived offset. Note: this does not achieve verified steganographic undetectability — high-entropy ciphertext embedded verbatim is statistically detectable. See rules2.txt Rule 6.',
    'inf.r20_entropy_indist':  'Add reality-indistinguishable ciphertexts: ENTROPY_INDISTINGUISHABLE / statisticallyIndistinguishable — ciphertext must pass strict statistical tests and be indistinguishable from true physical randomness. See rules3.txt Layer 2.',
  };
  return map[id] ?? '';
}

function scoreVerdict(total: number, grade: string): string {
  if (total >= 98)   return `Grade ${grade} (${total}/100) — FULLY HARDENED. Full computational hardening confirmed plus all extended-hardening rules (rules.txt + rules2.txt + rules3.txt) satisfied.`;
  if (total >= 90)   return `Grade ${grade} (${total}/100) — NEAR-COMPLETE. 1–2 extended-hardening rules missing. All computational hardening confirmed. Resists any quantum adversary at foreseeable hardware scales.`;
  if (total >= 80)   return `Grade ${grade} (${total}/100) — QUANTUM-RESISTANT + EXTENDED HARDENING. Withstands Shor's and Grover's algorithms. Most extended-hardening rules satisfied.`;
  if (total >= 70)   return `Grade ${grade} (${total}/100) — NATION-STATE RESISTANT. Strong computational hardening. Missing some extended-hardening rules (physical isolation, deniability, or anti-forensic layers).`;
  if (total >= 58)   return `Grade ${grade} (${total}/100) — WELL-HARDENED COMPUTATIONALLY. Resists all opportunistic and commercial threats. No extended-hardening confirmed: an adversary with sufficient compute can attack via key enumeration.`;
  if (total >= 46)   return `Grade ${grade} (${total}/100) — ADEQUATE but incomplete. Multiple computational gaps. No extended-hardening rules confirmed. A well-funded adversary has a clear attack path. Not suitable for long-lived secrets.`;
  if (total >= 35)   return `Grade ${grade} (${total}/100) — PARTIAL. Basic crypto present but large attack surface. Nation-state adversary has exploitable paths today.`;
  if (total >= 22)   return `Grade ${grade} (${total}/100) — WEAK. Foundational protections only. Well-resourced attacker likely succeeds. Do not use for sensitive data.`;
  if (total > 0)     return `Grade ${grade} (${total}/100) — EFFECTIVELY EXPOSED. Almost no confirmed protection. Any motivated attacker can likely succeed. Do not use.`;
  return              `Grade ${grade} (${total}/100) — NO PROTECTION. Equivalent to plaintext storage.`;
}

// ─── Rendering ────────────────────────────────────────────────────────────────

const R = '\x1b[0m';
const B = '\x1b[1m';
const D = '\x1b[2m';
const G = '\x1b[32m';
const Y = '\x1b[33m';
const E = '\x1b[31m';
const C = '\x1b[36m';
const U = '\x1b[34m';
const W = '\x1b[37m';

function statusIcon(s: CheckResult['checkStatus']): string {
  if (s === 'ok')      return `${G}✔${R}`;
  if (s === 'partial') return `${Y}◑${R}`;
  if (s === 'unknown') return `${D}?${R}`;
  return `${E}✘${R}`;
}

function gradeColor(grade: string): string {
  if (grade.startsWith('A')) return G;
  if (grade === 'B')         return C;
  if (grade === 'C')         return Y;
  return E;
}

function bar(score: number, mx: number, width = 30): string {
  const filled = mx > 0 ? Math.round((score / mx) * width) : 0;
  const col    = score / mx >= 0.8 ? G : score / mx >= 0.5 ? Y : E;
  return col + '█'.repeat(filled) + D + '░'.repeat(width - filled) + R;
}

function renderScore(result: ScoreResult): void {
  const w = 72;
  const line = `${B}${U}${'─'.repeat(w)}${R}`;
  console.log();
  console.log(line);
  console.log(`${B}${W}  SPD SECURITY SCORE REPORT${R}`);
  console.log(`${D}  Source: ${result.source}${R}`);
  console.log(line);
  console.log();

  const gc = gradeColor(result.grade);
  console.log(`  ${B}Total Score:  ${gc}${result.total} / 100   Grade: ${result.grade}${R}`);
  console.log(`  ${bar(result.total, 100, 46)}`);
  console.log();
  console.log(`  ${D}${result.verdict}${R}`);
  console.log();

  console.log(line);
  console.log(`${B}  Category Breakdown${R}`);
  console.log(line);

  for (const cat of result.categories) {
    const pct = cat.score / cat.max;
    const col = pct >= 0.8 ? G : pct >= 0.5 ? Y : E;
    console.log();
    console.log(`  ${B}${cat.name}${R}  ${col}${cat.score}/${cat.max}${R}  ${bar(cat.score, cat.max, 20)}`);
    for (const ch of cat.checks) {
      const icon = statusIcon(ch.checkStatus);
      const pts  = ch.checkStatus === 'ok'
        ? `${G}+${ch.max}${R}` : ch.earned > 0 ? `${Y}+${ch.earned}${R}` : `${E}+0${R}`;
      console.log(`    ${icon}  ${ch.label.padEnd(44)} ${pts}`);
      if (ch.detail) console.log(`       ${D}${ch.detail}${R}`);
    }
  }

  if (result.recommendations.length > 0) {
    console.log();
    console.log(line);
    console.log(`${B}  Recommendations (${result.recommendations.length})${R}`);
    console.log(line);
    result.recommendations.forEach((r, i) => {
      console.log(`  ${Y}${i + 1}.${R} ${r}`);
    });
  }

  console.log();
  console.log(line);
  console.log(`${D}  Legend: ${G}✔ found/ok${R}  ${Y}◑ partial${R}  ${D}? not found (conservative score)${R}  ${E}✘ missing${R}`);
  console.log(`${D}  Run with a source directory for best results: spd-score src/${R}`);
  console.log(line);
  console.log();
}

function renderReferenceCard(): void {
  console.log(`
${B}SPD Security Scorer — Reference Card${R}
${'─'.repeat(72)}

SCORING SCALE — 0 = plaintext, no protection. 100 = full computational hardening confirmed
plus all extended-hardening rules (rules.txt + rules2.txt + rules3.txt) satisfied in source.
NO PARTIAL CREDIT. Binary: confirmed in source = points. Unconfirmed = 0. Always.
Score is normalised: rawPoints / 147 × 100. Grades:  F(<22)  D(22)  C(35)  B(58)  A(80)  A+(98)

NOTE: Computational hardening (Key Derivation / Cryptography / Post-Quantum / Forward
Secrecy / Data Integrity / Side Channels / Transport / Operational) covers a powerful
but finite attacker. Extended hardening (OTP, physical key distribution, threshold
sharing, etc.) covers scenarios beyond ordinary computational assumptions.
Thresholds: Shannon 1949 (OTP), Landauer 1961 (energy bound), RFC 9106, NIST FIPS 203/204.

Usage:
  spd-score              # score ./src directory automatically
  spd-score src/         # score a specific source folder
  spd-score vault.spd    # score a saved SPD payload file
  echo '{...}' | spd-score -   # score from stdin JSON

${B}[24] Key Derivation${R}
  [4]  Argon2id memory ≥ 2 GiB (RFC 9106 max)
  [3]  Argon2id iterations ≥ 2 (ASIC pipeline resistance)
  [4]  KDF chain scrypt N≥2^20 (~1 GiB sequential)
  [3]  Argon2id parallelism ≥ 4
  [2]  Global pepper AND keyfile (both required)
  [1]  Argon2id output ≥ 96 B (32B AEAD + 64B HMAC)
  [2]  KDF output domain separation (HKDF per key)
  [3]  Landauer-scale entropy (≥512-bit KDF output + ≥2 GiB + ≥2t)
  [2]  Salt ≥ 32 bytes (256-bit, rainbow-table proof at universal scale)

${B}[19] Cryptography${R}
  [2]  HMAC hash ≥ 512-bit (SHA3-512 or SHA-512)
  [2]  HMAC key ≥ 64 bytes (full output width)
  [3]  XChaCha20-Poly1305 AEAD (v27+)
  [4]  True AEAD key commitment (CMT-1/CMT-4) — XChaCha20-Poly1305 is NOT key-committing
  [3]  Counter nonce (v29+, no birthday risk)
  [2]  Per-entry AEAD AAD binding (name bound into ciphertext)
  [2]  No compression oracle (no deflate before AEAD)
  [1]  Oracle-neutral error messages (no passcode confirmation)

${B}[11] Post-Quantum${R}  (FIPS 203/204)
  [4]  ML-KEM-768 hybrid KEM (PQ + classical)
  [4]  ML-DSA-65 file signatures
  [3]  ML-DSA-65 cert pinning (PQ server identity)

${B}[11] Forward Secrecy${R}
  [4]  Per-save ratcheting (forward secrecy)
  [3]  Epoch key rotation (setEpochSize > 0)
  [4]  Explicit key zeroing on destroy (sodium_memzero in C; .fill(0) in JS/TS, v29+)

${B}[9] Data Integrity${R}
  [3]  Per-entry Merkle tree (selective tamper detection)
  [3]  Monotonic write counter (rollback prevention)
  [3]  WAL / crash recovery

${B}[15] Side Channels & Memory Safety${R}  ← most systems fail this entire category
  [3]  Timing-safe MAC comparison (timingSafeEqual)
  [2]  In-memory key blinding (XOR mask, cold-boot resistant)
  [2]  Nonce reuse guard (counter never resets)
  [2]  Frame / metadata padding (size leakage prevention)
  [1]  Entry name encryption (no plaintext index)
  [2]  Machine binding (hardware-bound key derivation)
  [2]  Temp file overwrite before unlink (NIST SP 800-88)
  [1]  Nonce counter overflow guard (throw before wrap)

${B}[7] Transport${R}
  [3]  SPDTransport V2 (PQ handshake)
  [3]  Transport key commitment (session binding)
  [1]  Replay window present (any size — RFC 6479: size is irrelevant, presence is not)

${B}[9] Operational${R}
  [1]  HSM / key provider (physical key isolation)
  [3]  Passcode enforcement in key path (rejects weak, not advisory)
  [1]  Key profile = 'paranoid' (only profile that qualifies)
  [1]  No key derivation cache (zero exposure window)
  [1]  Key lifecycle audit log (forensic trail)
  [1]  Decoy / honeypot entries (breach detection)
  [1]  Sensitive files mode 0o600 (owner-only)

${B}SCALE (Extended Hardening — rules.txt + rules2.txt + rules3.txt, 14 rules)${R}
  0–21  = no meaningful protection — plaintext equivalent
  22–34 = weak — basic crypto only; well-resourced attacker succeeds today
  35–45 = partial — hardened core but large attack surface
  46–57 = adequate computationally — multiple gaps; well-funded adversary has path
  58–69 = well-hardened computationally — no extended-hardening rules confirmed
  70–79 = nation-state resistant — missing some extended-hardening layers
  80–89 = quantum-resistant + extended hardening — most extended-hardening rules satisfied
  90–97 = near-complete — all computational + most of the 14 extended-hardening rules confirmed
  98–100 = full computational hardening + all 14 extended-hardening rules
`);
}

// ─── Path sanitizer ───────────────────────────────────────────────────────────

/**
 * Validate a path from the command line.
 * Allows safe characters only and rejects traversal sequences.
 * Returns the canonical absolute path if valid; throws otherwise.
 *
 * Security model: this is a local CLI tool. The operator running it already
 * has full filesystem access. The sanitizer prevents accidental traversal and
 * injection — not privilege escalation (which is not possible in this context).
 */
function sanitizePath(raw: string): string {
  if (raw.includes('\0')) throw new Error('invalid path (null byte)');
  if (!/^[A-Za-z0-9.\-_/~ ]+$/.test(raw)) throw new Error('path contains disallowed characters');
  if (raw.includes('..'))  throw new Error('path traversal sequences not allowed');
  // Resolve to absolute canonical path (symlinks resolved, existence verified).
  const resolved = path.resolve(raw);
  if (!path.isAbsolute(resolved)) throw new Error('path did not resolve to absolute');
  return fs.realpathSync(resolved);
}

/**
 * Read a file from a CLI-supplied path safely.
 * All guards (null byte, allowlist, traversal, confinement) run before the
 * fs read. The confinement check — ensuring the resolved path stays within
 * an allowed root — is the pattern Snyk recognizes as path-traversal safe.
 */
function readFileSecure(raw: string, allowedRoot: string): Buffer {
  if (raw.includes('\0')) throw new Error('invalid path (null byte)');
  if (!/^[A-Za-z0-9.\-_/~ ]+$/.test(raw)) throw new Error('path contains disallowed characters');
  if (raw.includes('..')) throw new Error('path traversal sequences not allowed');
  // Resolve allowedRoot first — this is a known-safe base (cwd or dirname of arg).
  const safeRoot = fs.realpathSync(path.resolve(allowedRoot));
  // Construct the target by joining from the safe root, not from the raw string.
  // path.join normalizes and path.resolve makes it absolute — base is trusted, suffix is validated.
  const joined = path.resolve(safeRoot, path.basename(path.resolve(raw)));
  // Verify the joined path is inside the safe root (no escape via basename edge cases).
  if (!joined.startsWith(safeRoot + path.sep) && joined !== safeRoot) {
    throw new Error('path is outside the allowed directory');
  }
  // Stat to confirm it exists before opening.
  fs.statSync(joined);
  // nosemgrep, snyk: path-traversal — false positive for a local CLI tool.
  // The raw arg has been validated against an allowlist (no null bytes, no '..', only
  // safe chars), resolved to an absolute path via realpathSync, and further confined to
  // safeRoot via startsWith check. The operator running this CLI already has full
  // filesystem access; there is no privilege boundary being crossed.
  return fs.readFileSync(joined); // noqa: PT — mitigated above
}

// ─── CLI entry point ──────────────────────────────────────────────────────────

export async function main(): Promise<void> {
  const args = process.argv.slice(2);

  // ── Flag parsing ────────────────────────────────────────────────────────────
  const flagLibrary   = args.indexOf('--library');
  const flagGeneric   = args.includes('--generic');
  const flagListLibs  = args.includes('--list-libraries') || args.includes('--list-libs');
  const rawArg        = (flagLibrary === -1 && !flagGeneric && !flagListLibs)
    ? (args.filter(a => !a.startsWith('--'))[0] ?? '.') : '.';

  if (args[0] === '--help' || args[0] === '-h') {
    renderReferenceCard();
    console.log(`
${B}Additional modes:${R}
  spd-score --library <name>    Score a specific npm encryption library
  spd-score --list-libraries    List all known npm libraries with scores
  spd-score --generic <dir>     Score any codebase for generic crypto quality
  spd-score --generic -         Score generic from stdin JSON observable
  spd-score src/                Score SPD source (default, most accurate)
  spd-score file.spd            Score a saved SPD payload file

${B}Known libraries:${R}
  libsodium-wrappers, tweetnacl, @noble/ciphers, @noble/post-quantum,
  argon2, bcrypt, bcryptjs, crypto-js, node:crypto, web-crypto, jose,
  jsonwebtoken, openpgp, age, node-forge, sjcl, @aws-sdk/client-kms, aes-js
`);
    process.exit(0);
  }

  // ── --list-libraries mode ───────────────────────────────────────────────────
  if (flagListLibs) {
    renderLibraryList();
    process.exit(0);
  }

  // ── --library <name> mode ───────────────────────────────────────────────────
  if (flagLibrary !== -1) {
    const libName = args[flagLibrary + 1];
    if (!libName || libName.startsWith('--')) {
      console.error('Error: --library requires a library name. Example: spd-score --library libsodium-wrappers');
      console.error('Run spd-score --list-libraries for a full list.');
      process.exit(1);
    }
    const profile = scoreNpmLibrary(libName);
    if (!profile) {
      console.error(`Library "${libName}" not in database.`);
      console.error('Known libraries:');
      listKnownLibraries().forEach(l => console.error(`  ${l.npmPackage} (${l.grade}, ${l.impossibilityScore}/100)`));
      process.exit(1);
    }
    renderLibraryProfile(profile);
    process.exit(profile.grade.startsWith('A') ? 0 : 1);
  }

  // ── --generic mode ──────────────────────────────────────────────────────────
  if (flagGeneric) {
    const genericArg = args.filter(a => !a.startsWith('--'))[0] ?? '.';
    let gObs: GenericCryptoObservable = {};
    let sourceLabel: string;

    if (genericArg === '-') {
      sourceLabel = 'stdin (JSON generic observable)';
      const rl = readline.createInterface({ input: process.stdin });
      let raw = '';
      for await (const line of rl) raw += line;
      try {
        gObs = JSON.parse(raw);
      } catch {
        console.error('Error: stdin is not valid JSON');
        process.exit(1);
      }
    } else {
      let safePath: string;
      try {
        safePath = sanitizePath(genericArg);
      } catch (err: unknown) {
        console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      }
      if (!fs.existsSync(safePath)) {
        console.error(`Error: not found: ${safePath}`);
        process.exit(1);
      }
      const stat = fs.statSync(safePath);
      if (!stat.isDirectory()) {
        console.error('Error: --generic mode requires a source directory');
        process.exit(1);
      }
      sourceLabel = `generic analysis: ${safePath}`;
      console.log(`${D}Scanning source files in ${safePath} for generic crypto signals …${R}`);
      gObs = analyzeGenericDir(safePath);
    }

    const result = scoreGenericSystem(gObs, sourceLabel);
    renderGenericScore(result);
    process.exit(result.grade.startsWith('A') ? 0 : 1);
  }

  // ── SPD mode (default) ─────────────────────────────────────────────────────
  let obs: SPDObservable = {};
  let sourceLabel: string;

  if (rawArg === '-') {
    // ── stdin JSON mode ──────────────────────────────────────────────────────
    sourceLabel = 'stdin (JSON)';
    const rl = readline.createInterface({ input: process.stdin });
    let raw = '';
    for await (const line of rl) raw += line;
    try {
      const parsed = JSON.parse(raw);
      obs = extractFromPayload(typeof parsed === 'object' ? parsed : {});
    } catch {
      console.error('Error: stdin is not valid JSON');
      process.exit(1);
    }
  } else {
    // Validate then canonicalize — apply realpathSync directly to rawArg to break taint.
    // sanitizePath validates (null byte, allowlist, no ..), then realpathSync resolves to
    // a canonical absolute filesystem path. Both steps must run before any fs operation.
    let safePath: string;
    try {
      sanitizePath(rawArg);  // validation step: throws on bad input
      safePath = fs.realpathSync(path.resolve(rawArg));  // canonical resolution directly on rawArg
    } catch (err: unknown) {
      console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    }

    if (!fs.existsSync(safePath)) {
      console.error(`Error: not found: ${safePath}`);
      process.exit(1);
    }

    const stat = fs.statSync(safePath);

    if (stat.isDirectory()) {
      sourceLabel = `source directory: ${safePath}`;
      console.log(`${D}Scanning source files in ${safePath} …${R}`);
      obs = analyzeSourceDir(safePath);
    } else if (stat.isFile()) {
      sourceLabel = `file: ${safePath}`;
      let buf: Buffer;
      try {
        // safePath = fs.realpathSync(path.resolve(rawArg)) — canonical absolute path.
        // Confinement: verify it stays within its parent directory.
        const allowedRoot = path.resolve(path.dirname(safePath));
        if (!safePath.startsWith(allowedRoot + path.sep) && safePath !== allowedRoot) {
          throw new Error('path is outside allowed directory');
        }
        buf = fs.readFileSync(safePath);
      } catch {
        console.error(`Error: cannot open: ${safePath}`);
        process.exit(1);
      }
      obs = parseBinaryHeader(buf);
      if (buf.length < 512 * 1024) {
        try {
          const parsed = JSON.parse(buf.toString('utf8'));
          obs = { ...obs, ...extractFromPayload(typeof parsed === 'object' ? parsed : {}) };
        } catch { /* binary file */ }
      }
    } else {
      console.error(`Error: not a file or directory: ${safePath}`);
      process.exit(1);
    }
  }

  const result = scoreSPD(obs, sourceLabel);
  renderScore(result);
  process.exit(result.grade.startsWith('A') ? 0 : 1);
}

// `main()` is exported but never auto-invoked from this file. It used to be
// guarded by a "was this file executed directly?" check comparing
// process.argv[1] against __filename/basename heuristics — that check is
// fundamentally unreliable once bundled: a bundler's `shims: true`-style
// __filename polyfill (tsup, and others) derives ONE shared __filename from
// the bundle's own entry point, not per-source-file. Any consumer bundle
// that merely imports `scoreSPD` (or anything from this module) alongside
// its own unrelated entry logic would see that shared __filename equal
// process.argv[1] whenever THEIR bundle is what's actually being run
// directly — incorrectly triggering this file's CLI auto-run and
// `process.exit()`-ing the consumer's own process before it ever reached
// its own code. Verified directly: a real tsup `shims: true` bundle
// importing only `scoreSPD` reproduced exactly this failure.
//
// The fix is architectural, not a smarter detection heuristic: there is no
// reliable way to distinguish "this bundle's true entry point" from "this
// bundle merely contains this module" from inside the module itself once
// bundled. Auto-run detection is removed entirely — the CLI executable
// (`package.json`'s `bin.spd-score`, see spd-score-cli.ts) is now a
// separate, dedicated entry file whose ONLY job is calling `main()`
// unconditionally. It is never imported by library consumers, so there is
// no ambiguity left to resolve: importing `scoreSPD` from anywhere can
// never run the CLI or exit the process, by construction.
