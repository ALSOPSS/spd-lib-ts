# Changelog

All notable changes to `spd-lib` are documented here. SPD *format* versions
(v24–v29) are separate from the npm package version and are not
cross-compatible; see the table in [README.md](./README.md#versioning).

## Unreleased

No wire-format change.

- **Strict mode covers clients.** With `SPDTransport.setStrictMode(true)`,
  `clientConnect` now refuses to start without `pinnedSigningKey` (or over V1).
  An unpinned client cannot check the ServerHello signature, so before this it
  silently accepted an unsigned server and relied on the classical Curve25519
  key alone.
- **PSK length.** `clientConnect` and `serverAccept` reject a PSK that is not
  exactly 32 bytes (the documented size, and what `exportPSK()` returns); an
  empty PSK was accepted before.
- **Docs.** The `SPDTransport` and `SPDHandshake` headers now describe the
  derivation the code uses (concatenated hybrid IKM, HMAC-SHA3-512 HKDF,
  `spd-hs-session-v2`, the V2 signed transcript).

## 2.1.1 — 2026-10-28

Bug fixes only; no wire-format change.

- **Trailing bytes.** The Node build's inflate stopped at the zlib stream end and
  ignored anything after it, so bytes appended to a `saveData()` string or a
  JSON-format file went unnoticed. They are now rejected, matching the browser
  build's `DecompressionStream` and the Rust crate.
- **Format sniffing.** `loadFromFile` opens binary files and
  `loadFromFileStreaming` opens JSON files instead of failing with zlib's
  "incorrect header check". `loadWithRandomKey`, `loadWithKeyfileOnly` and
  `loadFromFileSealed` inherit this, so keyless JSON files open without
  `streaming: false`.
- **Signatures on strings.** `loadFromString` and `loadFromChunks` take a
  `verifyKey` third argument.
- **Docs.** The ECC claim is now stated as "4 damaged 4 KiB shards per 64 KiB
  block" rather than "20% of bytes"; README and SPEC note that signature
  verification needs the decryption key.

## 2.1.0 — 2026-10-26

Everything below was developed after the published 2.0.1. No `.spd` wire-format
change — files are still v29 and every 2.0.1/1.4.0 file opens unchanged — but
there are behaviour changes worth reading before upgrading:

- **Default unlock cost.** `new SPD()` (`'high'` profile) no longer chains scrypt
  after Argon2id; only `'paranoid'` does. New files written with the default
  profile derive keys differently from the same passphrase than 2.0.1 did, and
  open roughly 4× faster. Old files carry their chain flag and open as before.
  Call `enableKdfChain()` to keep the old behaviour per instance.
- **Index tail.** Binary files now embed the `SPDy` tail with keyed name tags;
  the plaintext-name `SPDx` tail is read but no longer written, and the `.spdi`
  sidecar is gone. 2.0.1 falls back to a scan on `SPDy`, so files stay readable
  by the older release.
- **`repairBitRot(path, passcode?)`** writes `<file>.repaired` unless the
  repaired bytes re-authenticate; **`enableKeyBlinding()`** is a no-op;
  `generatePassphrase()` defaults to 9 words and refuses fewer than 7.
- Six no-benefit utilities are `@deprecated` (see Removed/Deprecated) and will
  go in 3.0.
- A Rust implementation (`spd-lib` crate) reads and writes the same files.

### Added
- A Rust implementation (`spd-lib` crate, `~/projects/spd_lib_rs`) that reads and writes the same v29 files, `SPDR` envelopes, composite signatures and Shamir shares; verified in both directions against the golden fixtures.
- **Golden fixtures** (`test/fixtures/v29/`): files written at a fixed point
  — passphrase JSON and binary, composite-signed, keyless with a recipient
  envelope and `saveData` string, Shamir v2 shares — are committed and read
  back by every future version, so an accidental format change fails CI
  instead of stranding users' data.
- **`SPDUtils`**: the 18 standalone utilities (OTP, air-gap checks, temporal
  keys, noise, carrier embedding, …) moved out of `SPD.ts` into their own
  module. Still reachable as `SPD.<name>`; behaviour unchanged. The ones that
  provide no cryptographic benefit (`multiPadEncrypt/Decrypt`,
  `inflateEntropy`, `timeSmear`, `generateQuantumKey`,
  `assertPhysicalKeyDistrib`, `assertKnowledgeSeparation`) are now
  `@deprecated` with an honest note each. `SPD.ts` is down from 6,523 to
  under 5,900 lines this release.
- **`SPEC.md`** — a standalone wire-format and cryptographic specification
  (containers, record layout, key schedule, metadata, envelopes, shares,
  handshake, transport) so the format can be implemented and audited without
  reading this codebase. Shipped in the npm package.
- **Property-based tests** (`test/properties.test.ts`, fast-check): every
  supported value type round-trips through memory and string persistence;
  Shamir k-of-n for all small (n, k); recipient envelopes for 1–6 recipients;
  WAL codec; transport frames of arbitrary size with and without padding;
  base64/base64url/hex codecs against Node `Buffer`.
- Supply chain: Dependabot (crypto deps grouped separately), `npm audit
  signatures` (registry signatures + provenance of every installed package) and
  a CycloneDX SBOM artifact in CI.
- `loadFromFileStreaming` accepts the verify key in the third position (where
  `loadFromFile` takes it) and rejects it being passed twice — the exact
  argument-order slip that previously produced a silent hang.
- **`SPDRecipient` — post-quantum hybrid public-key recipients.** Seal the
  keyless master secret to one or more MLKEM768-X25519 public keys (the PQ/T
  KEM of `draft-ietf-hpke-pq` / age v1.3) with a key-committing
  XChaCha20-Poly1305 wrap per recipient; `open()` with any listed identity.
  Envelopes carry a version and KEM id for future agility and no recipient
  identifiers.
- **Composite file signatures.** `SPD.generateSigningKeyPair({ composite:
  true })` yields an ML-DSA-65 + Ed25519 pair (after
  `draft-ietf-lamps-pq-composite-sigs`); both components must verify. Kinds
  are length-separated and non-separable. Default remains ML-DSA-65 only.

### Performance
- The default `'high'` profile no longer chains scrypt (N=2²⁰, ≈1 GiB, p=4) after Argon2id 512 MiB/8 — only `'paranoid'` does. Default unlocks drop from Argon2id+scrypt to Argon2id alone; `enableKdfChain()` restores the old behaviour per instance, and `disableKdfChain()` now actually disables it (it was silently overridden for `high`/`paranoid` before). Existing files are unaffected: the chain flag is read from the file.
- **Opt-in unlock cache** (`SPD.setKeyCacheTtl(ms)`, default off). A warm
  open skips both Argon2id runs — the salt unwrap included — so repeated
  reads of one file take ~1 ms instead of ~0.7 s. Cache entries are keyed by
  an HMAC under a per-process random key (not a plain passcode hash), hand
  out copies (so `destroy()` cannot corrupt them), and are zeroed on
  eviction; `enableAntiForensic()` forces the TTL to 0.
- **Wrap-KDF lanes** (`setWrapKeyProfile(memory, time, parallelism)`). The
  salt-unwrap KDF ran on 1 lane while the main key used 4, making it the
  slower half of every open; with 4 lanes a full open measured ~45%
  faster (655 → 361 ms, idle 4-core) at the same memory cost. Opt-in: such files record `wrapArgon2Parallelism`.
- `argon2Stats.calls` (internal) lets tests pin "N KDF runs per operation".

### Fixed
- `spd-score` no longer awards points for rules whose only implementation was a deprecated no-benefit utility (R2, R9/R24, R15, R17, R19, R22, R25). The extended-hardening tier is now 14 rules / 42 raw points (147 raw total, still normalised to 100).
- `destroy()` now emits the `key_destroyed` log event that `SPDLogEvent` has declared since 1.x but nothing ever sent.
- `SECURITY_RULES_IMPLEMENTATION.md` rewritten to the rules that have code behind them, with deprecated and removed ones in two tables.
- **Browser bundle leaked a Node built-in**: `spd-key-material.ts` and `spd-lock.ts` imported `./node-platform.js` via a sibling path that the browser-build redirect did not match, so `dist/browser.js` contained `import { createRequire } from "module"` and failed to bundle with esbuild/vite/webpack. Redirect filters now match any import path; a compat test and a CI bundle-size step (`scripts/bundle-size.mjs --check`) guard it.
- **Keyless data could not be saved or loaded as strings.** `saveData()` /
  `saveDataChunked()` on a keyless instance fed an empty passcode to the
  passphrase KDF and threw, and no string/chunk counterpart to
  `loadWithRandomKey()` existed — so browsers, whose only persistence is
  strings, could not persist keyless or recipient-sealed data at all. Added
  `SPD.loadStringWithRandomKey()` / `loadChunksWithRandomKey()`; found by a
  new cross-runtime smoke test that runs the built package under Node, Bun
  and Deno.
- `SPDWriter` now emits `writeCounter` + `counterHMAC` like `SPD` does, so
  readers apply the same rollback/counter checks to its files (a Merkle root
  would need a format change, since meta precedes the entries).
- Packaging: `dist/package.json` shipped `bin` paths pointing at `./dist/…`
  from inside `dist/` and a nested `exports` field Node ignores; root manifest
  gains `sideEffects: false` and `typesVersions` so `spd-lib/browser` etc.
  resolve under legacy TypeScript resolution. `publint` and
  `are-the-types-wrong` now run in CI, as does `npm audit --omit=dev`.
- `SPD.verify()` derived the wrap key from the *main* KDF params, so it
  reported every file whose main profile differs from the wrap default —
  including the default `high` profile — as invalid; `repair()` and the JSON
  verify path ignored custom wrap params too. All readers now share one
  `unlockKeys` path that uses the file's wrap params.
- `changePasscode` / `upgradeKdfParams` / `rotateRandomKey` re-wrapped the
  salt with standard params while the file's meta kept a custom wrap profile,
  leaving the file unreadable.
- `addMany`'s worker path used `__dirname`, which does not exist in ESM
  (crashed under node/tsx; masked by the build shim). Now `import.meta.url`.
- `extractFromFileStreaming` could hang if a caller's `onProgress` threw.
- `spd-inspect` derived the wrap key from the main params and ignored
  `argon2Parallelism`, and its private key schedule had drifted from the
  library's (no HKDF, no pepper/keyfile, legacy `number[]` payloads), so it
  failed on every current-format file. Key-dependent layers now delegate to
  the library (`SPD.verify` + the real loaders), it describes recipient
  envelopes, and it no longer blocks on an interactive prompt without a TTY.
  Covered by a new CLI test.

### Stability
- New mutation-fuzz suite (`test/fuzz.test.ts`): ~900 random structural
  mutations across envelopes, Shamir shares, WAL buffers, transport frames
  and hellos, handshake hellos, and keyless `.spd` files (both formats) must
  each throw an `Error` or load identical data — never hang, crash, or
  succeed with wrong data.
- `SECURITY.md` now carries a threat model / known-limitations section
  (advisory ACLs, forgeable sidecars, decoys, no forward secrecy, process
  memory, unauthenticated transport unless pinned, lexical scorer, no external
  audit yet).
- Key derivation, salt wrapping, the unlock cache and the small crypto helpers
  moved from `SPD.ts` to `src/internal/spd-kdf.ts` (~400 lines). Every
  function stays reachable as a `SPD.*` static; behaviour and wire format are
  unchanged (golden fixtures, Argon2 vectors and the full suite pass).

### Security
- **The binary tail index stored entry names in plaintext**, next to records
  whose names v29 encrypts — so any file written with an index (the default)
  leaked every entry name, and a write-only `.spdi` sidecar duplicated it.
  The index now stores 16-byte keyed name tags (`SPDy`); `getEntry` derives
  the tag for the requested name. Old `SPDx` tails are still read. The
  `.spdi` sidecar is no longer written (nothing ever read it).
- **Decoy entries were trivially identifiable on disk**: a cleartext
  `dataType: "_decoy"` and a `_decoy_` name suffix. A decoy is now a normal
  `string` record whose encrypted value starts with a marker; readers skip it
  only after decryption. Legacy sentinel entries are still skipped.
- **Key rotation under `enableKeyBlinding()` silently kept the OLD key** and
  the blinded state made the instance unusable; the method is now a documented
  no-op (deprecated). Rotation paths zero the superseded live key buffers and
  the old keys on an authentication failure.
- **Lock breaking is serialised through a `.lock.break` mutex** (the
  rename-aside scheme still had a window in which two processes judging the
  same lock stale could delete a fresh lock); lock contents are validated
  (pid > 1, no future timestamps).
- `snapshot()` is ACL-gated and `restoreSnapshot()` merges roles instead of
  replacing them; the unlock-cache key covers every KDF parameter a file can
  specify (prevents cache poisoning by a crafted file sharing a `wrapSalt`);
  `setKeyCacheTtl` refuses while an anti-forensic instance is live;
  `repairBitRot` holds the file lock and uses a unique temp name;
  `generatePassphrase` requires ≥ 7 words (≈55 bits); `spd-inspect` reads
  `SPD_PASSCODE` so the passcode need not appear in `ps`.
- **Entry ACLs were not enforced on `extractDataStreaming`, `exportEntries`
  or `deniableDecryptView`**, and an exported instance dropped the
  restriction. All read paths now check the role; exports and snapshots
  carry the ACL. README now states plainly that the ACL is advisory (one key
  for all entries), not a cryptographic boundary.
- **A forged `.ecc` sidecar could overwrite the vault with attacker-chosen
  bytes** via `repairBitRot`/`autoRepair` (the sidecar's HMAC key is stored
  inside it, so it proves integrity, not authenticity). Repairs now replace
  the original only after the repaired bytes pass the file's MAC
  (`repairBitRot(path, passcode)`, used by `autoRepair`); without a passcode
  the result goes to `<file>.repaired`. Sidecar parsing rejects zero block
  sizes/shard counts and truncated records instead of looping.
- **Decoy entries (`addDecoy`) broke `extractData`, `changePasscode`,
  `upgradeKdfParams` and `rotateRandomKey`** (random bodies cannot inflate);
  a vault with decoys could never be rotated. All four now skip and carry
  decoys.
- **Key rotation is atomic.** A failure while re-encrypting (e.g. a schema
  validator) used to leave the instance on the new keys with entries
  missing and old/new records mixed in the WAL. Rotation now re-encrypts
  without schema/WAL side effects and restores the previous keys and
  entries on any error.
- `embedInCarrier`/`extractFromCarrier` used different offset moduli and
  failed to round-trip almost always; `addMany`'s worker path could hang if a
  worker died before replying; `startNoiseBaseline` now delivers packets to
  a caller-supplied callback (it previously generated and discarded them
  while the docs claimed it "emitted" traffic); timers are `unref()`'d.
- Documentation honesty: `deniableDecryptView` is documented as a view
  filter, not a hidden volume; per-save re-salting is no longer called
  "forward secrecy"; the scorer is described as the lexical self-check it is.
- **Decompression-bomb cap on JSON-format files.** The whole-file inflate in
  `loadFromFile` / `loadFromString` / `loadFromChunks` ran before
  authentication with no size limit; a few-KB file could expand to many GiB.
  Now capped by `SPD.maxJsonInflateBytes` (default 1 GiB) on both the Node
  and browser zlib backends.
- **`extractFromFileStreaming` wrote the `.seq` rollback sidecar before
  verifying the MAC**, so an unauthenticated crafted file with a large
  `writeCounter` could lock out the genuine file with `ESPD_ROLLBACK`. It
  now runs after MAC and signature verification, like the other load paths.
  It also now honours non-default `wrapArgon2Memory/Time`.
- **`SPDTransport` v2 signature now covers the full transcript**
  (SHA3-512 of label ‖ ClientHello ‖ KEM ciphertext ‖ server static key ‖
  key commitment). Previously only kemCT‖salt‖ecdhPub were signed, so a
  substituted client KEM public key produced a validly signed ServerHello
  (caught only by the key-commitment check). Pinned-key v2 peers must
  upgrade together. Also: ML-KEM/ML-DSA seeds, KEM shared secrets and IKM
  are zeroized; `processServerHello` rejects a second call.
- **`SPDWriter` bypassed the global pepper, keyfile and machine binding** —
  its files were silently weaker and unreadable by `SPD` once a pepper was
  set. It now uses `SPD.deriveKeys`/`SPD.encryptSalt` and emits
  `keyCommitment`.
- `spd.setSigningKey()` now stores a private copy. It kept the caller's
  buffer by reference and `destroy()` zeroed it in place, so a signing key
  reused across instances was silently wiped after the first `destroy()`
  and every later signature was garbage.
- `loadFromFileStreaming` no longer hangs forever if a caller's `onProgress`
  callback throws; the load rejects with that error.
- `SPDWeb` (deprecated) refuses imports with `pbkdf2Iter < 100000` or a
  salt shorter than 16 bytes, and `changePassphrase` now actually verifies
  the old passphrase.
- **`SPDHandshake` supports authentication.** Unauthenticated, comparing
  commitments cannot stop an active man-in-the-middle (it runs one handshake
  with each side). New `SPDHandshake.generateIdentity()` (ML-DSA-65) and an
  optional `{ identity, peerPublicKey }` argument on `createInitiator` /
  `createResponder`: the responder signs the transcript in its hello; the
  initiator signs it in `result.signature`, which a pinning responder checks
  with `verifyInitiator()` before `responderResult()` is released. FIPS 204
  context strings separate the two roles (no reflection). Fully optional and
  backward compatible with unauthenticated use.
- **`SPDShamir` shares are now integrity-checked (v2 format).** `combine()`
  throws instead of silently returning garbage on fewer than `k` shares,
  shares from different `split()` calls, or a corrupted/forged share: a
  SHA3-256 tag is appended to the secret before splitting (so it is itself
  secret-shared), and each share carries `k` and a random set id. v2 shares
  are 52 bytes longer; legacy v1 shares are still accepted by `combine()`.
- **`SPDHandshake` now binds every public value into the key derivation.**
  The session key was HKDF over the two shared secrets salted only with the
  nonces; neither X25519 public key nor the ML-KEM public key/ciphertext was
  hashed in. Raw X25519 output does not commit to the public keys behind it,
  and a secrets-only combiner is not IND-CCA in general — X-Wing
  (draft-connolly-cfrg-xwing-kem) and the GHP18 combiner both hash the
  classical keys/ciphertext into the KDF. The transcript is now
  SHA3-512(label ‖ nonces ‖ both X25519 public keys ‖ ML-KEM public key ‖
  ciphertext) in role order. **Handshake wire-compatible but not
  key-compatible with earlier builds** (info label bumped to
  `spd-hs-session-v2`): mixed-version peers fail closed at the commitment
  check. `.spd` files and `SPDTransport` are unaffected.
- **XChaCha20-Poly1305 now comes from the audited `@noble/ciphers`** instead
  of the in-house implementation, whose Poly1305 used BigInt arithmetic —
  variable-time on the secret one-time key `r` — and whose ChaCha20 silently
  wrapped its 32-bit block counter (keystream reuse) past 256 GiB. Output is
  unchanged: RFC vectors, new libsodium differential tests (random and
  unaligned buffers), and an RFC-formula oracle on Poly1305 carry edge cases.
  `@noble/ciphers` was already a transitive dependency of `@noble/post-quantum`.
- Upgraded `@noble/curves` 2.0.1 → 2.4.0: fixes an X25519 remote-timing leak
  of up to ~4 bits of a long-term private key (AIKIDO-2026-26118), used by
  `SPDHandshake`/`SPDTransport`.
- Upgraded `@noble/post-quantum` 0.5.4 → 0.7.1: ML-KEM `MultiplyNTTs`
  intermediate-overflow fix, ML-DSA signing entropy-ordering and zeroization
  hardening, Wycheproof vector coverage.
- The static key cache no longer retains derived AEAD/MAC keys (and a
  SHA-256 passcode digest used as the map key) after a load when
  `KEY_CACHE_TTL_MS = 0`; evicted entries are now zeroed, and the SHA-256
  passcode digest is no longer computed at all while caching is disabled.
- `acquireLock` no longer breaks a live lock held by another user's process:
  `kill(pid, 0)` failing with `EPERM` means the process is alive.
- Breaking a stale lock is now race-safe: the lock is atomically renamed
  aside and only discarded if it still holds the content judged stale
  (otherwise it is restored with `link()`, never clobbering a newer lock).
  Previously two processes could both judge a lock stale and one could delete
  the other's freshly acquired lock. Lock tokens now carry a random nonce.
- Pepper and keyfile buffers are copied on set and zeroed when replaced; the
  pepper‖passcode buffer fed to Argon2id is zeroed after derivation.
- `SPDShamir`'s GF(256) multiply is now branchless (no secret-dependent
  branches), the formulation HashiCorp Vault adopted after its Shamir
  timing side channel (CVE-2023-25000). Verified identical to the previous
  multiply on all 65,536 input pairs.
- `SPDVault` expiry timers are `unref()`'d — scripts using the vault no
  longer hang for up to `timeoutMs` (default 5 min) after their last call —
  and `genKeyBytes` now supports keys larger than 64 KiB.
- `generatePassphrase` now draws words by rejection sampling. The built-in
  list has 240 words (not 256 as documented), so `% 240` on 16-bit values was
  slightly biased toward the first 16 words. Docs now state ~7.9 bits/word.

### Performance
- Argon2id gained a top tier: Node's built-in `crypto.argon2` (Node ≥ 24.7,
  OpenSSL-backed). Same speed as the `argon2` addon (~470 ms at the standard
  128 MiB/6-pass profile) and byte-identical output, but needs no third-party
  native code or install scripts — so Node ≥ 24.7 gets native speed even when
  the optional addon can't install (e.g. npm's install-script gating).
- XChaCha20-Poly1305 is ~9× faster on large payloads (~20 → ~190 MiB/s on
  Node 24/x86-64) with `@noble/ciphers`.

### Changed
- Split WAL record encoding/replay (`internal/spd-wal.ts`), file locking and
  rollback sidecars (`internal/spd-lock.ts`), and passphrase generation
  (`internal/spd-passphrase.ts`), and pepper/keyfile/machine-binding state
  (`internal/spd-key-material.ts`) out of `SPD.ts`. Public API unchanged.
- **Compression backend is now build-specific.** The Node build uses Node's
  native `zlib`; the browser build uses native `CompressionStream` (see
  Removed: `fflate`). Both emit the same RFC 1950
  zlib-wrapped stream, verified bidirectionally compatible — a `.spd` file
  written by either is readable by the other. Measured ~3.7×/4.6× faster
  compress/decompress on the Node path.
- **Argon2id gained a middle WebAssembly tier.** Fallback chain is now native
  `argon2` addon → `hash-wasm` (hand-tuned WASM, ~6× faster than pure JS, the
  default path for browsers/Deno/Workers) → `@noble/hashes` pure JS (only
  reached if WASM instantiation fails, e.g. a CSP without `wasm-unsafe-eval`).
  Output is byte-identical across all three tiers (RFC 9106), cross-checked
  against golden vectors.
- Removed pointless `Promise.all` wrapping around synchronous work and made
  several internally-`async` helpers synchronous — no API or behavior change.

### Removed
- **`fflate` dependency.** The browser build now compresses with the
  platform's native `CompressionStream`/`DecompressionStream` (`'deflate'` =
  RFC 1950, byte-compatible with Node zlib; Safari ≥ 16.4, all evergreen
  browsers, Node ≥ 18, Deno, Bun). Faster, smaller, one fewer third-party
  codebase in the trust base. Shared code paths moved to the async
  `inflate()`/`deflate()` (no public API change — every caller was already
  async). The per-entry compression `level` is honoured on Node only.
- **ESM-only** (`"type": "module"`, no CJS `require()`), Node ≥ 20.19. Required
  because `@noble/post-quantum` ships ESM-only.
- Dropped the `libsodium-wrappers` dependency — XChaCha20-Poly1305 AEAD
  (`@noble/ciphers`) and the X25519 key exchange are pure JS, verified
  against RFC 8439 / draft-irtf-cfrg-xchacha-03 vectors and cross-checked
  against real libsodium output.
- Removed all `Buffer` usage from the core library (portable `Uint8Array`
  helpers instead) — this is what lets `spd-lib/browser` work with zero
  bundler configuration.
- Removed `SPDLegacy` (read v24-and-earlier files) and `SPD.getSodium()`.
- Removed 11 non-functional "security" methods that did not do what their names
  and docs claimed, and re-documented 4 more whose docs overclaimed. No change
  to any real cryptographic property or to the wire format.

### Added
- `hash-wasm` as a regular dependency (the Argon2id WASM tier above).
- Golden-vector tests covering the `hash-wasm` tier against the pure-JS tier.

## 1.4.0

SPD format v29: CMT-4 key commitment, HKDF key expansion, encrypted entry
names, 256-byte compression padding, 256-bit salt, OTP mode, and the
additional cryptographic utilities documented in the README.

## 1.3.1

SPD format v26: hash algorithm and Argon2 parameters embedded in the payload,
secure key zeroing, `null` type support.

## 1.3.0

SPD format v25: 512-bit Argon2id master secret, domain-separated AEAD + HMAC
keys, HMAC-SHA3-512.

## < 1.3.0

SPD format v24: 256-bit Argon2id, single key for AEAD + MAC.
