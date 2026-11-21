# spd-lib

**SPD (Secure Packaged Data)** — a post-quantum-hardened encrypted data format, portable across Node.js, browsers, Deno, and Bun.

Encrypt any JavaScript value (strings, numbers, objects, typed arrays, Maps, Sets, Dates, etc.) into a compressed, authenticated, tamper-proof container. Supports file storage, base64 string transport, chunked internet transfer, and streaming I/O for files larger than 2 GB.

The core in-memory encrypt/decrypt path has no native bindings, no Node-only built-ins, and no `Buffer` dependency — every cipher and hash is pure JS (`@noble/hashes`, `@noble/curves`, `@noble/ciphers`) on plain `Uint8Array`, verified by exercising the built browser bundle's API in the browser-compat test suite (`test/spd-browser-compat.test.ts`) and in CI's Chrome smoke job. Argon2id degrades in tiers — Node's built-in `crypto.argon2` on Node ≥ 24.7, the optional native `argon2` addon on older Node, hand-tuned WebAssembly (`hash-wasm`) in browsers/Deno/Workers, pure JS (`@noble/hashes`) as a last resort — with byte-identical output (RFC 9106) at every tier; compression is Node's native `zlib` in the Node build and the platform's native `CompressionStream` in the browser build, producing the same RFC 1950 stream either way. For browser/Deno/Workers use, `import { SPD } from 'spd-lib/browser'` — the identical class and `.spd` binary format as the main entry, with zero bundler configuration required (no `module` alias, no `Buffer` polyfill). File-I/O methods (`saveToFile`, `loadFromFileStreaming`, WAL, locking, `addMany`'s worker-thread path, etc.) remain Node-only by nature — they need a real filesystem — and throw a clear "requires Node.js" error if called from the browser entry. See [Browser usage](#browser-usage) below.

The built-in scorer (`npx spd-score` or `npm run score`) is a **lexical self-check**: it scans the source for the presence of the mechanisms below (Argon2id KDF, XChaCha20-Poly1305 AEAD with CMT-4 key commitment, HMAC-SHA3-512 authentication, HKDF domain separation, per-save re-salting, side-channel mitigations, NIST post-quantum KEM/signatures). It does not execute code and is not a substitute for the test suites or an independent audit; the actual evidence is in `test/` and [SPEC.md](./SPEC.md).

Maintained by [Al's-Ops LLC](https://alsopss.com) ([product page](https://alsopss.com/products#spd-lib)).

---

## Security model (v29)

The wire format, key schedule and every constant an independent implementation needs are specified in [SPEC.md](./SPEC.md); the security model below is the rationale, the spec is the contract.

| Layer | Algorithm | Notes |
|---|---|---|
| Key derivation | Argon2id (512 MiB / 8 passes by default — the `'high'` profile; 128 MiB / 6 for `'standard'`), plus a scrypt chain for `'paranoid'` | Raises brute-force cost against quantum search. Four-tier fallback: Node's built-in `crypto.argon2` (Node ≥ 24.7) → native `argon2` addon → hand-tuned WASM `hash-wasm` (browsers/Deno/Workers, ~6× faster than pure JS) → pure-JS `@noble/hashes` (only if WASM instantiation is blocked, e.g. strict CSP). Byte-identical output at every tier (RFC 9106). Full key schedule: [SPEC.md §1–2](./SPEC.md). |
| Key expansion | HKDF-SHA3-512 (domain-separated) | Separate AEAD and MAC keys from one master secret |
| Encryption | XChaCha20-Poly1305 (256-bit key, per-entry) | 128-bit PQ security via Grover's algorithm |
| Key commitment | CMT-4: SHA3-256(key ∥ nonce) prefix | Prevents partitioning oracle / multi-key attacks |
| Authentication | HMAC-SHA3-512 (512-bit key, full-file) | 128-bit PQ security, domain-separated |
| Name encryption | XChaCha20-Poly1305 (dedicated name key) | Entry names are never stored in plaintext |
| Compression privacy | Pad-to-256B blocks before deflate | Mitigates CRIME/BREACH length-based oracle |
| Salt wrapping | Argon2id + XChaCha20-Poly1305 | Encrypts the KDF salt under the passcode |
| Salt size | 256-bit random salt | Rainbow-table proof at universal-adversary scale |
| OTP mode | XOR key ≥ message length, never reused | Information-theoretic perfect secrecy (Shannon 1949) |
| Threshold sharing | Shamir secret sharing (SPDShamir) | Key fragments require threshold to reconstruct |
| Air-gap check | `os.networkInterfaces()` check at decrypt | Refuses to proceed if any non-loopback interface is active |
| Decoy-prefixed view | `deniableDecryptView()` returns only `_decoy_`-prefixed entries | A presentation filter under the same key — not a hidden volume and no deniability against a passcode holder |
| Post-quantum | ML-KEM-768 hybrid KEM + ML-DSA-65 sigs | NIST FIPS 203/204 — resists Shor's algorithm |

**Key derivation chain:**
1. Argon2id(passcode, random 256-bit salt) → 96-byte master secret
2. HKDF-SHA3-512(master, `'spd-aead-key-v1'`) → 32-byte AEAD key
3. HKDF-SHA3-512(master, `'spd-mac-key-v1'`) → 64-byte MAC key
4. Per-entry key: HKDF-SHA3-512(AEAD key, entry name) → 32-byte entry key

**`SPDTransport` and the classical-only V1 handshake:** the file-encryption
path above (Argon2id/XChaCha20-Poly1305/HMAC-SHA3-512) has no asymmetric
component and is not affected by a future quantum computer beyond the
Grover-algorithm margins already noted in the table. `SPDTransport` (the
client↔server session layer) is different — its V2 handshake hybridizes
classical X25519 ECDH with ML-KEM-768 specifically to resist
harvest-now-decrypt-later, but it also has a legacy **V1** handshake
(classical X25519 only, no PQ component) kept for interop with older peers.
As of v2.0, `SPDTransport.serverAccept()`/`accept()` **reject any V1
ClientHello by default** (`setRequireV2` defaults to `true`) — every session
gets the quantum-resistant hybrid path unless a server explicitly calls
`SPDTransport.setRequireV2(false)` to allow legacy V1 interop. Only turn
that off if you genuinely need to talk to a peer that predates the hybrid
handshake.

---

## Security score

```sh
npm run score
```

Runs the built-in scorer against the SPD source. It is a lexical presence check (it does not run code): Argon2id KDF parameters, AEAD construction and key commitment, MAC domain separation, post-quantum KEM/signatures, per-save re-salting, side-channel mitigations, transport handshake requirements, and a set of additional hardening utilities (one-time-pad mode, threshold key sharing, air-gap enforcement, temporal keys, channel noise injection, and similar — see [Cryptographic utilities](#cryptographic-utilities) below for what each one actually does and does not guarantee).

Run `npm run score` for the current number and full category breakdown — it's not restated here since it changes as the source does and a stale number in a README is worse than no number.

---

## Performance (Node.js 22, Apple M3, standard profile)

Measured with the native `argon2` addon and native `zlib` (the Node build's defaults).

| Operation | Throughput / Latency |
|---|---|
| Key derivation (Argon2id, 128 MiB) | ~380 ms (one-time per session) |
| addData ~36 B | ~10k ops/s |
| addData 10 KB | ~3k ops/s |
| addData 100 KB | ~750 ops/s |
| addData 1 MB | ~100 ops/s |
| saveToFileStreaming / loadFromFileStreaming 10×10 KB | ~400 ms (dominated by KDF) |
| getEntry (random-access lookup, binary file) | ~400 ms (dominated by KDF) |
| addMany 1000 items (parallel workers) | ~1–2 s |

The dominant cost in all file operations is the single Argon2id call (~380 ms). CMT-4 commitment, compression padding, HKDF, and name encryption add < 5 µs per entry.

**Argon2id by tier** (128 MiB / 6-iteration standard profile, same machine): native `argon2` addon ~380 ms · `hash-wasm` WASM ~840 ms · pure-JS `@noble/hashes` ~5 s. Browsers/Deno/Workers get the WASM tier automatically; the pure-JS tier is only reached if WASM can't instantiate (e.g. a CSP without `wasm-unsafe-eval`).

---

## Install

```sh
npm install spd-lib
```

> **Requires Node.js ≥ 20.19** (ESM-only — see Design notes below). No C++ build toolchain required: Argon2id uses the native `argon2` addon when available (fast path), then hand-tuned WebAssembly (`hash-wasm`, ~6× faster than pure JS) on any runtime without the addon, then a pure-JS implementation (`@noble/hashes`) only if WASM itself can't instantiate — byte-identical output at every tier (verified against golden vectors), just progressively slower. `argon2` is listed as an **optional** dependency (`optionalDependencies`, not `dependencies`) specifically so `npm install` succeeds even on platforms where its native binary can't be built or fetched (older/unusual Node ABIs, restricted sandboxes, etc.) — the WASM/pure-JS tiers take over silently rather than failing the whole install. `hash-wasm` is a regular dependency; browser-build compression uses the platform `CompressionStream` API (no package).

> **Design notes** (how the current 2.x code works):
> - **ESM-only** (`"type": "module"`, no CJS `require()` support), Node ≥ 20.19. Necessary because `@noble/post-quantum` (ML-KEM-768/ML-DSA-65) ships ESM-only, and Node's CJS `require()` cannot load an ESM module synchronously. Use `import()` (dynamic import) from CJS code if needed.
> - **Compression backend is build-specific.** The Node build (`spd-lib`) compresses with Node's native `zlib`; the browser build (`spd-lib/browser`) uses the platform's native `CompressionStream`/`DecompressionStream` (`'deflate'` format = RFC 1950, zlib-wrapped) — available in every evergreen browser (Safari ≥ 16.4), Node ≥ 18, Deno and Bun. No third-party compression code is shipped at all. Both emit the same RFC 1950 stream, verified bidirectionally compatible in `test/portable-zlib.test.ts`: a `.spd` file written by either build is readable by the other. The per-entry compression `level` is honoured by the Node build; the browser build uses the platform default.
> - **Argon2id gained a middle WASM tier.** `hash-wasm` (hand-tuned WebAssembly Argon2id) sits between the native `argon2` addon and the pure-JS `@noble/hashes` fallback — ~6× faster than pure JS, the default path for browsers/Deno/Workers. Output was cross-checked byte-for-byte against `@noble/hashes` for SPD's exact parameter shape (no `secret`, no associated data). The pure-JS tier is now only reached if WASM instantiation itself fails.
> - **`SPD.setPepper()` with a binary `Buffer` pepper** (not a string) mixes the pepper into Argon2id key derivation as raw bytes, not decoded back to a UTF-8 string first — decoding non-UTF-8-valid bytes back to a string is lossy and non-injective (distinct binary peppers could collide to the same effective string, silently losing entropy). String peppers are unaffected either way; valid UTF-8 always round-trips losslessly. `setPepper()` also validates a minimum length (16 bytes) and rejects degenerate values (a single byte repeated throughout, e.g. all-zero) — a short or trivial pepper defeats its own purpose, which is to require an attacker to also guess/obtain a separate, never-stored secret before a stolen file's passphrase can even be attacked. Pass `''` to clear/disable the pepper, which always succeeds regardless of these checks. Generate a real pepper with `SPD.generateRandomKey()` (or a subarray of it) rather than typing one by hand — it's meant to be an application-level secret (e.g. from a secrets manager), not something a human memorizes.
> - **No `libsodium-wrappers` dependency.** XChaCha20-Poly1305 AEAD comes from the audited, pure-JS `@noble/ciphers` (`internal/portable-aead.ts`), and the `crypto_kx` X25519 key exchange is a from-spec composition over `@noble/curves` + BLAKE2b (`internal/portable-kx.ts`). Both are verified against the official RFC 8439 / draft-irtf-cfrg-xchacha-03 test vectors and cross-checked byte-for-byte against real libsodium output. The on-disk `.spd` file format and wire protocol are unaffected — same standard cipher, same algorithm. Why not libsodium: it lacks a single well-maintained binding across every language SPD aims to support (Python, Swift, etc.); `@noble/ciphers` was already a transitive dependency via `@noble/post-quantum`.
> - **`SPDLegacy`** (read v24-and-earlier `.spd` files, XSalsa20-Poly1305 + PBKDF2) has been removed — unused internally, no test coverage. Pin an older commit if you need it.
> - **`SPD.getSodium()`** has been removed — it exposed the whole libsodium module for direct use, no longer meaningful once libsodium is gone. `npm install libsodium-wrappers` yourself if you need it for unrelated purposes.
> - **No `Buffer` anywhere in the core library.** Every internal byte type is a plain `Uint8Array`; `Buffer`-only conveniences (`.toString('hex'/'base64'/'base64url'/'utf8')`, `Buffer.concat`, `readUInt*`/`writeUInt*`) are replaced by portable equivalents in `internal/portable-crypto.ts`/`internal/portable-binary.ts`. This is what makes the `spd-lib/browser` entry point (below) work with zero bundler configuration.

---

## Browser usage

`spd-lib/browser` exports the **same `SPD` class and `.spd` binary format** as the main entry — not a weaker, format-incompatible variant. A file (or `saveData()` string) produced on desktop opens correctly in a browser tab, and vice versa.

```ts
import { SPD } from 'spd-lib/browser';

const spd = new SPD();
await spd.setPassKey('MyStr0ng!Passphrase#2024');
await spd.addData('username', 'alice');

// In-memory only — no filesystem in a browser
const saved = await spd.saveData('MyStr0ng!Passphrase#2024');

const loaded = await SPD.loadFromString(saved, 'MyStr0ng!Passphrase#2024');
console.log((await loaded.extractData()).username); // 'alice'
loaded.destroy();
```

Works with **zero bundler configuration** — no `module` alias, no `Buffer` polyfill, no `path`/`fs`/`os` shims. XChaCha20-Poly1305, ML-KEM-768, and ML-DSA-65 run as pure JS; Argon2id runs as hand-tuned WASM (`hash-wasm`), falling back to pure JS only if WASM instantiation is blocked (e.g. a CSP without `wasm-unsafe-eval`).

File-I/O methods (`saveToFile`, `loadFromFileStreaming`, WAL, locking, `addMany`'s worker-thread path, and every `SPDWriter` method) are Node-only by nature — a browser has no filesystem — and throw a clear `... requires Node.js` error if called from the browser entry. Use the in-memory API (`addData`/`extractData`/`saveData`/`loadFromString`) instead; everything else (`SPDTransport` sessions, `SPDVault`, `SPDShamir`, `SPDHandshake`) works identically to the desktop build.

**Page-weight note:** if a page only needs `SPD` (encrypt/decrypt) and not `SPDTransport`/`SPDHandshake` (the post-quantum client↔server session layer), import only what you use — `import { SPD } from 'spd-lib/browser'`, not a barrel `import *`. Measured by `node scripts/bundle-size.mjs` (esbuild, minified, run in CI with a size budget): an `SPD`-only bundle tree-shakes to ~117 KB of spd-lib code, vs. ~132 KB for the full entry. Dependencies are left external, so your bundler adds `@noble/*` (ML-KEM-768/ML-DSA-65 are the large part, ~150–200 KB minified) and `hash-wasm`'s ~32 KB base64-inlined Argon2id WASM on top.

**`spd-lib/web` (`SPDWeb`) is deprecated** — it predates `spd-lib/browser` above and exists only for existing consumers of its weaker, format-incompatible payload (PBKDF2 + AES-GCM + JSON, not Argon2id + XChaCha20-Poly1305 + the real `.spd` binary format). It won't gain new features. Use `spd-lib/browser` for all new browser/Deno/Bun code — it's the same `SPD` class as the main entry, with the real security model and file format, and no bundler configuration required.

---

## Quick start

```ts
import { SPD } from 'spd-lib';

const spd = new SPD();
await spd.setPassKey('MyStr0ng!Passphrase#2024');

await spd.addData('username', 'alice');
await spd.addData('apiKey', 'sk-abc123');
await spd.addData('config', { theme: 'dark', retries: 3 });

// Save to file (binary streaming format — recommended)
await spd.saveToFileStreaming('./vault.spd', 'MyStr0ng!Passphrase#2024');

// Load from file
const loaded = await SPD.loadFromFileStreaming('./vault.spd', 'MyStr0ng!Passphrase#2024');
const data = await loaded.extractData();
console.log(data.username); // 'alice'
loaded.destroy();
```

---

## API reference

### `new SPD()`

Creates a new empty SPD instance. You must call `setPassKey()` before adding or saving data.

---

### `spd.setPassKey(passcode: string): Promise<void>`

Derives encryption and authentication keys from the passcode using Argon2id + HKDF. Must be called before any data operation.

**Passcode requirements:** minimum 12 characters; rejected if it contains a common phrase, matches a weak pattern after leet-normalisation (e.g. `Word` + digits), or its estimated entropy is below the threshold. A passphrase of 5+ space-separated lowercase words (e.g. from `generatePassphrase()`) is scored by word count instead.

```ts
await spd.setPassKey('MyStr0ng!Passphrase#2024');
```

**Why this matters more than the cipher itself:** the derived AEAD key is 256 bits — already infeasible to brute-force directly, classically or with a quantum computer (Grover's algorithm only gives a quadratic speedup against symmetric keys, and this library's Argon2id costs already exceed OWASP's own minimum recommendation at every profile, even `standard`). The real attack surface in any password-based scheme is always the human-chosen passphrase itself, not the KDF — so this entropy check is enforced on **every** code path that derives keys from a human passcode: `setPassKey`, `changePasscode` (the new passcode, not just the initial one), and `SPDWriter`'s constructor. None of them can silently accept a weak passphrase.

---

### `spd.setKeyProfile(profile: 'standard' | 'high' | 'paranoid'): void`

Sets the Argon2id memory and time parameters before calling `setPassKey`.

| Profile | Memory | Iterations | Use case |
|---|---|---|---|
| `'standard'` | 128 MiB | 6 | Fastest — interactive applications where unlock latency matters most |
| `'high'` | 512 MiB | 8 | **Default** for a fresh `new SPD()` — a stronger floor than `'standard'` at a modest cost increase |
| `'paranoid'` | 2048 MiB | 16 | Long-term archive, server-side, offline — also auto-enables `SPD.enableMachineBinding()` (see below) |

`'paranoid'` additionally runs scrypt (N = 2²⁰, r = 8, p = 4, ≈1 GiB) over the Argon2id output; `enableKdfChain()` adds it to any profile and `disableKdfChain()` removes it. (Before 2.0.1 `'high'` chained scrypt too, and `disableKdfChain()` could not turn it off; files written that way still open — the flag is stored in the file.) The performance table above is measured with `'standard'`; a default `new SPD()` (`'high'`) is roughly 4× that.

```ts
spd.setKeyProfile('standard'); // fastest
spd.setKeyProfile('high');     // default
spd.setKeyProfile('paranoid'); // maximum resistance
```

**`'paranoid'` and machine binding:** choosing this profile automatically calls `SPD.enableMachineBinding()`, which mixes a stable machine-specific secret (derived from `/etc/machine-id`, hostname, and a random per-user sidecar file) into every key derivation via an extra HMAC step — so a `'paranoid'`-profile file is not just slower to brute-force, its key is only reproducible on the machine that saved it at all, dramatically raising the cost of an offline attack against a stolen file. This is a **global, process-wide** flag (`SPD.enableMachineBinding()`/`SPD.disableMachineBinding()` affect every `SPD` instance in the process, not just one) — so it must be active again (call `setKeyProfile('paranoid')` again, or `SPD.enableMachineBinding()` directly) before loading a file that was saved this way, even in a fresh process; loading without it active fails with `"Authentication failed."`, not a special error. Call `SPD.disableMachineBinding()` right after `setKeyProfile('paranoid')` if you specifically want `'paranoid'`'s KDF cost without the machine-binding property.

---

### Faster opens — `spd.setWrapKeyProfile(memory, time, parallelism?)` / `SPD.setKeyCacheTtl(ms)`

Every file open runs Argon2id twice: once to unwrap the file's salt (the *wrap* KDF, 128 MiB / 6 passes / 1 lane by default) and once for the main key (which already uses 4 lanes). Two opt-in knobs:

- `spd.setWrapKeyProfile(131072, 6, 4)` runs the wrap KDF across 4 lanes (threads in the native tiers) at the same memory cost. Measured on an idle 4-core machine: a full open (wrap + main key) drops from ~655 ms to ~360 ms (~45% faster). Files written this way record `wrapArgon2Parallelism` and need a reader of this version or later.
- `SPD.setKeyCacheTtl(ms)` keeps derived keys for a (passcode, file) pair in memory for `ms`; repeated reads of the same file (`getEntry` in a loop, a hot config file) then skip both KDF runs entirely (~1 ms instead of ~0.7 s). Live keys sit in process memory for the TTL, so keep it short and leave it off where a memory dump is in your threat model. `enableAntiForensic()` forces it off. Default: 0 (off).

---

### `SPD.generatePassphrase(wordCount?: number): string`

Generates a cryptographically random space-separated passphrase from a 240-word list (~7.9 bits per word). Default is 9 words (~71 bits); fewer than 7 throws.

```ts
const pass = SPD.generatePassphrase();    // 9 words, ~71 bits entropy
const pass = SPD.generatePassphrase(10);  // 10 words, ~80 bits entropy
```

---

### `spd.addData(name: string, value: unknown): Promise<void>`

Encrypts and stores a single value. The name is sanitized (lowercased; characters outside `a-z0-9_-` replaced with `_`). Entry names are encrypted and never stored in plaintext (v29+).

> **Collision risk if you use real filenames as entry names** (a common pattern for file-sharing / document-storage applications): sanitization is lossy — `"Report.pdf"`, `"report.pdf"`, `"report_pdf"`, and `"report-pdf"` all sanitize to the same `"report_pdf"` and **silently overwrite each other**, with no error and no warning by default. Call `SPD.enableNameCollisionWarnings()` during development to log every case where sanitization changes a name, and either pre-sanitize/de-duplicate filenames yourself before calling `addData`, or store the original filename as part of the entry's *value* (e.g. `{ filename: 'Report.pdf', content: ... }`) rather than relying on it surviving as the entry name.

**Supported types:** `string`, `number`, `boolean`, `null`, `object`, `Array`, `Uint8Array`, `Uint16Array`, `Uint32Array`, `BigInt64Array`, `BigUint64Array`, `Float32Array`, `Float64Array`, `Map`, `Set`, `Date`, `RegExp`, `Error`

```ts
await spd.addData('score', 42);
await spd.addData('tags', ['a', 'b', 'c']);
await spd.addData('created', new Date());
await spd.addData('raw', new Uint8Array([1, 2, 3]));
await spd.addData('lookup', new Map([['key', 'val']]));
```

---

### `spd.addMany(items: { name: string; data: unknown }[]): Promise<void>`

Batch version of `addData`. Large batches (≥ 256 items) are encrypted in parallel using worker threads.

```ts
await spd.addMany([
  { name: 'firstName', data: 'Alice' },
  { name: 'age',       data: 30 },
  { name: 'prefs',     data: { darkMode: true } },
]);
```

---

### `spd.extractData(): Promise<Record<string, unknown>>`

Decrypts and returns all stored entries as a plain object.

```ts
const data = await spd.extractData();
console.log(data.firstName); // 'Alice'
```

---

### `spd.saveToFileStreaming(path: string, passcode: string): Promise<void>`
### `SPD.loadFromFileStreaming(path: string, passcode: string): Promise<SPD>`

**Recommended for all file I/O.** Writes/reads the binary SPD wire format. Heap usage stays bounded regardless of file size. Required format for `getEntry` random-access lookups.

The file embeds an offset index tail (`SPDy`, keyed name tags — reveals no names) for O(1) entry lookups without a sidecar file.

```ts
await spd.saveToFileStreaming('./large.spd', 'MyStr0ng!Passphrase#2024');
const spd = await SPD.loadFromFileStreaming('./large.spd', 'MyStr0ng!Passphrase#2024');
```

---

### `spd.saveToFile(path: string, passcode: string): Promise<void>`
### `SPD.loadFromFile(path: string, passcode: string): Promise<SPD>`

JSON-envelope file format. Suitable for files up to ~1–2 GB. Not compatible with `getEntry`.

```ts
await spd.saveToFile('./secrets.spd', 'MyStr0ng!Passphrase#2024');
const spd = await SPD.loadFromFile('./secrets.spd', 'MyStr0ng!Passphrase#2024');
```

---

### `SPD.getEntry(filePath, passcode, entryName, verifyKey?, role?): Promise<{ name, value, dataType }>`

Random-access lookup of a single entry from a binary SPD file (written by `saveToFileStreaming`). Uses the embedded `SPDy` index tail (keyed name tags; legacy `SPDx` still readable) to jump directly to the entry — no full scan. MAC-verified before decryption. Returns a `{ name, value, dataType }` object, not the raw value directly. Pass `verifyKey` (an ML-DSA-65 public key) to also enforce a pinned file signature, same as `loadFromFile`. Pass `role` to satisfy an entry-level ACL set via `spd.restrictEntry()` (see below) — omitting it behaves like no role at all, so a restricted entry throws `Access denied`.

```ts
const { value } = await SPD.getEntry('./vault.spd', 'MyStr0ng!Passphrase#2024', 'username');
const { value: adminOnly } = await SPD.getEntry('./vault.spd', 'MyStr0ng!Passphrase#2024', 'ssn', undefined, 'admin');
```

---

### Entry ACLs — `spd.restrictEntry(name, roles)` / `spd.setRole(role)`

Restrict individual entries to one or more roles. Every read path enforces it (`extractData`, `extractDataStreaming`, `entries()`, `getEntry`'s `role` parameter, `exportEntries`, `deniableDecryptView`) — an unset or wrong role throws `Access denied`.

**This is an advisory control, not a cryptographic boundary.** The role map is stored inside the authenticated metadata, so someone *without* the passcode cannot alter it — but there is one key for all entries, so anyone *with* the passcode can call `setRole()` with the role named in the error, or rewrite the metadata. Use it to prevent mistakes within a trusted application, not to separate mutually distrusting parties; for that, use separate files or recipients.

```ts
await spd.addData('ssn', '123-45-6789');
spd.restrictEntry('ssn', ['admin']);   // only readable with this role set

spd.setRole('guest');
await spd.extractData();               // throws: Access denied

spd.setRole('admin');
await spd.extractData();               // { ssn: '123-45-6789', ... }
```

Restrictions persist across a real save/load round trip (both the JSON and binary streaming formats) — reloading a file preserves whatever `restrictEntry()` calls were made before saving; you don't need to re-apply them after `loadFromFile`/`loadFromFileStreaming`.

---

### Auto-destruct — `SPD.setFileMaxOpenCount(filePath, n)` / `spd.setMaxOpenCount(n)`

Limits how many times a file can be opened before it's automatically and irreversibly wiped ("burn after N reads"). `setFileMaxOpenCount` writes a `.maxcount` sidecar next to the file (the authoritative source — takes precedence over `setMaxOpenCount`'s in-instance default); a `.ocount` sidecar tracks the running count. Exceeding the limit zeroes the file's bytes on disk and deletes it, throwing an `ESPD_AUTODESTRUCT`-coded error.

The `.maxcount`/`.ocount` sidecars (like the `.seq` rollback sidecar) are plain, unauthenticated files. This is a safeguard for ordinary use, not a defence against someone with write access to the directory, who can delete `.ocount` or edit `.maxcount`.

```ts
SPD.setFileMaxOpenCount('./one-time.spd', 1); // burn after the first successful open

await SPD.loadFromFileStreaming('./one-time.spd', pass); // succeeds, consumes the budget
await SPD.loadFromFileStreaming('./one-time.spd', pass); // throws — file has been wiped
```

The limit is shared across **every** read path against the same file — `loadFromFile`, `loadFromFileStreaming`, and `getEntry` all increment and check the same `.ocount` sidecar, so mixing them still enforces one consistent total.

---

### `spd.extractDataStreaming(callback): Promise<void>`

Decrypts one entry at a time and invokes `callback` for each, instead of
`extractData()`'s "decrypt everything, return one object." **Entirely
in-memory — no temp files, no disk I/O at all.**

> **Design note:** this method used to take a `tmpDir: string` first
> argument and wrote each entry's decrypted plaintext to a
> `<tmpDir>/<name>.ssf` temp file before reading it back — purely to reuse
> an internal string-conversion helper that only ever needed a string, not
> a file path. That disk round-trip served no functional purpose and was a
> real, if narrow, source of risk any disk-touching decrypt path carries:
> temp-file leakage, backup/snapshot exposure, and crash-recovery residue
> if the process died between the write and the cleanup unlink. `tmpDir`
> has been removed — this method never touches disk now. (Not a versioned
> breaking change — see the pre-release design notes under Install above.)

```ts
await spd.extractDataStreaming(async (name, value) => {
  console.log(name, value);
});
```

---

### `SPD.extractFromFileStreaming(filePath, passcode, tmpDir, callback, onProgress?, verifyKey?): Promise<void>`

Bounded-memory extraction from a binary `.spd` file (written by `saveToFileStreaming`). Spools the decompressed plaintext to a single `<tmpDir>/_spd_plaintext.ssf` for whole-file MAC verification, then decrypts one entry at a time — peak RAM is proportional to the largest entry, not the file.

Peak RAM usage is proportional to the largest single entry, not the file size.

Pass `verifyKey` (an ML-DSA-65 public key) to also enforce a pinned file signature, same as `loadFromFile`.

```ts
await SPD.extractFromFileStreaming(
  './huge.spd',
  'MyStr0ng!Passphrase#2024',
  '/tmp/spd_scratch',
  async (name, value) => {
    console.log(name, typeof value);
  }
);
```

---

### `spd.saveData(passcode: string): Promise<string>`

Serializes the payload to a base64 string for in-memory or network transport.

```ts
const b64 = await spd.saveData('MyStr0ng!Passphrase#2024');
```

**Size guidance:** this (and `saveToFile`/`saveDataChunked`, which share the same
underlying JSON serialization) is genuinely fine for typical entries — small
files, config blobs, credentials, session data. For very large entries
(tens of MB and up of real, high-entropy data — encrypted blobs, images,
already-compressed files), expect it to get slow well before it fails
outright: measured directly on this project's dev machine, a single ~25MB
incompressible entry took **~76 seconds** to serialize before a since-fixed
optimization, and even after that fix, very large single entries (100MB+)
can still take a minute or more and use several GB of RAM, because the
whole payload — including this format's own JSON envelope layered around
each entry — has to be assembled as one in-memory string. **For large
files or entries, use `saveToFileStreaming`/`loadFromFileStreaming`
instead** — a genuinely different binary-framed code path with none of
this ceiling, built specifically for large files (see below).

---

### `SPD.loadFromString(data: string, passcode: string, verifyKey?: Uint8Array): Promise<SPD>`

Loads from a base64 string produced by `saveData`. Pass `verifyKey` to require and verify a file signature, same as `loadFromFile` (`loadFromChunks` takes it as its third argument too). Any bytes after the end of the compressed container are rejected, not ignored.

```ts
const spd = await SPD.loadFromString(b64, 'MyStr0ng!Passphrase#2024');
```

---

### Chunked internet transfer

Split a payload into chunks for HTTP uploads or any transport with a body-size limit.

```ts
// Sender — chunk size is chosen automatically
const chunks = await spd.saveDataChunked('MyStr0ng!Passphrase#2024');

// Override chunk size when you have a strict body limit (e.g. 256 KB per request)
const chunks = await spd.saveDataChunked('MyStr0ng!Passphrase#2024', 256 * 1024);

// Receiver — pass all chunks in order including the manifest
const spd = await SPD.loadFromChunks(receivedChunks, 'MyStr0ng!Passphrase#2024');
```

The last element of the array is always a JSON manifest (`{ totalChunks, chunkSize, totalBytes, version }`). The receiver validates chunk count and byte count before decrypting.

**Auto chunk size** (when `chunkSize` is omitted): targets ~32 chunks, clamped between 64 KB and 8 MB, rounded to the nearest 64 KB boundary.

---

### `spd.changePasscode(oldPasscode: string, newPasscode: string): Promise<void>`

Re-derives keys under the new passcode and re-encrypts all data. Verifies the old passcode via MAC before doing anything.

```ts
await spd.changePasscode('MyStr0ng!Passphrase#2024', 'EvenStr0nger!Pass#9999');
```

---

### `spd.upgradeKdfParams(passcode: string, { memory, time, parallelism? }): Promise<void>`

Re-derives keys under the **same** passcode but **stronger** Argon2id cost parameters — for periodically re-hardening long-term archival data as hardware improves, without waiting until someone actually needs to open the file (by which point the passphrase may no longer be remembered). New `memory`/`time` must both be ≥ the file's current values; this method only ever strengthens a file's KDF cost. A fresh salt is generated too. Does not save to disk — call `saveToFile`/`saveToFileStreaming` after, same as `changePasscode`.

```ts
const spd = await SPD.loadFromFileStreaming('./archive.spd', passcode);
await spd.upgradeKdfParams(passcode, { memory: 262144, time: 8 }); // e.g. double the standard profile's cost
await spd.saveToFileStreaming('./archive.spd', passcode);
```

---

### Bit-rot / silent-corruption resilience

For archival storage over years or decades, individual bytes on disk can silently flip (media degradation, filesystem bugs, cosmic-ray-induced bit flips) with no I/O error at all — the first sign is usually a file that suddenly fails to decrypt. SPD can generate a Reed-Solomon parity sidecar that lets a corrupted `.spd` file **self-heal** on load, up to a configurable amount of damage.

Design note: parity is computed over the `.spd` file's raw **encrypted** bytes, stored in a completely separate `<file>.ecc` sidecar — the `.spd` file's format, its embedded offset index, and `getEntry()`'s random-access reads are all completely unmodified by this feature. It's 100% additive and opt-in, and needs no passcode (the sidecar carries no secrets, only parity over already-opaque ciphertext).

**Explicit API:**

```ts
await SPD.writeParityFile('./archive.spd');
// ... time passes, a few bytes rot ...
const result = await SPD.repairBitRot('./archive.spd', passcode); // verified in place; without a passcode writes archive.spd.repaired
// { repaired: true, blocksChecked: 8, blocksCorrupted: 1, blocksRepaired: 1, unrecoverableBlocks: [] }
```

With the default parameters (64 KiB blocks, 16 data + 4 parity shards per block), each block is split into 20 shards of 4 KiB and any 4 of them may be damaged. A single flipped byte spoils its whole shard, so the budget is really "up to 4 damaged 4 KiB regions per 64 KiB block": one contiguous run of up to ~16 KiB recovers, but 5 scattered bit flips in 5 different shards of the same block do not. Tune via `{ blockSize, dataShards, parityShards }` on `writeParityFile` — more parity shards tolerate more corruption per block at the cost of a larger `.ecc` file.

**Sugar — integrated into save/load:**

```ts
await spd.saveToFileStreaming('./archive.spd', passcode, undefined, { errorCorrection: true });
// later, possibly after some bit-rot:
const loaded = await SPD.loadFromFileStreaming('./archive.spd', passcode, undefined, undefined, { autoRepair: true });
```

`{ errorCorrection: true }` also works on `saveToFile` (JSON format); `{ autoRepair: true }` also works on `loadFromFile`. The `.ecc` sidecar is integrity-checked but not authenticated (its key is inside it), so a repaired file only replaces the original after it passes the file's own MAC — `repairBitRot(path, passcode)` and `autoRepair` do this; `repairBitRot(path)` without a passcode writes `<file>.repaired` and leaves the original untouched. `repairBitRot`/`autoRepair` throw a clear error if the file's size no longer matches what the sidecar was built for (the file was replaced, not just bit-rotted) or if corruption in any block exceeds the parity budget — in the latter case nothing is written back, so a partially-repaired, silently-wrong file is never produced.

---

### Keyless key system — no human-typed passcode

`setPassKey()` always requires a human passphrase. For fully automated/unattended systems — CI secrets, service-to-service storage, anything with no human available to type or remember a passphrase — SPD supports unlocking with a raw, machine-generated master secret instead.

```ts
const secret = SPD.generateRandomKey(); // 96 bytes of CSPRNG output, no human input
await putInYourSecretsManager('my-app/spd-key', secret); // you own storage/retrieval

const spd = new SPD();
await spd.setRandomKey(secret);
await spd.addData('config', myConfig);
await spd.saveToFileStreaming('./data.spd', ''); // passcode arg ignored in keyless mode

// later, anywhere:
const loaded = await SPD.loadWithRandomKey('./data.spd', secret);
```

This deliberately skips Argon2id (and KDF chaining) entirely — a passphrase needs a slow, memory-hard KDF because it has limited, guessable entropy; a 96-byte CSPRNG secret has 768 bits with nothing to brute-force, so spending wall-clock time "stretching" it buys no security and only slows down every unlock. Same XChaCha20-Poly1305 encryption, same file format, same signatures/ratchet/epoch-rotation support as the passphrase path — only the derivation of the master secret differs, and it's dramatically faster (no Argon2id run at all, vs. ~0.5s+ even at the cheapest profile).

**Keyfile-only variant** — if you'd rather not build your own secret-storage integration:

```ts
SPD.generateKeyfileOnly('/secure/vault/my.key'); // writes a 96-byte CSPRNG file
const spd = new SPD();
await spd.setKeyfileOnly('/secure/vault/my.key');
// ...
const loaded = await SPD.loadWithKeyfileOnly('./data.spd', '/secure/vault/my.key');
```

The keyfile *is* the entire credential here — protect it like a private key (separate storage from the `.spd` file, restricted permissions, backed up). This is distinct from the older `SPD.generateKeyfile()`/`loadKeyfile()` pair, which produces a 64-byte file that only *supplements* a passphrase (both are still required) rather than replacing it.

You are responsible for storing the master secret durably and appropriately (OS keychain, secrets manager, HSM, or the keyfile above). Losing it means permanent, unrecoverable data loss — same as forgetting a passphrase, with no recovery path, by design. `changePasscode()`/`upgradeKdfParams()` throw a clear error on keyless instances (there's no passphrase to change and no Argon2id cost to strengthen) — use `rotateRandomKey()` instead.

**Rotating the secret periodically** — the keyless counterpart to `changePasscode()`/`upgradeKdfParams()`, for unattended systems where nobody would otherwise think to rotate credentials manually:

```ts
const newSecret = await spd.rotateRandomKey(oldSecret); // auto-generates a fresh one
await spd.saveToFileStreaming('./data.spd', '');
await putInYourSecretsManager('my-app/spd-key', newSecret); // your own storage

// or supply your own replacement:
await spd.rotateRandomKey(oldSecret, myPreGeneratedSecret);
```

Verifies `oldSecret` is actually correct before changing anything (throws `Authentication failed` otherwise, leaving the instance untouched), decrypts every entry, re-derives under a fresh salt + the new secret, and re-encrypts everything. Does not save to disk on its own — call `saveToFile`/`saveToFileStreaming` after, same as `upgradeKdfParams`.

---

### Public-key recipients — `SPDRecipient` (post-quantum hybrid)

Encrypt a file *to people*, not to a shared passphrase. `SPDRecipient` seals the keyless master secret (see above) to one or more public keys using the **MLKEM768-X25519** hybrid KEM — the same PQ/T KEM as `draft-ietf-hpke-pq` and age's `age1pq` recipients — with a key-committing XChaCha20-Poly1305 wrap per recipient. Any one listed recipient can open the envelope; the envelope itself reveals nothing about who they are.

```ts
import { SPD, SPDRecipient } from 'spd-lib';

// Each recipient, once:
const me = SPDRecipient.generateIdentity();            // { publicKey (1216 B), secretKey (32 B) }
share(SPDRecipient.encodePublicKey(me.publicKey));      // "spdpq1...."

// Sender:
const { masterSecret, envelope } = SPDRecipient.newSealedKey([alicePk, bobPk]);
const spd = new SPD();
await spd.setRandomKey(masterSecret);
masterSecret.fill(0);
await spd.addData('report', data);
await spd.saveToFile('report.spd', '');                 // keyless: passcode ignored
// deliver report.spd + envelope (7 + 1,264 bytes per recipient)

// Recipient:
const master = SPDRecipient.open(envelope, me.secretKey);
const file   = await SPD.loadWithRandomKey('report.spd', master);
master.fill(0);
```

`SPDRecipient.inspect(envelope)` reports version, KEM and recipient count without any key. Works in the browser build too.

In the browser (no files), persist as strings: `await spd.saveData('')` on a keyless instance and `SPD.loadStringWithRandomKey(str, masterSecret)` (or `loadChunksWithRandomKey` for `saveDataChunked` output) on the way back — the in-memory counterparts of `loadWithRandomKey`.

One-call form (Node): `SPD.createSealed(recipients)` returns an unlocked instance plus its envelope; `spd.saveToFileSealed(path, recipients, { streaming? })` writes the file and a `<path>.spdr` envelope sidecar; `SPD.loadFromFileSealed(path, secretKey, { envelope?, verifyKey?, streaming? })` opens it as a recipient. `loadFromFile` and `loadFromFileStreaming` (and therefore `loadWithRandomKey` and `loadFromFileSealed`) sniff the file header and open either the JSON or the binary format. `spd-inspect` describes `.spdr` envelopes (and reports a sidecar next to a `.spd`) without any key.

---

### `spd.setHash(hash: 'sha3-512' | 'sha256' | 'sha512'): void`

Sets the hash algorithm used for per-entry integrity checks. Default is `'sha3-512'`. Must be set before adding data.

```ts
spd.setHash('sha3-512'); // default, recommended
```

---

### `spd.setCompressionLevel(level: number): void`

Sets the zlib deflate compression level (1–9). Default is `6`.

```ts
spd.setCompressionLevel(9); // maximum compression
spd.setCompressionLevel(1); // fastest, largest output
```

---

### `spd.setSigningKey(privateKey: Uint8Array)` / `SPD.generateSigningKeyPair({ composite? })`

Post-quantum file signatures. `SPD.generateSigningKeyPair()` returns an **ML-DSA-65** (FIPS 204) key pair as raw bytes (4032-byte private key, 1952-byte public key). When a signing key is set, every save embeds a 3309-byte signature over the file's MAC; pass the public key as `verifyKey` to `loadFromFile` / `loadFromFileStreaming` / `loadFromString` / `loadFromChunks` / `getEntry` / `extractFromFileStreaming` to require and verify it.

`SPD.generateSigningKeyPair({ composite: true })` returns a **PQ/T composite** pair — ML-DSA-65 **+ Ed25519**, after `draft-ietf-lamps-pq-composite-sigs` — with 4064/1984-byte keys and 3373-byte signatures. A composite signature verifies only if *both* components verify, so signed files stay unforgeable if a flaw is ever found in either algorithm. The kinds are non-separable: an ML-DSA-only verify key rejects a composite signature (and vice versa) instead of accepting a stripped one.

```ts
const { privateKey, publicKey } = SPD.generateSigningKeyPair({ composite: true });

spd.setSigningKey(privateKey);
await spd.saveToFileStreaming('./signed.spd', PASS);

const loaded = await SPD.loadFromFileStreaming('./signed.spd', PASS, publicKey); // throws if missing/invalid
```

The signature is verified only when a `verifyKey` is supplied: it proves *who signed* to a reader who already holds the passcode. Because the signed message is the keyed MAC, a signature cannot be checked without the decryption key — there is no "verify but don't decrypt" mode, and a third party without the passcode cannot audit who signed a file. Anyone with the passcode can re-save the file unsigned, so pin the public key out of band wherever authenticity matters.

---

### `spd.setEpochSize(bytes: number): void`

Controls the epoch size (in bytes) for the key-ratcheting mechanism used in chunked exports. Default `0` (ratcheting disabled).

---

### `spd.destroy()` / `spd.clearCache()`

Zeros all key material in place with `fill(0)`, then clears all stored data.

```ts
spd.destroy();
```

---

## Cryptographic utilities

These live in `SPDUtils` (also reachable as `SPD.<name>`). Each entry below states what the function actually does; several are marked `@deprecated` in the API because they add no cryptographic strength beyond what `SPD` entries already provide — they remain for compatibility only.

Beyond the core Argon2id/XChaCha20-Poly1305/HMAC-SHA3-512 pipeline, SPD ships a set of standalone utility functions for specific, narrower use cases. Each one below does exactly what its description says — no more. Where a mechanism's real guarantee is narrower than its name might suggest, that's called out explicitly rather than left implied.

### One-time pad (OTP)

Information-theoretically secure encryption (Shannon 1949): a genuinely random key, at least as long as the message and never reused, XORed with the plaintext. This is a real, correctly-implemented OTP — its secrecy guarantee holds regardless of attacker compute, but only as long as you actually respect "random, as-long-as-the-message, never reused." Reusing a pad or deriving it non-randomly breaks the guarantee completely; SPD does not and cannot enforce non-reuse across calls — that's on the caller.

```ts
const key        = SPD.generateOtpKey(message.length);
const ciphertext = SPD.otpEncrypt(message, key);
const plaintext  = SPD.otpDecrypt(ciphertext, key);
```

`multiPadEncrypt`/`multiPadDecrypt` are **deprecated**: XOR with several pads is a single XOR with their XOR, so a leaked pad gives exactly the same protection as with one pad. Use one pad (or an `SPD` entry). Kept for compatibility:

```ts
const pad1 = SPD.generateOtpKey(msg.length);
const pad2 = SPD.generateOtpKey(msg.length);
const ct   = SPD.multiPadEncrypt(msg, [pad1, pad2]);  // OTP2(OTP1(msg))
const pt   = SPD.multiPadDecrypt(ct, [pad1, pad2]);
```

### Air-gap check

Checks `os.networkInterfaces()` and throws if any non-loopback network interface is active — a best-effort software signal, not a hardware guarantee (it can't detect physical network taps, and a sufficiently privileged process could spoof the interface list).

```ts
SPD.requiresAirGap(); // throws if this machine has any non-loopback interface

if (SPD.isAirGapped()) {
  // no non-loopback interface detected
}
```

### Decoy-prefixed entries (`deniableDecryptView`)

`deniableDecryptView()` decrypts and returns only entries whose names start with `_decoy_`, skipping everything else. It is a **view filter under the same key — not a hidden volume**, and it provides no deniability against anyone who holds the passcode: they can run `extractData()`/`keys()` instead, and the binary format's metadata states the total entry count in clear. (A VeraCrypt-style hidden volume needs a second, independent key; SPD does not have one.) Use it for UI presentation only.

```ts
await spd.addData('_decoy_message', 'innocent content');
await spd.addData('real_secret', 'the actual sensitive value');
const decoyView = await spd.deniableDecryptView(); // only the _decoy_-prefixed entries
```

### Key destruction receipt

`destroyWithProof(key, signingKey)` computes an HMAC-SHA3-512 receipt over the key and a timestamp, then zeroes the key. The zeroing is real. The receipt is a genuine, verifiable audit-log entry — proof that *someone holding `signingKey` attested to this destruction event at this time* — but it is not a cryptographic proof that zeroing actually occurred: a caller could construct the same receipt without ever calling `.fill(0)`. Treat it as an audit trail, not a guarantee independent of trusting the caller.

```ts
const proof = SPD.destroyWithProof(keyBytes, signingKey);
// proof = hex HMAC receipt — auditable, not independently verifiable
```

### Temporal keys

Keys valid only within a short absolute time window; after expiry (or on manual `cancel()`), the key material is zeroed via a real `setTimeout`-scheduled callback.

```ts
const { temporalKey, absoluteDeadline, cancel } = SPD.wrapTemporalKey(key, 5 * 60 * 1000);
cancel(); // erase early
```

### Channel noise injection

Random transmission delays and padding lengths, drawn from a real CSPRNG, to reduce the reliability of traffic-timing/size analysis. This raises the cost of traffic analysis; it does not make it impossible on its own — pair it with other mitigations if you need a stronger guarantee.

```ts
const { delayMs, padding } = SPD.noiseInjection();
await new Promise(r => setTimeout(r, delayMs));
```

Related: `startNoiseBaseline(intervalMs?, onPacket?)` generates randomly-sized dummy payloads at random intervals and hands each to your `onPacket` callback — it sends nothing itself; without a callback it only counts. Your transport must actually transmit them for the cover traffic to exist:

```ts
const noise = SPD.startNoiseBaseline();
noise.stop();
```

### Physical key distribution / knowledge separation (self-reported checks)

`assertPhysicalKeyDistrib(mode)` and `assertKnowledgeSeparation(acks)` check that a caller-supplied label or acknowledgment matches an expected shape (an allowlist of channel names; truthy role acknowledgments). **Neither function independently verifies anything about what actually happened** — they exist to make an operational process fail loudly if a step is skipped or mislabeled by whoever is calling them, which is useful as a process guardrail, but they cannot detect a caller lying about how a key was actually delivered or who actually holds what.

```ts
SPD.assertPhysicalKeyDistrib('QKD');      // throws unless the label is a recognized channel
SPD.assertKnowledgeSeparation({ entropyOperator: true, fragmentKeeper: true });
```

### Carrier embedding (not steganography)

`embedInCarrier`/`extractFromCarrier` write ciphertext into a carrier buffer at an HMAC-derived offset. This hides the ciphertext's *location* from someone who doesn't know the secret offset key, but it does **not** hide that the carrier contains high-entropy data — ciphertext looks statistically like noise, and any entropy analysis of the carrier will flag the embedded region as anomalous compared to structured content (audio, images, etc.) around it. Use this for simple offset-based obscurity, not as a substitute for real steganography (which requires shaping the embedded data to match the carrier's own statistical distribution — SPD does not implement that).

```ts
const carrier   = crypto.randomBytes(4096);
const secret    = crypto.randomBytes(32);
const hidden    = SPD.embedInCarrier(ciphertext, carrier, secret);
const recovered = SPD.extractFromCarrier(hidden, secret);
```

### Anti-forensic mode

`enableAntiForensic(true)` disables the process-wide unlock cache (`SPD.setKeyCacheTtl(0)`; it cannot be re-enabled while any anti-forensic instance is alive) and flips a flag other code can check. It reduces how long derived keys linger in memory that this process controls; it cannot prevent the OS from having already paged memory to swap, and it has no control over process logging outside SPD's own code.

```ts
spd.enableAntiForensic(true);
if (spd.isAntiForensicMode()) { /* ... */ }
```

### Entropy inflation / time-smearing / quantum-sourced keys

All three are **deprecated**: `inflateEntropy` and `timeSmear` are plaintext padding/splitting, not encryption, and `generateQuantumKey` is an alias for the CSPRNG.

Three independent utilities for burying or spreading real content:

```ts
// Bury a message inside much larger random padding at a secret CSPRNG-chosen offset
const { inflated, realOffset } = SPD.inflateEntropy(message, 50); // ~50x padding

// Split a message into fragments meant to be sent at random delays over a window
// (the fragments themselves don't carry any linking metadata, but nothing here
// prevents an observer who captures every fragment from eventually reassembling
// them by other means — this raises the cost of correlation, it doesn't remove it)
const fragments = SPD.timeSmear(message, 16, 2_592_000_000); // spread across ~30 days

// CSPRNG-sourced key material. Despite the name, this is crypto.randomBytes under
// the hood, not a literal hardware quantum RNG — see the function's own doc comment.
const key = SPD.generateQuantumKey(32);
```

---

## SPDWriter — streaming disk-backed writer

`SPDWriter` encrypts and writes entries one at a time to disk — the full plaintext never exists in RAM simultaneously. Suitable for constructing large SPD files from a stream of records.

Also exported from `spd-lib/browser` (so importing it never fails), but every method needs a real filesystem and throws a clear `... requires Node.js` error if called there — it's disk-backed by nature, there's no in-memory equivalent. Use it from a Node environment only.

```ts
import { SPDWriter } from 'spd-lib';

const writer = new SPDWriter('./output.spd', 'MyStr0ng!Passphrase#2024');
await writer.init();

await writer.addEntry('username', 'alice');
await writer.addEntry('config', { theme: 'dark' });

await writer.finalize();
```

After `finalize()`, the file contains an embedded `SPDy` index tail compatible with `SPD.getEntry()` — no sidecar file needed.

**Options:**

| Option | Default | Description |
|---|---|---|
| `compressionLevel` | `9` | zlib deflate level |
| `hashAlgorithm` | `'sha3-512'` | Per-entry hash |
| `argon2Memory` | `131072` (128 MiB) | Argon2id memory cost |
| `argon2Time` | `6` | Argon2id time cost |

Call `writer.destroy()` to zero keys and delete the partial file if `finalize()` was never called.

---

## SPDVault — in-memory key vault

`SPDVault` is a time-limited in-memory store for passcodes or keys. Keys expire automatically after a configurable TTL.

```ts
import { SPDVault } from 'spd-lib';

const vault = new SPDVault(300_000); // 5-minute TTL

vault.genKey('session');
vault.pushKey('myKey', 'MyStr0ng!Passphrase#2024');
const key = vault.pullKey('myKey'); // resets TTL
vault.updateKey('myKey', 'MyStr0ng!Passphrase#2024', 'NewPass!99');
vault.destroyKey('myKey');
vault.stop();
vault.destroy();
```

**Note:** the string-based API above (`genKey`/`pushKey`/`pullKey`/`updateKey`/`destroyKey`) can't actually wipe key material from memory — JS strings are immutable, so "expiration" only drops the vault's internal reference, not the underlying string data. If you need an actual memory-safety guarantee (the key bytes provably overwritten on expiry/destroy), use the byte-based API instead:

```ts
vault.genKeyBytes('session', 32);              // generates a random 32-byte key
vault.pushKeyBytes('myKey', someUint8Array);    // takes ownership — don't reuse the array after
const keyBytes = vault.pullKeyBytes('myKey');   // resets TTL; Uint8Array | undefined
vault.updateKeyBytes('myKey', oldBytes, newBytes);
vault.destroyKeyBytes('myKey');                 // zeroes before dropping
```

Generated keys are 500–699 characters from a 91-character charset using rejection sampling (no modulo bias).

---

## SPDTransport — encrypted client↔server sessions

`SPDTransport` is an authenticated, forward-secret secure channel — X25519 ECDH (V1) or a hybrid X25519 + ML-KEM-768 handshake with optional ML-DSA-65 certificate pinning (V2, the default). Independent monotonic per-direction counters feed the XChaCha20-Poly1305 nonce, so every frame is both encrypted and replay-protected.

**High-level API — `connect`/`accept`** (recommended): provide `send`/`receive` functions over whatever real transport you have (WebSocket, TCP, HTTP long-poll), and the handshake round-trip — V1 or V2, `processServerHello`, all of it — is handled for you:

```ts
import { SPDTransport } from 'spd-lib';

// ── Server ───────────────────────────────────────────────────────────────
const identity = await SPDTransport.generateServerIdentity();
const session = await SPDTransport.accept(identity, {
  send:    (bytes) => ws.send(bytes),
  receive: () => new Promise((resolve) => ws.once('message', resolve)),
});
const plaintext = session.decrypt(incomingFrame);
const reply     = session.encrypt(responseBytes);

// ── Client ───────────────────────────────────────────────────────────────
const session = await SPDTransport.connect(identity.publicKey, {
  send:    (bytes) => ws.send(bytes),
  receive: () => new Promise((resolve) => ws.once('message', resolve)),
});
session.encrypt(payload);
```

`connect` takes the same `SPDClientConnectOptions` as `clientConnect` (`pinnedSigningKey`, `psk`, `padding`, `v2`), and `accept` takes the same `psk`/`padding` as `serverAccept` — nothing about the handshake itself changes, only who drives the round-trip.

**Low-level API** (manual wiring — use this if you need to send `clientHello`/`serverHello` over a channel `connect`/`accept` can't express as simple send/receive, e.g. splitting the handshake across separate HTTP requests):

```ts
// ── Server ───────────────────────────────────────────────────────────────
const identity = await SPDTransport.generateServerIdentity();
const { session, serverHello } = await SPDTransport.serverAccept(identity, clientHello);
session.decrypt(encryptedFrame);

// ── Client ───────────────────────────────────────────────────────────────
const { session, clientHello } = await SPDTransport.clientConnect(identity.publicKey, {
  pinnedSigningKey: serverSigningPubKey, // optional cert pin
  psk: sharedSecret32,                    // optional PSK resumption
});
send(clientHello);
await session.processServerHello(await receive());
session.encrypt(payload);
```

**Re-keying before counter exhaustion:** each direction's send counter is a 64-bit value — practically inexhaustible for almost every use case, but a long-lived session (e.g. a persistent server connection open for months) can check proactively instead of waiting for `encrypt()` to throw:

```ts
if (session.isNearExhaustion()) {           // default threshold: 1% of range remaining
  // perform a fresh connect()/accept() (or clientConnect/serverAccept) handshake
  // and switch this connection's read/write paths to the new session
}
session.sendCounterRemaining(); // exact bigint count, if you want a custom threshold
```

---

## Security scanner — scan any codebase

`spd-lib` ships a standalone security scanner that analyzes **any** codebase (TypeScript, JavaScript, Python, Go, Java, Rust, etc.) for cryptographic security issues and scores it out of 100 — not just `.spd` files or spd-lib consumers. It's part of this package, not a separate published package; install `spd-lib` and both a CLI command and a programmatic API are available.

```sh
npm install spd-lib
```

### CLI usage

```sh
npx spd-score ./src         # scan a directory
npx spd-score --json ./src  # output raw JSON
npx spd-score --help        # show scoring criteria
```

### What it detects

| Category | Max | Issues flagged |
|---|---|---|
| Cipher strength | 25 | AEAD vs AES-CBC/ECB/DES/RC4, key size |
| Key derivation | 25 | Argon2id > scrypt > bcrypt > PBKDF2 > MD5/SHA1 |
| Integrity & auth | 20 | Missing AEAD/HMAC, weak hash |
| Nonce / IV safety | 10 | Static IV, missing random nonce |
| Post-Quantum & FS (scorer label; the "forward secrecy" item is per-save re-salting) | 10 | ML-KEM, ML-DSA, per-save re-salting (not forward secrecy: every file stays decryptable with the passcode) |
| Implementation safety | 10 | Timing-safe compare, memzero, hardcoded keys |

Security issues appear at the top before the category breakdown:

```
  SECURITY ISSUES FOUND (5)
  ✘  Legacy cipher detected (AES-CBC): vulnerable to padding oracles...
  ✘  MD5/SHA1 used for password hashing — completely broken. Migrate to Argon2id.
  ✘  Encryption without authentication — attacker can flip ciphertext bits...
  ✘  Static or zero IV detected — nonce reuse allows full plaintext recovery...
  ✘  Hardcoded cryptographic key detected — rotate immediately...
```

Exits with code `0` for any A grade (A-/A/A+), `1` for anything below, `2` on a usage error.

### Programmatic API

```ts
import { analyzeGenericDir, scoreGenericSystem } from 'spd-lib/score';

const obs    = analyzeGenericDir('./src');
const result = scoreGenericSystem(obs, 'my-project');

console.log(result.total);    // 0–100
console.log(result.grade);    // 'F' | 'D' | 'C' | 'B-' | 'B' | 'B+' | 'A-' | 'A' | 'A+'
console.log(result.warnings); // string[] of security issue descriptions
```

Importing from `spd-lib/score` never runs the CLI scanner or calls `process.exit()` — the CLI executable (`npx spd-score`) is a separate, dedicated entry point that never gets pulled in by this import, even inside a bundled consumer application. (An earlier version of this package detected "am I being run directly?" by comparing `process.argv[1]` against `__filename`, which broke under some bundler configurations — a consumer bundle that merely imported `scoreSPD` could see its own `__filename` shim match `process.argv[1]` and incorrectly trigger the CLI's `process.exit()`. Fixed by separating the CLI entry point out entirely rather than tightening the detection further.)

---

## spd-inspect — interactive `.spd` file inspector

Breaks open a `.spd` file (JSON or streaming binary format) layer by layer for debugging: raw header bytes, the compressed body, the metadata block, per-entry details, and (with a passcode) the decrypted values themselves.

```sh
npx spd-inspect ./vault.spd                          # interactive, prompts for passcode
npx spd-inspect ./vault.spd --pass 'MyStr0ng!Pass'    # non-interactive
npx spd-inspect ./vault.spd --layer 2                 # stop after the metadata layer
npx spd-inspect ./vault.spd --entry username          # inspect just one entry
npx spd-inspect ./vault.spd --streaming               # for files written by saveToFileStreaming
```

---

## Full example — save and load a config

```ts
import { SPD } from 'spd-lib';
import * as path from 'path';

const FILE = path.join(process.env.HOME!, '.myapp', 'config.spd');
const PASS = process.env.APP_PASS!;

async function saveConfig(config: Record<string, unknown>) {
  const spd = new SPD();
  await spd.setPassKey(PASS);
  await spd.addMany(Object.entries(config).map(([name, data]) => ({ name, data })));
  await spd.saveToFileStreaming(FILE, PASS);
  spd.destroy();
}

async function loadConfig(): Promise<Record<string, unknown>> {
  const spd = await SPD.loadFromFileStreaming(FILE, PASS);
  const data = await spd.extractData();
  spd.destroy();
  return data;
}
```

---

## Full example — chunked HTTP upload

```ts
// Sender
const spd = new SPD();
await spd.setPassKey(PASS);
await spd.addData('payload', largeObject);
const chunks = await spd.saveDataChunked(PASS, 256 * 1024);
spd.destroy();

for (let i = 0; i < chunks.length; i++) {
  await fetch('https://example.com/upload', {
    method: 'POST',
    body: JSON.stringify({ index: i, chunk: chunks[i] }),
  });
}

// Receiver
const spd = await SPD.loadFromChunks(receivedChunks, PASS);
const data = await spd.extractData();
spd.destroy();
```

---

## Versioning

| npm version | SPD format version | Notes |
|---|---|---|
| 2.1.1 | v29 | Bug fixes: trailing bytes after the JSON container are rejected; `loadFromFile`/`loadFromFileStreaming` sniff the format and open either; `verifyKey` on `loadFromString`/`loadFromChunks`; corrected ECC repair claim. Same v29 wire format. |
| 2.1.0 | v29 | `SPDRecipient` (MLKEM768-X25519 envelopes), composite ML-DSA-65+Ed25519 signatures, keyed `SPDy` index tail, opt-in unlock cache, `setWrapKeyProfile`, verified `repairBitRot`, atomic key rotation, `SPEC.md`; default `'high'` profile drops the scrypt chain (several× faster unlocks); three internal audit passes with regression tests; Rust implementation. Same v29 wire format. |
| 2.0.1 | v29 | ESM-only (no CJS `require()`); no `libsodium-wrappers` dependency (pure-JS `@noble/ciphers` AEAD, from-spec KX); no `Buffer` in the core library; `SPDLegacy` and `getSodium()` removed; native `zlib` for the Node build and native `CompressionStream` for the browser build (no `fflate`); `hash-wasm` WASM Argon2id tier added between the native addon and the pure-JS fallback; 11 non-functional "security" methods removed and six no-benefit utilities marked `@deprecated` (honesty pass — no behavior or wire-format change). See the design notes under [Install](#install). Same v29 wire format as 1.4.0 — no file-format changes. |
| 1.4.0 | v29 | CMT-4 key commitment, HKDF key expansion, encrypted entry names, 256-byte compression padding, 256-bit salt, OTP mode, additional cryptographic utilities (see [Cryptographic utilities](#cryptographic-utilities)) |
| 1.3.1 | v26 | Hash algo + Argon2 params embedded in payload, secure key zeroing, `null` type support |
| 1.3.0 | v25 | 512-bit Argon2id master secret, domain-separated AEAD + HMAC keys, HMAC-SHA3-512 |
| < 1.3.0 | v24 | 256-bit Argon2id, single key for AEAD + MAC |

SPD format versions are not cross-compatible. v29 files cannot be read by older library versions. `SPDLegacy` (which read v24-and-earlier files) was removed in the version that dropped libsodium — pin an older release if you still need to read files that old.

---

## Wire format (v29 binary)

The normative record layout, header, `SPDy` index tail, key schedule, signature and envelope formats live in [SPEC.md](./SPEC.md). In one line: the file is a sequence of per-entry XChaCha20-Poly1305 records (CMT-4 commitment ‖ nonce ‖ ciphertext) under a zlib-deflated, HMAC-SHA3-512-authenticated container with a 72-byte header and an `SPDy` index tail with keyed name tags.

## License

ISC
