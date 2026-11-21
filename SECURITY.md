# Security Policy

`spd-lib` is a cryptography library. Bugs in it can translate directly into
data exposure for its users, so security reports are taken seriously and
prioritised over feature work.

## Supported versions

| Version | Supported |
|---|---|
| 2.0.x | ✅ |
| 1.4.x | ⚠️ critical fixes only |
| < 1.4 | ❌ |

The `.spd` file formats are not cross-compatible between major format versions
(see [README.md](./README.md#versioning)); a fix that requires a format change
will ship in a new minor/major, not be backported.

## Reporting a vulnerability

**Do not report security bugs in a public forum.**

Report privately through either channel:

- **Email:** <security@alsopss.com>
- **Web form:** <https://report.alsopss.com>

Please include:

- affected version(s) and platform (Node version / browser / Deno / Bun);
- a minimal reproduction, or a clear description of the weakness and its impact;
- whether the issue is already public anywhere.

### What to expect

- Acknowledgement within **5 working days**.
- An initial assessment (severity, affected versions, likely fix approach)
  within **10 working days**.
- Coordinated disclosure: a fixed release and a published advisory, with credit
  to the reporter unless anonymity is requested.

## Scope

In scope: anything in `src/` — the KDF chain, AEAD/MAC construction, the
transport handshake (`SPDTransport`), the wire format, key handling and
zeroing, and the bundled security scanner (`spd-score`).

Out of scope: the strength of a caller-chosen passphrase, misuse of the
explicitly-narrow cryptographic utilities documented as such in the README
(e.g. `embedInCarrier`, `timeSmear`), and denial of service from
attacker-controlled decompression input already bounded by the streaming
decompression-bomb defense.

## Threat model and known limitations

What SPD protects, against whom, and what it deliberately does not claim. The
normative format is in [SPEC.md](./SPEC.md); the evidence is the test suites
(`test/`), including differential tests against libsodium and RFC vectors,
mutation fuzzing, property tests and committed golden fixtures.

**Protected (given a strong passcode or a random key):**
- Confidentiality and integrity of entry values and entry names at rest
  (XChaCha20-Poly1305 with CMT-4 key commitment per entry, HMAC-SHA3-512 over
  the whole file, encrypted names in records and keyed name tags in the index).
- Offline guessing cost: Argon2id (128 MiB–2 GiB profiles) plus the salt-wrap
  derivation; keyless/recipient files use 768-bit random secrets.
- Post-quantum confidentiality for recipient envelopes and sessions
  (MLKEM768-X25519 hybrid), and PQ or PQ/T-composite file signatures.

**Not protected / advisory only — read before relying on a feature:**
- *Entry ACLs* (`restrictEntry`) are stored in authenticated metadata but
  there is one key for all entries: anyone holding the passcode can set any
  role. They prevent mistakes inside a trusted application, not between
  mutually distrusting parties.
- *Sidecars* (`.seq` rollback counter, `.ocount`/`.maxcount` open budget,
  `.lock`) are plain files; an attacker with write access to the directory can
  reset or forge them. `.ecc` parity is integrity-checked but not
  authenticated; repairs only replace the original after the repaired bytes
  pass the file's MAC.
- *Decoys and `deniableDecryptView`* give no deniability against anyone who
  has the passcode (they can read everything, and the binary metadata states
  the entry count).
- *Per-save re-salting* is not forward secrecy: every earlier file stays
  decryptable with the passcode.
- *Process memory*: keys are zeroed on `destroy()`, but JavaScript strings
  (passcodes, decrypted string values) cannot be wiped; a memory dump of a
  live process is out of scope. The opt-in unlock cache keeps derived keys in
  memory for its TTL.
- *Transport/handshake* are unauthenticated unless keys are pinned
  (`pinnedSigningKey`, `SPDHandshakeAuthOptions`); the commitment check alone
  does not stop an active man-in-the-middle.
- *The built-in scorer* (`spd-score`) is a lexical presence check over the
  source, comments included. Its score is not a security measurement.
- The utilities marked `@deprecated` in `SPDUtils` add no cryptographic
  strength and exist for compatibility only.

**Dependencies and supply chain:** runtime dependencies are `@noble/hashes`,
`@noble/curves`, `@noble/ciphers`, `@noble/post-quantum` and `hash-wasm`
(WASM Argon2id for runtimes without a native tier; no upstream release since late 2024 per npm metadata,
pinned and signature-verified in CI). The optional native `argon2` addon
is used only where Node has no built-in `crypto.argon2`.

**Independent review:** this library has had three internal review passes
(documented in CHANGELOG.md) and no external cryptographic audit yet. Treat it
accordingly for high-assurance use.
