# SPD wire format and cryptographic specification

Normative description of everything an independent implementation needs to
read and write SPD data. Derived from and kept in lockstep with `src/`; where
the two disagree, the code is a bug or this document is — file an issue.

Byte orders are stated per field. `‖` is concatenation. All hashes are from
FIPS 202 (SHA-3). "Authentication failed." is the single error every integrity
failure surfaces as; implementations MUST NOT distinguish wrong-key from
tampered-data to callers.

## 1. Primitives

| Role | Algorithm | Notes |
|---|---|---|
| Password KDF | Argon2id (RFC 9106), v0x13, 96-byte tag | p=4 lanes for the main key; wrap KDF p=1 unless `wrapArgon2Parallelism` says otherwise |
| Optional KDF chain | scrypt (RFC 7914) over the Argon2id output | salt = `fileSalt ‖ "spd-kdf-chain-v1"`, dkLen 96 |
| Key expansion | HKDF-Expand (RFC 5869 §2.3) with HMAC-SHA3-512 | Extract is skipped: the master is already uniform |
| AEAD | XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03), 24-byte nonce, 16-byte tag | |
| Key commitment (CMT-4) | `SHA3-256(key ‖ nonce)` prepended to every entry ciphertext | 32 bytes; verified in constant time before decryption |
| File MAC | HMAC-SHA3-512 | key = `macKey` (64 bytes) |
| Hybrid KEM | MLKEM768-X25519 (draft-ietf-hpke-pq / concrete-hybrid-kems) | recipients, handshake |
| Signatures | ML-DSA-65 (FIPS 204); optional composite with Ed25519 | files, transport, handshake |
| Compression | zlib (RFC 1950), i.e. deflate with 2-byte header + Adler-32 | |

## 2. Key schedule (passphrase files)

```
peppered   = pepper ‖ UTF-8(passcode)                 (pepper optional, process-wide)
input      = keyfile ? hex(HMAC-SHA3-512(keyfile, salt ‖ peppered)) : peppered
master     = Argon2id(input, salt, m=argon2Memory, t=argon2Time, p=argon2Parallelism, tag=96)
master     = kdfChain ? scrypt(master, salt ‖ "spd-kdf-chain-v1", N, r, p, 96) : master
aeadKey    = HKDF-Expand(master, "spd-aead-key-v1", 32)
macKey     = HKDF-Expand(master, "spd-mac-key-v1",  64)       (32 for format v26)
machine binding (optional): key = HMAC-SHA3-512(machineSecret, key)[0..len]
```

Keyless files (`keylessMode: true`) replace Argon2id with
`HKDF-Expand(masterSecret96, "spd-keyless-pbk-v1:" ‖ hex(salt), 96)`; the
passcode slot carries the sentinel string `"\0SPD-KEYLESS-V1\0" ‖ base64(masterSecret)`
in-process only — it is never written.

Per-entry keys and the name key:

```
entryKey = HMAC-SHA3-512(HMAC-SHA3-512(key=UTF-8(entryName), msg=aeadKey), "spd-entry-v27" ‖ 0x01)[0..32]
nameKey  = HMAC-SHA3-512(HMAC-SHA3-512(key=aeadKey, msg="spd-name-key-v1"), "expand" ‖ 0x01)[0..32]
```

Derived tokens stored in metadata:

```
keyCommitment = hex(HMAC-SHA3-256(aeadKey, "spd-key-commit-v1"))
counterHMAC   = hex(HMAC-SHA3-256(macKey, "counter-v1" ‖ u64be(writeCounter)))
merkleRoot    = hex(root of SHA3-256 tree over entry hash hex strings; odd node duplicated; empty → SHA3-256(""))
```

## 3. Salt wrapping

The 32-byte file salt is stored encrypted ("wrapped"):

```
wrapSalt  = 32 random bytes
wrapKey   = Argon2id(input, wrapSalt, m=wrapArgon2Memory, t=wrapArgon2Time, p=wrapArgon2Parallelism, tag=96)[0..32]
            (defaults 131072 KiB / 6 / 1 when the fields are absent)
saltNonce = 24 random bytes
encryptedSalt = XChaCha20-Poly1305(wrapKey, saltNonce, salt, aad=∅)        (no CMT-4 prefix)
```

Readers MUST validate every KDF parameter read from a file (bounds: memory ≤ 8 GiB,
passes ≤ 64, lanes ≤ 16; scrypt N ≤ 2^23, r ≤ 32, p ≤ 16) before deriving anything,
since this happens before authentication.

## 4. Entry encryption

```
serialized = type-tagged UTF-8 string of the value (see §8)
padded     = u32le(len(serialized)) ‖ serialized ‖ random bytes to a multiple of 256
compressed = zlib(padded)                               (level 1–9, Node build)
nonce      = 24 random bytes
data       = SHA3-256(entryKey ‖ nonce) ‖ XChaCha20-Poly1305(entryKey, nonce, compressed, aad=UTF-8(sanitizedName))
hash       = hex(hashAlgorithm(data))                   (sha3-512 default; sha256/sha512/sha3-256 allowed)
```

Entry names are sanitized to `^[a-z0-9_-]{1,255}$` at write time and re-checked
after decryption; a name failing the check is an authentication failure.

## 5. Binary container (`saveToFileStreaming`, `SPDWriter`) — format v29

```
file = header(72) ‖ zlib(plaintext) ‖ [index tail]

header  = u64le(len(plaintext)) ‖ HMAC-SHA3-512(macKey, plaintext ‖ "application/spd-binary")
plaintext = u32le(len(meta)) ‖ meta ‖ record*
record  = u16le(len(encName)) ‖ encName ‖ u8(len(type)) ‖ type ‖ u16le(len(hash)) ‖ hash
        ‖ u24le(len(nonce)) ‖ nonce ‖ u64le(len(data)) ‖ data
encName = nonce24 ‖ SHA3-256(nameKey ‖ nonce24) ‖ XChaCha20-Poly1305(nameKey, nonce24, UTF-8(name), aad=∅)
```

`meta` is UTF-8 JSON with the fields of §7. Readers MUST verify the header MAC
over the entire decompressed plaintext before decrypting any entry, and MUST
bound decompression by the declared plaintext length. Formats v26–v28 store the
name in clear (`u8(len) ‖ name`) and are read-only.

Index tail (optional, for O(1) `getEntry`), version 2:

```
tail = HMAC-SHA3-256(macKey[0..32], body) ‖ body ‖ u64le(indexStart) ‖ "SPDy"
body = (tag16 ‖ u64le(recordOffsetInPlaintext))*
tag16 = HMAC-SHA3-256(macKey[0..32], "spd-index-name-v2" ‖ UTF-8(name))[0..16]
```

A reader derives the tag of the name it is looking for; the tail reveals no
names. The earlier tail (magic `"SPDx"`, body `(u8(len) ‖ name ‖ u64le(offset))*`)
stored names in clear and is read-only. A tail whose HMAC fails is ignored
(fall back to a scan), never trusted.

Signature: when present, `meta.fileSignature` (JSON number array) is a signature
over the header MAC computed with `fileSignature` absent from `meta` (§6 sizes).

## 6. JSON container (`saveToFile`, `saveData`)

```
file     = zlib(UTF-8(JSON { payload: base64(payloadBytes), mac: number[64] }))
payloadBytes = UTF-8(JSON SPDPayload)                     (§7; entries carry base64 nonce/data)
mac      = HMAC-SHA3-512(macKey, payloadBytes ‖ "application/json")
```

Legacy writers emitted `payload`, `nonce` and `data` as JSON number arrays;
readers accept both. Readers MUST cap the outer inflate (default 1 GiB) because
it runs before authentication, and MUST reject a container with any bytes after
the end of the zlib stream (unlike the binary container, which carries an index
tail there).

Because the signed message is the keyed `mac`, verifying a signature requires
the file's key material; signatures cannot be checked by a party that cannot
decrypt the file.

Signature kinds are identified by length alone and are non-separable:

| Kind | public key | secret key | signature | message |
|---|---|---|---|---|
| ML-DSA-65 | 1952 | 4032 | 3309 | `mac` |
| Composite ML-DSA-65 ‖ Ed25519 | 1984 | 4064 | 3373 | `"spd-file-sig-composite-mldsa65-ed25519-v1" ‖ mac`, ML-DSA context = same label; both must verify |

## 7. Metadata fields

Required: `version` (26–29), `encryptedSalt`, `saltNonce`, `wrapSalt` (number
arrays), `entryCount` (0 = scan to end), `hashAlgorithm`, `argon2Memory`,
`argon2Time`, `argon2HashLen` (96; 64 for v26), `hashKeyLen` (64; 32 for v26).
Optional: `argon2Parallelism` (1), `kdfChain` + `scryptN/R/P`,
`wrapArgon2Memory/Time/Parallelism`, `writeCounter`, `counterHMAC`,
`keyCommitment`, `merkleRoot`, `fileSignature`, `entryRoles`
(name → roles; advisory, enforced client-side), `ratchetEnabled/ratchetCounter`,
`epochNumber/epochSize`, `keylessMode`. Unknown fields MUST be ignored.
Writers emit optional fields only when they differ from the default.

Sidecars (`.seq` write counter, `.ocount`/`.maxcount` open budget, `.lock`,
`.ecc` Reed-Solomon parity, `.spdr` recipient envelope) are plain files. `.ecc`
carries an HMAC under a key stored inside it (integrity only, not authenticity):
readers MUST NOT commit a repair over the original without re-authenticating
the repaired bytes with the file MAC. `.spdr` is self-authenticating per
recipient (key-committing AEAD). `entryRoles` in metadata is advisory.

## 8. Value serialization

`dataType` ∈ string, number, boolean, object, Array, Uint8Array, Uint16Array,
Uint32Array, BigInt64Array, BigUint64Array, Float32Array, Float64Array, Map,
Set, Date, RegExp, Error. Strings are stored raw; numbers/booleans as their
decimal/`true|false` text; Date as ISO-8601; typed arrays, Map and Set as JSON
arrays (BigInt arrays as decimal strings); RegExp as `{source, flags}`; Error as
its message. Readers MUST NOT construct a RegExp from file data without a
ReDoS-safe policy.

## 9. Recipient envelope (`SPDRecipient`, `.spdr`)

```
envelope = "SPDR" ‖ 0x01 ‖ 0x01 ‖ u8(count) ‖ stanza[count]
stanza   = kemCt(1120) ‖ SHA3-256(wrapKey ‖ 0^24) ‖ XChaCha20-Poly1305(wrapKey, 0^24, masterSecret96, aad=header7)
wrapKey  = HKDF-SHA3-512 Extract(salt="spd-recipient-v1/mlkem768x25519", ikm=ss) → Expand(info=kemCt ‖ pk, 32)
```

KEM id 0x01 = MLKEM768-X25519 (`@noble/post-quantum` `ml_kem768_x25519`:
pk 1216, sk 32-byte seed, ss 32). Public keys are shared as
`"spdpq1." ‖ base64url(pk)`.

## 10. Shamir shares (`SPDShamir`, v2)

```
payload = secret ‖ SHA3-256("spd-shamir-v2" ‖ setId ‖ u8(k) ‖ secret)
share   = 0x00 ‖ 0x02 ‖ u8(k) ‖ u8(x) ‖ setId(16) ‖ f_i(x) for each payload byte i
```

GF(2^8) with polynomial 0x11b, x = 1..n, branch-free multiply. `combine`
rejects fewer than `k` shares, mixed `setId`, or a tag mismatch. Legacy v1
shares are `x ‖ f(x)…` with `x ≠ 0`.

## 11. Session handshake (`SPDHandshake`)

```
transcript = SHA3-512("spd-hs-transcript-v2" ‖ nonce_I ‖ nonce_R ‖ x25519pk_I ‖ x25519pk_R ‖ kemPk_I ‖ kemCt_R)
sessionKey = HKDF-SHA3-512(ikm = x25519ss ‖ kemss, salt = transcript, info = "spd-hs-session-v2", 32)
commitment = base64url(SHA3-256(sessionKey ‖ transcript))
auth (optional) = ML-DSA-65 over transcript, context "spd-hs-responder-v2" / "spd-hs-initiator-v2"
```

## 12. Transport (`SPDTransport` v2)

```
ClientHello = 0x02 ‖ x25519pk_C(32) ‖ sessionSalt(32) ‖ kemPk_C(1184)
ServerHello = 0x02 ‖ kemCt(1088) ‖ sig(3309, zero = unsigned) ‖ keyCommit(32)
ikm   = kx(C↔S)(64) ‖ kemss(32)   [‖ PSK mixing, see code]
prk   = HMAC-SHA3-512(sessionSalt, ikm ‖ "spd-transport-v1-hkdf-info")
c2s   = HMAC-SHA3-512(prk, "spd-transport-v1-client-to-server" ‖ 0x01)[0..32];  s2c analogous
keyCommit = HMAC-SHA3-256(c2s ‖ s2c, "spd-transport-key-commit-v1")
sig over SHA3-512("spd-transport-v2-transcript-sig-v2" ‖ ClientHello ‖ kemCt ‖ x25519pk_S ‖ keyCommit)
frame = 0x01 ‖ u64be(counter) ‖ XChaCha20-Poly1305(dirKey, nonce = u64be(counter) ‖ 0^16, msg)
```

Receivers keep a replay window and reject a counter seen before; the counter
MUST NOT wrap.

## 13. Versioning

Format versions are integers in `meta.version`; readers accept 26–29 and write
29. Additive metadata fields do not bump the version. Anything that changes the
key schedule, record layout, or MAC input bumps it. `SPDR`, Shamir and the
transport carry their own one-byte versions.
