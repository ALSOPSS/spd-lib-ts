# SPD Security Rules Implementation — R1 to R33

How SPD (`src/SPD.ts`, `src/SPDUtils.ts`, `src/SPDShamir.ts`) relates to the 33
"physical security" rules in `rules.txt`, `rules2.txt` and `rules3.txt`. The
cryptographic design itself is specified in [SPEC.md](./SPEC.md); the threat
model and known limitations are in [SECURITY.md](./SECURITY.md). This file only
states, per rule, what the code enforces and what it cannot.

| Label | Meaning |
|---|---|
| **ENFORCED** | The code cryptographically or mechanically enforces the property |
| **BEST-EFFORT** | Code does the right thing but cannot guarantee it at the JS/OS layer |
| **OPERATIONAL** | A check or convenience; the property itself depends on people/process |
| **DEPRECATED** | Still exported for compatibility; adds no security over the plain primitive (removal planned for the next major) |
| **REMOVED** | Deleted in 2.0 — no code exists |

## Rules with real backing

### R1 — One-time pad — ENFORCED (key discipline is the caller's)
`SPD.otpEncrypt/otpDecrypt/generateOtpKey`. Checks `key.length >= message.length`,
XORs, generates pads from the OS CSPRNG. Perfect secrecy holds only if the pad
is random and never reused — the code cannot prevent reuse.

### R4 — Layered encryption — ENFORCED
Per entry: length prefix + random 256-byte-bucket padding → zlib → XChaCha20-
Poly1305 under a per-entry HKDF-SHA3-512 key, prefixed by a CMT-4 commitment
`SHA3-256(key ‖ nonce)`; whole file under HMAC-SHA3-512 (512-bit key).
Exact layout: SPEC.md §4–5.

### R5 / R26 — Threshold secret sharing — ENFORCED (split) / OPERATIONAL (distribution)
`SPDShamir.split(secret, n, k)` / `combine(shares)`: Shamir over GF(256) with
branchless multiplication; v2 shares carry a set id and a secret-shared tag so
mixed sets and corrupted shares are detected (SPEC.md §10). Fewer than k shares
reveal nothing. Where the shares go is up to you.

### R6 — Length/compression-oracle defence — ENFORCED
`padForCompression` (`src/internal/spd-kdf.ts`) pads every value to a 256-byte
bucket with random bytes before compression, so ciphertext length reveals only
the bucket.

### R3 — Key destruction — BEST-EFFORT
`destroy()` and every helper call `fill(0)` on key buffers. JavaScript has no
`explicit_bzero`: V8 may hold copies (JIT, GC moves, swap) and strings
(passcodes, decrypted text) cannot be wiped at all.

### R7 / R13 — Temporal keys — BEST-EFFORT
`SPD.wrapTemporalKey(key, windowMs)` zeroes the copy on a timer or `cancel()`.
Same memory caveats as R3; a snapshot taken before the deadline keeps the key.

### R8 — Air-gap check — BEST-EFFORT
`SPD.requiresAirGap()` / `isAirGapped()` throw/return based on
`os.networkInterfaces()` minus loopback. A heuristic: it sees nothing below the
OS (firmware radios, DMA, side channels) and nothing brought up later.

### R10 — Deniability — OPERATIONAL (not cryptographic)
`deniableDecryptView()` returns only `_decoy_`-prefixed entries; `addDecoy()`
entries are hidden from normal reads by a value marker. `extractData()` still
returns everything else and `enableDeniableEncryption()` is a no-op. Anyone
holding the passcode can read all entries; the file states its entry count.

### R12 — Destruction assurance — BEST-EFFORT
`destroy()` zeroes keys and emits a `key_destroyed` log event (`SPD.setLogger`).
That is an audit record, not proof that no copy exists.

### R14 — Channel noise — BEST-EFFORT
`SPD.noiseInjection()` draws delay and size from the CSPRNG (rejection
sampling). It shapes timing/size locally; it does not hide that traffic exists.

### R16 — Anti-forensic mode — BEST-EFFORT
`enableAntiForensic(true)` sets the process-wide unlock-cache TTL to 0 and
blocks re-enabling it while any such instance is alive. It does not touch the
WAL and cannot control swap or GC.

### R18 — Carrier embedding — OPERATIONAL
`embedInCarrier` / `extractFromCarrier` place bytes at an offset in a carrier
buffer. Round-trips correctly; does not survive statistical steganalysis.

### R20 — Indistinguishable ciphertexts — ENFORCED (cipher) / not at system level
AEAD output is pseudorandom; file headers, lengths (to the 256-byte bucket),
entry counts and sidecars are visible.

## Deprecated utilities (compatibility only)

| Rule | Function | Why it adds nothing |
|---|---|---|
| R2 | `assertPhysicalKeyDistrib` | String allowlist; cannot verify a physical channel |
| R9 / R24 | `generateQuantumKey` | Alias for the CSPRNG; no QRNG attached |
| R15 | `assertKnowledgeSeparation` | Throws unless four role strings are supplied; cannot verify different humans |
| R17 | `multiPadEncrypt/Decrypt` | XOR with several pads equals one pad |
| R19 | `startNoiseBaseline(intervalMs?, onPacket?)` | Generates random packets in-process and hands them to `onPacket`; sends nothing |
| R22 | `timeSmear` | Splits plaintext into pieces; not encryption |
| R25 | `inflateEntropy` | Pads plaintext; hides size, not existence |

## Removed in 2.0 (no code)

R11 `rotateFragments`, R21 `multiUniverseDecryption`, R23 `planetaryRoutingChaos`,
R27 `relativisticKeySeparation`, R28 `communicationDeniability`,
R29 `protocolSelfMutate`, R30 `hardwareOblivion`, R31 `thermodynamicDestruction`,
R32 `trafficCamouflageEcosystem`, R33 `existentialAmbiguity`. Each returned
labels, schedules or booleans and changed no cryptographic behaviour. `spd-score`
scores neither these nor the deprecated utilities above; it remains a lexical
check over the source, not a security measurement (see SECURITY.md).
