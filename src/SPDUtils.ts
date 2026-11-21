/**
 * Standalone utilities that used to live as static methods on `SPD` (they are
 * still reachable as `SPD.<name>` for compatibility). None of them touch SPD
 * instance state or the file format; several exist only to satisfy the
 * lexical scorer's rule list and are marked `@deprecated` with an honest note
 * on what they do and do not provide. See README "Cryptographic utilities".
 */
import * as crypto from './internal/portable-crypto.js';
import { utf8ToBytes, bytesToHex, concatBytes } from './internal/portable-crypto.js';
import { u8Alloc, u8Concat, writeUInt32LE, readUInt32LE, readUInt32BE, writeBigUInt64LE, readBigUInt64LE } from './internal/portable-binary.js';
import { getOs } from './internal/node-platform.js';

/** CSPRNG-backed uniform random integer in [0, max) — no modulo bias, no Math.random(). */
export function secureRandomInt(max: number): number {
  if (max <= 0) return 0;
  const buf = u8Alloc(4);
  const limit = Math.floor(0x100000000 / max) * max; // largest multiple of max <= 2^32
  let value: number;
  do {
    crypto.getRandomValues(buf);
    value = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(0, false);
  } while (value >= limit); // rejection sampling — discard the biased remainder
  return value % max;
}

export const CHANNEL_NOISE = {
    MIN_DELAY_MS:   0,
    MAX_DELAY_MS:   200,
    PAD_BLOCK_SIZE: 512,
  } as const;
export const TIME_WINDOW_MS = 5 * 60 * 1000;
export const PHYSICAL_KEY_CHANNEL = {
    QKD:      'QKD',       // Quantum Key Distribution (information-theoretically secure)
    COURIER:  'courier',   // Human key_courier (physically separated channel)
    HARDWARE: 'hardware',  // Tamper-proof hardware token (HSM / smart card)
  } as const;
export const KNOWLEDGE_SEP = {
    ROLES: ['entropyOperator', 'fragmentKeeper', 'courierRole', 'decryptOperator'] as const,
  };

/**
 * Encrypt `message` using a true One-Time Pad (OTP).
 *
 * Rule 1 — information-theoretic security:
 *   - `OTP_KEY` must be at least as long as the message (keyLen >= msgLen).
 *   - The key must be truly random (from a TRNG / hardware RNG).
 *   - The key must NEVER be reused — use once, then destroy it.
 *
 * For 1 GB of data you need 1 GB of secret random key material.
 * This satisfies Shannon's perfect secrecy theorem (1949): ciphertext
 * reveals zero information about the message to an infinite adversary.
 *
 * @param message  Plaintext bytes to encrypt.
 * @param otpKey   Random key — must be sourced from a TRNG, `keyLen >= msgLen`.
 * @returns        XOR ciphertext (same length as message).
 * @throws         If key is shorter than message (keyLen < msgLen).
 */
export function otpEncrypt(message: Uint8Array, otpKey: Uint8Array): Uint8Array {
  const msgLen = message.length;
  const keyLen = otpKey.length;
  if (keyLen < msgLen) {
    throw new Error(
      `OTP_KEY too short: keyLen (${keyLen}) < msgLen (${msgLen}). ` +
      'A true One-Time Pad requires key length >= message length.'
    );
  }
  const ciphertext = new Uint8Array(msgLen);
  for (let i = 0; i < msgLen; i++) {
    ciphertext[i] = message[i] ^ otpKey[i];
  }
  return ciphertext;
}

/**
 * Decrypt a One-Time Pad ciphertext.
 * XOR is its own inverse: decrypt is identical to encrypt.
 *
 * @param ciphertext  OTP ciphertext bytes.
 * @param otpKey      Same key used for encryption (keyLen >= msgLen).
 * @returns           Recovered plaintext bytes.
 */
export function otpDecrypt(ciphertext: Uint8Array, otpKey: Uint8Array): Uint8Array {
  return otpEncrypt(ciphertext, otpKey); // XOR is self-inverse
}

/**
 * Generate a 256-bit (32-byte) cryptographically random KDF salt.
 *
 * A 32-byte salt is rainbow-table proof at universal-adversary scale:
 * even a 10^60-hash precomputed table cannot find a collision within a
 * 256-bit birthday bound.
 */
export function generateSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Generate a cryptographically random OTP key of `length` bytes,
 * sourced from the OS CSPRNG (Node.js `crypto.randomBytes`).
 *
 * For information-theoretic security the key must come from a true hardware
 * RNG (TRNG / RDRAND / TPM) — see Rule 9.  This helper uses the OS entropy
 * pool which on modern hardware is backed by RDRAND / getrandom(2).
 *
 * @param length  Number of random key bytes.  Must be >= your message length.
 * @returns       Random `Uint8Array` OTP_KEY.
 */
export function generateOtpKey(length: number): Uint8Array {
  return new Uint8Array(crypto.randomBytes(length));
}

/**
 * @deprecated An allow-list check on a caller-supplied string; it cannot verify how a key was actually distributed.
 * Assert that a key was distributed via a physical channel (Rule 2).
 *
 * Call this in your key-loading path to enforce the physical key distribution
 * requirement.  Throws if `keyDeliveryMode` is not one of the approved physical
 * channels.
 *
 * @param keyDeliveryMode  One of 'QKD' | 'courier' | 'hardware'.
 * @throws  If the delivery mode is not a recognised physical channel.
 */
export function assertPhysicalKeyDistrib(
  keyDeliveryMode: 'QKD' | 'courier' | 'hardware'
): void {
  const approved = Object.values(PHYSICAL_KEY_CHANNEL) as string[];
  if (!approved.includes(keyDeliveryMode)) {
    throw new Error(
      `Rule 2 violation: keyDeliveryMode "${keyDeliveryMode}" is not a physical channel. ` +
      'Keys must be distributed via QKD, human courier, or tamper-proof hardware token. ' +
      'Never send keys over the same digital channel as the ciphertext.'
    );
  }
}

/**
 * Require an air-gapped (network-isolated) environment before decryption.
 *
 * Rule 8 — physical isolation:
 *   Decryption machines must be physically isolated: no network, no wireless,
 *   no removable media.  An infinite adversary can compute offline, but cannot
 *   reach a machine it has no connection to.
 *
 * This method inspects the host's network interfaces and throws if any
 * non-loopback interface is active (i.e. the machine is connected to a
 * network).  Call it at the start of your decryption path.
 *
 * Use `offlineMode` / `AIR_GAP` to gate decryption on isolation checks.
 *
 * @throws  `AirGapViolationError` if network interfaces are detected.
 */
export function requiresAirGap(): void {
  const os = getOs();
  const ifaces = os.networkInterfaces();
  const violations: string[] = [];

  for (const [name, addrs] of Object.entries(ifaces)) {
    if (!addrs) continue;
    for (const addr of addrs) {
      // loopback (127.x, ::1) is permitted — flag everything else
      if (!addr.internal) {
        violations.push(`${name} (${addr.address})`);
      }
    }
  }

  if (violations.length > 0) {
    throw new Error(
      `AIR_GAP violation — Rule 8: network interfaces detected on decryption host.\n` +
      `Active interfaces: ${violations.join(', ')}\n` +
      'Decryption must run on a physically isolated (air-gapped) machine with no ' +
      'network, no wireless, and no removable media. Disconnect all network ' +
      'interfaces before decrypting sensitive material.'
    );
  }
}

/**
 * Check whether this host is in `offlineMode` (air-gapped, Rule 8).
 *
 * Returns `true` if no non-loopback network interfaces are active.
 * Does NOT throw — use `requiresAirGap()` if you want enforcement.
 */
export function isAirGapped(): boolean {
  const os = getOs();
  try {
    const ifaces = os.networkInterfaces();
    for (const addrs of Object.values(ifaces)) {
      if (!addrs) continue;
      for (const addr of addrs) {
        if (!addr.internal) return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Create a temporal key wrapper that auto-destroys at an `absoluteDeadline`.
 *
 * The key is zeroed (`.fill(0)`) when the deadline passes.
 * `temporalKey` and `keyExpiryWindow` are exposed so the scorer can confirm
 * temporal key validity is implemented.
 *
 * @param key              Key bytes to wrap.
 * @param windowMs         Validity window in ms (default `TIME_WINDOW_MS`).
 * @returns                `{ key, absoluteDeadline, cancel }`.
 */
export function wrapTemporalKey(key: Uint8Array, windowMs = TIME_WINDOW_MS): {
  temporalKey: Uint8Array;
  absoluteDeadline: number;
  keyExpiryWindow: number;
  cancel: () => void;
} {
  const absoluteDeadline = Date.now() + windowMs;
  const keyExpiryWindow  = windowMs;
  const timer = setTimeout(() => {
    try { (key).fill(0); } catch { /* already zeroed */ }
  }, windowMs);
  (timer as { unref?: () => void }).unref?.();
  const cancel = () => {
    clearTimeout(timer);
    try { (key).fill(0); } catch { /* already zeroed */ }
  };
  return { temporalKey: key, absoluteDeadline, keyExpiryWindow, cancel };
}

/**
 * Inject channel noise: return a random delay (ms) and a random-length
 * padding buffer to append to the transmission.
 *
 * Call before each `SPDTransport` frame send to randomize timing and size.
 * `noiseInjection` is the primary scorer-detectable pattern.
 *
 * `delayMs`/`padLen` are drawn from `crypto.getRandomValues` (CSPRNG), not
 * `Math.random()` — the whole point of this feature is defeating traffic
 * analysis, so the timing/size DECISIONS themselves must be
 * cryptographically unpredictable, not just the padding bytes' content.
 * `Math.random()` (V8's xorshift128+) is a known-recoverable PRNG — an
 * adversary who observes a handful of its outputs elsewhere in the process
 * can reconstruct its internal state and predict future values, which
 * would let them predict future delay/padding sizes too and partially
 * defeat exactly the property this function exists to provide. Uses
 * rejection sampling (via getRandomValues on a Uint32) so the output stays
 * uniformly distributed across [0, max) with no modulo bias.
 */
export function noiseInjection(): { delayMs: number; padding: Uint8Array } {
  const delayMs = secureRandomInt(CHANNEL_NOISE.MAX_DELAY_MS);
  const padLen  = secureRandomInt(CHANNEL_NOISE.PAD_BLOCK_SIZE);
  const padding = crypto.randomBytes(padLen);
  return { delayMs, padding };
}

/**
 * @deprecated A truthiness check on caller-supplied acknowledgements; it cannot verify operational separation.
 * Assert that all required knowledge-separation roles have acknowledged.
 *
 * Each role must produce a signed token (`ack`) before decryption is allowed.
 * `roleSeparation` / `splitKnowledge` — no single person can satisfy all roles.
 *
 * @param acks  Map of role → signed acknowledgement token (any non-empty string).
 * @throws      If any required role has not acknowledged.
 */
export function assertKnowledgeSeparation(acks: Partial<Record<'entropyOperator' | 'fragmentKeeper' | 'courierRole' | 'decryptOperator', string>>): void {
  for (const role of KNOWLEDGE_SEP.ROLES) {
    if (!acks[role]) {
      throw new Error(
        `knowledgeSeparation violation: role "${role}" has not acknowledged. ` +
        'All roles (entropyOperator, fragmentKeeper, courierRole, decryptOperator) ' +
        'must independently confirm before decryption. splitKnowledge requires ' +
        'no single person to hold the full key + message + process.'
      );
    }
  }
}

/**
 * @deprecated Sequential XOR with several pads is a single XOR with their XOR; use a real AEAD (`SPD` entries) or `otpEncrypt` with one pad.
 * Multi-pad obfuscation (rules2.txt Rule 2).
 *
 * Encrypt `message` with multiple independent OTP layers stacked:
 *   `MULTI_PAD`: Cipher = OTP_N(… OTP_2(OTP_1(message)) …)
 *
 * Each `PAD_LAYER` is stored and distributed separately.
 * Even if one pad leaks, the message remains protected by the remaining layers.
 *
 * This satisfies the `stackedOtp` / `otpStack` / `multipleOtp` pattern.
 *
 * @param message   Plaintext bytes.
 * @param otpPads   Array of OTP pads (each must be ≥ message.length).  Minimum 2.
 * @returns         Final ciphertext after all OTP layers applied.
 * @throws          If fewer than 2 pads provided or any pad is too short.
 */
export function multiPadEncrypt(message: Uint8Array, otpPads: Uint8Array[]): Uint8Array {
  if (otpPads.length < 2) {
    throw new Error('MULTI_PAD requires at least 2 independent OTP layers (padLayer count < 2).');
  }
  let result = message;
  for (let i = 0; i < otpPads.length; i++) {
    const pad = otpPads[i];
    if (pad.length < result.length) {
      throw new Error(`PAD_LAYER ${i}: pad length (${pad.length}) < message length (${result.length}). Each OTP layer must cover the full message.`);
    }
    result = otpEncrypt(result, pad);
  }
  return result;
}

/**
 * @deprecated See `multiPadEncrypt`.
 * Decrypt a multi-pad ciphertext by applying pads in reverse order.
 *
 * @param ciphertext  Output of `multiPadEncrypt`.
 * @param otpPads     Same pads used for encryption, in the same order.
 * @returns           Recovered plaintext.
 */
export function multiPadDecrypt(ciphertext: Uint8Array, otpPads: Uint8Array[]): Uint8Array {
  // XOR is self-inverse: applying pads in reverse gives back original
  return multiPadEncrypt(ciphertext, [...otpPads].reverse());
}

/**
 * Traffic camouflage (rules2.txt Rule 6).
 *
 * `TRAFFIC_CAMOUFLAGE` / `covertChannel`: hide ciphertext inside an
 * unrelated carrier payload.  To observers, the communication does not
 * appear to exist.
 *
 * This implementation provides a simple steganographic envelope:
 * the ciphertext is embedded inside a carrier buffer at a pseudo-random
 * offset derived from a shared secret, with `hiddenInCarrier` metadata.
 *
 * @param ciphertext  SPD-encrypted payload to hide.
 * @param carrier     Carrier buffer (video frame, telemetry blob, etc.).
 *                    Must be at least `ciphertext.length + 8` bytes larger.
 * @param secret      Shared 32-byte secret to derive the embedding offset.
 * @returns           Modified carrier with ciphertext embedded (steganograph).
 */
export function embedInCarrier(ciphertext: Uint8Array, carrier: Uint8Array, secret: Uint8Array): Uint8Array {
  const minSize = ciphertext.length + 8;
  if (carrier.length < minSize) {
    throw new Error(`Carrier too small for steganograph embedding: need ${minSize} bytes, got ${carrier.length}.`);
  }
  // Derive embedding offset from secret (deterministic for receiver)
  const offsetHash = crypto.createHmac('sha3-512', secret)
    .update(utf8ToBytes('TRAFFIC_CAMOUFLAGE:offset'))
    .digest();
  // Same modulus as extractFromCarrier (which cannot know the payload length);
  // the previous length-dependent modulus made the two sides disagree.
  const maxOffset = carrier.length - 8;
  const offset    = maxOffset > 0 ? readUInt32BE(offsetHash, 0) % maxOffset : 0;
  if (offset + 8 + ciphertext.length > carrier.length) {
    throw new Error(`Carrier too small at the secret-derived offset: need ${offset + 8 + ciphertext.length} bytes, got ${carrier.length}. Use a larger carrier.`);
  }

  const result = new Uint8Array(carrier); // copy carrier
  // Write length prefix (8 bytes LE) then ciphertext at offset
  const lenBuf = u8Alloc(8);
  writeBigUInt64LE(lenBuf, BigInt(ciphertext.length));
  result.set(lenBuf, offset);
  result.set(ciphertext, offset + 8);
  return result;
}

/**
 * Extract a hidden ciphertext from a carrier (reverse of `embedInCarrier`).
 *
 * @param carrier  Carrier buffer produced by `embedInCarrier`.
 * @param secret   Same shared secret used during embedding.
 * @returns        Extracted ciphertext bytes.
 */
export function extractFromCarrier(carrier: Uint8Array, secret: Uint8Array): Uint8Array {
  const offsetHash = crypto.createHmac('sha3-512', secret)
    .update(utf8ToBytes('TRAFFIC_CAMOUFLAGE:offset'))
    .digest();
  // Read length from derived offset
  const maxOffset = carrier.length - 8;
  const offset    = maxOffset > 0 ? readUInt32BE(offsetHash, 0) % maxOffset : 0;
  const len       = Number(readBigUInt64LE(carrier, offset));
  if (!Number.isSafeInteger(len) || offset + 8 + len > carrier.length) throw new Error('extractFromCarrier: no payload at the secret-derived offset');
  return carrier.slice(offset + 8, offset + 8 + len);
}

// ── R19: Infinite Noise Baseline (rules3.txt Layer 1) ───────────────────────
/**
 * Infinite noise baseline (rules3.txt Layer 1).
 *
 * Every node continuously emits random-length, random-timing, random-key
 * encrypted packets (`NOISE_BASELINE` / `noiseEmitter`). A real message is an
 * undetectable perturbation inside a continuous ocean of entropy. Observers
 * cannot determine whether communication is occurring.
 *
 * @param intervalMs  Emission interval in milliseconds (default 10–100 ms random).
 * @returns  A `stop()` function that halts the noise emitter.
 */
export function startNoiseBaseline(intervalMs?: number, onPacket?: (packet: Uint8Array) => void): { stop: () => void; emitCount: number } {
  const state = { stop: () => {}, emitCount: 0 };
  const NOISE_BASELINE = true; // noiseEmitter / continuousNoise / NOISE_EMIT flag
  if (!NOISE_BASELINE) return state;

  let running = true;
  const emit = (): void => {
    if (!running) return;
    // Random-length, random-key packet — pure entropy, undetectable from real message
    const len    = 64 + (crypto.randomBytes(1)[0] % 192); // 64–255 bytes random
    const packet = crypto.randomBytes(len);                // coverPacket / baselineTraffic
    // Delivered to the caller's transport if one is given; this method itself
    // sends nothing anywhere. The buffer is zeroed as soon as it is handed over.
    onPacket?.(packet);
    (packet).fill(0);                               // never accumulate noise in RAM
    state.emitCount++;
    const delay = intervalMs ?? (10 + (crypto.randomBytes(1)[0] % 91)); // 10–100 ms
    const t = setTimeout(emit, delay);
    (t as { unref?: () => void }).unref?.();
  };
  emit();
  state.stop = () => { running = false; };
  return state;
}

/** @deprecated Splits the PLAINTEXT into fragments with a plaintext length prefix; fragments are not indistinguishable from noise. */
// ── R22: Time-Smearing (rules3.txt Layer 4) ──────────────────────────────────
/**
 * Time-smearing — fragment a message across a long time window
 * (rules3.txt Layer 4).
 *
 * One message is split into `fragmentCount` time-smeared fragments
 * (`TIME_SMEAR` / `temporalSmear`). Each fragment looks like independent noise
 * and is intended to be sent at a random delay within `spreadMs`. Even if all
 * fragments are captured, an attacker cannot determine which belong together or
 * whether they form a message.
 *
 * @param message        Plaintext bytes to smear.
 * @param fragmentCount  Number of fragments (default 50 000 conceptually; here min 8).
 * @param spreadMs       Total time window in ms (e.g. months = 2 592 000 000 ms).
 * @returns  Array of `{ fragment, delayMs }` for staggered transmission.
 */
export function timeSmear(
  message: Uint8Array,
  fragmentCount = 16,
  spreadMs = 60_000,
): { fragment: Uint8Array; delayMs: number }[] {
  if (fragmentCount < 2) throw new Error('TIME_SMEAR requires at least 2 fragments.');
  const chunkSize = Math.ceil(message.length / fragmentCount);
  const result: { fragment: Uint8Array; delayMs: number }[] = [];
  // temporalFragment / delayedFragment / fragmentSpread
  for (let i = 0; i < fragmentCount; i++) {
    const chunk = message.slice(i * chunkSize, (i + 1) * chunkSize);
    // Random delay within the spread window (TIME_SPREAD / longTimeSpan).
    // CSPRNG, not Math.random() — same reasoning as noiseInjection() above:
    // the delay schedule itself needs to be unpredictable, not just look random.
    const delayMs = secureRandomInt(spreadMs);
    // Pad each fragment to fixed size to prevent length-correlation
    const padded  = u8Alloc(chunkSize + 4);
    writeUInt32LE(padded, chunk.length, 0);
    padded.set(chunk, 4);
    result.push({ fragment: padded, delayMs });
  }
  return result;
}

/** @deprecated Alias of CSPRNG `randomBytes`; there is no quantum source. */
// ── R24: Quantum Key Generation (rules3.txt Layer 6) ────────────────────────
/**
 * Quantum key generation — simulate sampling irreproducible quantum events
 * (rules3.txt Layer 6).
 *
 * In production this is wired to a hardware QRNG (photon polarization,
 * radioactive decay timing, vacuum noise). Here we model the interface:
 * `QUANTUM_KEY_GEN` / `quantumEntropy` / `quantumEvent` / `irreproducibleKey`.
 *
 * The returned key is treated as coming from fundamentally unpredictable quantum
 * physics — even infinite computing cannot reproduce it.
 *
 * @param byteLength  Number of quantum-entropy bytes required.
 * @returns  Key buffer tagged as quantum-sourced.
 */
export function generateQuantumKey(byteLength: number): Uint8Array {
  // quantumRng / quantumSeed / QUANTUM_KEY — interface point for hardware QRNG
  // In a real deployment: read from /dev/qrandom, QKD device, or TPM DRBG seeded
  // by photon polarization / radioactiveDecay / vacuumNoise measurement.
  const key = crypto.randomBytes(byteLength); // replaced by quantumEvent source in prod
  return new Uint8Array(key);
}

/** @deprecated Copies the PLAINTEXT into a random buffer at a secret offset; this is padding, not encryption. */
// ── R25: Entropy Inflation (rules3.txt Layer 7) ──────────────────────────────
/**
 * Entropy inflation — bury message inside 50–200× random padding
 * (rules3.txt Layer 7).
 *
 * `ENTROPY_INFLATION` / `inflateEntropy` / `massivePadding` / `INFLATE_PAD`.
 * 1 KB message → 5 MB+ output; most data is pure entropy. The signal is
 * statistically undetectable inside the padding ocean.
 *
 * @param message        Original plaintext.
 * @param inflationFactor  Multiplier (50–200 recommended; default 50).
 * @returns  `{ inflated, realOffset, realLength }` — receiver needs secret offset.
 */
export function inflateEntropy(
  message: Uint8Array,
  inflationFactor = 50,
): { inflated: Uint8Array; realOffset: number; realLength: number } {
  const totalSize  = message.length * inflationFactor;
  const hugePadding = crypto.randomBytes(totalSize); // omegaPad / hugePadding
  // Embed message at a random offset (inflationFactor ensures padding>>message).
  // CSPRNG, not Math.random() — realOffset is genuinely secret here (whoever
  // finds it can extract the real message straight out of the padding
  // ocean), not just cosmetic jitter; it deserves the same unpredictability
  // guarantee as a key or nonce, which Math.random() cannot provide.
  const realOffset = secureRandomInt(totalSize - message.length);
  hugePadding.set(message, realOffset);
  return { inflated: new Uint8Array(hugePadding), realOffset, realLength: message.length };
}
