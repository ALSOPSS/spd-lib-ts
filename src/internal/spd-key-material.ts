/**
 * Process-wide secret inputs to SPD key derivation: the global pepper, the
 * optional keyfile, and machine binding. SPD's static methods (setPepper,
 * loadKeyfile, enableMachineBinding, ...) are thin wrappers over this module;
 * SPD still owns logging and key-cache eviction around them.
 */

import * as crypto from './portable-crypto.js';
import { utf8ToBytes, concatBytes, bytesToHex } from './portable-crypto.js';
import { getFs, getPath, getOs } from './node-platform.js';

let globalPepper: Uint8Array = new Uint8Array(0);
let keyfileBytes: Uint8Array | undefined; // 512-bit CSPRNG keyfile
let machineBindingEnabled = false;

// ─── Pepper ──────────────────────────────────────────────────────────────────

/**
 * Validates and installs the global pepper (see SPD.setPepper for the full
 * rationale). Empty clears it. Non-empty must be ≥ 16 bytes and not a single
 * repeated byte value. Stores a private copy and zeroes the previous pepper.
 */
export function setPepper(pepper: string | Uint8Array): void {
  const bytes = typeof pepper === 'string' ? utf8ToBytes(pepper) : pepper;

  if (bytes.length > 0) {
    if (bytes.length < 16) {
      throw new Error(
        `setPepper: pepper must be at least 16 bytes (got ${bytes.length}). ` +
        'A short pepper defeats its own purpose — use SPD.generateRandomKey() or a secrets manager to generate one. ' +
        "Pass '' to clear/disable the pepper instead."
      );
    }
    if (bytes.every((b) => b === bytes[0])) {
      throw new Error(
        'setPepper: pepper cannot be a single byte value repeated throughout (e.g. all-zero) — ' +
        'this is almost certainly a placeholder/mistake, not a real secret.'
      );
    }
  }

  globalPepper.fill(0);
  globalPepper = new Uint8Array(bytes);
}

// ─── Keyfile ─────────────────────────────────────────────────────────────────

export function hasKeyfile(): boolean {
  return keyfileBytes !== undefined;
}

/** Writes 64 bytes (512 bits) of CSPRNG output to `filePath` with mode 0600. */
export function generateKeyfile(filePath: string): void {
  getFs().writeFileSync(filePath, crypto.randomBytes(64), { mode: 0o600 });
}

/** Loads a keyfile (≥ 32 bytes), zeroing any previously loaded one. Returns its length. */
export function loadKeyfile(filePath: string): number {
  const bytes = getFs().readFileSync(filePath);
  if (bytes.length < 32) {
    throw new Error('Keyfile is too short — must be at least 32 bytes. Regenerate with SPD.generateKeyfile().');
  }
  keyfileBytes?.fill(0);
  keyfileBytes = new Uint8Array(bytes);
  bytes.fill(0);
  return keyfileBytes.length;
}

export function unloadKeyfile(): void {
  if (keyfileBytes) {
    keyfileBytes.fill(0);
    keyfileBytes = undefined;
  }
}

// ─── Passcode mixing ─────────────────────────────────────────────────────────

/**
 * The password input actually fed to Argon2id: the passcode, prefixed with
 * the pepper (as raw bytes — decoding a binary pepper to a string would be
 * lossy and non-injective), then, if a keyfile is loaded, replaced by
 * HMAC-SHA3-512(keyfile, salt || pepperedPasscode) in hex so the same keyfile
 * yields a different effective passcode per file.
 */
export function mixPasscode(passcode: string, salt: Uint8Array): Uint8Array | string {
  const peppered: Uint8Array | string = globalPepper.length > 0
    ? concatBytes(globalPepper, utf8ToBytes(passcode))
    : passcode;
  if (!keyfileBytes) return peppered;
  const mixed = crypto.createHmac('sha3-512', keyfileBytes)
    .update(salt)
    .update(peppered)
    .digest('hex');
  if (peppered instanceof Uint8Array) peppered.fill(0);
  return mixed;
}

// ─── Machine binding ─────────────────────────────────────────────────────────

export function enableMachineBinding(): void {
  machineBindingEnabled = true;
}

export function disableMachineBinding(): void {
  machineBindingEnabled = false;
}

export function isMachineBindingEnabled(): boolean {
  return machineBindingEnabled;
}

/** Machine secret: SHA3-512 over /etc/machine-id, hostname, and a ~/.spd-machine-id sidecar, truncated to 32 bytes. */
export function getMachineSecret(): Uint8Array {
  const fs = getFs();
  const path = getPath();
  const os = getOs();
  const sources: string[] = [];
  try { sources.push(fs.readFileSync('/etc/machine-id', 'utf8').trim()); } catch {}
  try { sources.push(os.hostname()); } catch {}
  const sidePath = path.join(os.homedir(), '.spd-machine-id');
  try {
    sources.push(fs.readFileSync(sidePath, 'utf8').trim());
  } catch {
    const id = bytesToHex(crypto.randomBytes(32));
    // tmp-then-rename: a torn write would regenerate a different id on every
    // boot, silently making every machine-bound file undecryptable.
    try {
      const tmpPath = sidePath + '.tmp';
      fs.writeFileSync(tmpPath, id, { mode: 0o600 });
      fs.renameSync(tmpPath, sidePath);
    } catch {}
    sources.push(id);
  }
  return crypto.createHash('sha3-512').update(sources.join('|')).digest().subarray(0, 32);
}

/** Post-KDF machine binding: HMAC-SHA3-512(machineSecret, key)[0..key.length]. */
export function applyMachineBinding(key: Uint8Array): Uint8Array {
  const secret = getMachineSecret();
  const bound = crypto.createHmac('sha3-512', secret).update(key).digest();
  secret.fill(0);
  return new Uint8Array(bound.buffer, bound.byteOffset, key.length);
}
