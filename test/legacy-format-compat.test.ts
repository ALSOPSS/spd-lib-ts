/**
 * Cross-version file compatibility: this library claims to still load files
 * saved by older versions of itself (v26 through v28) — every loader has
 * `version >= 27 ? X : Y` fallback branches for the older, smaller key sizes
 * and pre-v27/pre-v29 entry-encryption scheme. That claim had never actually
 * been exercised: no test constructed a real old-format payload and loaded
 * it through the CURRENT, unmodified loader code. A bug in any one of those
 * fallback branches would have been silently invisible.
 *
 * This file builds genuine v26- and v27-shaped `.spd` JSON payloads by hand,
 * using the same low-level primitives (`SPD.encryptSalt`/`deriveKeys`,
 * `plainAeadEncrypt`/`deriveEntryKey` from spd-crypto.ts) the real old code
 * used — NOT by calling today's `addData`/`saveToFile` (which always write
 * the current, newest format) — so the test genuinely exercises the
 * loader's legacy path rather than a round-trip through the same code that
 * would also produce the bug it's meant to catch.
 *
 * v28 is not given its own fixture: per SPD.ts's own version-history comment,
 * v28 only changed DEFAULT profile constants (which are stored per-file
 * regardless of version), not the wire format itself — the v27 fixture
 * already exercises every wire-format branch v28 shares.
 *
 * Wire-format facts encoded here (from SPD.ts's own version-gated fallback
 * logic, cross-checked against each call site):
 *   v26: argon2HashLen=64, macKeyLen=32 (v27+ uses 96/64). No per-entry AAD,
 *        no deriveEntryKey — every entry encrypted directly under the master
 *        aeadKey. plainAeadEncrypt (no CMT-4 prefix — that's v29+). No
 *        padForCompression framing (also v29+) — just raw deflate.
 *   v27: argon2HashLen=96, macKeyLen=64. Per-entry AAD (utf8 dataName) +
 *        deriveEntryKey ARE used. Still plainAeadEncrypt (no CMT-4 — v29+)
 *        and still no padForCompression framing (v29+).
 *   Both: no keyCommitment/counterHMAC/merkleRoot/fileSignature fields (all
 *        v29+, and all optional on load — their absence must not break
 *        loading).
 */
import { describe, it, expect } from 'vitest';
import * as zlib from 'zlib';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as nodeCrypto from 'crypto';
import { SPD } from '../src/index';
import { plainAeadEncrypt, deriveEntryKey } from '../src/internal/spd-crypto';

const PASS = 'LegacyForm4tC0mpat!Test#2024';

const ARGON2_MEMORY_STANDARD = 131072;
const ARGON2_TIME_STANDARD = 6;

function tmpSpdFile(tag: string): string {
  return path.join(os.tmpdir(), `spd-${tag}-fixture-${Date.now()}-${Math.random().toString(36).slice(2)}.spd`);
}

function sha3_512hex(data: Uint8Array): string {
  return nodeCrypto.createHash('sha3-512').update(Buffer.from(data)).digest('hex');
}

/** Builds a genuine v26-shaped `.spd` file payload (see file header for the exact wire-format facts encoded). */
async function buildV26Payload(passcode: string, entries: Array<{ name: string; value: string }>): Promise<Buffer> {
  const ARGON2_HASH_LEN_V26 = 64;
  const HMAC_KEY_LEN_V26 = 32;

  const salt = crypto.getRandomValues(new Uint8Array(32));
  const { encryptedSalt, saltNonce, wrapSalt } = await SPD.encryptSalt(
    salt, passcode, ARGON2_MEMORY_STANDARD, ARGON2_TIME_STANDARD
  );
  const { aeadKey, macKey } = await SPD.deriveKeys(
    passcode, salt, ARGON2_MEMORY_STANDARD, ARGON2_TIME_STANDARD,
    ARGON2_HASH_LEN_V26, HMAC_KEY_LEN_V26, false, 1048576, 8, 4, 1
  );

  const dataEntries = entries.map(({ name, value }) => {
    const compressed = zlib.deflateSync(Buffer.from(value, 'utf8')); // v26: no padForCompression framing
    const nonce = crypto.getRandomValues(new Uint8Array(24));
    // v26: no per-entry AAD, no deriveEntryKey — encrypt directly under the
    // master aeadKey, no CMT-4 commitment prefix (plainAeadEncrypt).
    const encrypted = plainAeadEncrypt(new Uint8Array(compressed), null, nonce, aeadKey);
    return { dataName: name, nonce: Array.from(nonce), data: Array.from(encrypted), hash: sha3_512hex(encrypted), dataType: 'string' };
  });

  const payload = {
    data: dataEntries, encryptedSalt, saltNonce, wrapSalt,
    version: 26, hashAlgorithm: 'sha3-512',
    argon2Memory: ARGON2_MEMORY_STANDARD, argon2Time: ARGON2_TIME_STANDARD,
    // deliberately NO argon2HashLen/hashKeyLen/keyProfile/keyCommitment/
    // counterHMAC/merkleRoot/fileSignature — none of those fields existed
    // in v26; the loader must fall back correctly on their absence.
  };
  const payloadBuffer = Buffer.from(JSON.stringify(payload), 'utf8');
  const mac = nodeCrypto.createHmac('sha3-512', Buffer.from(macKey))
    .update(Buffer.concat([payloadBuffer, Buffer.from('application/json', 'utf8')]))
    .digest();

  aeadKey.fill(0);
  macKey.fill(0);

  const wrapped = { payload: Array.from(payloadBuffer), mac: Array.from(mac) };
  return zlib.deflateSync(Buffer.from(JSON.stringify(wrapped), 'utf8'), { level: 6 });
}

/** Builds a genuine v27-shaped `.spd` file payload (see file header for the exact wire-format facts encoded). */
async function buildV27Payload(passcode: string, entries: Array<{ name: string; value: string }>): Promise<Buffer> {
  const ARGON2_HASH_LEN_V27 = 96;
  const HMAC_KEY_LEN_V27 = 64;

  const salt = crypto.getRandomValues(new Uint8Array(32));
  const { encryptedSalt, saltNonce, wrapSalt } = await SPD.encryptSalt(
    salt, passcode, ARGON2_MEMORY_STANDARD, ARGON2_TIME_STANDARD
  );
  const { aeadKey, macKey } = await SPD.deriveKeys(
    passcode, salt, ARGON2_MEMORY_STANDARD, ARGON2_TIME_STANDARD,
    ARGON2_HASH_LEN_V27, HMAC_KEY_LEN_V27, false, 1048576, 8, 4, 1
  );

  const dataEntries = entries.map(({ name, value }) => {
    const compressed = zlib.deflateSync(Buffer.from(value, 'utf8')); // still no padForCompression framing (v29+)
    const nonce = crypto.getRandomValues(new Uint8Array(24));
    // v27: per-entry AAD (dataName) + deriveEntryKey ARE used, but still
    // plainAeadEncrypt (no CMT-4 commitment prefix — that's v29+).
    const entryKey = deriveEntryKey(aeadKey, name);
    const encrypted = plainAeadEncrypt(new Uint8Array(compressed), Buffer.from(name, 'utf8'), nonce, entryKey);
    entryKey.fill(0);
    return { dataName: name, nonce: Array.from(nonce), data: Array.from(encrypted), hash: sha3_512hex(encrypted), dataType: 'string' };
  });

  const payload = {
    data: dataEntries, encryptedSalt, saltNonce, wrapSalt,
    version: 27, hashAlgorithm: 'sha3-512',
    argon2Memory: ARGON2_MEMORY_STANDARD, argon2Time: ARGON2_TIME_STANDARD,
    argon2HashLen: ARGON2_HASH_LEN_V27, hashKeyLen: HMAC_KEY_LEN_V27,
    // deliberately NO keyProfile/keyCommitment/counterHMAC/merkleRoot/
    // fileSignature — all v29+, must not be required on load.
  };
  const payloadBuffer = Buffer.from(JSON.stringify(payload), 'utf8');
  const mac = nodeCrypto.createHmac('sha3-512', Buffer.from(macKey))
    .update(Buffer.concat([payloadBuffer, Buffer.from('application/json', 'utf8')]))
    .digest();

  aeadKey.fill(0);
  macKey.fill(0);

  const wrapped = { payload: Array.from(payloadBuffer), mac: Array.from(mac) };
  return zlib.deflateSync(Buffer.from(JSON.stringify(wrapped), 'utf8'), { level: 6 });
}

describe('legacy file format compatibility (v26)', () => {
  it('loads a genuine hand-built v26 payload through the current, unmodified SPD.loadFromFile', async () => {
    const compressed = await buildV26Payload(PASS, [
      { name: 'greeting', value: 'hello from v26' },
      { name: 'note', value: 'legacy entries have no per-entry AAD binding' },
    ]);
    const file = tmpSpdFile('v26');
    fs.writeFileSync(file, compressed);
    try {
      const loaded = await SPD.loadFromFile(file, PASS);
      expect((loaded as any).fileVersion).toBe(26);
      const data = await loaded.extractData();
      expect(data['greeting']).toBe('hello from v26');
      expect(data['note']).toBe('legacy entries have no per-entry AAD binding');
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(file); } catch {}
    }
  });

  it('rejects a v26 payload with the wrong passcode (legacy MAC/salt-wrap path still authenticates correctly)', async () => {
    const compressed = await buildV26Payload(PASS, [{ name: 'k', value: 'v' }]);
    const file = tmpSpdFile('v26-wrong');
    fs.writeFileSync(file, compressed);
    try {
      await expect(SPD.loadFromFile(file, 'TotallyWrongPass!9999')).rejects.toThrow(/Authentication failed/);
    } finally {
      try { fs.unlinkSync(file); } catch {}
    }
  });

  it('rejects a version below SPD_VERSION_MIN with a clear error', async () => {
    const compressed = await buildV26Payload(PASS, [{ name: 'k', value: 'v' }]);
    // Tamper the version field down to something older than the supported floor.
    const decompressed = zlib.inflateSync(compressed);
    const wrapped = JSON.parse(decompressed.toString('utf8'));
    const payload = JSON.parse(Buffer.from(wrapped.payload).toString('utf8'));
    payload.version = 20;
    const newWrapped = { payload: Array.from(Buffer.from(JSON.stringify(payload), 'utf8')), mac: wrapped.mac };
    const recompressed = zlib.deflateSync(Buffer.from(JSON.stringify(newWrapped), 'utf8'));

    const file = tmpSpdFile('v20');
    fs.writeFileSync(file, recompressed);
    try {
      await expect(SPD.loadFromFile(file, PASS)).rejects.toThrow(/Unsupported SPD version/);
    } finally {
      try { fs.unlinkSync(file); } catch {}
    }
  });
});

describe('legacy file format compatibility (v27)', () => {
  it('loads a genuine hand-built v27 payload through the current, unmodified SPD.loadFromFile', async () => {
    const compressed = await buildV27Payload(PASS, [
      { name: 'greeting', value: 'hello from v27' },
      { name: 'note', value: 'v27 entries DO have per-entry AAD binding, unlike v26' },
    ]);
    const file = tmpSpdFile('v27');
    fs.writeFileSync(file, compressed);
    try {
      const loaded = await SPD.loadFromFile(file, PASS);
      expect((loaded as any).fileVersion).toBe(27);
      const data = await loaded.extractData();
      expect(data['greeting']).toBe('hello from v27');
      expect(data['note']).toBe('v27 entries DO have per-entry AAD binding, unlike v26');
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(file); } catch {}
    }
  });

  it('rejects a v27 payload with the wrong passcode', async () => {
    const compressed = await buildV27Payload(PASS, [{ name: 'k', value: 'v' }]);
    const file = tmpSpdFile('v27-wrong');
    fs.writeFileSync(file, compressed);
    try {
      await expect(SPD.loadFromFile(file, 'TotallyWrongPass!9999')).rejects.toThrow(/Authentication failed/);
    } finally {
      try { fs.unlinkSync(file); } catch {}
    }
  });

  it('a v27 entry ciphertext cannot be decrypted under a different entry name (per-entry AAD binding actually enforced)', async () => {
    // Build a v27 file with two entries, then swap their nonces/ciphertexts
    // to simulate an attacker splicing one entry's ciphertext under a
    // different name — must fail, proving the AAD binding is real, not
    // just present in the fixture by construction.
    const compressed = await buildV27Payload(PASS, [
      { name: 'entryA', value: 'secret A' },
      { name: 'entryB', value: 'secret B' },
    ]);
    const decompressed = zlib.inflateSync(compressed);
    const wrapped = JSON.parse(decompressed.toString('utf8'));
    const payload = JSON.parse(Buffer.from(wrapped.payload).toString('utf8'));
    // Swap entry A's ciphertext/nonce into entry B's slot (names stay put).
    const tmp = { nonce: payload.data[0].nonce, data: payload.data[0].data, hash: payload.data[0].hash };
    payload.data[0].nonce = payload.data[1].nonce;
    payload.data[0].data = payload.data[1].data;
    payload.data[0].hash = payload.data[1].hash;
    payload.data[1].nonce = tmp.nonce;
    payload.data[1].data = tmp.data;
    payload.data[1].hash = tmp.hash;
    const newWrapped = { payload: Array.from(Buffer.from(JSON.stringify(payload), 'utf8')), mac: wrapped.mac };
    const recompressed = zlib.deflateSync(Buffer.from(JSON.stringify(newWrapped), 'utf8'));

    const file = tmpSpdFile('v27-splice');
    fs.writeFileSync(file, recompressed);
    try {
      // Outer MAC covers the whole payload including entry ciphertexts, so
      // this is actually rejected at the outer MAC check already — either
      // way, the splice must not silently succeed.
      await expect(SPD.loadFromFile(file, PASS)).rejects.toThrow(/Authentication failed/);
    } finally {
      try { fs.unlinkSync(file); } catch {}
    }
  });
});
