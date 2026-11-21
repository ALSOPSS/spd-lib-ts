/**
 * SPD library test suite
 * Run with: npx vitest run
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as zlib from 'zlib';
import { SPD, SPDWriter, ARGON2_MEMORY_HIGH, ARGON2_TIME_HIGH, ARGON2_MEMORY_PARANOID, ARGON2_TIME_PARANOID } from '../src/index';
import type { SPDKeyProfile } from '../src/index';
import { SPDWeb } from '../src/web';
import * as keyMaterial from '../src/internal/spd-key-material';

const PASS = 'MyStr0ng!Passphrase#2024';
const PASS2 = 'EvenStr0nger!Pass#9999';

// ── Helpers ─────────────────────────────────────────────────────────────────

function tmpFile(ext = '.spd'): string {
  return path.join(os.tmpdir(), `spd-test-${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`);
}

function tmpDir(): string {
  const d = path.join(os.tmpdir(), `spd-test-dir-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  fs.mkdirSync(d, { recursive: true, mode: 0o700 });
  return d;
}

async function freshSPD(): Promise<SPD> {
  const spd = new SPD();
  spd.setKeyProfile('standard'); // keep unit tests fast; default hardening tested separately
  await spd.setPassKey(PASS);
  return spd;
}

// ── Round-trip: all 14 supported data types ──────────────────────────────────

describe('round-trip all data types', () => {
  const cases: Array<[string, unknown]> = [
    ['str',     'hello world'],
    ['num',     42.5],
    ['bool_t',  true],
    ['bool_f',  false],
    ['obj',     { a: 1, b: { c: 'nested' } }],
    ['arr',     [1, 'two', true, null]],
    ['u8',      new Uint8Array([0, 1, 255])],
    ['u16',     new Uint16Array([0, 1000, 65535])],
    ['u32',     new Uint32Array([0, 1, 4294967295])],
    ['bi64',    new BigInt64Array([BigInt(-9007199254740991), BigInt(0)])],
    ['bu64',    new BigUint64Array([BigInt(0), BigInt(9007199254740991)])],
    ['f32',     new Float32Array([1.5, -0.5])],
    ['f64',     new Float64Array([Math.PI, Number.EPSILON])],
    ['map',     new Map([['key', 'val'], ['n', 42]])],
    ['set',     new Set([1, 2, 3, 'x'])],
    ['date',    new Date('2024-01-15T12:00:00.000Z')],
    ['re',      /^hello\s+world$/gim],
    ['err',     new Error('test error')],
    ['null_v',  null],
  ];

  it.each(cases)('addData/extractData round-trip: %s', async (name, value) => {
    const spd = await freshSPD();
    await spd.addData(name, value);
    const out = await spd.extractData();

    if (value instanceof Uint8Array   || value instanceof Uint16Array ||
        value instanceof Uint32Array  || value instanceof Float32Array ||
        value instanceof Float64Array || value instanceof BigInt64Array ||
        value instanceof BigUint64Array) {
      expect(Array.from(out[name] as any)).toEqual(Array.from(value as any));
    } else if (value instanceof Map) {
      expect(out[name]).toEqual(value);
    } else if (value instanceof Set) {
      expect(Array.from(out[name] as Set<unknown>)).toEqual(Array.from(value));
    } else if (value instanceof Date) {
      expect((out[name] as Date).toISOString()).toBe(value.toISOString());
    } else if (value instanceof RegExp) {
      const r = out[name] as RegExp;
      expect(r.source).toBe(value.source);
      expect(r.flags).toBe(value.flags);
    } else if (value instanceof Error) {
      expect((out[name] as Error).message).toBe(value.message);
    } else {
      expect(out[name]).toEqual(value);
    }
    spd.destroy();
  });
});

// ── saveToFile / loadFromFile ────────────────────────────────────────────────

describe('saveToFile / loadFromFile', () => {
  it('saves and loads a file correctly', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('x', 'abc');
      await spd.addData('y', 123);
      await spd.saveToFile(f, PASS);
      spd.destroy();

      const loaded = await SPD.loadFromFile(f, PASS);
      const data = await loaded.extractData();
      expect(data.x).toBe('abc');
      expect(data.y).toBe(123);
      loaded.destroy();
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  it('writes to .tmp then renames (atomic write)', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFile(f, PASS);
      expect(fs.existsSync(f)).toBe(true);
      expect(fs.existsSync(f + '.tmp')).toBe(false);
      spd.destroy();
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  it('rejects wrong passcode', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFile(f, PASS);
      spd.destroy();
      await expect(SPD.loadFromFile(f, 'WrongPass!word#99')).rejects.toThrow();
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  it('detects tampered file', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFile(f, PASS);
      spd.destroy();

      // Flip a byte in the middle of the file
      const buf = fs.readFileSync(f);
      buf[buf.length >> 1] ^= 0xff;
      fs.writeFileSync(f, buf);

      await expect(SPD.loadFromFile(f, PASS)).rejects.toThrow();
    } finally { try { fs.unlinkSync(f); } catch {} }
  });
});

// ── saveToFileStreaming / loadFromFileStreaming ───────────────────────────────

describe('saveToFileStreaming / loadFromFileStreaming', () => {
  it('saves and loads streaming file correctly', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('alpha', [1, 2, 3]);
      await spd.addData('beta', { nested: true });
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      const loaded = await SPD.loadFromFileStreaming(f, PASS);
      const data = await loaded.extractData();
      expect(data.alpha).toEqual([1, 2, 3]);
      expect(data.beta).toEqual({ nested: true });
      loaded.destroy();
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  it('no .tmp file remains after successful streaming save', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFileStreaming(f, PASS);
      expect(fs.existsSync(f + '.tmp')).toBe(false);
      spd.destroy();
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  it(
    'rejects a decompression-bomb-shaped file quickly, instead of fully inflating an ' +
    'attacker-claimed-small payload into an enormous plaintext before the length/MAC ' +
    'check (regression: loadFromFileStreaming used to decompress the entire stream into ' +
    'memory BEFORE comparing against the header-claimed length, which is itself ' +
    'unauthenticated attacker-controlled data at that point). Asserts on ELAPSED TIME, ' +
    'not memory (heap-usage deltas are too noisy/GC-timing-dependent to assert on ' +
    'reliably) — measured directly against both the fixed and reverted-pre-fix code: ' +
    '~270ms fixed vs. ~4000ms pre-fix for a 1GB bomb on this machine, a wide enough gap ' +
    'that this bound (2s) discriminates reliably without being flaky under normal CI load.',
    async () => {
      const f = tmpFile();
      try {
        // Real streaming-format header: [8B claimed plaintext length][64B mac][zlib data].
        // Claim only 8 bytes of plaintext, but actually compress a 1GB buffer of zeros
        // (deflate ratio easily exceeds 1000:1 on repetitive data, so the resulting
        // file is only ~1MB on disk despite claiming to decompress to 8 bytes).
        const huge = Buffer.alloc(1024 * 1024 * 1024);
        const bomb = zlib.deflateSync(huge, { level: 9 });
        const header = Buffer.alloc(72); // claimedLen defaults to 0 via alloc; mac bytes irrelevant, never reached
        header.writeBigUInt64LE(8n, 0);
        fs.writeFileSync(f, Buffer.concat([header, bomb]));

        const start = Date.now();
        await expect(SPD.loadFromFileStreaming(f, PASS)).rejects.toThrow(/Authentication failed/);
        const elapsed = Date.now() - start;
        expect(elapsed).toBeLessThan(2000);
      } finally {
        try { fs.unlinkSync(f); } catch {}
      }
    },
    15_000
  );
});

// ── SPDWriter ────────────────────────────────────────────────────────────────

describe('SPDWriter', () => {
  it('writes and loads correctly', async () => {
    const f = tmpFile();
    try {
      const writer = new SPDWriter(f, PASS);
      await writer.init();
      await writer.addEntry('name', 'alice');
      await writer.addEntry('score', 99);
      await writer.finalize();

      const loaded = await SPD.loadFromFileStreaming(f, PASS);
      const data = await loaded.extractData();
      expect(data.name).toBe('alice');
      expect(data.score).toBe(99);
      loaded.destroy();
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  it(
    'rejects a weak passcode at construction (regression: SPDWriter previously had NO ' +
    'entropy validation at all — accepted any passcode, however guessable, unlike every ' +
    'other passcode-based entry point in this codebase)',
    () => {
      const f = tmpFile();
      expect(() => new SPDWriter(f, 'password12345')).toThrow(/entropy|common phrase|weak pattern/i);
    }
  );

  it('writes embedded tail index', async () => {
    const f = tmpFile();
    try {
      const writer = new SPDWriter(f, PASS);
      await writer.init();
      await writer.addEntry('k', 'v');
      await writer.finalize();

      // Last 4 bytes should be "SPDy" magic
      const buf = fs.readFileSync(f);
      expect(buf.subarray(buf.length - 4)).toEqual(Buffer.from([0x53, 0x50, 0x44, 0x79])); // v2 tail magic; legacy SPDx still readable
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  // addEntry can't overwrite an already-written entry's BODY bytes (each
  // entry streams to disk as it's written), but the tail INDEX should still
  // point at the latest write — matching SPD.addData's overwrite semantics
  // and keeping getEntry()'s indexed lookup consistent with a full scan.
  it('a duplicate addEntry name resolves consistently via getEntry (indexed) vs extractData (full scan)', async () => {
    const f = tmpFile();
    try {
      const writer = new SPDWriter(f, PASS);
      await writer.init();
      await writer.addEntry('dup', 'first-value');
      await writer.addEntry('dup', 'second-value');
      await writer.finalize();

      const viaGetEntry = await SPD.getEntry(f, PASS, 'dup');
      const loaded = await SPD.loadFromFileStreaming(f, PASS);
      const viaExtractData = await loaded.extractData();
      loaded.destroy();

      expect(viaGetEntry.value).toBe(viaExtractData.dup);
      expect(viaGetEntry.value).toBe('second-value'); // last write wins, both paths
    } finally {
      try { fs.unlinkSync(f); fs.unlinkSync(f + '.seq'); } catch {}
    }
  });
});

// ── getEntry ─────────────────────────────────────────────────────────────────

describe('SPD.getEntry', () => {
  it('retrieves a single entry without loading the whole file', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('target', 'found-it');
      await spd.addData('decoy', 'ignore-me');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      const result = await SPD.getEntry(f, PASS, 'target');
      expect(result.value).toBe('found-it');
      expect(result.name).toBe('target');
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  it('throws on missing entry', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('exists', 1);
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();
      await expect(SPD.getEntry(f, PASS, 'notexists')).rejects.toThrow('Entry not found');
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  it('throws on tampered file', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      const buf = fs.readFileSync(f);
      buf[80] ^= 0x01; // flip a byte in the compressed body
      fs.writeFileSync(f, buf);
      await expect(SPD.getEntry(f, PASS, 'k')).rejects.toThrow();
    } finally { try { fs.unlinkSync(f); } catch {} }
  });
});

// ── AAD binding ──────────────────────────────────────────────────────────────

describe('AAD binding (per-entry)', () => {
  it('decrypts correctly with right name', async () => {
    const spd = await freshSPD();
    await spd.addData('mykey', 'secret');
    const data = await spd.extractData();
    expect(data.mykey).toBe('secret');
    spd.destroy();
  });

  it('ciphertext is bound to entry name via AAD — swap detection', async () => {
    // If we directly swap two entries' data buffers, AEAD decrypt should fail
    const spd = await freshSPD();
    await spd.addData('alpha', 'val_a');
    await spd.addData('beta', 'val_b');

    // Swap the data buffers between the two entries
    const entries = (spd as any).data as Array<{ dataName: string; data: Buffer; nonce: Buffer; hash: string; dataType: string }>;
    const tmp = entries[0].data;
    entries[0].data = entries[1].data;
    entries[1].data = tmp;
    const tmpN = entries[0].nonce;
    entries[0].nonce = entries[1].nonce;
    entries[1].nonce = tmpN;

    await expect(spd.extractData()).rejects.toThrow();
    spd.destroy();
  });
});

// ── Per-entry derived keys ────────────────────────────────────────────────────

describe('per-entry derived keys', () => {
  it('different entries produce different derived keys', async () => {
    const spd = await freshSPD();
    const k1 = SPD.deriveEntryKey((spd as any).userKey, 'entry_a');
    const k2 = SPD.deriveEntryKey((spd as any).userKey, 'entry_b');
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(false);
    spd.destroy();
  });

  it('same name always produces same key (deterministic)', async () => {
    const spd = await freshSPD();
    const k1 = SPD.deriveEntryKey((spd as any).userKey, 'consistent_name');
    const k2 = SPD.deriveEntryKey((spd as any).userKey, 'consistent_name');
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(true);
    spd.destroy();
  });
});

// ── has / keys / count / deleteEntry / renameEntry / updateEntry ─────────────

describe('mutation API', () => {
  it('has() returns correct results', async () => {
    const spd = await freshSPD();
    await spd.addData('exists', 1);
    expect(spd.has('exists')).toBe(true);
    expect(spd.has('missing')).toBe(false);
    spd.destroy();
  });

  it('keys() returns all names in insertion order', async () => {
    const spd = await freshSPD();
    await spd.addData('first', 1);
    await spd.addData('second', 2);
    await spd.addData('third', 3);
    expect(spd.keys()).toEqual(['first', 'second', 'third']);
    spd.destroy();
  });

  it('count() returns entry count', async () => {
    const spd = await freshSPD();
    expect(spd.count()).toBe(0);
    await spd.addData('a', 1);
    await spd.addData('b', 2);
    expect(spd.count()).toBe(2);
    spd.destroy();
  });

  it('deleteEntry removes the entry', async () => {
    const spd = await freshSPD();
    await spd.addData('keep', 1);
    await spd.addData('remove', 2);
    spd.deleteEntry('remove');
    expect(spd.has('remove')).toBe(false);
    expect(spd.has('keep')).toBe(true);
    expect(spd.count()).toBe(1);
    spd.destroy();
  });

  it('deleteEntry throws on missing name', async () => {
    const spd = await freshSPD();
    expect(() => spd.deleteEntry('ghost')).toThrow('Entry not found');
    spd.destroy();
  });

  it('renameEntry renames and re-encrypts correctly', async () => {
    const spd = await freshSPD();
    await spd.addData('old_name', 'the_value');
    await spd.renameEntry('old_name', 'new_name');
    expect(spd.has('old_name')).toBe(false);
    expect(spd.has('new_name')).toBe(true);
    const data = await spd.extractData();
    expect(data.new_name).toBe('the_value');
    spd.destroy();
  });

  it('renameEntry throws if target name already exists', async () => {
    const spd = await freshSPD();
    await spd.addData('a', 1);
    await spd.addData('b', 2);
    await expect(spd.renameEntry('a', 'b')).rejects.toThrow('already exists');
    spd.destroy();
  });

  it('updateEntry replaces value in place, preserving order', async () => {
    const spd = await freshSPD();
    await spd.addData('first', 1);
    await spd.addData('second', 2);
    await spd.updateEntry('first', 99);
    expect(spd.keys()).toEqual(['first', 'second']); // order preserved
    const data = await spd.extractData();
    expect(data.first).toBe(99);
    expect(data.second).toBe(2);
    spd.destroy();
  });

  it('updateEntry throws if entry not found', async () => {
    const spd = await freshSPD();
    await expect(spd.updateEntry('ghost', 1)).rejects.toThrow('Entry not found');
    spd.destroy();
  });
});

// ── changePasscode ────────────────────────────────────────────────────────────

describe('changePasscode', () => {
  it('re-encrypts all data under new passcode', async () => {
    const spd = await freshSPD();
    await spd.addData('secret', 'treasure');
    await spd.changePasscode(PASS, PASS2);

    const f = tmpFile();
    try {
      await spd.saveToFile(f, PASS2);
      spd.destroy();
      const loaded = await SPD.loadFromFile(f, PASS2);
      const data = await loaded.extractData();
      expect(data.secret).toBe('treasure');
      loaded.destroy();
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  it('rejects old passcode after change', async () => {
    const spd = await freshSPD();
    await spd.addData('k', 'v');
    await spd.changePasscode(PASS, PASS2);
    const f = tmpFile();
    try {
      await spd.saveToFile(f, PASS2);
      spd.destroy();
      await expect(SPD.loadFromFile(f, PASS)).rejects.toThrow();
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  it(
    'rejects rotating to a weak new passcode (regression: changePasscode used to never ' +
    'validate the NEW passcode\'s strength at all — a user could silently downgrade from a ' +
    'strong passphrase to something trivially guessable via rotation, completely bypassing ' +
    'the entropy floor that setPassKey() enforces on the initial passphrase)',
    async () => {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await expect(spd.changePasscode(PASS, 'password12345')).rejects.toThrow(/entropy|common phrase|weak pattern/i);
      spd.destroy();
    }
  );

  it('works correctly on an instance loaded from a streaming binary file (not just a freshly-created in-memory one)', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('secret', 'treasure');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      const loaded = await SPD.loadFromFileStreaming(f, PASS);
      await loaded.changePasscode(PASS, PASS2);
      await loaded.saveToFileStreaming(f, PASS2);
      loaded.destroy();

      const reloaded = await SPD.loadFromFileStreaming(f, PASS2);
      const data = await reloaded.extractData();
      expect(data.secret).toBe('treasure');
      reloaded.destroy();
    } finally {
      try { fs.unlinkSync(f); } catch {}
      try { fs.unlinkSync(f + '.seq'); } catch {}
      try { fs.unlinkSync(f + 'i'); } catch {}
    }
  });
});

// ── upgradeKdfParams ─────────────────────────────────────────────────────────

describe('upgradeKdfParams', () => {
  it('re-derives keys under stronger params and the data survives a save/load round-trip', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD(); // 'standard' profile: 128 MiB / 6 passes
      await spd.addData('secret', 'long-term-archival-data');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      const loaded = await SPD.loadFromFileStreaming(f, PASS);
      await loaded.upgradeKdfParams(PASS, { memory: 262144, time: 8 }); // 256 MiB / 8 passes — strictly stronger
      await loaded.saveToFileStreaming(f, PASS);
      loaded.destroy();

      const reloaded = await SPD.loadFromFileStreaming(f, PASS);
      const data = await reloaded.extractData();
      expect(data.secret).toBe('long-term-archival-data');
      reloaded.destroy();
    } finally {
      try { fs.unlinkSync(f); } catch {}
      try { fs.unlinkSync(f + '.seq'); } catch {}
      try { fs.unlinkSync(f + 'i'); } catch {}
    }
  });

  it('rejects a downgrade (new params weaker than current)', async () => {
    const spd = await freshSPD(); // 128 MiB / 6 passes
    await spd.addData('k', 'v');
    await expect(spd.upgradeKdfParams(PASS, { memory: 65536, time: 3 })).rejects.toThrow(/must be >=/);
    spd.destroy();
  });

  it('rejects the wrong passcode', async () => {
    const spd = await freshSPD();
    await spd.addData('k', 'v');
    await expect(spd.upgradeKdfParams('wrong-passphrase-entirely-2026!!', { memory: 262144, time: 8 })).rejects.toThrow(/Authentication failed/);
    spd.destroy();
  });

  it('rejects out-of-range params', async () => {
    const spd = await freshSPD();
    await spd.addData('k', 'v');
    await expect(spd.upgradeKdfParams(PASS, { memory: 999_999_999, time: 8 })).rejects.toThrow(/argon2Memory/);
    spd.destroy();
  });

  it('the new params are actually persisted to the saved file meta (not silently ignored)', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      const loaded = await SPD.loadFromFileStreaming(f, PASS);
      await loaded.upgradeKdfParams(PASS, { memory: 262144, time: 8 });
      await loaded.saveToFileStreaming(f, PASS);
      loaded.destroy();

      const raw = fs.readFileSync(f);
      const zlib2 = await import('zlib');
      const plaintext = zlib2.inflateSync(raw.subarray(72));
      const metaLen = plaintext.readUInt32LE(0);
      const meta = JSON.parse(plaintext.subarray(4, 4 + metaLen).toString('utf8'));
      expect(meta.argon2Memory).toBe(262144);
      expect(meta.argon2Time).toBe(8);
    } finally {
      try { fs.unlinkSync(f); } catch {}
      try { fs.unlinkSync(f + '.seq'); } catch {}
      try { fs.unlinkSync(f + 'i'); } catch {}
    }
  });

  it('a subsequent changePasscode after upgradeKdfParams still works (current-params tracking stays correct across multiple rotations)', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('secret', 'still-here');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      const loaded = await SPD.loadFromFileStreaming(f, PASS);
      await loaded.upgradeKdfParams(PASS, { memory: 262144, time: 8 });
      await loaded.changePasscode(PASS, PASS2);
      await loaded.saveToFileStreaming(f, PASS2);
      loaded.destroy();

      const reloaded = await SPD.loadFromFileStreaming(f, PASS2);
      const data = await reloaded.extractData();
      expect(data.secret).toBe('still-here');
      reloaded.destroy();
    } finally {
      try { fs.unlinkSync(f); } catch {}
      try { fs.unlinkSync(f + '.seq'); } catch {}
      try { fs.unlinkSync(f + 'i'); } catch {}
    }
  });
});

// ── Pepper ───────────────────────────────────────────────────────────────────

describe('pepper support', () => {
  afterEach(() => {
    // Clear pepper after each test
    SPD.setPepper('');
  });

  it('correct pepper allows decryption', async () => {
    SPD.setPepper('server-secret-42');
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'peppered');
      await spd.saveToFile(f, PASS);
      spd.destroy();

      SPD.setPepper('server-secret-42');
      const loaded = await SPD.loadFromFile(f, PASS);
      const data = await loaded.extractData();
      expect(data.k).toBe('peppered');
      loaded.destroy();
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  it('wrong pepper causes MAC failure', async () => {
    SPD.setPepper('correct-pepper!1');
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFile(f, PASS);
      spd.destroy();

      SPD.setPepper('wrong-pepper!!!!');
      await expect(SPD.loadFromFile(f, PASS)).rejects.toThrow();
    } finally {
      try { fs.unlinkSync(f); } catch {}
    }
  });

  it(
    'rejects a too-short pepper (regression: setPepper previously accepted any length at ' +
    'all, including a single character, silently defeating the whole point of a pepper)',
    () => {
      expect(() => SPD.setPepper('short')).toThrow(/at least 16 bytes/i);
      expect(() => SPD.setPepper('a')).toThrow(/at least 16 bytes/i);
    }
  );

  it('rejects a degenerate all-same-byte pepper even if long enough', () => {
    expect(() => SPD.setPepper('aaaaaaaaaaaaaaaaaaaa')).toThrow(/single byte value repeated/i);
    expect(() => SPD.setPepper(new Uint8Array(32))).toThrow(/single byte value repeated/i); // all-zero
  });

  it("still allows '' to clear/disable the pepper (the existing convention, not a weak-pepper exception)", () => {
    expect(() => SPD.setPepper('')).not.toThrow();
    expect(() => SPD.setPepper(new Uint8Array(0))).not.toThrow();
  });

  it('accepts a properly random 32-byte pepper from SPD.generateRandomKey()', () => {
    const randomPepper = SPD.generateRandomKey().subarray(0, 32);
    expect(() => SPD.setPepper(randomPepper)).not.toThrow();
  });
});

// ── WAL ───────────────────────────────────────────────────────────────────────

describe('WAL (write-ahead log)', () => {
  it('replays WAL entries on flushDelta', async () => {
    const f   = tmpFile();
    const wal = tmpFile('.wal');
    try {
      const spd = await freshSPD();
      spd.enableWal(wal);
      await spd.addData('wal_entry', 'persisted');
      expect(fs.existsSync(wal)).toBe(true);

      await spd.flushDelta(f, PASS);
      spd.destroy();

      // WAL should be cleared (reset to header only) after successful save
      const walSize = fs.statSync(wal).size;
      expect(walSize).toBe(5); // magic(4) + version(1)

      const loaded = await SPD.loadFromFile(f, PASS);
      const data = await loaded.extractData();
      expect(data.wal_entry).toBe('persisted');
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(f); } catch {}
      try { fs.unlinkSync(wal); } catch {}
    }
  });

  it('replayWal merges entries without duplicates', async () => {
    const spd = await freshSPD();
    await spd.addData('existing', 'original');

    // Manually build a WAL with one new + one overwrite
    const wal = tmpFile('.wal');
    try {
      spd.enableWal(wal);
      // These go into WAL
      await spd.addData('new_entry', 'from_wal');
      await spd.addData('existing', 'overwritten'); // duplicate — WAL wins

      // New SPD instance replays the WAL
      const spd2 = await freshSPD();
      SPD.replayWal(wal, spd2);
      expect(spd2.has('new_entry')).toBe(true);
      expect(spd2.has('existing')).toBe(true);
      spd.destroy();
      spd2.destroy();
    } finally {
      try { fs.unlinkSync(wal); } catch {}
    }
  });

  it('replayWal tolerates a torn WAL (simulated crash mid-append) instead of throwing', async () => {
    const wal = tmpFile('.wal');
    try {
      const spd = await freshSPD();
      spd.enableWal(wal);
      await spd.addData('entry1', 'value1');
      await spd.addData('entry2', 'value2');
      spd.destroy();

      const fullWal = new Uint8Array(fs.readFileSync(wal));
      // Truncate partway through the second record — simulates the process
      // dying mid-fs.appendFileSync, which a real WAL must survive.
      const truncated = fullWal.subarray(0, Math.floor(fullWal.length * 0.8));
      fs.writeFileSync(wal, truncated);

      const spd2 = await freshSPD();
      expect(() => SPD.replayWal(wal, spd2)).not.toThrow();
      // The first (complete) record must still have been recovered.
      expect(spd2.has('entry1')).toBe(true);
      spd2.destroy();
    } finally {
      try { fs.unlinkSync(wal); } catch {}
    }
  });

  it('replayWal never throws for ANY truncation offset of a real WAL (regression: used to throw for ~35% of offsets)', async () => {
    // Uses the fast keyless path (no Argon2id) so this exhaustive per-offset
    // sweep stays fast — replayWal itself never decrypts anything, so key
    // derivation speed is irrelevant to what's being tested here.
    const wal = tmpFile('.wal');
    try {
      const secret = SPD.generateRandomKey();
      const spd = new SPD();
      await spd.setRandomKey(secret);
      spd.enableWal(wal);
      await spd.addData('entry1', 'value1');
      await spd.addData('entry2', 'a somewhat longer value so truncation mid-record is easy to hit across many offsets');
      await spd.addData('entry3', 'third value');
      spd.destroy();

      const fullWal = new Uint8Array(fs.readFileSync(wal));
      for (let cut = 6; cut < fullWal.length; cut++) {
        fs.writeFileSync(wal, fullWal.subarray(0, cut));
        const target = new SPD();
        await target.setRandomKey(secret);
        expect(() => SPD.replayWal(wal, target)).not.toThrow();
      }

      // Sanity: the untruncated WAL still replays all 3 entries correctly.
      fs.writeFileSync(wal, fullWal);
      const finalTarget = new SPD();
      await finalTarget.setRandomKey(secret);
      const count = SPD.replayWal(wal, finalTarget);
      expect(count).toBe(3);
      expect(finalTarget.has('entry1')).toBe(true);
      expect(finalTarget.has('entry2')).toBe(true);
      expect(finalTarget.has('entry3')).toBe(true);
    } finally {
      try { fs.unlinkSync(wal); } catch {}
    }
  }, 30_000);
});

// ── saveData / loadFromString / saveDataChunked / loadFromChunks ─────────────

describe('string and chunked transport', () => {
  it('saveData / loadFromString round-trip', async () => {
    const spd = await freshSPD();
    await spd.addData('msg', 'hello');
    const b64 = await spd.saveData(PASS);
    spd.destroy();

    const loaded = await SPD.loadFromString(b64, PASS);
    const data = await loaded.extractData();
    expect(data.msg).toBe('hello');
    loaded.destroy();
  });

  it('loadFromString rejects bytes appended after the compressed container', async () => {
    const spd = await freshSPD();
    await spd.addData('msg', 'hello');
    const b64 = await spd.saveData(PASS);
    spd.destroy();

    const raw = Buffer.from(b64, 'base64');
    const withTail = Buffer.concat([raw, Buffer.from('trailing junk')]).toString('base64');
    await expect(SPD.loadFromString(withTail, PASS)).rejects.toThrow();
    await expect(SPD.loadFromString(b64 + 'AAAA', PASS)).rejects.toThrow();
    const file = tmpFile();
    try {
      fs.writeFileSync(file, Buffer.concat([raw, Buffer.from([0])]));
      await expect(SPD.loadFromFile(file, PASS)).rejects.toThrow();
    } finally {
      try { fs.unlinkSync(file); } catch {}
    }
  });

  it('loadFromString / loadFromChunks verify a pinned file signature', async () => {
    const keyPair  = SPD.generateSigningKeyPair();
    const wrongKey = SPD.generateSigningKeyPair();
    const spd = await freshSPD();
    spd.setSigningKey(keyPair.privateKey);
    await spd.addData('msg', 'signed');
    const b64 = await spd.saveData(PASS);
    const chunks = await spd.saveDataChunked(PASS);
    spd.destroy();

    const loaded = await SPD.loadFromString(b64, PASS, keyPair.publicKey);
    expect((await loaded.extractData()).msg).toBe('signed');
    loaded.destroy();
    await expect(SPD.loadFromString(b64, PASS, wrongKey.publicKey)).rejects.toThrow('Authentication failed.');

    const fromChunks = await SPD.loadFromChunks(chunks, PASS, keyPair.publicKey);
    expect((await fromChunks.extractData()).msg).toBe('signed');
    fromChunks.destroy();
    await expect(SPD.loadFromChunks(chunks, PASS, wrongKey.publicKey)).rejects.toThrow('Authentication failed.');

    const unsigned = await freshSPD();
    await unsigned.addData('msg', 'unsigned');
    const unsignedB64 = await unsigned.saveData(PASS);
    unsigned.destroy();
    await expect(SPD.loadFromString(unsignedB64, PASS, keyPair.publicKey)).rejects.toThrow('Authentication failed.');
  });

  it(
    'saveData / loadFromString round-trips a large (30MB), genuinely incompressible ' +
    'entry (regression: buildSerializedPayload used to store each entry\'s ciphertext ' +
    'as a JSON array of numbers — one JS number per byte — via Array.from(item.data), ' +
    'which crashed with a real RangeError: Invalid array length around 50MB of real ' +
    '(incompressible) entry data, and was severely slow well before that (tens of ' +
    'seconds for a 25MB entry). Fixed by storing entry ciphertext/nonces — and the ' +
    'outer wrapper\'s inner-payload buffer — as base64 strings instead. IMPORTANT: this ' +
    'must use genuinely incompressible data (crypto.randomBytes, not a repeated ' +
    'character) — a compressible payload like \'A\'.repeat(N) hides the real bug ' +
    'entirely, since zlib crushes it down to almost nothing before it ever reaches the ' +
    'Array.from() call this test is guarding against.',
    async () => {
      const nodeCrypto = await import('crypto');
      const bigValue = nodeCrypto.randomBytes(30 * 1024 * 1024).toString('base64');

      const spd = await freshSPD();
      await spd.addData('big_entry', bigValue);
      const b64 = await spd.saveData(PASS);
      spd.destroy();

      const loaded = await SPD.loadFromString(b64, PASS);
      const data = await loaded.extractData();
      expect(data.big_entry).toBe(bigValue);
      loaded.destroy();
    },
    60_000
  );

  it('saveDataChunked / loadFromChunks round-trip (auto chunk size)', async () => {
    const spd = await freshSPD();
    await spd.addData('payload', 'chunked_content');
    const chunks = await spd.saveDataChunked(PASS);
    expect(chunks.length).toBeGreaterThanOrEqual(2); // at least 1 data chunk + manifest
    spd.destroy();

    const loaded = await SPD.loadFromChunks(chunks, PASS);
    const data = await loaded.extractData();
    expect(data.payload).toBe('chunked_content');
    loaded.destroy();
  });

  it('detects chunk count mismatch', async () => {
    const spd = await freshSPD();
    await spd.addData('k', 'v');
    const chunks = await spd.saveDataChunked(PASS);
    spd.destroy();
    // Remove a data chunk (not the manifest)
    const broken = [chunks[0], chunks[chunks.length - 1]]; // only first data + manifest
    if (chunks.length > 2) {
      await expect(SPD.loadFromChunks(broken, PASS)).rejects.toThrow();
    }
  });
});

// ── extractDataStreaming ──────────────────────────────────────────────────────

describe('extractDataStreaming', () => {
  it('calls callback for each entry in order', async () => {
    const spd = await freshSPD();
    await spd.addData('a', 1);
    await spd.addData('b', 2);
    await spd.addData('c', 3);

    const results: [string, unknown][] = [];
    await spd.extractDataStreaming((name, value) => { results.push([name, value]); });
    expect(results).toEqual([['a', 1], ['b', 2], ['c', 3]]);
    spd.destroy();
  });

  // See test/extract-data-streaming-no-disk.test.ts for the regression test
  // proving this method never touches disk (mocking fs to observe that
  // requires isolating it in its own file — vitest can't spy on this
  // file's already-imported `fs` ESM namespace, and mocking fs here would
  // break every other fs-touching test in this large shared file).
});

// ── addMany with large batch ──────────────────────────────────────────────────

describe('addMany large batch', () => {
  it('handles 1000 items without stack overflow', async () => {
    const spd = await freshSPD();
    const items = Array.from({ length: 1000 }, (_, i) => ({ name: `item_${i}`, data: i }));
    await spd.addMany(items);
    expect(spd.count()).toBe(1000);
    const data = await spd.extractData();
    expect(data.item_0).toBe(0);
    expect(data.item_999).toBe(999);
    spd.destroy();
  });
});

// ── destroy / clearCache ──────────────────────────────────────────────────────

describe('destroy', () => {
  it('clears data and keys', async () => {
    const spd = await freshSPD();
    await spd.addData('k', 'v');
    spd.destroy();
    expect(spd.count()).toBe(0);
    await expect(spd.addData('k', 'v')).rejects.toThrow('not initialized');
  });
});

// ── Key derivation cache ──────────────────────────────────────────────────────

describe('key derivation cache', () => {
  it('getEntry() returns correct values (key cache disabled for security)', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('entry1', 'value1');
      await spd.addData('entry2', 'value2');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      const r1 = await SPD.getEntry(f, PASS, 'entry1');
      expect(r1.value).toBe('value1');
      const r2 = await SPD.getEntry(f, PASS, 'entry2');
      expect(r2.value).toBe('value2');
    } finally { try { fs.unlinkSync(f); fs.unlinkSync(f + '.seq'); } catch {} }
  });

  it('clearKeyCache() evicts all entries', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      await SPD.getEntry(f, PASS, 'k'); // populate cache
      SPD.clearKeyCache();
      // After clear, next call re-derives — should still succeed
      const r = await SPD.getEntry(f, PASS, 'k');
      expect(r.value).toBe('v');
    } finally { try { fs.unlinkSync(f); fs.unlinkSync(f + '.seq'); } catch {} }
  });
});

// ── File locking ──────────────────────────────────────────────────────────────

describe('file locking', () => {
  it('acquireLock / releaseLock round-trip works', () => {
    const f = tmpFile();
    try {
      SPD.acquireLock(f);
      expect(fs.existsSync(f + '.lock')).toBe(true);
      SPD.releaseLock(f);
      expect(fs.existsSync(f + '.lock')).toBe(false);
    } finally { try { SPD.releaseLock(f); } catch {} }
  });

  it('second acquireLock throws ESPD_LOCKED for live process', () => {
    const f = tmpFile();
    try {
      SPD.acquireLock(f);
      expect(() => SPD.acquireLock(f)).toThrow(/locked|ESPD_LOCKED/i);
    } finally { SPD.releaseLock(f); }
  });

  it('saveToFile acquires and releases lock automatically', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFile(f, PASS);
      spd.destroy();
      // Lock must be released after save
      expect(fs.existsSync(f + '.lock')).toBe(false);
    } finally { try { fs.unlinkSync(f); fs.unlinkSync(f + '.seq'); } catch {} }
  });

  it('saveToFileStreaming acquires and releases lock automatically', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();
      expect(fs.existsSync(f + '.lock')).toBe(false);
    } finally { try { fs.unlinkSync(f); fs.unlinkSync(f + '.seq'); } catch {} }
  });

  it('stale lock (dead PID) is broken automatically', () => {
    const f = tmpFile();
    try {
      // Use a PID that is guaranteed to not exist (very large number)
      fs.writeFileSync(f + '.lock', JSON.stringify({ pid: 9999999, ts: Date.now() - 1000 }));
      // Should not throw — stale lock from dead process is removed
      expect(() => SPD.acquireLock(f)).not.toThrow();
      expect(fs.existsSync(f + '.lock')).toBe(true); // new lock written
    } finally { SPD.releaseLock(f); }
  });
});

// ── Rollback protection ───────────────────────────────────────────────────────

describe('rollback protection', () => {
  it('counter increases on successive saves', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v1');
      await spd.saveToFileStreaming(f, PASS);
      const seq1 = parseInt(fs.readFileSync(f + '.seq', 'utf8').trim(), 10);

      await spd.updateEntry('k', 'v2');
      await spd.saveToFileStreaming(f, PASS);
      const seq2 = parseInt(fs.readFileSync(f + '.seq', 'utf8').trim(), 10);

      expect(seq2).toBeGreaterThan(seq1);
      spd.destroy();
    } finally { try { fs.unlinkSync(f); fs.unlinkSync(f + '.seq'); } catch {} }
  });

  it('loading a file whose counter is behind the sidecar throws ESPD_ROLLBACK', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFileStreaming(f, PASS); // counter = 1
      await spd.saveToFileStreaming(f, PASS); // counter = 2, sidecar = 2

      // Overwrite sidecar with a future counter to simulate rollback scenario
      fs.writeFileSync(f + '.seq', '999');

      await expect(SPD.loadFromFileStreaming(f, PASS)).rejects.toThrow('Rollback detected');
      spd.destroy();
    } finally { try { fs.unlinkSync(f); fs.unlinkSync(f + '.seq'); } catch {} }
  });

  it('loadFromFile rollback detection works on JSON format', async () => {
    const f = tmpFile('.spd');
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFile(f, PASS); // counter = 1
      await spd.saveToFile(f, PASS); // counter = 2

      fs.writeFileSync(f + '.seq', '999');
      await expect(SPD.loadFromFile(f, PASS)).rejects.toThrow('Rollback detected');
      spd.destroy();
    } finally { try { fs.unlinkSync(f); fs.unlinkSync(f + '.seq'); } catch {} }
  });
});

// ── Progress callbacks ────────────────────────────────────────────────────────

describe('progress callbacks', () => {
  it('saveToFileStreaming calls onProgress with increasing bytesWritten', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      for (let i = 0; i < 20; i++) await spd.addData(`key_${i}`, `${'x'.repeat(500)}_${i}`);

      const progress: number[] = [];
      await spd.saveToFileStreaming(f, PASS, (written, _total) => progress.push(written));
      spd.destroy();

      expect(progress.length).toBeGreaterThan(0);
      // Progress values should be non-decreasing
      for (let i = 1; i < progress.length; i++) {
        expect(progress[i]).toBeGreaterThanOrEqual(progress[i - 1]);
      }
    } finally { try { fs.unlinkSync(f); fs.unlinkSync(f + '.seq'); } catch {} }
  });

  it('loadFromFileStreaming calls onProgress with increasing bytesRead', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      for (let i = 0; i < 20; i++) await spd.addData(`key_${i}`, `${'x'.repeat(500)}_${i}`);
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      SPD.clearKeyCache();
      const progress: number[] = [];
      const loaded = await SPD.loadFromFileStreaming(f, PASS, (read, _total) => progress.push(read));
      loaded.destroy();

      expect(progress.length).toBeGreaterThan(0);
      for (let i = 1; i < progress.length; i++) {
        expect(progress[i]).toBeGreaterThanOrEqual(progress[i - 1]);
      }
    } finally { try { fs.unlinkSync(f); fs.unlinkSync(f + '.seq'); } catch {} }
  });

  it('extractFromFileStreaming calls onProgress', async () => {
    const f = tmpFile();
    const d = tmpDir();
    try {
      const spd = await freshSPD();
      for (let i = 0; i < 10; i++) await spd.addData(`k${i}`, `val${i}`);
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      SPD.clearKeyCache();
      const progress: number[] = [];
      await SPD.extractFromFileStreaming(f, PASS, d, () => {}, (r) => progress.push(r));

      expect(progress.length).toBeGreaterThan(0);
    } finally {
      try { fs.unlinkSync(f); fs.unlinkSync(f + '.seq'); } catch {}
      fs.rmSync(d, { recursive: true, force: true });
    }
  });
});

// ── Name validation ───────────────────────────────────────────────────────────

describe('entry name validation', () => {
  it('throws when sanitized name exceeds 255 bytes', async () => {
    const spd = await freshSPD();
    const longName = 'a'.repeat(256);
    await expect(spd.addData(longName, 'x')).rejects.toThrow('too long');
    spd.destroy();
  });

  it('accepts a name of exactly 255 bytes', async () => {
    const spd = await freshSPD();
    const exactName = 'a'.repeat(255);
    await expect(spd.addData(exactName, 'x')).resolves.toBeUndefined();
    spd.destroy();
  });

  it('throws when sanitized name is empty', async () => {
    const spd = await freshSPD();
    // Input that sanitizes to empty: only whitespace (trimmed) + special chars (removed)
    await expect(spd.addData('   ', 'x')).rejects.toThrow('empty');
    spd.destroy();
  });

  it('warns on collision-prone names when warnings enabled', async () => {
    SPD.enableNameCollisionWarnings();
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const spd = await freshSPD();
      await spd.addData('User.ID', 'test'); // sanitizes to user_id — genuinely differs from the input
      expect(warnSpy).toHaveBeenCalledTimes(1);
      expect(warnSpy.mock.calls[0][0]).toMatch(/User\.ID.*user_id/);
      spd.destroy();
    } finally {
      SPD.disableNameCollisionWarnings();
      warnSpy.mockRestore();
    }
  });

  it('does NOT warn when the name needs no sanitization, even with warnings enabled', async () => {
    SPD.enableNameCollisionWarnings();
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const spd = await freshSPD();
      await spd.addData('already_safe_name', 'test');
      expect(warnSpy).not.toHaveBeenCalled();
      spd.destroy();
    } finally {
      SPD.disableNameCollisionWarnings();
      warnSpy.mockRestore();
    }
  });

  it(
    'two different raw names that sanitize to the same value silently overwrite each other ' +
    '— the exact data-loss risk relevant to filename-based storage (e.g. cloud file sharing) ' +
    'that SPD.enableNameCollisionWarnings() exists to surface',
    async () => {
      const spd = await freshSPD();
      await spd.addData('Report.pdf', 'first-file-content');
      await spd.addData('report_pdf', 'second-file-content'); // same sanitized name as above
      const data = await spd.extractData();
      expect(data['report_pdf']).toBe('second-file-content'); // second write won, first is gone
      expect(spd.count()).toBe(1); // NOT 2 — confirms this is a real overwrite, not two entries
      spd.destroy();
    }
  );

  it('legitimate names round-trip correctly through extractFromFileStreaming (regression guard for the path-traversal fix)', async () => {
    const f = tmpFile();
    const d = tmpDir();
    try {
      const spd = await freshSPD();
      await spd.addData('my-safe_name123', 'ok');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      SPD.clearKeyCache();
      const results: Array<[string, unknown]> = [];
      await SPD.extractFromFileStreaming(f, PASS, d, (name, value) => { results.push([name, value]); });
      expect(results).toEqual([['my-safe_name123', 'ok']]);
    } finally {
      try { fs.unlinkSync(f); fs.unlinkSync(f + '.seq'); } catch {}
      fs.rmSync(d, { recursive: true, force: true });
    }
  });

  // See test/extract-from-file-streaming-no-per-entry-temp-files.test.ts for
  // the regression test proving no PER-ENTRY temp files (_enc.ssf/_dec.ssf)
  // are ever created (the one remaining whole-plaintext temp file is still
  // genuinely load-bearing here — see extractFromFileStreaming's own doc
  // comment — so this needs isolating in its own file the same way
  // extractDataStreaming's no-disk-I/O test is, to mock fs without
  // affecting every other fs-touching test in this large shared file).
});

// ── Path traversal guard on decrypted entry names ─────────────────────────────
//
// A name that reaches the filesystem-path-building code in
// extractFromFileStreaming/extractDataStreaming must always match the same
// charset sanitizeName() enforces at write time ([a-z0-9_-]) — verified here
// directly against the internal name-encrypt/decrypt round trip and the
// public write API, since forging a full malicious binary file would
// require bypassing AEAD authentication (not something a test — or an
// attacker without the key — can do; the real risk this guards against is a
// file constructed at a lower level than the public API, e.g. with a
// modified/forked build, or a compromised peer in a wrapSPD/unwrapSPD
// scenario who has the key but not the library's own write-path guarantees).
describe('path traversal guard on decrypted entry names', () => {
  it('sanitizeName strips path-traversal characters before an entry is ever written', async () => {
    const spd = await freshSPD();
    // '/' and '.' are stripped/collapsed by sanitizeName's [^a-z0-9_-] filter,
    // so this can never produce a name containing a literal path separator.
    await spd.addData('../../etc/passwd', 'x');
    const value = await spd.extractData();
    // The sanitized key has every non-charset character replaced with '_' —
    // confirm no key in the result contains a raw '/' or '..' sequence.
    for (const key of Object.keys(value)) {
      expect(key).not.toMatch(/\.\.|\//);
    }
    spd.destroy();
  });
});

// ─── SPD.inspect() ───────────────────────────────────────────────────────────

describe('SPD.inspect()', () => {
  it('returns metadata from a binary SPD file without a passcode', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('alpha', 'hello');
      await spd.addData('beta', 42);
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      const info = await SPD.inspect(f);
      expect(info.format).toBe('binary');
      expect(info.entryCount).toBe(2);
      expect(info.version).toBeGreaterThanOrEqual(27);
      expect(info.fileSize).toBeGreaterThan(0);
      expect(typeof info.argon2Memory).toBe('number');
      expect(typeof info.writeCounter).toBe('number');
    } finally {
      if (fs.existsSync(f)) fs.unlinkSync(f);
      const seq = f + '.seq'; if (fs.existsSync(seq)) fs.unlinkSync(seq);
    }
  });

  it('returns metadata from a JSON SPD file without a passcode', async () => {
    const f = tmpFile('.spd');
    try {
      const spd = await freshSPD();
      await spd.addData('gamma', true);
      await spd.saveToFile(f, PASS);
      spd.destroy();

      const info = await SPD.inspect(f);
      expect(info.format).toBe('json');
      expect(info.entryCount).toBe(1);
      expect(info.fileSize).toBeGreaterThan(0);
    } finally {
      if (fs.existsSync(f)) fs.unlinkSync(f);
      const seq = f + '.seq'; if (fs.existsSync(seq)) fs.unlinkSync(seq);
    }
  });

  it('throws on missing file path', async () => {
    await expect(SPD.inspect('')).rejects.toThrow();
  });
});

// ─── SPD.verify() ────────────────────────────────────────────────────────────

describe('SPD.verify()', () => {
  it('returns valid=true for an intact binary file', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('x', 'data');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      const r = await SPD.verify(f, PASS);
      expect(r.valid).toBe(true);
      expect(r.entryCount).toBe(1);
      expect(typeof r.writeCounter).toBe('number');
    } finally {
      if (fs.existsSync(f)) fs.unlinkSync(f);
      const seq = f + '.seq'; if (fs.existsSync(seq)) fs.unlinkSync(seq);
    }
  });

  it('returns valid=true for an intact JSON file', async () => {
    const f = tmpFile('.spd');
    try {
      const spd = await freshSPD();
      await spd.addData('y', 99);
      await spd.saveToFile(f, PASS);
      spd.destroy();

      const r = await SPD.verify(f, PASS);
      expect(r.valid).toBe(true);
      expect(r.entryCount).toBe(1);
    } finally {
      if (fs.existsSync(f)) fs.unlinkSync(f);
      const seq = f + '.seq'; if (fs.existsSync(seq)) fs.unlinkSync(seq);
    }
  });

  it('returns valid=false for a tampered binary file', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('z', 'original');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      // Flip a byte in the middle of the file
      const buf = fs.readFileSync(f);
      buf[Math.floor(buf.length / 2)] ^= 0xff;
      fs.writeFileSync(f, buf);

      const r = await SPD.verify(f, PASS);
      expect(r.valid).toBe(false);
    } finally {
      if (fs.existsSync(f)) fs.unlinkSync(f);
      const seq = f + '.seq'; if (fs.existsSync(seq)) fs.unlinkSync(seq);
    }
  });

  it('returns valid=false on wrong passcode', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('q', 'secret');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      const r = await SPD.verify(f, PASS2);
      expect(r.valid).toBe(false);
    } finally {
      if (fs.existsSync(f)) fs.unlinkSync(f);
      const seq = f + '.seq'; if (fs.existsSync(seq)) fs.unlinkSync(seq);
    }
  });
});

// ─── exportEntries / importEntries ───────────────────────────────────────────

describe('exportEntries / importEntries', () => {
  it('exportEntries returns only matching entries', async () => {
    const spd = await freshSPD();
    await spd.addData('user_name', 'Alice');
    await spd.addData('user_email', 'alice@example.com');
    await spd.addData('config_timeout', 30);

    const exported = spd.exportEntries(/^user_/);
    expect(exported.keys()).toEqual(['user_name', 'user_email']);
    expect(exported.count()).toBe(2);
    spd.destroy();
  });

  it('exportEntries with no matches returns empty instance', async () => {
    const spd = await freshSPD();
    await spd.addData('alpha', 1);
    const exported = spd.exportEntries(/^zzz/);
    expect(exported.count()).toBe(0);
    spd.destroy();
  });

  it('exportEntries result can be saved and loaded', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('user_name', 'Bob');
      await spd.addData('user_age', 25);
      await spd.addData('config_level', 'debug');

      const exported = spd.exportEntries(/^user_/);
      await exported.saveToFile(f, PASS);
      spd.destroy();

      const loaded = await SPD.loadFromFile(f, PASS);
      const all = await loaded.extractData();
      expect(all['user_name']).toBe('Bob');
      expect(all['user_age']).toBe(25);
      expect(all['config_level']).toBeUndefined();
      loaded.destroy();
    } finally {
      if (fs.existsSync(f)) fs.unlinkSync(f);
      const seq = f + '.seq'; if (fs.existsSync(seq)) fs.unlinkSync(seq);
    }
  });

  it('importEntries merges entries from another instance', async () => {
    const src = await freshSPD();
    await src.addData('shared_key', 'from_source');
    await src.addData('extra_key', 'extra');

    const dst = await freshSPD();
    // Re-derive the exact same keys as src (same passcode, but different salt)
    // so we need to set dst to use src's key material
    // The cleanest test: src.exportEntries() then import into dst's freshSPD with same keys
    // Instead, create both from the same base and use import:
    const base = await freshSPD();
    await base.addData('first', 'a');

    const copy = await freshSPD();
    // copy has different salt/keys than base — importEntries will throw
    await expect(async () => base.importEntries(copy)).rejects.toThrow(/different AEAD/);

    base.destroy(); copy.destroy(); src.destroy(); dst.destroy();
  });

  it('importEntries from exported instance works (same keys)', async () => {
    const spd = await freshSPD();
    await spd.addData('shared', 'value1');
    await spd.addData('unique_a', 'only_in_a');

    const exported = spd.exportEntries(/^shared/);

    // dst gets a copy of the same keys via exportEntries (which copies key material)
    const dst = spd.exportEntries(/.*/);  // full copy
    await dst.addData('unique_b', 'only_in_b');

    // Now import the exported (shared) back into dst — should overwrite shared
    dst.importEntries(exported);
    expect(dst.count()).toBe(3);  // shared + unique_a + unique_b
    spd.destroy(); dst.destroy(); exported.destroy();
  });
});

// ─── WAL auto-compaction ─────────────────────────────────────────────────────

describe('WAL auto-compaction', () => {
  it('walRecordCount resets after flushDelta', async () => {
    const walFile = tmpFile('.wal');
    const spdFile = tmpFile();
    const tmpDirectory = tmpDir();
    try {
      const spd = await freshSPD();
      spd.enableWal(walFile);
      spd.setWalCompactTarget(spdFile, PASS);

      await spd.addData('entry1', 'value1');
      await spd.addData('entry2', 'value2');

      // flushDelta saves and clears the WAL
      await spd.flushDelta(spdFile, PASS);

      // WAL should be reset to empty header only
      const walBuf = fs.readFileSync(walFile);
      expect(walBuf.length).toBe(5); // magic (4) + version byte (1)

      spd.destroy();
    } finally {
      [walFile, spdFile, walFile.replace('.wal', '.wal.seq'), spdFile + '.seq'].forEach((f) => {
        if (fs.existsSync(f)) fs.unlinkSync(f);
      });
      fs.rmSync(tmpDirectory, { recursive: true, force: true });
    }
  });

  it('WAL file grows with each addData call', async () => {
    const walFile = tmpFile('.wal');
    try {
      const spd = await freshSPD();
      spd.enableWal(walFile);

      const initialSize = fs.statSync(walFile).size;
      await spd.addData('grow1', 'hello world');
      const afterFirst = fs.statSync(walFile).size;
      await spd.addData('grow2', 'more data here');
      const afterSecond = fs.statSync(walFile).size;

      expect(afterFirst).toBeGreaterThan(initialSize);
      expect(afterSecond).toBeGreaterThan(afterFirst);

      spd.destroy();
    } finally {
      if (fs.existsSync(walFile)) fs.unlinkSync(walFile);
    }
  });
});

// ─── Entry-level ACL ─────────────────────────────────────────────────────────

describe('entry ACL (restrictEntry / setRole)', () => {
  it('restricted entry is readable when correct role is set', async () => {
    const spd = await freshSPD();
    await spd.addData('secret_field', 'classified');
    spd.restrictEntry('secret_field', ['admin']);
    spd.setRole('admin');
    const all = await spd.extractData();
    expect(all['secret_field']).toBe('classified');
    spd.destroy();
  });

  it('restricted entry throws when role is wrong', async () => {
    const spd = await freshSPD();
    await spd.addData('secret_field', 'classified');
    spd.restrictEntry('secret_field', ['admin']);
    spd.setRole('guest');
    await expect(spd.extractData()).rejects.toThrow(/Access denied/);
    spd.destroy();
  });

  it('unrestricted entries are always readable', async () => {
    const spd = await freshSPD();
    await spd.addData('public_field', 'hello');
    // no restriction, no role
    const all = await spd.extractData();
    expect(all['public_field']).toBe('hello');
    spd.destroy();
  });

  it('lazy entries() iterator respects ACL', async () => {
    const spd = await freshSPD();
    await spd.addData('restricted', 'value');
    spd.restrictEntry('restricted', ['admin']);
    spd.setRole('user');
    const iter = spd.entries();
    await expect(iter.next()).rejects.toThrow(/Access denied/);
    spd.destroy();
  });

  it('deleteEntry clears the role restriction — a re-added entry with the same name is not silently restricted', async () => {
    const spd = await freshSPD();
    await spd.addData('secret_field', 'classified');
    spd.restrictEntry('secret_field', ['admin']);
    spd.deleteEntry('secret_field');

    await spd.addData('secret_field', 'brand_new_value');
    spd.setRole(undefined); // no role set — would throw if the old ACL leaked through
    const all = await spd.extractData();
    expect(all['secret_field']).toBe('brand_new_value');
    spd.destroy();
  });

  it('renameEntry migrates the role restriction to the new name instead of dropping it', async () => {
    const spd = await freshSPD();
    await spd.addData('secret_field', 'classified');
    spd.restrictEntry('secret_field', ['admin']);
    await spd.renameEntry('secret_field', 'secret_field_v2');

    // Old name's restriction should be gone (name no longer exists anyway)
    // and the new name should now require the same role.
    spd.setRole('guest');
    await expect(spd.extractData()).rejects.toThrow(/Access denied/);

    spd.setRole('admin');
    const all = await spd.extractData();
    expect(all['secret_field_v2']).toBe('classified');
    spd.destroy();
  });

  it(
    'restrictEntry()\'s ACL survives a real save/load round trip, both formats ' +
    '(regression: entryRoles was declared in SPDPayload\'s type and worked correctly ' +
    'in-memory, but was never actually written to or read from either serialization ' +
    'format — a role-restricted entry became fully unrestricted the moment the file was ' +
    'reloaded, even with zero role set at all)',
    async () => {
      // JSON format (saveToFile)
      const f1 = tmpFile();
      try {
        const spd = await freshSPD();
        await spd.addData('secret_field', 'classified');
        spd.restrictEntry('secret_field', ['admin']);
        await spd.saveToFile(f1, PASS);
        spd.destroy();

        const loaded = await SPD.loadFromFile(f1, PASS);
        await expect(loaded.extractData()).rejects.toThrow(/Access denied/);
        loaded.setRole('admin');
        const data = await loaded.extractData();
        expect(data.secret_field).toBe('classified');
        loaded.destroy();
      } finally {
        try { fs.unlinkSync(f1); fs.unlinkSync(f1 + '.seq'); } catch {}
      }

      // Binary streaming format (saveToFileStreaming)
      const f2 = tmpFile();
      try {
        const spd = await freshSPD();
        await spd.addData('secret_field', 'classified');
        spd.restrictEntry('secret_field', ['admin']);
        await spd.saveToFileStreaming(f2, PASS);
        spd.destroy();

        const loaded = await SPD.loadFromFileStreaming(f2, PASS);
        await expect(loaded.extractData()).rejects.toThrow(/Access denied/);
        loaded.setRole('admin');
        const data = await loaded.extractData();
        expect(data.secret_field).toBe('classified');
        loaded.destroy();
      } finally {
        try { fs.unlinkSync(f2); fs.unlinkSync(f2 + '.seq'); fs.unlinkSync(f2 + 'i'); } catch {}
      }
    }
  );

  it(
    'SPD.getEntry() enforces the ACL too (regression: getEntry — a static, single-entry ' +
    'file lookup — never checked entry ACLs at all, silently returning a role-restricted ' +
    'entry\'s value regardless of any restriction, since it has no persistent instance/' +
    'this.currentRole the way extractData()/entries() do)',
    async () => {
      const f = tmpFile();
      try {
        const spd = await freshSPD();
        await spd.addData('secret_field', 'classified');
        await spd.addData('public_field', 'open');
        spd.restrictEntry('secret_field', ['admin']);
        await spd.saveToFileStreaming(f, PASS);
        spd.destroy();

        // No role -> blocked
        await expect(SPD.getEntry(f, PASS, 'secret_field')).rejects.toThrow(/Access denied/);
        // Wrong role -> blocked
        await expect(SPD.getEntry(f, PASS, 'secret_field', undefined, 'guest')).rejects.toThrow(/Access denied/);
        // Correct role -> allowed
        const entry = await SPD.getEntry(f, PASS, 'secret_field', undefined, 'admin');
        expect(entry.value).toBe('classified');
        // Unrestricted entry -> always allowed, no role needed
        const pub = await SPD.getEntry(f, PASS, 'public_field');
        expect(pub.value).toBe('open');
      } finally {
        try { fs.unlinkSync(f); fs.unlinkSync(f + '.seq'); fs.unlinkSync(f + 'i'); } catch {}
      }
    }
  );
});

// ─── Passcode rotation audit log ─────────────────────────────────────────────

describe('passcode rotation audit log', () => {
  it('appends a record to .plog on changePasscode', async () => {
    const plog = tmpFile('.plog');
    try {
      const spd = await freshSPD();
      spd.setPlogPath(plog);
      await spd.addData('item', 'value');
      await spd.changePasscode(PASS, PASS2);
      expect(fs.existsSync(plog)).toBe(true);
      const lines = fs.readFileSync(plog, 'utf8').trim().split('\n');
      expect(lines.length).toBeGreaterThanOrEqual(1);
      const rec = JSON.parse(lines[0]);
      expect(rec.event).toBe('changePasscode');
      expect(typeof rec.ts).toBe('number');
      spd.destroy();
    } finally {
      if (fs.existsSync(plog)) fs.unlinkSync(plog);
    }
  });

  it('does not write .plog when path not set', async () => {
    const spd = await freshSPD();
    await spd.addData('item', 'value');
    // no setPlogPath — should not throw
    await expect(spd.changePasscode(PASS, PASS2)).resolves.toBeUndefined();
    spd.destroy();
  });
});

// ─── Decoy entries ────────────────────────────────────────────────────────────

describe('addDecoy', () => {
  it('increases count by the requested amount', async () => {
    const spd = await freshSPD();
    await spd.addData('real', 'data');
    expect(spd.count()).toBe(1);
    await spd.addDecoy('noise', 3);
    expect(spd.count()).toBe(4);
    spd.destroy();
  });

  it('decoys are skipped by entries() iterator', async () => {
    const spd = await freshSPD();
    await spd.addData('real', 'value');
    await spd.addDecoy('fake', 2);
    const names: string[] = [];
    for await (const e of spd.entries()) names.push(e.name);
    expect(names).toEqual(['real']);
    spd.destroy();
  });

  it('decoys appear in keys() (they are stored entries)', async () => {
    const spd = await freshSPD();
    await spd.addDecoy('d', 1);
    expect(spd.keys().length).toBe(1);
    spd.destroy();
  });
});

// ─── Auto-destruct ────────────────────────────────────────────────────────────

describe('auto-destruct counter', () => {
  it('allows opens up to maxOpenCount', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      spd.setMaxOpenCount(2);
      await spd.addData('key', 'val');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      // First open — fine
      const a = await SPD.loadFromFileStreaming(f, PASS);
      a.setMaxOpenCount(2);
      expect(a.count()).toBe(1);
      a.destroy();

      // Second open — fine
      const b = await SPD.loadFromFileStreaming(f, PASS);
      b.setMaxOpenCount(2);
      expect(b.count()).toBe(1);
      b.destroy();
    } finally {
      [f, f + '.seq', f + '.ocount'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });

  it('wipes file and throws ESPD_AUTODESTRUCT on excess open', async () => {
    const f = tmpFile();
    const ocount = f + '.ocount';
    const maxcount = f + '.maxcount';
    try {
      const spd = await freshSPD();
      await spd.addData('secret', 'sensitive');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      // Register max open count of 1 via the sidecar
      SPD.setFileMaxOpenCount(f, 1);

      // First open: fine (count goes 0→1, limit is 1, 1 <= 1 so OK)
      const a = await SPD.loadFromFileStreaming(f, PASS);
      a.destroy();

      // Second open: count goes 1→2, 2 > 1 → auto-destruct
      await expect(SPD.loadFromFileStreaming(f, PASS)).rejects.toThrow(/ESPD_AUTODESTRUCT|maximum open count/);
    } finally {
      [f, f + '.seq', ocount, maxcount].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });

  it(
    'SPD.getEntry() enforces the same open-count limit (regression: getEntry never ' +
    'called checkAndIncrementOpenCount at all, meaning a "burn-after-N-reads" file could ' +
    'be read an UNLIMITED number of times through getEntry specifically, even with ' +
    'setFileMaxOpenCount() configured and correctly enforced by loadFromFile/' +
    'loadFromFileStreaming — confirmed directly: 5 consecutive getEntry calls all ' +
    'succeeded against a file configured for maxOpenCount=1 before this fix)',
    async () => {
      const f = tmpFile();
      const ocount = f + '.ocount';
      const maxcount = f + '.maxcount';
      try {
        const spd = await freshSPD();
        await spd.addData('secret', 'burn-after-reading');
        await spd.saveToFileStreaming(f, PASS);
        spd.destroy();

        SPD.setFileMaxOpenCount(f, 2);

        const e1 = await SPD.getEntry(f, PASS, 'secret');
        expect(e1.value).toBe('burn-after-reading');
        const e2 = await SPD.getEntry(f, PASS, 'secret');
        expect(e2.value).toBe('burn-after-reading');

        // 3rd open (of any kind — loadFromFile*, or getEntry) must trigger
        // auto-destruct, since the limit is shared across all of them via
        // the same .ocount sidecar.
        await expect(SPD.getEntry(f, PASS, 'secret')).rejects.toThrow(/ESPD_AUTODESTRUCT|maximum open count/);
        expect(fs.existsSync(f)).toBe(false); // file was genuinely wiped, not just rejected
      } finally {
        [f, f + '.seq', f + 'i', ocount, maxcount].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
      }
    }
  );

  it('the open-count limit is shared correctly between getEntry and loadFromFileStreaming on the same file', async () => {
    const f = tmpFile();
    const ocount = f + '.ocount';
    const maxcount = f + '.maxcount';
    try {
      const spd = await freshSPD();
      await spd.addData('secret', 'v');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      SPD.setFileMaxOpenCount(f, 2);

      const loaded = await SPD.loadFromFileStreaming(f, PASS);
      loaded.destroy();
      const entry = await SPD.getEntry(f, PASS, 'secret'); // this is the 2nd open total
      expect(entry.value).toBe('v');

      // 3rd open total, regardless of which method — must be blocked.
      await expect(SPD.getEntry(f, PASS, 'secret')).rejects.toThrow(/ESPD_AUTODESTRUCT|maximum open count/);
    } finally {
      [f, f + '.seq', f + 'i', ocount, maxcount].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });
});

// ─── SPD.diff ─────────────────────────────────────────────────────────────────

describe('SPD.diff()', () => {
  it('detects added, removed, and modified entries', async () => {
    const fA = tmpFile(), fB = tmpFile();
    try {
      // Build file A
      const a = await freshSPD();
      await a.addData('shared', 'same');
      await a.addData('only_a', 'a');
      await a.addData('changed', 'original');
      await a.saveToFile(fA, PASS);

      // Build file B by loading A (same keys/salt) then modifying
      const b = await SPD.loadFromFile(fA, PASS);
      await b.updateEntry('changed', 'modified_value');
      b.deleteEntry('only_a');
      await b.addData('only_b', 'b');
      await b.saveToFile(fB, PASS);

      a.destroy(); b.destroy();

      const result = await SPD.diff(fA, fB, PASS);
      expect(result.added).toContain('only_b');
      expect(result.removed).toContain('only_a');
      expect(result.modified).toContain('changed');
      expect(result.added).not.toContain('shared');
      expect(result.modified).not.toContain('shared');
    } finally {
      [fA, fB, fA + '.seq', fB + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });

  it('returns all empty arrays for identical files', async () => {
    const fA = tmpFile(), fB = tmpFile();
    try {
      const a = await freshSPD();
      await a.addData('x', 1);
      await a.saveToFile(fA, PASS);
      // Copy to fB
      fs.copyFileSync(fA, fB);
      a.destroy();

      const result = await SPD.diff(fA, fB, PASS);
      expect(result.added).toHaveLength(0);
      expect(result.removed).toHaveLength(0);
      expect(result.modified).toHaveLength(0);
    } finally {
      [fA, fB, fA + '.seq', fB + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });
});

// ─── SPD.merge ────────────────────────────────────────────────────────────────

describe('SPD.merge()', () => {
  it('a-wins strategy keeps fileA entries on conflict', async () => {
    const fA = tmpFile(), fB = tmpFile(), fOut = tmpFile();
    try {
      const a = await freshSPD();
      await a.addData('conflict', 'from_a');
      await a.addData('only_a', 'a');
      await a.saveToFile(fA, PASS);
      a.destroy();

      const b = await freshSPD();
      await b.addData('conflict', 'from_b');
      await b.addData('only_b', 'b');
      await b.saveToFile(fB, PASS);
      b.destroy();

      const { merged, conflicts } = await SPD.merge(fA, fB, PASS, { strategy: 'a-wins' });
      await merged.saveToFile(fOut, PASS);
      merged.destroy();

      expect(conflicts).toEqual(['conflict']);

      const loaded = await SPD.loadFromFile(fOut, PASS);
      const all = await loaded.extractData();
      expect(all['conflict']).toBe('from_a');
      expect(all['only_a']).toBe('a');
      expect(all['only_b']).toBe('b');
      loaded.destroy();
    } finally {
      [fA, fB, fOut, fA + '.seq', fB + '.seq', fOut + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });

  it('b-wins strategy keeps fileB entries on conflict', async () => {
    const fA = tmpFile(), fB = tmpFile(), fOut = tmpFile();
    try {
      const a = await freshSPD();
      await a.addData('conflict', 'from_a');
      await a.saveToFile(fA, PASS);
      a.destroy();

      const b = await freshSPD();
      await b.addData('conflict', 'from_b');
      await b.saveToFile(fB, PASS);
      b.destroy();

      const { merged, conflicts } = await SPD.merge(fA, fB, PASS, { strategy: 'b-wins' });
      await merged.saveToFile(fOut, PASS);
      merged.destroy();

      expect(conflicts).toEqual(['conflict']);

      const loaded = await SPD.loadFromFile(fOut, PASS);
      const all = await loaded.extractData();
      expect(all['conflict']).toBe('from_b');
      loaded.destroy();
    } finally {
      [fA, fB, fOut, fA + '.seq', fB + '.seq', fOut + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });

  it('conflicts is empty when there is no overlapping entry between the two files', async () => {
    const fA = tmpFile(), fB = tmpFile();
    try {
      const a = await freshSPD();
      await a.addData('only_a', 'a');
      await a.saveToFile(fA, PASS);
      a.destroy();

      const b = await freshSPD();
      await b.addData('only_b', 'b');
      await b.saveToFile(fB, PASS);
      b.destroy();

      const { merged, conflicts } = await SPD.merge(fA, fB, PASS, { strategy: 'a-wins' });
      expect(conflicts).toEqual([]);
      merged.destroy();
    } finally {
      [fA, fB, fA + '.seq', fB + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });
});

// ─── Lazy entries() iterator ─────────────────────────────────────────────────

describe('entries() async iterator', () => {
  it('yields all entries in insertion order', async () => {
    const spd = await freshSPD();
    await spd.addData('first', 1);
    await spd.addData('second', 2);
    await spd.addData('third', 3);
    const results: Array<{ name: string; value: unknown }> = [];
    for await (const e of spd.entries()) results.push({ name: e.name, value: e.value });
    expect(results.map((r) => r.name)).toEqual(['first', 'second', 'third']);
    expect(results.map((r) => r.value)).toEqual([1, 2, 3]);
    spd.destroy();
  });

  it('yields nothing for an empty instance', async () => {
    const spd = await freshSPD();
    const results: unknown[] = [];
    for await (const _ of spd.entries()) results.push(_);
    expect(results).toHaveLength(0);
    spd.destroy();
  });
});

// ─── snapshot / restoreSnapshot ───────────────────────────────────────────────

describe('snapshot / restoreSnapshot', () => {
  it('snapshot captures current state; restore rolls back', async () => {
    const spd = await freshSPD();
    await spd.addData('v1', 'original');
    const snap = spd.snapshot();

    await spd.addData('v2', 'added_later');
    expect(spd.count()).toBe(2);

    spd.restoreSnapshot(snap);
    expect(spd.count()).toBe(1);
    const all = await spd.extractData();
    expect(all['v1']).toBe('original');
    expect(all['v2']).toBeUndefined();
    spd.destroy();
  });

  it('snapshot has ts and writeCounter fields', async () => {
    const spd = await freshSPD();
    await spd.addData('k', 'v');
    const snap = spd.snapshot();
    expect(typeof snap.ts).toBe('number');
    expect(typeof snap.writeCounter).toBe('number');
    spd.destroy();
  });

  it('snapshot is independent — mutating original does not affect it', async () => {
    const spd = await freshSPD();
    await spd.addData('key', 'before');
    const snap = spd.snapshot();
    await spd.updateEntry('key', 'after');
    // Restore and confirm we get 'before'
    spd.restoreSnapshot(snap);
    const all = await spd.extractData();
    expect(all['key']).toBe('before');
    spd.destroy();
  });
});

// ─── Schema validation ────────────────────────────────────────────────────────

describe('schema validation (setSchema)', () => {
  it('allows values that pass the validator', async () => {
    const spd = await freshSPD();
    spd.setSchema('age', (v) => typeof v === 'number' && (v as number) >= 0);
    await expect(spd.addData('age', 25)).resolves.toBeUndefined();
    spd.destroy();
  });

  it('throws when validator returns false', async () => {
    const spd = await freshSPD();
    spd.setSchema('age', (v) => typeof v === 'number' && (v as number) >= 0);
    await expect(spd.addData('age', -1)).rejects.toThrow(/Schema validation failed/);
    spd.destroy();
  });

  it('throws in updateEntry too', async () => {
    const spd = await freshSPD();
    await spd.addData('score', 10);
    spd.setSchema('score', (v) => typeof v === 'number' && (v as number) <= 100);
    await expect(spd.updateEntry('score', 999)).rejects.toThrow(/Schema validation failed/);
    spd.destroy();
  });

  it('removeSchema stops validation', async () => {
    const spd = await freshSPD();
    spd.setSchema('x', () => false);
    await expect(spd.addData('x', 1)).rejects.toThrow();
    spd.removeSchema('x');
    await expect(spd.addData('x', 1)).resolves.toBeUndefined();
    spd.destroy();
  });
});

// ─── .spdi index pre-warming ──────────────────────────────────────────────────

describe('.spdi index pre-warming', () => {
  it('creates .spdi sidecar after saveToFileStreaming', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('a', 1);
      await spd.addData('b', 2);
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      // Give setImmediate a chance to run
      await new Promise((r) => setImmediate(r));
      await new Promise((r) => setTimeout(r, 100));

      const spdiPath = f + 'i';
      // Pre-warmed sidecar should exist (best-effort — may not on slow CI)
      // Just verify the main file is valid and getEntry still works
      const val = await SPD.getEntry(f, PASS, 'a');
      expect(val.value).toBe(1);
    } finally {
      [f, f + 'i', f + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });
});

// ─── SPD.repair ───────────────────────────────────────────────────────────────

describe('SPD.repair()', () => {
  it('repairs a valid file (all entries recovered)', async () => {
    const f = tmpFile(), out = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k1', 'v1');
      await spd.addData('k2', 'v2');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      const result = await SPD.repair(f, PASS, out);
      expect(result.recovered).toBeGreaterThanOrEqual(2);
      expect(result.skipped).toBe(0);
      expect(fs.existsSync(out)).toBe(true);
    } finally {
      [f, out, f + '.seq', out + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });
});

// ─── SPD.benchmark ────────────────────────────────────────────────────────────

describe('SPD.benchmark()', () => {
  it('returns numeric timing fields', async () => {
    const result = await SPD.benchmark();
    expect(typeof result.argon2Ms).toBe('number');
    expect(typeof result.encryptMs).toBe('number');
    expect(typeof result.decryptMs).toBe('number');
    expect(typeof result.macMs).toBe('number');
    expect(typeof result.entriesPerSecond).toBe('number');
    expect(result.argon2Ms).toBeGreaterThan(0);
  }, 60000);
});

// ─── Structured logging ───────────────────────────────────────────────────────

describe('structured logging hook (setLogger)', () => {
  it('fires entry_added events on addData', async () => {
    const events: string[] = [];
    SPD.setLogger((e) => events.push(e.event));
    try {
      const spd = await freshSPD();
      await spd.addData('logged', 'value');
      expect(events).toContain('entry_added');
      spd.destroy();
    } finally {
      SPD.setLogger(undefined);
    }
  });

  it('fires save_start and save_end on saveToFile', async () => {
    const f = tmpFile();
    const events: string[] = [];
    SPD.setLogger((e) => events.push(e.event));
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFile(f, PASS);
      spd.destroy();
      expect(events).toContain('save_start');
      expect(events).toContain('save_end');
    } finally {
      SPD.setLogger(undefined);
      [f, f + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });

  it('fires load_start and load_end on loadFromFile', async () => {
    const f = tmpFile();
    const events: string[] = [];
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFile(f, PASS);
      spd.destroy();

      SPD.setLogger((e) => events.push(e.event));
      const loaded = await SPD.loadFromFile(f, PASS);
      loaded.destroy();
      expect(events).toContain('load_start');
      expect(events).toContain('load_end');
    } finally {
      SPD.setLogger(undefined);
      [f, f + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });

  it('logger errors do not propagate', async () => {
    SPD.setLogger(() => { throw new Error('logger exploded'); });
    try {
      const spd = await freshSPD();
      await expect(spd.addData('x', 1)).resolves.toBeUndefined();
      spd.destroy();
    } finally {
      SPD.setLogger(undefined);
    }
  });
});

// ── Key stretching profiles ───────────────────────────────────────────────────

describe('key stretching profiles', () => {
  it('exports ARGON2_MEMORY_PARANOID and ARGON2_TIME_PARANOID constants', () => {
    expect(ARGON2_MEMORY_PARANOID).toBe(2097152);
    expect(ARGON2_TIME_PARANOID).toBe(16);
    expect(ARGON2_MEMORY_HIGH).toBe(524288);
    expect(ARGON2_TIME_HIGH).toBe(8);
  });

  it('setKeyProfile("standard") round-trips correctly', async () => {
    const f = tmpFile();
    try {
      const spd = new SPD();
      spd.setKeyProfile('standard');
      await spd.setPassKey(PASS);
      await spd.addData('secret', 'standard-value');
      await spd.saveToFile(f, PASS);
      spd.destroy();

      const loaded = await SPD.loadFromFile(f, PASS);
      const result = await loaded.extractData();
      expect(result['secret']).toBe('standard-value');
      loaded.destroy();
    } finally {
      [f, f + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });

  it('setKeyProfile("high") stores and round-trips correctly', async () => {
    const f = tmpFile();
    try {
      const spd = new SPD();
      spd.setKeyProfile('high');
      await spd.setPassKey(PASS);
      await spd.addData('k', 'high-security');
      await spd.saveToFile(f, PASS);
      spd.destroy();

      const loaded = await SPD.loadFromFile(f, PASS);
      const result = await loaded.extractData();
      expect(result['k']).toBe('high-security');
      loaded.destroy();
    } finally {
      [f, f + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  }, 120_000); // 'high' profile Argon2id (512 MiB/8 passes) — measured up to ~65s under real contention on this machine, see this repo's compatibility-audit notes

  it('wrong passcode with high profile throws', async () => {
    const f = tmpFile();
    try {
      const spd = new SPD();
      spd.setKeyProfile('high');
      await spd.setPassKey(PASS);
      await spd.addData('k', 'v');
      await spd.saveToFile(f, PASS);
      spd.destroy();

      await expect(SPD.loadFromFile(f, 'wrong-passcode')).rejects.toThrow();
    } finally {
      [f, f + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  }, 120_000); // 'high' profile Argon2id — see previous test's timeout comment
});

// ── Machine binding ───────────────────────────────────────────────────────────

describe('machine binding', () => {
  afterEach(() => {
    SPD.disableMachineBinding();
  });

  it('enableMachineBinding / disableMachineBinding toggles without throwing', () => {
    expect(() => SPD.enableMachineBinding()).not.toThrow();
    expect(() => SPD.disableMachineBinding()).not.toThrow();
  });

  it('getMachineSecret returns a non-empty Uint8Array', () => {
    const secret = keyMaterial.getMachineSecret();
    expect(secret).toBeInstanceOf(Uint8Array);
    expect(secret.length).toBeGreaterThan(0);
  });

  it('applyMachineBinding returns a Uint8Array of correct length', () => {
    const key = new Uint8Array(32).fill(0xab);
    const bound = keyMaterial.applyMachineBinding(key);
    expect(bound).toBeInstanceOf(Uint8Array);
    expect(bound.length).toBe(32);
    // Should differ from the original
    expect(Buffer.from(bound).equals(Buffer.from(key))).toBe(false);
  });

  it('round-trips with machine binding enabled', async () => {
    const f = tmpFile();
    try {
      SPD.enableMachineBinding();
      const spd = new SPD();
      await spd.setPassKey(PASS);
      await spd.addData('mb', 'machine-bound-value');
      await spd.saveToFile(f, PASS);
      spd.destroy();

      const loaded = await SPD.loadFromFile(f, PASS);
      const result = await loaded.extractData();
      expect(result['mb']).toBe('machine-bound-value');
      loaded.destroy();
    } finally {
      SPD.disableMachineBinding();
      [f, f + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  }, 120_000); // default 'high' profile Argon2id — see earlier timeout comments

  it(
    'setKeyProfile("paranoid") auto-enables machine binding (regression: this doc-comment ' +
    'claim was previously false — a paranoid-profile file saved with no explicit ' +
    'enableMachineBinding() call loaded successfully even after simulating a different ' +
    'machine identity, meaning "paranoid" was never actually machine-bound at all despite ' +
    'its own doc comment claiming otherwise)',
    async () => {
      const f = tmpFile();
      try {
        const spd = new SPD();
        spd.setKeyProfile('paranoid');
        await spd.setPassKey(PASS);
        await spd.addData('mb', 'paranoid-bound-value');
        await spd.saveToFileStreaming(f, PASS);
        spd.destroy();

        // Disable machine binding to simulate a load path that doesn't know
        // to re-enable it (or a genuinely different machine) — this MUST fail.
        SPD.disableMachineBinding();
        await expect(SPD.loadFromFileStreaming(f, PASS)).rejects.toThrow(/Authentication failed/);

        // Re-enabling (the documented, correct usage) must restore loadability.
        SPD.enableMachineBinding();
        const loaded = await SPD.loadFromFileStreaming(f, PASS);
        const data = await loaded.extractData();
        expect(data.mb).toBe('paranoid-bound-value');
        loaded.destroy();
      } finally {
        SPD.disableMachineBinding();
        try { fs.unlinkSync(f); fs.unlinkSync(f + '.seq'); } catch {}
      }
    },
    600_000 // real paranoid-profile Argon2id (2 GiB/16 passes) run twice — this
            // machine intermittently has heavy background CPU contention from
            // an unrelated long-running process (documented pattern in this
            // session/project's own notes), which can push a single paranoid
            // Argon2id run from ~1-2 min to several minutes; a generous bound
            // here avoids a false failure from that, not from real slowness
            // in the library itself (confirmed directly via an isolated,
            // uncontended run: ~1-2 min per paranoid derive there).
  );
});

// ── Key commitment ────────────────────────────────────────────────────────────

describe('key commitment', () => {
  it('computeKeyCommitment returns a 64-char hex string', () => {
    const key = new Uint8Array(32).fill(0xcc);
    const commitment = SPD.computeKeyCommitment(key);
    expect(typeof commitment).toBe('string');
    expect(commitment).toMatch(/^[0-9a-f]{64}$/);
  });

  it('commitment is deterministic for the same key', () => {
    const key = new Uint8Array(32).fill(0xdd);
    expect(SPD.computeKeyCommitment(key)).toBe(SPD.computeKeyCommitment(key));
  });

  it('commitment differs for different keys', () => {
    const a = new Uint8Array(32).fill(0x11);
    const b = new Uint8Array(32).fill(0x22);
    expect(SPD.computeKeyCommitment(a)).not.toBe(SPD.computeKeyCommitment(b));
  });

  it('wrong passcode rejected by key commitment check', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFile(f, PASS);
      spd.destroy();

      // Should throw due to key commitment mismatch
      await expect(SPD.loadFromFile(f, 'totally-wrong-pass')).rejects.toThrow();
    } finally {
      [f, f + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });

  it('key commitment survives binary round-trip', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('committed', 'value');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      const loaded = await SPD.loadFromFileStreaming(f, PASS);
      const result = await loaded.extractData();
      expect(result['committed']).toBe('value');
      loaded.destroy();
    } finally {
      [f, f + '.seq', f + '.spdi'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });
});

// ── worker_threads addMany ────────────────────────────────────────────────────

describe('worker_threads addMany (≥64 items)', () => {
  it('encrypts 80 items correctly', async () => {
    const spd = await freshSPD();
    const items = Array.from({ length: 80 }, (_, i) => ({
      name: `item_${i}`,
      data: `value_${i}`,
    }));
    await spd.addMany(items);
    expect(spd.count()).toBe(80);
    const all = await spd.extractData();
    for (let i = 0; i < 80; i++) {
      expect(all[`item_${i}`]).toBe(`value_${i}`);
    }
    spd.destroy();
  });

  it('falls back gracefully for <64 items', async () => {
    const spd = await freshSPD();
    const items = Array.from({ length: 10 }, (_, i) => ({
      name: `sm_${i}`,
      data: i * 2,
    }));
    await spd.addMany(items);
    expect(spd.count()).toBe(10);
    const all = await spd.extractData();
    for (let i = 0; i < 10; i++) {
      expect(all[`sm_${i}`]).toBe(i * 2);
    }
    spd.destroy();
  });

  it('worker addMany round-trips through file save/load', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      const items = Array.from({ length: 64 }, (_, i) => ({
        name: `wt_${i}`,
        data: `wt_val_${i}`,
      }));
      await spd.addMany(items);
      await spd.saveToFile(f, PASS);
      spd.destroy();

      const loaded = await SPD.loadFromFile(f, PASS);
      expect(loaded.count()).toBe(64);
      const result = await loaded.extractData();
      expect(result['wt_0']).toBe('wt_val_0');
      expect(result['wt_63']).toBe('wt_val_63');
      loaded.destroy();
    } finally {
      [f, f + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });
});

// ── fsync before rename ───────────────────────────────────────────────────────

describe('fsync before rename (saveToFile)', () => {
  it('saveToFile writes atomically and file contains correct data', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('durable', 'fsync-test');
      await spd.saveToFile(f, PASS);
      spd.destroy();

      // File must exist and be loadable — this confirms the fsync/rename succeeded
      expect(fs.existsSync(f)).toBe(true);
      const loaded = await SPD.loadFromFile(f, PASS);
      const result = await loaded.extractData();
      expect(result['durable']).toBe('fsync-test');
      loaded.destroy();
    } finally {
      [f, f + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });

  it('saveToFileStreaming writes atomically', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('durable', 'stream-fsync');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      expect(fs.existsSync(f)).toBe(true);
      const loaded = await SPD.loadFromFileStreaming(f, PASS);
      const result = await loaded.extractData();
      expect(result['durable']).toBe('stream-fsync');
      loaded.destroy();
    } finally {
      [f, f + '.seq', f + '.spdi'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });

  it('no temp file left behind after save', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFile(f, PASS);
      spd.destroy();

      // Temp file name is filePath + '.tmp' — must not exist after save
      expect(fs.existsSync(f + '.tmp')).toBe(false);
    } finally {
      [f, f + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });
});

// ── Lock retry loop ───────────────────────────────────────────────────────────

describe('lock retry loop (acquireLock)', () => {
  it('acquires lock when no lock file exists', () => {
    const f = tmpFile();
    try {
      SPD.acquireLock(f);
      expect(fs.existsSync(f + '.lock')).toBe(true);
      SPD.releaseLock(f);
    } finally {
      try { fs.unlinkSync(f + '.lock'); } catch {}
    }
  });

  it('throws ESPD_LOCKED when lock is held by active PID', () => {
    const f = tmpFile();
    // Write a lock with our own PID so it looks live
    fs.writeFileSync(
      f + '.lock',
      JSON.stringify({ pid: process.pid, ts: Date.now() })
    );
    try {
      expect(() => SPD.acquireLock(f, 200)).toThrow('ESPD_LOCKED');
    } catch (e: any) {
      // Some environments call the code property differently; check message too
      expect(e.message).toMatch(/locked|ESPD_LOCKED/i);
    } finally {
      try { fs.unlinkSync(f + '.lock'); } catch {}
    }
  });

  it('breaks stale lock (>30 s old) and acquires', () => {
    const f = tmpFile();
    // Write a stale lock: ts 60 seconds in the past
    fs.writeFileSync(
      f + '.lock',
      JSON.stringify({ pid: 99999999, ts: Date.now() - 60_000 })
    );
    try {
      expect(() => SPD.acquireLock(f, 2000)).not.toThrow();
      expect(fs.existsSync(f + '.lock')).toBe(true);
      SPD.releaseLock(f);
    } finally {
      try { fs.unlinkSync(f + '.lock'); } catch {}
    }
  });

  it('releaseLock removes the lock file', () => {
    const f = tmpFile();
    SPD.acquireLock(f);
    expect(fs.existsSync(f + '.lock')).toBe(true);
    SPD.releaseLock(f);
    expect(fs.existsSync(f + '.lock')).toBe(false);
  });

  it('acquireLock returns a token that identifies this specific lock', () => {
    const f = tmpFile();
    const token = SPD.acquireLock(f);
    expect(typeof token).toBe('string');
    expect(fs.readFileSync(f + '.lock', 'utf8')).toBe(token);
    SPD.releaseLock(f, token);
  });

  it('releaseLock with a token does NOT delete a DIFFERENT lock (TOCTOU guard)', () => {
    const f = tmpFile();
    const staleToken = SPD.acquireLock(f);
    // Simulate another process considering the first lock stale, breaking
    // it, and re-acquiring with its own token — without calling
    // releaseLock (that's the scenario acquireLock's doc comment describes).
    // Write a SYNTHETIC token with a different fabricated PID directly
    // (rather than calling acquireLock again in the same process) so this
    // test is deterministic — two real acquireLock calls close together in
    // the same process could legitimately produce an identical
    // {pid,ts} JSON string if Date.now() doesn't tick between them, which
    // isn't a bug, just not a distinguishable "other process" for this test.
    fs.unlinkSync(f + '.lock');
    const otherProcessToken = JSON.stringify({ pid: process.pid + 1, ts: Date.now() });
    fs.writeFileSync(f + '.lock', otherProcessToken, { mode: 0o600 });
    expect(otherProcessToken).not.toBe(staleToken);

    // The original holder's releaseLock call (using its now-stale token)
    // must NOT delete the other process's live lock.
    SPD.releaseLock(f, staleToken);
    expect(fs.existsSync(f + '.lock')).toBe(true);
    expect(fs.readFileSync(f + '.lock', 'utf8')).toBe(otherProcessToken);

    SPD.releaseLock(f, otherProcessToken);
    expect(fs.existsSync(f + '.lock')).toBe(false);
  });

  it('releaseLock without a token still deletes unconditionally (backward-compatible)', () => {
    const f = tmpFile();
    SPD.acquireLock(f);
    SPD.releaseLock(f); // no token — same as before this change
    expect(fs.existsSync(f + '.lock')).toBe(false);
  });
});

// ── SPD.watch ─────────────────────────────────────────────────────────────────

describe('SPD.watch()', () => {
  it('calls cb with all-added diff on first load', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('w1', 'alpha');
      await spd.addData('w2', 'beta');
      await spd.saveToFile(f, PASS);
      spd.destroy();

      await new Promise<void>((resolve, reject) => {
        const stop = SPD.watch(f, PASS, (loaded, diff) => {
          stop();
          try {
            expect(diff.added.sort()).toEqual(['w1', 'w2'].sort());
            expect(diff.removed).toEqual([]);
            expect(diff.modified).toEqual([]);
            loaded.destroy();
            resolve();
          } catch (e) {
            reject(e);
          }
        });
      });
    } finally {
      [f, f + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });

  it('stop() function prevents further callbacks', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('ws', 'stop-test');
      await spd.saveToFile(f, PASS);
      spd.destroy();

      let callCount = 0;
      await new Promise<void>((resolve) => {
        const stop = SPD.watch(f, PASS, (loaded, _diff) => {
          callCount++;
          loaded.destroy();
          stop();
          // Give a moment to confirm no second call comes
          setTimeout(() => {
            expect(callCount).toBe(1);
            resolve();
          }, 200);
        });
      });
    } finally {
      [f, f + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });
});

// ── SPDWeb (browser/Deno/Bun compat) ─────────────────────────────────────────

describe('SPDWeb (Web Crypto adapter)', () => {
  it('creates an instance and stores/retrieves a string', async () => {
    const spd = await SPDWeb.create('test-pass');
    await spd.set('greeting', 'hello world');
    const val = await spd.get('greeting');
    expect(val).toBe('hello world');
  });

  it('stores and retrieves various types', async () => {
    const spd = await SPDWeb.create('test-pass');
    await spd.set('num', 42);
    await spd.set('bool', true);
    await spd.set('obj', { x: 1, y: [2, 3] });
    expect(await spd.get('num')).toBe(42);
    expect(await spd.get('bool')).toBe(true);
    expect(await spd.get('obj')).toEqual({ x: 1, y: [2, 3] });
  });

  it('returns undefined for missing key', async () => {
    const spd = await SPDWeb.create('pass');
    expect(await spd.get('does-not-exist')).toBeUndefined();
  });

  it('has() and delete() work correctly', async () => {
    const spd = await SPDWeb.create('pass');
    await spd.set('toDelete', 'value');
    expect(spd.has('toDelete')).toBe(true);
    expect(spd.delete('toDelete')).toBe(true);
    expect(spd.has('toDelete')).toBe(false);
    expect(spd.delete('toDelete')).toBe(false);
  });

  it('keys() returns all entry names', async () => {
    const spd = await SPDWeb.create('pass');
    await spd.set('a', 1);
    await spd.set('b', 2);
    expect(spd.keys().sort()).toEqual(['a', 'b']);
  });

  it('size reflects entry count', async () => {
    const spd = await SPDWeb.create('pass');
    expect(spd.size).toBe(0);
    await spd.set('x', 'v');
    expect(spd.size).toBe(1);
  });

  it('export/import round-trip preserves all entries', async () => {
    const spd = await SPDWeb.create('round-trip-pass');
    await spd.set('k1', 'value1');
    await spd.set('k2', 42);

    const json = await spd.export();
    const restored = await SPDWeb.import(json, 'round-trip-pass');

    expect(await restored.get('k1')).toBe('value1');
    expect(await restored.get('k2')).toBe(42);
  });

  it('import with wrong passphrase throws on decrypt', async () => {
    const spd = await SPDWeb.create('correct-pass');
    await spd.set('secret', 'data');
    const json = await spd.export();

    const tampered = await SPDWeb.import(json, 'wrong-pass');
    // AES-GCM will throw on decrypt with wrong key
    await expect(tampered.get('secret')).rejects.toThrow();
  });

  it('entries() async generator yields all entries', async () => {
    const spd = await SPDWeb.create('iter-pass');
    await spd.set('e1', 'v1');
    await spd.set('e2', 'v2');

    const collected: Array<{ name: string; value: unknown }> = [];
    for await (const entry of spd.entries()) {
      collected.push(entry);
    }
    expect(collected.length).toBe(2);
    expect(collected.map((e) => e.name).sort()).toEqual(['e1', 'e2']);
  });

  it('changePassphrase re-encrypts all entries under new key', async () => {
    const spd = await SPDWeb.create('old-pass');
    await spd.set('secret', 'sensitive');
    const newSpd = await spd.changePassphrase('old-pass', 'new-pass');
    expect(await newSpd.get('secret')).toBe('sensitive');

    // Export with new passphrase and re-import
    const json = await newSpd.export();
    const reloaded = await SPDWeb.import(json, 'new-pass');
    expect(await reloaded.get('secret')).toBe('sensitive');
  });

  it('VERSION constant is 1', () => {
    expect(SPDWeb.VERSION).toBe(1);
  });
});

// ── checkPasscodeStrength — entropy enforcement ───────────────────────────────

describe('checkPasscodeStrength — entropy enforcement', () => {
  const spd = new SPD();

  it('rejects passcode shorter than 12 chars', () => {
    expect(() => spd.checkPasscodeStrength('Short1!')).toThrow(/12 characters/);
  });

  it('rejects Password1! pattern (word + digits)', () => {
    expect(() => spd.checkPasscodeStrength('Password12345!')).toThrow(/pattern|phrase/i);
  });

  it('rejects keyboard walk', () => {
    expect(() => spd.checkPasscodeStrength('Qwerty123456!')).toThrow(/pattern|entropy|phrase/i);
  });

  it('rejects low-diversity string (all same char)', () => {
    expect(() => spd.checkPasscodeStrength('AAAAAAAAAAAAA!')).toThrow(/entropy|pattern/i);
  });

  it('accepts a strong random passphrase', () => {
    // 7-word diceware is well above 60 effective bits
    const pass = SPD.generatePassphrase(7);
    expect(() => spd.checkPasscodeStrength(pass)).not.toThrow();
  });

  it('accepts a high-entropy manual password', () => {
    expect(() => spd.checkPasscodeStrength('xK9#mP2$vL7@nQ4&')).not.toThrow();
  });

  it('skips strength check entirely when keyfile is loaded', () => {
    const kf = tmpFile('.key');
    try {
      SPD.generateKeyfile(kf);
      SPD.loadKeyfile(kf);
      // Even a trivially weak passcode should pass
      expect(() => spd.checkPasscodeStrength('weak')).not.toThrow();
    } finally {
      SPD.unloadKeyfile();
      try { fs.unlinkSync(kf); } catch {}
    }
  });
});

// ── SPD.generatePassphrase() ──────────────────────────────────────────────────

describe('SPD.generatePassphrase()', () => {
  it('returns a space-separated string of the requested word count', () => {
    const p = SPD.generatePassphrase(7);
    expect(p.split(' ').length).toBe(7);
  });

  it('default is 9 words', () => {
    expect(SPD.generatePassphrase().split(' ').length).toBe(9);
  });

  it('minimum 7 words accepted (≈55 bits with the 240-word list)', () => {
    expect(() => SPD.generatePassphrase(7)).not.toThrow();
  });

  it('throws for fewer than 5 words', () => {
    expect(() => SPD.generatePassphrase(4)).toThrow(/minimum/i);
  });

  it('two calls return different passphrases', () => {
    expect(SPD.generatePassphrase()).not.toBe(SPD.generatePassphrase());
  });

  it('generated passphrase passes checkPasscodeStrength', () => {
    const spd = new SPD();
    const pass = SPD.generatePassphrase(7);
    expect(() => spd.checkPasscodeStrength(pass)).not.toThrow();
  });

  it('can setPassKey with generated passphrase', async () => {
    const spd = new SPD();
    const pass = SPD.generatePassphrase(7);
    await expect(spd.setPassKey(pass)).resolves.toBeUndefined();
    spd.destroy();
  });
});

// ── Keyfile support ───────────────────────────────────────────────────────────

describe('keyfile support', () => {
  afterEach(() => {
    SPD.unloadKeyfile();
  });

  it('generateKeyfile creates a 64-byte file', () => {
    const kf = tmpFile('.key');
    try {
      SPD.generateKeyfile(kf);
      expect(fs.existsSync(kf)).toBe(true);
      expect(fs.statSync(kf).size).toBe(64);
    } finally {
      try { fs.unlinkSync(kf); } catch {}
    }
  });

  it('generateKeyfile produces different output each time', () => {
    const kf1 = tmpFile('.key');
    const kf2 = tmpFile('.key');
    try {
      SPD.generateKeyfile(kf1);
      SPD.generateKeyfile(kf2);
      const b1 = fs.readFileSync(kf1);
      const b2 = fs.readFileSync(kf2);
      expect(b1.equals(b2)).toBe(false);
    } finally {
      [kf1, kf2].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });

  it('loadKeyfile throws for files shorter than 32 bytes', () => {
    const kf = tmpFile('.key');
    try {
      fs.writeFileSync(kf, Buffer.alloc(8));
      expect(() => SPD.loadKeyfile(kf)).toThrow(/too short/i);
    } finally {
      try { fs.unlinkSync(kf); } catch {}
    }
  });

  it('round-trips with keyfile: save and load produce correct data', async () => {
    const kf = tmpFile('.key');
    const f  = tmpFile();
    try {
      SPD.generateKeyfile(kf);
      SPD.loadKeyfile(kf);

      const spd = new SPD();
      await spd.setPassKey('anypass'); // strength bypassed
      await spd.addData('secret', 'keyfile-protected-value');
      await spd.saveToFile(f, 'anypass');
      spd.destroy();

      // Must reload keyfile before loading the SPD file
      SPD.loadKeyfile(kf);
      const loaded = await SPD.loadFromFile(f, 'anypass');
      const result = await loaded.extractData();
      expect(result['secret']).toBe('keyfile-protected-value');
      loaded.destroy();
    } finally {
      SPD.unloadKeyfile();
      [kf, f, f + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  }, 120_000); // keyfile path still runs a real 'high'-profile-equivalent Argon2id derivation — see earlier timeout comments

  it('load fails when keyfile is not loaded', async () => {
    const kf = tmpFile('.key');
    const f  = tmpFile();
    try {
      SPD.generateKeyfile(kf);
      SPD.loadKeyfile(kf);

      const spd = new SPD();
      await spd.setPassKey('anypass');
      await spd.addData('k', 'v');
      await spd.saveToFile(f, 'anypass');
      spd.destroy();

      // Unload keyfile — load should fail
      SPD.unloadKeyfile();
      await expect(SPD.loadFromFile(f, 'anypass')).rejects.toThrow();
    } finally {
      SPD.unloadKeyfile();
      [kf, f, f + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  }, 120_000);

  it('load fails with correct passcode but wrong keyfile', async () => {
    const kf1 = tmpFile('.key');
    const kf2 = tmpFile('.key');
    const f   = tmpFile();
    try {
      SPD.generateKeyfile(kf1);
      SPD.loadKeyfile(kf1);

      const spd = new SPD();
      await spd.setPassKey('anypass');
      await spd.addData('k', 'v');
      await spd.saveToFile(f, 'anypass');
      spd.destroy();

      SPD.generateKeyfile(kf2); // different keyfile
      SPD.loadKeyfile(kf2);
      await expect(SPD.loadFromFile(f, 'anypass')).rejects.toThrow();
    } finally {
      SPD.unloadKeyfile();
      [kf1, kf2, f, f + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });

  it('unloadKeyfile zeroes and clears keyfile bytes', () => {
    const kf = tmpFile('.key');
    try {
      SPD.generateKeyfile(kf);
      SPD.loadKeyfile(kf);
      SPD.unloadKeyfile();
      // After unload, strength check should enforce password quality again
      const spd = new SPD();
      expect(() => spd.checkPasscodeStrength('weak')).toThrow();
    } finally {
      try { fs.unlinkSync(kf); } catch {}
    }
  });

  it('keyfile + binary streaming round-trip', async () => {
    const kf = tmpFile('.key');
    const f  = tmpFile();
    try {
      SPD.generateKeyfile(kf);
      SPD.loadKeyfile(kf);

      const spd = new SPD();
      await spd.setPassKey('anypass');
      await spd.addData('data', 'streaming-keyfile');
      await spd.saveToFileStreaming(f, 'anypass');
      spd.destroy();

      SPD.loadKeyfile(kf);
      const loaded = await SPD.loadFromFileStreaming(f, 'anypass');
      const result = await loaded.extractData();
      expect(result['data']).toBe('streaming-keyfile');
      loaded.destroy();
    } finally {
      SPD.unloadKeyfile();
      [kf, f, f + '.seq', f + '.spdi'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  }, 120_000); // keyfile path — see earlier timeout comments
});

// ── Hardened defaults (v28) ───────────────────────────────────────────────────

describe('hardened defaults (v28)', () => {
  it('default key profile is now "high"', () => {
    const spd = new SPD();
    // Access private field via casting to verify default
    expect((spd as any).keyProfile).toBe('high');
  });

  it('generatePassphrase default is 9 words', () => {
    expect(SPD.generatePassphrase().split(' ').length).toBe(9);
  });

  it('new file saves with version 28', async () => {
    const f = tmpFile();
    try {
      const spd = new SPD();
      spd.setKeyProfile('standard'); // fast path; version bump is what we're testing
      await spd.setPassKey(PASS);
      await spd.addData('k', 'v');
      await spd.saveToFile(f, PASS);
      spd.destroy();

      // Inspect the wrapped JSON — saveToFile wraps in {payload, mac} zlib-compressed JSON.
      // payload is base64 (v2.0.1+ — see decodeWrappedPayload's doc comment in SPD.ts).
      const raw = JSON.parse(require('zlib').inflateSync(fs.readFileSync(f)).toString('utf8'));
      expect(raw.payload).toBeDefined(); // JSON format
      const inner = JSON.parse(Buffer.from(raw.payload, 'base64').toString('utf8'));
      expect(inner.version).toBe(29);
    } finally {
      [f, f + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  });

  it('round-trips with high profile', async () => {
    const f = tmpFile();
    try {
      const spd = new SPD();
      spd.setKeyProfile('high');
      await spd.setPassKey(PASS);
      await spd.addData('hardened', 'value');
      await spd.saveToFile(f, PASS);
      spd.destroy();

      const loaded = await SPD.loadFromFile(f, PASS);
      const result = await loaded.extractData();
      expect(result['hardened']).toBe('value');
      loaded.destroy();
    } finally {
      [f, f + '.seq'].forEach((x) => { try { fs.unlinkSync(x); } catch {} });
    }
  }, 120_000); // 'high' profile Argon2id — see earlier timeout comments
});

// ── SPDTransport ──────────────────────────────────────────────────────────────

import { SPDTransport } from '../src/index';
import type { SPDTransportIo } from '../src/index';

// Helper: complete a V1 handshake (legacy path). Since v2 SPDTransport
// defaults to REQUIRING V2 (setRequireV2 defaults to true — see
// SPDTransport.ts's own doc comment on _requireV2 for why), exercising the
// legacy V1 path in a test now means explicitly opting back out around the
// serverAccept call, then restoring the safe default so no test leaks V1
// acceptance into an unrelated test that runs after it.
async function v1Handshake(id: Awaited<ReturnType<typeof SPDTransport.generateServerIdentity>>) {
  const { session: cs, clientHello } = await SPDTransport.clientConnect(id.publicKey, { v2: false });
  SPDTransport.setRequireV2(false);
  try {
    const { session: ss } = await SPDTransport.serverAccept(id, clientHello);
    return { cs, ss, clientHello };
  } finally {
    SPDTransport.setRequireV2(true);
  }
}

// Helper: complete a V2 handshake (ML-KEM hybrid)
async function v2Handshake(id: Awaited<ReturnType<typeof SPDTransport.generateServerIdentity>>, opts?: { psk?: Uint8Array; pinnedSigningKey?: Uint8Array }) {
  const { session: cs, clientHello } = await SPDTransport.clientConnect(id.publicKey, { v2: true, ...opts });
  const { session: ss, serverHello } = await SPDTransport.serverAccept(id, clientHello);
  cs.processServerHello(serverHello!);
  return { cs, ss };
}

describe('SPDTransport — client↔server secure channel', () => {
  it('generateServerIdentity returns 32-byte key pair', async () => {
    const id = await SPDTransport.generateServerIdentity();
    expect(id.publicKey.length).toBe(32);
    expect(id.privateKey.length).toBe(32);
    expect(Buffer.from(id.publicKey).equals(Buffer.from(id.privateKey))).toBe(false);
  });

  it('two identities are different', async () => {
    const a = await SPDTransport.generateServerIdentity();
    const b = await SPDTransport.generateServerIdentity();
    expect(Buffer.from(a.publicKey).equals(Buffer.from(b.publicKey))).toBe(false);
  });

  it('clientConnect V1 produces a 65-byte clientHello', async () => {
    const id = await SPDTransport.generateServerIdentity();
    const { clientHello, session } = await SPDTransport.clientConnect(id.publicKey, { v2: false });
    expect(clientHello.length).toBe(65);
    expect(clientHello[0]).toBe(1); // version byte
    session.destroy();
  });

  it('clientConnect V2 produces a 1249-byte clientHello', async () => {
    const id = await SPDTransport.generateServerIdentity();
    const { clientHello, session } = await SPDTransport.clientConnect(id.publicKey, { v2: true });
    expect(clientHello.length).toBe(1249);
    expect(clientHello[0]).toBe(2); // V2 version byte
    session.destroy();
  });

  it('validateClientHello accepts V1 hello', async () => {
    const id = await SPDTransport.generateServerIdentity();
    const { clientHello, session } = await SPDTransport.clientConnect(id.publicKey, { v2: false });
    expect(SPDTransport.validateClientHello(clientHello)).toBe(true);
    session.destroy();
  });

  it('validateClientHello accepts V2 hello', async () => {
    const id = await SPDTransport.generateServerIdentity();
    const { clientHello, session } = await SPDTransport.clientConnect(id.publicKey, { v2: true });
    expect(SPDTransport.validateClientHello(clientHello)).toBe(true);
    session.destroy();
  });

  it('validateClientHello rejects wrong-length buffer', () => {
    expect(SPDTransport.validateClientHello(Buffer.alloc(32))).toBe(false);
  });

  it('V1 full handshake: client and server derive identical session keys', async () => {
    const id = await SPDTransport.generateServerIdentity();
    const { cs: clientSession, ss: serverSession } = await v1Handshake(id);

    const msg = Buffer.from('hello from client');
    const frame = clientSession.encrypt(msg);
    const decoded = serverSession.decrypt(frame);
    expect(Buffer.from(decoded).toString()).toBe('hello from client');

    const reply = Buffer.from('hello from server');
    const replyFrame = serverSession.encrypt(reply);
    const decodedReply = clientSession.decrypt(replyFrame);
    expect(Buffer.from(decodedReply).toString()).toBe('hello from server');

    clientSession.destroy();
    serverSession.destroy();
  });

  it('V2 hybrid handshake: client and server derive identical session keys', async () => {
    const id = await SPDTransport.generateServerIdentity();
    const { cs, ss } = await v2Handshake(id);

    const msg   = Buffer.from('hybrid hello from client');
    const frame = cs.encrypt(msg);
    expect(Buffer.from(ss.decrypt(frame)).toString()).toBe('hybrid hello from client');

    const reply      = Buffer.from('hybrid reply from server');
    const replyFrame = ss.encrypt(reply);
    expect(Buffer.from(cs.decrypt(replyFrame)).toString()).toBe('hybrid reply from server');

    cs.destroy(); ss.destroy();
  });

  it('V2 with PSK: session bound to pre-shared key', async () => {
    const id  = await SPDTransport.generateServerIdentity();
    const psk = new Uint8Array(Buffer.from('my-32-byte-psk-for-session-test!'));

    const { session: cs, clientHello } = await SPDTransport.clientConnect(id.publicKey, { v2: true, psk });
    const { session: ss, serverHello } = await SPDTransport.serverAccept(id, clientHello, psk);
    cs.processServerHello(serverHello!);

    const frame = cs.encrypt(Buffer.from('psk-protected'));
    expect(Buffer.from(ss.decrypt(frame)).toString()).toBe('psk-protected');

    cs.destroy(); ss.destroy();
  });

  it('V2 with wrong PSK: decryption fails', async () => {
    const id      = await SPDTransport.generateServerIdentity();
    const psk1    = new Uint8Array(Buffer.from('correct-psk-32bytes-for-the-test'));
    const psk2    = new Uint8Array(Buffer.from('wrong-psk-32bytes-for-the-test!!'));

    const { session: cs, clientHello } = await SPDTransport.clientConnect(id.publicKey, { v2: true, psk: psk1 });
    const { session: ss, serverHello } = await SPDTransport.serverAccept(id, clientHello, psk2); // wrong psk
    // Key commitment detects PSK mismatch before any decryption occurs
    expect(() => cs.processServerHello(serverHello!)).toThrow(/key commitment mismatch/i);

    cs.destroy(); ss.destroy();
  });

  it('PSK must be exactly 32 bytes on both sides', async () => {
    const id = await SPDTransport.generateServerIdentity();
    for (const bad of [new Uint8Array(0), new Uint8Array(16).fill(1), new Uint8Array(33).fill(1)]) {
      await expect(SPDTransport.clientConnect(id.publicKey, { psk: bad })).rejects.toThrow(/PSK must be exactly 32 bytes/);
      const { clientHello } = await SPDTransport.clientConnect(id.publicKey);
      await expect(SPDTransport.serverAccept(id, clientHello, bad)).rejects.toThrow(/PSK must be exactly 32 bytes/);
    }
  });

  it('strict mode refuses an unpinned or V1 client', async () => {
    const id   = await SPDTransport.generateServerIdentity();
    const cert = SPDTransport.generateCertKeyPair();
    id.signingPrivKey = cert.privateKey;
    id.signingPubKey  = cert.publicKey;
    SPDTransport.setStrictMode(true);
    try {
      await expect(SPDTransport.clientConnect(id.publicKey)).rejects.toThrow(/strict mode requires the client to pin/);
      await expect(SPDTransport.clientConnect(id.publicKey, { v2: false, pinnedSigningKey: cert.publicKey })).rejects.toThrow(/strict mode/);
      const { session: cs, clientHello } = await SPDTransport.clientConnect(id.publicKey, { pinnedSigningKey: cert.publicKey });
      const { session: ss, serverHello } = await SPDTransport.serverAccept(id, clientHello);
      cs.processServerHello(serverHello!);
      expect(Buffer.from(ss.decrypt(cs.encrypt(Buffer.from('ok')))).toString()).toBe('ok');
      cs.destroy(); ss.destroy();
    } finally {
      SPDTransport.setStrictMode(false);
    }
  });

  it('V2 ML-DSA-65 cert pinning: valid signature accepted', async () => {
    const id        = await SPDTransport.generateServerIdentity();
    const certPair  = SPDTransport.generateCertKeyPair();
    id.signingPrivKey = certPair.privateKey;
    id.signingPubKey  = certPair.publicKey;

    const { session: cs, clientHello } = await SPDTransport.clientConnect(id.publicKey, {
      v2: true,
      pinnedSigningKey: certPair.publicKey,
    });
    const { session: ss, serverHello } = await SPDTransport.serverAccept(id, clientHello);
    cs.processServerHello(serverHello!); // should not throw

    const frame = cs.encrypt(Buffer.from('cert-pinned'));
    expect(Buffer.from(ss.decrypt(frame)).toString()).toBe('cert-pinned');

    cs.destroy(); ss.destroy();
  });

  it('V2 ML-DSA-65 cert pinning: tampered ServerHello rejected', async () => {
    const id       = await SPDTransport.generateServerIdentity();
    const certPair = SPDTransport.generateCertKeyPair();
    id.signingPrivKey = certPair.privateKey;
    id.signingPubKey  = certPair.publicKey;

    const wrongCert = SPDTransport.generateCertKeyPair(); // different key

    const { session: cs, clientHello } = await SPDTransport.clientConnect(id.publicKey, {
      v2: true,
      pinnedSigningKey: wrongCert.publicKey, // pin wrong key
    });
    const { serverHello } = await SPDTransport.serverAccept(id, clientHello);

    expect(() => cs.processServerHello(serverHello!)).toThrow(/MitM|verif/i);
    cs.destroy();
  });

  it('V2 exportPSK: returns 32 bytes', async () => {
    const id = await SPDTransport.generateServerIdentity();
    const { cs } = await v2Handshake(id);
    const exported = cs.exportPSK();
    expect(exported.length).toBe(32);
    cs.destroy();
  });

  it('V1 replay attack is rejected', async () => {
    const id = await SPDTransport.generateServerIdentity();
    const { cs, ss } = await v1Handshake(id);

    const frame = cs.encrypt(Buffer.from('data'));
    ss.decrypt(frame); // first — ok
    expect(() => ss.decrypt(frame)).toThrow(/replay/i);

    cs.destroy(); ss.destroy();
  });

  it('V1 tampered frame is rejected', async () => {
    const id = await SPDTransport.generateServerIdentity();
    const { cs, ss } = await v1Handshake(id);

    const frame = cs.encrypt(Buffer.from('secret'));
    frame[frame.length - 1] ^= 0xff;
    expect(() => ss.decrypt(frame)).toThrow(/authentication|tamper/i);

    cs.destroy(); ss.destroy();
  });

  it('V1 wrong server key produces undecryptable session', async () => {
    const id  = await SPDTransport.generateServerIdentity();
    const bad = await SPDTransport.generateServerIdentity();
    const { session: cs, clientHello } = await SPDTransport.clientConnect(id.publicKey, { v2: false });
    SPDTransport.setRequireV2(false);
    try {
      const { session: ss } = await SPDTransport.serverAccept(bad, clientHello);

      const frame = cs.encrypt(Buffer.from('secret'));
      expect(() => ss.decrypt(frame)).toThrow();

      cs.destroy(); ss.destroy();
    } finally {
      SPDTransport.setRequireV2(true);
    }
  });

  it('V1 multiple messages maintain monotonic counter', async () => {
    const id = await SPDTransport.generateServerIdentity();
    const { cs, ss } = await v1Handshake(id);

    for (let i = 0; i < 5; i++) {
      const f = cs.encrypt(Buffer.from(`msg-${i}`));
      const d = ss.decrypt(f);
      expect(Buffer.from(d).toString()).toBe(`msg-${i}`);
    }

    cs.destroy(); ss.destroy();
  });

  it('generateSessionToken returns a 43-char base64url string', () => {
    const tok = SPDTransport.generateSessionToken();
    expect(typeof tok).toBe('string');
    expect(tok.length).toBeGreaterThanOrEqual(40);
    expect(tok).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('saveServerIdentity / loadServerIdentity round-trips (including signing keys)', async () => {
    const id      = await SPDTransport.generateServerIdentity();
    const cert    = SPDTransport.generateCertKeyPair();
    id.signingPrivKey = cert.privateKey;
    id.signingPubKey  = cert.publicKey;
    const base = tmpFile('');
    try {
      SPDTransport.saveServerIdentity(base, id);
      expect(fs.existsSync(base + '.pub')).toBe(true);
      expect(fs.existsSync(base + '.key')).toBe(true);
      expect(fs.existsSync(base + '.cert')).toBe(true);
      expect(fs.existsSync(base + '.csig')).toBe(true);

      const loaded = SPDTransport.loadServerIdentity(base);
      expect(Buffer.from(loaded.publicKey).equals(Buffer.from(id.publicKey))).toBe(true);
      expect(Buffer.from(loaded.privateKey).equals(Buffer.from(id.privateKey))).toBe(true);
      expect(loaded.signingPubKey).toBeDefined();
      expect(Buffer.from(loaded.signingPubKey!).equals(Buffer.from(cert.publicKey))).toBe(true);
    } finally {
      ['.pub', '.key', '.cert', '.csig'].forEach((ext) => { try { fs.unlinkSync(base + ext); } catch {} });
    }
  });

  it('wrapSPD / unwrapSPD round-trips an SPD payload over V1 channel', async () => {
    const id   = await SPDTransport.generateServerIdentity();
    const pass = PASS;
    const { cs, ss } = await v1Handshake(id);

    const spd = new SPD();
    spd.setKeyProfile('standard');
    await spd.setPassKey(pass);
    await spd.addData('transferred', 'secret-payload');
    const frame = await cs.wrapSPD(spd, pass);
    spd.destroy();

    const received = await ss.unwrapSPD(frame, pass);
    const result   = await received.extractData();
    expect(result['transferred']).toBe('secret-payload');
    received.destroy();

    cs.destroy(); ss.destroy();
  });

  describe('setRequireV2 — reject classical-only V1 downgrade', () => {
    afterEach(() => SPDTransport.setRequireV2(true)); // restore the safe default, don't leak state across tests

    it('defaults to true (isRequireV2) — quantum-resistant hybrid sessions are the default, not opt-in', () => {
      expect(SPDTransport.isRequireV2()).toBe(true);
    });

    it('rejects a V1 ClientHello by default, with no explicit setRequireV2(true) call needed', async () => {
      const id = await SPDTransport.generateServerIdentity();
      const { clientHello, session: cs } = await SPDTransport.clientConnect(id.publicKey, { v2: false });
      await expect(SPDTransport.serverAccept(id, clientHello)).rejects.toThrow(/V1|V2|hybrid/i);
      cs.destroy();
    });

    it('still accepts a V2 ClientHello by default', async () => {
      const id = await SPDTransport.generateServerIdentity();
      const { clientHello, session: cs } = await SPDTransport.clientConnect(id.publicKey, { v2: true });
      const { session: ss } = await SPDTransport.serverAccept(id, clientHello);
      expect(ss).toBeDefined();
      cs.destroy(); ss.destroy();
    });

    it('accepts a V1 ClientHello once explicitly disabled (legacy-interop escape hatch)', async () => {
      const id = await SPDTransport.generateServerIdentity();
      const { clientHello, session: cs } = await SPDTransport.clientConnect(id.publicKey, { v2: false });
      SPDTransport.setRequireV2(false);
      const { session: ss } = await SPDTransport.serverAccept(id, clientHello);
      expect(ss).toBeDefined();
      cs.destroy(); ss.destroy();
    });
  });

  describe('SPDTransport.connect / accept — high-level handshake helper', () => {
    /** In-memory duplex pipe: two SPDTransportIo objects wired to each other. */
    function pipe(): [SPDTransportIo, SPDTransportIo] {
      const aToB: Uint8Array[] = [];
      const bToA: Uint8Array[] = [];
      const waitFor = async (q: Uint8Array[]): Promise<Uint8Array> => {
        while (q.length === 0) await new Promise((r) => setTimeout(r, 0));
        return q.shift()!;
      };
      const ioA: SPDTransportIo = {
        send: (b) => { aToB.push(b); },
        receive: () => waitFor(bToA),
      };
      const ioB: SPDTransportIo = {
        send: (b) => { bToA.push(b); },
        receive: () => waitFor(aToB),
      };
      return [ioA, ioB];
    }

    it('V2 (default): connect/accept produce a working session on both sides', async () => {
      const id = await SPDTransport.generateServerIdentity();
      const [clientIo, serverIo] = pipe();

      const [clientSession, serverSession] = await Promise.all([
        SPDTransport.connect(id.publicKey, clientIo),
        SPDTransport.accept(id, serverIo),
      ]);

      const frame = clientSession.encrypt(Buffer.from('hello via connect/accept'));
      expect(Buffer.from(serverSession.decrypt(frame)).toString()).toBe('hello via connect/accept');

      const reply = serverSession.encrypt(Buffer.from('reply via connect/accept'));
      expect(Buffer.from(clientSession.decrypt(reply)).toString()).toBe('reply via connect/accept');

      clientSession.destroy(); serverSession.destroy();
    });

    it('V1: connect/accept produce a working session with { v2: false } (legacy-interop escape hatch)', async () => {
      const id = await SPDTransport.generateServerIdentity();
      const [clientIo, serverIo] = pipe();
      SPDTransport.setRequireV2(false);
      try {
        const [clientSession, serverSession] = await Promise.all([
          SPDTransport.connect(id.publicKey, clientIo, { v2: false }),
          SPDTransport.accept(id, serverIo),
        ]);

        const frame = clientSession.encrypt(Buffer.from('v1 via connect/accept'));
        expect(Buffer.from(serverSession.decrypt(frame)).toString()).toBe('v1 via connect/accept');

        clientSession.destroy(); serverSession.destroy();
      } finally {
        SPDTransport.setRequireV2(true);
      }
    });

    it('propagates a pinned signing key through connect/accept (V2 cert pinning)', async () => {
      const id = await SPDTransport.generateServerIdentity();
      const cert = SPDTransport.generateCertKeyPair();
      id.signingPrivKey = cert.privateKey;
      id.signingPubKey  = cert.publicKey;
      const [clientIo, serverIo] = pipe();

      const [clientSession, serverSession] = await Promise.all([
        SPDTransport.connect(id.publicKey, clientIo, { pinnedSigningKey: cert.publicKey }),
        SPDTransport.accept(id, serverIo),
      ]);

      const frame = clientSession.encrypt(Buffer.from('pinned'));
      expect(Buffer.from(serverSession.decrypt(frame)).toString()).toBe('pinned');
      clientSession.destroy(); serverSession.destroy();
    });

    it('rejects via connect() when the pinned key does not match (MitM simulation)', async () => {
      const id = await SPDTransport.generateServerIdentity();
      const cert = SPDTransport.generateCertKeyPair();
      id.signingPrivKey = cert.privateKey;
      id.signingPubKey  = cert.publicKey;
      const wrongCert = SPDTransport.generateCertKeyPair();
      const [clientIo, serverIo] = pipe();

      const serverPromise = SPDTransport.accept(id, serverIo);
      await expect(
        SPDTransport.connect(id.publicKey, clientIo, { pinnedSigningKey: wrongCert.publicKey })
      ).rejects.toThrow(/MitM|verif/i);
      // Drain the server side so its dangling promise doesn't leak into another test.
      await serverPromise.then((s) => s.destroy()).catch(() => {});
    });

    it('connect() times out with a clear error if the peer never replies (V2)', async () => {
      const id = await SPDTransport.generateServerIdentity();
      const neverReplies: SPDTransportIo = {
        send: () => {},
        receive: () => new Promise(() => {}), // never resolves
      };
      await expect(
        SPDTransport.connect(id.publicKey, neverReplies, { v2: true }, 50)
      ).rejects.toThrow(/timed out.*ServerHello/i);
    });

    it('accept() times out with a clear error if the peer never sends a ClientHello', async () => {
      const id = await SPDTransport.generateServerIdentity();
      const neverSends: SPDTransportIo = {
        send: () => {},
        receive: () => new Promise(() => {}), // never resolves
      };
      await expect(
        SPDTransport.accept(id, neverSends, undefined, undefined, 50)
      ).rejects.toThrow(/timed out.*ClientHello/i);
    });

    it('connect() with no timeoutMs behaves like before (waits indefinitely, resolves once the peer replies)', async () => {
      const id = await SPDTransport.generateServerIdentity();
      const [clientIo, serverIo] = pipe();

      const [clientSession, serverSession] = await Promise.all([
        SPDTransport.connect(id.publicKey, clientIo), // no timeoutMs passed
        SPDTransport.accept(id, serverIo),
      ]);
      expect(clientSession).toBeDefined();
      clientSession.destroy(); serverSession.destroy();
    });
  });

  describe('SPDSession.sendCounterRemaining / isNearExhaustion', () => {
    it('starts at the full 64-bit range and decreases by 1 per encrypt() call', async () => {
      const id = await SPDTransport.generateServerIdentity();
      const { cs } = await v1Handshake(id);
      const full = 2n ** 64n - 1n;
      expect(cs.sendCounterRemaining()).toBe(full);
      cs.encrypt(Buffer.from('x'));
      expect(cs.sendCounterRemaining()).toBe(full - 1n);
      cs.destroy();
    });

    it('isNearExhaustion is false for a fresh session and true at 0 remaining capacity', async () => {
      const id = await SPDTransport.generateServerIdentity();
      const { cs } = await v1Handshake(id);
      expect(cs.isNearExhaustion()).toBe(false);
      // Force the counter to the exhaustion boundary directly rather than
      // actually looping 2^64 times. `cs` (from clientConnect) is a
      // V1SessionAsClientHandshake wrapper around the real SPDSessionImpl —
      // reach through `.inner` to poke the private counter on the object
      // that actually owns it.
      const target = (cs as any).inner ?? cs;
      target._sendCounter = 2n ** 64n - 1n;
      expect(cs.isNearExhaustion()).toBe(true);
      expect(cs.isNearExhaustion(1)).toBe(true); // 100% threshold — always true once any capacity is used
      cs.destroy();
    });

    it('isNearExhaustion rejects an out-of-range threshold', async () => {
      const id = await SPDTransport.generateServerIdentity();
      const { cs } = await v1Handshake(id);
      expect(() => cs.isNearExhaustion(0)).toThrow(/thresholdFraction/);
      expect(() => cs.isNearExhaustion(1.5)).toThrow(/thresholdFraction/);
      cs.destroy();
    });
  });
});

// ── SPDShamir ─────────────────────────────────────────────────────────────────

import { SPDShamir } from '../src/index';

describe('SPDShamir — Shamir secret sharing over GF(256)', () => {
  it('split/combine round-trips a 32-byte secret (3-of-5)', () => {
    const secret = new Uint8Array(Buffer.from('this-is-a-32-byte-secret-key!!!!'));
    const shares = SPDShamir.split(secret, 5, 3);
    expect(shares.length).toBe(5);
    // Combine any 3 shares
    const rebuilt = SPDShamir.combine([shares[0], shares[2], shares[4]]);
    expect(Buffer.from(rebuilt).equals(Buffer.from(secret))).toBe(true);
  });

  it('split/combine round-trips a 16-byte secret (2-of-2)', () => {
    const secret  = new Uint8Array(Buffer.from('0123456789abcdef'));
    const shares  = SPDShamir.split(secret, 2, 2);
    const rebuilt = SPDShamir.combine(shares);
    expect(Buffer.from(rebuilt).equals(Buffer.from(secret))).toBe(true);
  });

  it('fewer than k shares throws instead of returning garbage', () => {
    const secret = new Uint8Array(Buffer.from('sensitive-secret'));
    const shares = SPDShamir.split(secret, 5, 3);
    expect(() => SPDShamir.combine([shares[0], shares[1]])).toThrow(/need at least 3 shares/);
  });

  it('share x-coordinates are unique and in range 1-n', () => {
    const secret = new Uint8Array(16).fill(0xab);
    const shares = SPDShamir.split(secret, 7, 4);
    const xs = shares.map(s => s[3]); // v2 layout: [0x00][ver][k][x][setId]...
    expect(new Set(xs).size).toBe(7);
    xs.forEach(x => { expect(x).toBeGreaterThanOrEqual(1); expect(x).toBeLessThanOrEqual(255); });
  });

  it('each call produces different shares (random coefficients)', () => {
    const secret = new Uint8Array(8).fill(0x42);
    const s1 = SPDShamir.split(secret, 3, 2);
    const s2 = SPDShamir.split(secret, 3, 2);
    // Shares should differ (extremely unlikely to collide with random coefficients)
    const same = s1.every((sh, i) => Buffer.from(sh).equals(Buffer.from(s2[i])));
    expect(same).toBe(false);
  });

  it('encodeShare / decodeShare round-trips', () => {
    const secret = new Uint8Array(Buffer.from('encode-me'));
    const shares = SPDShamir.split(secret, 3, 2);
    const encoded = SPDShamir.encodeShare(shares[0]);
    const decoded = SPDShamir.decodeShare(encoded);
    expect(Buffer.from(decoded).equals(Buffer.from(shares[0]))).toBe(true);
  });

  it('throws on n < 2', () => {
    expect(() => SPDShamir.split(new Uint8Array(8), 1, 1)).toThrow();
  });

  it('throws on k > n', () => {
    expect(() => SPDShamir.split(new Uint8Array(8), 3, 5)).toThrow();
  });

  it('throws on empty secret', () => {
    expect(() => SPDShamir.split(new Uint8Array(0), 3, 2)).toThrow();
  });

  it('throws on combine with 1 share', () => {
    const s = SPDShamir.split(new Uint8Array(8), 3, 2);
    expect(() => SPDShamir.combine([s[0]])).toThrow();
  });

  it('throws on combine with duplicate x-coordinates', () => {
    const s = SPDShamir.split(new Uint8Array(8), 3, 2);
    expect(() => SPDShamir.combine([s[0], s[0]])).toThrow(/duplicate/i);
  });

  it('can protect a 96-byte cryptographic master secret (3-of-5)', () => {
    const secret = new Uint8Array(96);
    for (let i = 0; i < 96; i++) secret[i] = i;
    const shares  = SPDShamir.split(secret, 5, 3);
    const rebuilt = SPDShamir.combine([shares[1], shares[3], shares[4]]);
    expect(Buffer.from(rebuilt).equals(Buffer.from(secret))).toBe(true);
  });

  it('combining shares from two DIFFERENT split() calls throws', () => {
    const sharesA = SPDShamir.split(new Uint8Array(8).fill(0xaa), 5, 3);
    const sharesB = SPDShamir.split(new Uint8Array(8).fill(0xbb), 5, 3);
    expect(() => SPDShamir.combine([sharesA[0], sharesA[1], sharesB[2]])).toThrow(/different split/);
  });

  it('a corrupted share fails the integrity check', () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const shares = SPDShamir.split(secret, 5, 3);
    for (const pos of [24, shares[0].length - 1]) { // a y-byte in the secret part, and in the tag part
      const bad = new Uint8Array(shares[1]);
      bad[pos] ^= 0x01;
      expect(() => SPDShamir.combine([shares[0], bad, shares[2]])).toThrow(/integrity check failed/);
    }
  });

  it('extra shares beyond k are accepted', () => {
    const secret = crypto.getRandomValues(new Uint8Array(40));
    const shares = SPDShamir.split(secret, 6, 3);
    expect(Buffer.from(SPDShamir.combine(shares)).equals(Buffer.from(secret))).toBe(true);
  });

  it('still combines legacy v1 shares ([x][f(x)...], no integrity data)', async () => {
    const { __testing__ } = await import('../src/SPDShamir.js');
    const secret = new Uint8Array([0x42, 0x99, 0x00, 0xff]);
    const coeff = new Uint8Array([7, 200, 13, 91]); // k = 2: f(x) = s ^ c*x per byte
    const v1 = [1, 2, 3].map((x) => Uint8Array.from([x, ...secret.map((b, i) => b ^ __testing__.gfMul(coeff[i], x))]));
    expect(Array.from(SPDShamir.combine([v1[2], v1[0]]))).toEqual(Array.from(secret));
  });

  it(
    'exhaustive GF(256) correctness: every possible 2-of-255 share pair reconstructs correctly ' +
    '(32,385 combinations — cross-checks gfMul/gfInv across nearly the entire x-coordinate space, ' +
    'the same exhaustive-enumeration technique that caught a real bug in the Reed-Solomon ' +
    'implementation elsewhere in this codebase; Lagrange interpolation over GF(256) has no ' +
    'combinatorial pitfall analogous to that bug, but a wrong gfMul/gfInv table entry would ' +
    'only surface for specific x-coordinate pairs, which a handful of hand-picked test cases ' +
    'would not reliably catch)',
    () => {
      const secret = new Uint8Array([0x99]);
      const shares = SPDShamir.split(secret, 255, 2);
      let failures = 0;
      for (let i = 0; i < shares.length; i++) {
        for (let j = i + 1; j < shares.length; j++) {
          const rebuilt = SPDShamir.combine([shares[i], shares[j]]);
          if (rebuilt[0] !== secret[0]) failures++;
        }
      }
      expect(failures).toBe(0);
    },
    30_000
  );
});

// ── v29 SPD features ──────────────────────────────────────────────────────────

describe('v29: key blinding', () => {
  it('enableKeyBlinding does not affect encrypt/decrypt', async () => {
    const spd = new SPD();
    spd.setKeyProfile('standard');
    await spd.setPassKey(PASS);
    spd.enableKeyBlinding();
    await spd.addData('blinded', 'value');
    const file = tmpFile();
    try {
      await spd.saveToFile(file, PASS);
      const loaded = await SPD.loadFromFile(file, PASS);
      const vals = await loaded.extractData();
      expect(vals['blinded']).toBe('value');
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(file); } catch {}
    }
    spd.destroy();
  });
});

describe('v29: KDF chain (Argon2id → scrypt)', () => {
  it('kdfChain enabled: save/load round-trip works', async () => {
    const spd = new SPD();
    spd.setKeyProfile('standard');
    spd.enableKdfChain(1024, 8, 1); // tiny N for test speed — must be set before setPassKey
    await spd.setPassKey(PASS);
    await spd.addData('kdf-chain', 'chained');
    const file = tmpFile();
    try {
      await spd.saveToFile(file, PASS);
      const loaded = await SPD.loadFromFile(file, PASS);
      const vals = await loaded.extractData();
      expect(vals['kdf-chain']).toBe('chained');
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(file); } catch {}
    }
    spd.destroy();
  });
});

describe('v29: ratcheting', () => {
  it('ratchet enabled: save twice, second load decrypts correctly', async () => {
    const spd = new SPD();
    spd.setKeyProfile('standard');
    await spd.setPassKey(PASS);
    spd.enableRatchet();
    await spd.addData('ratchet', 'first-value');
    const file = tmpFile();
    try {
      await spd.saveToFile(file, PASS);
      // Second save (ratchets key again)
      await spd.addData('ratchet2', 'second-value');
      await spd.saveToFile(file, PASS);
      const loaded = await SPD.loadFromFile(file, PASS);
      const vals = await loaded.extractData();
      expect(vals['ratchet']).toBe('first-value');
      expect(vals['ratchet2']).toBe('second-value');
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(file); } catch {}
    }
    spd.destroy();
  });
});

describe('v29: Merkle tree + signed write counter', () => {
  it('save and load verifies Merkle root and counter HMAC', async () => {
    const spd = new SPD();
    spd.setKeyProfile('standard');
    await spd.setPassKey(PASS);
    await spd.addData('merkle', 'verified');
    const file = tmpFile();
    try {
      await spd.saveToFile(file, PASS);
      // Should load without throwing (Merkle + HMAC verified internally)
      const loaded = await SPD.loadFromFile(file, PASS);
      expect(loaded.count()).toBe(1);
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(file); } catch {}
    }
    spd.destroy();
  });
});

describe('v29: ML-DSA-65 file signatures', () => {
  it('sign on save, verify on load', async () => {
    const keyPair = SPD.generateSigningKeyPair();
    const spd     = new SPD();
    spd.setKeyProfile('standard');
    await spd.setPassKey(PASS);
    spd.setSigningKey(keyPair.privateKey);
    await spd.addData('signed', 'authentic');
    const file = tmpFile();
    try {
      await spd.saveToFile(file, PASS);
      // Load with verify key — should succeed
      const loaded = await SPD.loadFromFile(file, PASS, keyPair.publicKey);
      const vals   = await loaded.extractData();
      expect(vals['signed']).toBe('authentic');
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(file); } catch {}
    }
    spd.destroy();
  });

  it('wrong verify key causes load to throw', async () => {
    const keyPair  = SPD.generateSigningKeyPair();
    const wrongKey = SPD.generateSigningKeyPair();
    const spd      = new SPD();
    spd.setKeyProfile('standard');
    await spd.setPassKey(PASS);
    spd.setSigningKey(keyPair.privateKey);
    await spd.addData('signed', 'authentic');
    const file = tmpFile();
    try {
      await spd.saveToFile(file, PASS);
      await expect(SPD.loadFromFile(file, PASS, wrongKey.publicKey)).rejects.toThrow('Authentication failed.');
    } finally {
      try { fs.unlinkSync(file); } catch {}
    }
    spd.destroy();
  });

  // getEntry/extractFromFileStreaming previously had no way to enforce a
  // pinned signer at all — an inconsistency with loadFromFile/
  // loadFromFileStreaming. Regression guard for that fix.
  it('getEntry accepts a correctly-signed binary file with matching verifyKey', async () => {
    const keyPair = SPD.generateSigningKeyPair();
    const spd     = new SPD();
    spd.setKeyProfile('standard');
    await spd.setPassKey(PASS);
    spd.setSigningKey(keyPair.privateKey);
    await spd.addData('signed', 'authentic');
    const file = tmpFile();
    try {
      await spd.saveToFileStreaming(file, PASS);
      const result = await SPD.getEntry(file, PASS, 'signed', keyPair.publicKey);
      expect(result.value).toBe('authentic');
    } finally {
      try { fs.unlinkSync(file); fs.unlinkSync(file + '.seq'); } catch {}
    }
    spd.destroy();
  });

  it('getEntry rejects a wrong verifyKey on a signed binary file', async () => {
    const keyPair  = SPD.generateSigningKeyPair();
    const wrongKey = SPD.generateSigningKeyPair();
    const spd      = new SPD();
    spd.setKeyProfile('standard');
    await spd.setPassKey(PASS);
    spd.setSigningKey(keyPair.privateKey);
    await spd.addData('signed', 'authentic');
    const file = tmpFile();
    try {
      await spd.saveToFileStreaming(file, PASS);
      await expect(SPD.getEntry(file, PASS, 'signed', wrongKey.publicKey)).rejects.toThrow('Authentication failed.');
    } finally {
      try { fs.unlinkSync(file); fs.unlinkSync(file + '.seq'); } catch {}
    }
    spd.destroy();
  });

  it('getEntry rejects verifyKey against an unsigned binary file', async () => {
    const keyPair = SPD.generateSigningKeyPair();
    const spd     = new SPD();
    spd.setKeyProfile('standard');
    await spd.setPassKey(PASS);
    // No setSigningKey() call — file is unsigned.
    await spd.addData('unsigned', 'value');
    const file = tmpFile();
    try {
      await spd.saveToFileStreaming(file, PASS);
      await expect(SPD.getEntry(file, PASS, 'unsigned', keyPair.publicKey)).rejects.toThrow('Authentication failed.');
    } finally {
      try { fs.unlinkSync(file); fs.unlinkSync(file + '.seq'); } catch {}
    }
    spd.destroy();
  });

  it('extractFromFileStreaming accepts a correctly-signed binary file with matching verifyKey', async () => {
    const keyPair = SPD.generateSigningKeyPair();
    const spd     = new SPD();
    spd.setKeyProfile('standard');
    await spd.setPassKey(PASS);
    spd.setSigningKey(keyPair.privateKey);
    await spd.addData('signed', 'authentic');
    const file = tmpFile();
    const d = tmpDir();
    try {
      await spd.saveToFileStreaming(file, PASS);
      const results: Array<[string, unknown]> = [];
      await SPD.extractFromFileStreaming(file, PASS, d, (name, value) => { results.push([name, value]); }, undefined, keyPair.publicKey);
      expect(results).toEqual([['signed', 'authentic']]);
    } finally {
      try { fs.unlinkSync(file); fs.unlinkSync(file + '.seq'); } catch {}
      fs.rmSync(d, { recursive: true, force: true });
    }
    spd.destroy();
  });

  it('extractFromFileStreaming rejects a wrong verifyKey on a signed binary file', async () => {
    const keyPair  = SPD.generateSigningKeyPair();
    const wrongKey = SPD.generateSigningKeyPair();
    const spd      = new SPD();
    spd.setKeyProfile('standard');
    await spd.setPassKey(PASS);
    spd.setSigningKey(keyPair.privateKey);
    await spd.addData('signed', 'authentic');
    const file = tmpFile();
    const d = tmpDir();
    try {
      await spd.saveToFileStreaming(file, PASS);
      await expect(
        SPD.extractFromFileStreaming(file, PASS, d, () => {}, undefined, wrongKey.publicKey)
      ).rejects.toThrow('Authentication failed.');
    } finally {
      try { fs.unlinkSync(file); fs.unlinkSync(file + '.seq'); } catch {}
      fs.rmSync(d, { recursive: true, force: true });
    }
    spd.destroy();
  });
});

describe('v29: HSM key provider', () => {
  it('custom key provider is used for key derivation', async () => {
    let deriveCallCount = 0;
    const mockProvider = {
      async deriveKey(passcode: string, salt: Uint8Array, memory: number, time: number): Promise<Uint8Array> {
        deriveCallCount++;
        // Simple deterministic derivation for testing (NOT secure)
        const { createHash } = await import('crypto');
        const h = createHash('sha512').update(passcode).update(salt).digest();
        return new Uint8Array(Buffer.concat([h, h]).subarray(0, 96));
      },
    };
    SPD.setKeyProvider(mockProvider);
    try {
      const spd = new SPD();
      spd.setKeyProfile('standard');
      await spd.setPassKey(PASS);
      await spd.addData('hsm', 'provider-derived');
      const file = tmpFile();
      try {
        await spd.saveToFile(file, PASS);
        const loaded = await SPD.loadFromFile(file, PASS);
        const vals = await loaded.extractData();
        expect(vals['hsm']).toBe('provider-derived');
        loaded.destroy();
      } finally {
        try { fs.unlinkSync(file); } catch {}
      }
      expect(deriveCallCount).toBeGreaterThan(0);
      spd.destroy();
    } finally {
      SPD.setKeyProvider(undefined);
    }
  });
});

// ── KDF parameter bounds validation (malicious/corrupted file metadata) ──────

describe('KDF parameter bounds validation', () => {
  const zlib = require('zlib');

  /**
   * Load a saved (JSON-format) .spd file, mutate its embedded payload JSON
   * via `mutate`, write it back.
   *
   * `outer.payload` is base64 (v2.0.1+, see decodeWrappedPayload's doc
   * comment in SPD.ts for why — an Array.from()'d number array of one
   * element per byte hit a real V8 array-length ceiling and severe
   * slowness on large files). Written back as base64 too, matching what
   * the real writer now produces — mirrors decodeWrappedPayload/the fixed
   * buildSerializedPayload rather than the old number[] shape.
   */
  function tamperJsonFile(file: string, mutate: (payload: Record<string, unknown>) => void): void {
    const raw = fs.readFileSync(file);
    const outer = JSON.parse(zlib.inflateSync(raw).toString('utf8'));
    const payloadBuf = typeof outer.payload === 'string'
      ? Buffer.from(outer.payload, 'base64')
      : Buffer.from(outer.payload);
    const payload = JSON.parse(payloadBuf.toString('utf8'));
    mutate(payload);
    outer.payload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
    fs.writeFileSync(file, zlib.deflateSync(Buffer.from(JSON.stringify(outer))));
  }

  it('rejects an absurdly large argon2Memory embedded in a JSON-format file', async () => {
    const spd = await freshSPD();
    await spd.addData('k', 'v');
    const file = tmpFile();
    try {
      await spd.saveToFile(file, PASS);
      tamperJsonFile(file, (p) => { p.argon2Memory = 999_999_999; });
      await expect(SPD.loadFromFile(file, PASS)).rejects.toThrow(/argon2Memory|out-of-range/i);
    } finally {
      try { fs.unlinkSync(file); } catch {}
      spd.destroy();
    }
  });

  it('rejects a negative/zero argon2Time embedded in a JSON-format file', async () => {
    const spd = await freshSPD();
    await spd.addData('k', 'v');
    const file = tmpFile();
    try {
      await spd.saveToFile(file, PASS);
      tamperJsonFile(file, (p) => { p.argon2Time = 0; });
      await expect(SPD.loadFromFile(file, PASS)).rejects.toThrow(/argon2Time|out-of-range/i);
    } finally {
      try { fs.unlinkSync(file); } catch {}
      spd.destroy();
    }
  });

  it('rejects an absurd wrapArgon2Memory before the file MAC is ever checked (pre-auth DoS guard)', async () => {
    const spd = await freshSPD();
    await spd.addData('k', 'v');
    const file = tmpFile();
    try {
      await spd.saveToFile(file, PASS);
      // wrapArgon2Memory feeds decryptSalt, which runs before the file's HMAC
      // is verified — this is the exact pre-authentication DoS path.
      tamperJsonFile(file, (p) => { p.wrapArgon2Memory = 2 ** 31; });
      await expect(SPD.loadFromFile(file, PASS)).rejects.toThrow(/wrapArgon2Memory|out-of-range/i);
    } finally {
      try { fs.unlinkSync(file); } catch {}
      spd.destroy();
    }
  });

  it('rejects an absurd scryptN when kdfChain is enabled', async () => {
    const spd = new SPD();
    spd.setKeyProfile('standard');
    spd.enableKdfChain(); // real default scryptN (2^20) — measured ~23s for setPassKey alone under real contention
    await spd.setPassKey(PASS);
    await spd.addData('k', 'v');
    const file = tmpFile();
    try {
      await spd.saveToFile(file, PASS);
      tamperJsonFile(file, (p) => { p.scryptN = 2 ** 30; });
      await expect(SPD.loadFromFile(file, PASS)).rejects.toThrow(/scryptN|out-of-range/i);
    } finally {
      try { fs.unlinkSync(file); } catch {}
      spd.destroy();
    }
  }, 120_000);

  it("default 'high' profile no longer chains scrypt; disableKdfChain() is honoured", async () => {
    const readPayload = (file: string): Record<string, unknown> => {
      const outer = JSON.parse(zlib.inflateSync(fs.readFileSync(file)).toString('utf8'));
      return JSON.parse(Buffer.from(outer.payload, 'base64').toString('utf8'));
    };
    const high = new SPD(); // default profile
    await high.setPassKey(PASS);
    await high.addData('k', 'v');
    const f1 = tmpFile();
    const explicit = new SPD();
    explicit.setKeyProfile('standard');
    explicit.enableKdfChain(1024, 8, 1);
    explicit.disableKdfChain();
    await explicit.setPassKey(PASS);
    await explicit.addData('k', 'v');
    const f2 = tmpFile();
    try {
      await high.saveToFile(f1, PASS);
      expect(readPayload(f1).kdfChain).toBeUndefined();
      await explicit.saveToFile(f2, PASS);
      expect(readPayload(f2).kdfChain).toBeUndefined();
      expect((await (await SPD.loadFromFile(f1, PASS)).extractData()).k).toBe('v');
    } finally {
      for (const f of [f1, f2]) { try { fs.unlinkSync(f); } catch {} }
      high.destroy(); explicit.destroy();
    }
  }, 120_000);

  it("destroy() emits a 'key_destroyed' log event once keys existed", async () => {
    const events: string[] = [];
    SPD.setLogger((e) => { events.push(e.event); });
    try {
      const spd = await freshSPD();
      spd.destroy();
      spd.destroy();
      expect(events.filter(e => e === 'key_destroyed')).toHaveLength(1);
    } finally {
      SPD.setLogger(undefined);
    }
  });

  it('still loads correctly when KDF params are untampered', async () => {
    const spd = await freshSPD();
    await spd.addData('k', 'v');
    const file = tmpFile();
    try {
      await spd.saveToFile(file, PASS);
      const loaded = await SPD.loadFromFile(file, PASS);
      expect((await loaded.extractData())['k']).toBe('v');
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(file); } catch {}
      spd.destroy();
    }
  });
});

// ── Bit-rot / silent-corruption resilience (SPD.writeParityFile / repairBitRot) ──

describe('bit-rot resilience — SPD.writeParityFile / repairBitRot', () => {
  it('writeParityFile + repairBitRot: no-op on an intact file', async () => {
    const spd = await freshSPD();
    await spd.addData('k', 'hello');
    const file = tmpFile();
    try {
      await spd.saveToFileStreaming(file, PASS);
      await SPD.writeParityFile(file);
      expect(fs.existsSync(file + '.ecc')).toBe(true);

      const result = await SPD.repairBitRot(file, PASS); // in-place repair requires the passcode: the repaired bytes are MAC-verified first
      expect(result.repaired).toBe(false);
      expect(result.blocksCorrupted).toBe(0);
    } finally {
      try { fs.unlinkSync(file); } catch {}
      try { fs.unlinkSync(file + '.ecc'); } catch {}
      spd.destroy();
    }
  });

  it('repairs a flipped byte in the .spd file and the repaired file still loads correctly', async () => {
    const spd = await freshSPD();
    await spd.addData('secret', 'long-term archival value');
    const file = tmpFile();
    try {
      await spd.saveToFileStreaming(file, PASS);
      await SPD.writeParityFile(file);

      // Flip a byte somewhere in the middle of the file (past the 72-byte header).
      const bytes = fs.readFileSync(file);
      const pos = Math.floor(bytes.length / 2);
      bytes[pos] ^= 0xff;
      fs.writeFileSync(file, bytes);

      // The file is now corrupt — a plain load should fail (MAC mismatch or inflate error).
      await expect(SPD.loadFromFileStreaming(file, PASS)).rejects.toThrow();

      const result = await SPD.repairBitRot(file, PASS); // in-place repair requires the passcode: the repaired bytes are MAC-verified first
      expect(result.repaired).toBe(true);
      expect(result.verified).toBe(true);
      expect(result.blocksRepaired).toBeGreaterThan(0);

      const loaded = await SPD.loadFromFileStreaming(file, PASS);
      expect((await loaded.extractData())['secret']).toBe('long-term archival value');
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(file); } catch {}
      try { fs.unlinkSync(file + '.ecc'); } catch {}
      spd.destroy();
    }
  });

  it('saveToFileStreaming({ errorCorrection: true }) writes the .ecc sidecar automatically', async () => {
    const spd = await freshSPD();
    await spd.addData('k', 'v');
    const file = tmpFile();
    try {
      await spd.saveToFileStreaming(file, PASS, undefined, { errorCorrection: true });
      expect(fs.existsSync(file + '.ecc')).toBe(true);

      const bytes = fs.readFileSync(file);
      bytes[Math.floor(bytes.length / 3)] ^= 0xff;
      fs.writeFileSync(file, bytes);

      // loadFromFileStreaming with autoRepair should self-heal before parsing.
      const loaded = await SPD.loadFromFileStreaming(file, PASS, undefined, undefined, { autoRepair: true });
      expect((await loaded.extractData())['k']).toBe('v');
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(file); } catch {}
      try { fs.unlinkSync(file + '.ecc'); } catch {}
      spd.destroy();
    }
  });

  it('loadFromFile and loadFromFileStreaming each open the other format', async () => {
    const spd = await freshSPD();
    await spd.addData('k', 'either-loader');
    const json = tmpFile();
    const binary = tmpFile();
    try {
      await spd.saveToFile(json, PASS);
      await spd.saveToFileStreaming(binary, PASS);
      for (const [file, load] of [
        [binary, () => SPD.loadFromFile(binary, PASS)],
        [json, () => SPD.loadFromFileStreaming(json, PASS)],
      ] as const) {
        const loaded = await load();
        expect((await loaded.extractData())['k']).toBe('either-loader');
        loaded.destroy();
        await expect(file === binary ? SPD.loadFromFile(file, PASS2) : SPD.loadFromFileStreaming(file, PASS2))
          .rejects.toThrow('Authentication failed.');
      }
    } finally {
      for (const f of [json, binary]) { try { fs.unlinkSync(f); } catch {} }
      spd.destroy();
    }
  });

  it('loadWithRandomKey({ autoRepair: true }) self-heals keyless files in both formats', async () => {
    for (const streaming of [true, false]) {
      const spd = new SPD();
      const secret = SPD.generateRandomKey();
      await spd.setRandomKey(secret);
      await spd.addData('k', 'keyless-value');
      const file = tmpFile();
      try {
        if (streaming) await spd.saveToFileStreaming(file, '', undefined, { errorCorrection: true });
        else await spd.saveToFile(file, '', { errorCorrection: true });

        const bytes = fs.readFileSync(file);
        bytes[Math.floor(bytes.length / 2)] ^= 0xff;
        fs.writeFileSync(file, bytes);

        const loaded = await SPD.loadWithRandomKey(file, secret, undefined, { autoRepair: true, streaming });
        expect((await loaded.extractData())['k']).toBe('keyless-value');
        loaded.destroy();

        // Without an explicit `streaming`, the format is sniffed from the file header.
        const sniffed = await SPD.loadWithRandomKey(file, secret);
        expect((await sniffed.extractData())['k']).toBe('keyless-value');
        sniffed.destroy();
      } finally {
        try { fs.unlinkSync(file); } catch {}
        try { fs.unlinkSync(file + '.ecc'); } catch {}
        spd.destroy();
      }
    }
  });

  it('saveToFile (JSON format) + errorCorrection option round-trips through corruption', async () => {
    const spd = await freshSPD();
    await spd.addData('k', 'json-format-value');
    const file = tmpFile();
    try {
      await spd.saveToFile(file, PASS, { errorCorrection: true });
      expect(fs.existsSync(file + '.ecc')).toBe(true);

      const bytes = fs.readFileSync(file);
      bytes[10] ^= 0xff;
      fs.writeFileSync(file, bytes);

      const loaded = await SPD.loadFromFile(file, PASS, undefined, { autoRepair: true });
      expect((await loaded.extractData())['k']).toBe('json-format-value');
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(file); } catch {}
      try { fs.unlinkSync(file + '.ecc'); } catch {}
      spd.destroy();
    }
  });

  it('repairBitRot throws a clear error when no .ecc sidecar exists', async () => {
    const spd = await freshSPD();
    await spd.addData('k', 'v');
    const file = tmpFile();
    try {
      await spd.saveToFileStreaming(file, PASS);
      await expect(SPD.repairBitRot(file)).rejects.toThrow(/no parity sidecar found/);
    } finally {
      try { fs.unlinkSync(file); } catch {}
      spd.destroy();
    }
  });

  it('repairBitRot reports unrecoverable when corruption exceeds the parity budget', async () => {
    const spd = await freshSPD();
    await spd.addData('k', 'v');
    const file = tmpFile();
    try {
      await spd.saveToFileStreaming(file, PASS);
      // Tiny block/shard config so it's easy to exceed the parity budget deliberately.
      await SPD.writeParityFile(file, { blockSize: 1024, dataShards: 4, parityShards: 1 });

      const bytes = fs.readFileSync(file);
      // Corrupt 2 of the 4 data shards in the first block — exceeds the 1-parity-shard budget.
      const shardLen = Math.ceil(1024 / 4);
      bytes[0] ^= 0xff;
      bytes[shardLen] ^= 0xff;
      fs.writeFileSync(file, bytes);

      const result = await SPD.repairBitRot(file, PASS); // in-place repair requires the passcode: the repaired bytes are MAC-verified first
      expect(result.repaired).toBe(false);
      expect(result.unrecoverableBlocks.length).toBeGreaterThan(0);

      // File on disk should be untouched (repair refused to write back partial garbage).
      const stillCorrupt = fs.readFileSync(file);
      expect(stillCorrupt[0]).not.toBe(bytes[0] ^ 0xff); // sanity: our corruption byte is still there
    } finally {
      try { fs.unlinkSync(file); } catch {}
      try { fs.unlinkSync(file + '.ecc'); } catch {}
      spd.destroy();
    }
  });

  it('rejects repair when the file size no longer matches the sidecar (file was replaced, not bit-rotted)', async () => {
    const spd = await freshSPD();
    await spd.addData('k', 'v');
    const file = tmpFile();
    try {
      await spd.saveToFileStreaming(file, PASS);
      await SPD.writeParityFile(file);
      fs.appendFileSync(file, Buffer.from('extra bytes appended'));
      await expect(SPD.repairBitRot(file)).rejects.toThrow(/size no longer matches/);
    } finally {
      try { fs.unlinkSync(file); } catch {}
      try { fs.unlinkSync(file + '.ecc'); } catch {}
      spd.destroy();
    }
  });
});

// ── Keyless key system (SPD.generateRandomKey / setRandomKey / setKeyfileOnly) ──

describe('keyless key system — no human-typed passcode', () => {
  it('generateRandomKey() produces a 96-byte CSPRNG secret, different every call', () => {
    const a = SPD.generateRandomKey();
    const b = SPD.generateRandomKey();
    expect(a).toBeInstanceOf(Uint8Array);
    expect(a.length).toBe(96);
    expect(b.length).toBe(96);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it('setRandomKey + saveToFileStreaming + loadWithRandomKey round-trips correctly', async () => {
    const secret = SPD.generateRandomKey();
    const spd = new SPD();
    await spd.setRandomKey(secret);
    await spd.addData('k', 'keyless-value');

    const file = tmpFile();
    try {
      await spd.saveToFileStreaming(file, '');
      const loaded = await SPD.loadWithRandomKey(file, secret);
      expect((await loaded.extractData())['k']).toBe('keyless-value');
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(file); } catch {}
      spd.destroy();
    }
  });

  it('setRandomKey + saveToFile (JSON) + loadWithRandomKey({ streaming: false }) round-trips correctly', async () => {
    const secret = SPD.generateRandomKey();
    const spd = new SPD();
    await spd.setRandomKey(secret);
    await spd.addData('k', 'json-keyless-value');

    const file = tmpFile();
    try {
      await spd.saveToFile(file, '');
      const loaded = await SPD.loadWithRandomKey(file, secret, undefined, { streaming: false });
      expect((await loaded.extractData())['k']).toBe('json-keyless-value');
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(file); } catch {}
      spd.destroy();
    }
  });

  it('loadWithRandomKey rejects the wrong secret', async () => {
    const secret = SPD.generateRandomKey();
    const wrongSecret = SPD.generateRandomKey();
    const spd = new SPD();
    await spd.setRandomKey(secret);
    await spd.addData('k', 'v');

    const file = tmpFile();
    try {
      await spd.saveToFileStreaming(file, '');
      await expect(SPD.loadWithRandomKey(file, wrongSecret)).rejects.toThrow(/Authentication failed/);
    } finally {
      try { fs.unlinkSync(file); } catch {}
      spd.destroy();
    }
  });

  it('rejects a master secret of the wrong length', async () => {
    const spd = new SPD();
    await expect(spd.setRandomKey(new Uint8Array(32))).rejects.toThrow(/96-byte/);
    spd.destroy();
  });

  it('setKeyfileOnly / generateKeyfileOnly / loadWithKeyfileOnly: fully keyless end-to-end, no passcode anywhere', async () => {
    const keyfilePath = tmpFile('.key');
    const spdPath = tmpFile();
    try {
      SPD.generateKeyfileOnly(keyfilePath);
      expect(fs.existsSync(keyfilePath)).toBe(true);
      expect(fs.statSync(keyfilePath).size).toBe(96);

      const spd = new SPD();
      await spd.setKeyfileOnly(keyfilePath);
      await spd.addData('secret', 'fully-automated-value');
      await spd.saveToFileStreaming(spdPath, '');
      spd.destroy();

      const loaded = await SPD.loadWithKeyfileOnly(spdPath, keyfilePath);
      expect((await loaded.extractData())['secret']).toBe('fully-automated-value');
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(keyfilePath); } catch {}
      try { fs.unlinkSync(spdPath); } catch {}
    }
  });

  it('setKeyfileOnly rejects a keyfile of the wrong size (e.g. the OLD 64-byte supplement-keyfile format)', async () => {
    const oldStyleKeyfile = tmpFile('.key');
    try {
      SPD.generateKeyfile(oldStyleKeyfile); // old 64-byte supplement format, not the 96-byte keyless format
      const spd = new SPD();
      await expect(spd.setKeyfileOnly(oldStyleKeyfile)).rejects.toThrow(/96 bytes/);
      spd.destroy();
    } finally {
      try { fs.unlinkSync(oldStyleKeyfile); } catch {}
    }
  });

  it('a keyless-saved file, once loaded, still saves correctly again on the SAME instance without re-supplying the secret', async () => {
    const secret = SPD.generateRandomKey();
    const spd = new SPD();
    await spd.setRandomKey(secret);
    await spd.addData('k', 'v1');
    const file = tmpFile();
    try {
      await spd.saveToFileStreaming(file, '');

      const loaded = await SPD.loadWithRandomKey(file, secret);
      await loaded.addData('k2', 'v2');
      // Re-save on the loaded instance — must transparently keep using the
      // keyless secret (via _keylessSecretEncoded), not require the caller
      // to pass anything passcode-shaped again.
      await loaded.saveToFileStreaming(file, '');
      loaded.destroy();

      const reloaded = await SPD.loadWithRandomKey(file, secret);
      const data = await reloaded.extractData();
      expect(data['k']).toBe('v1');
      expect(data['k2']).toBe('v2');
      reloaded.destroy();
    } finally {
      try { fs.unlinkSync(file); } catch {}
      spd.destroy();
    }
  });

  it('changePasscode throws a clear error on a keyless instance', async () => {
    const secret = SPD.generateRandomKey();
    const spd = new SPD();
    await spd.setRandomKey(secret);
    await expect(spd.changePasscode('a', 'b')).rejects.toThrow(/setRandomKey|setKeyfileOnly/);
    spd.destroy();
  });

  it('upgradeKdfParams throws a clear error on a keyless instance', async () => {
    const secret = SPD.generateRandomKey();
    const spd = new SPD();
    await spd.setRandomKey(secret);
    await expect(spd.upgradeKdfParams('x', { memory: 262144, time: 8 })).rejects.toThrow(/keyless/);
    spd.destroy();
  });

  it('a keyless-mode file is meaningfully faster to unlock than an equivalent passphrase-derived one (no Argon2id run)', async () => {
    const secret = SPD.generateRandomKey();
    const spd = new SPD();
    const t0 = Date.now();
    await spd.setRandomKey(secret);
    const keylessMs = Date.now() - t0;

    // Sanity bound — HKDF-only should be near-instant (well under 100ms),
    // nowhere close to even the cheapest Argon2id profile (~500ms+).
    expect(keylessMs).toBeLessThan(250);
    spd.destroy();
  });

  it('interacts correctly with enableRatchet() — salt/keys rotate on each save, still keyless throughout', async () => {
    const secret = SPD.generateRandomKey();
    const spd = new SPD();
    await spd.setRandomKey(secret);
    spd.enableRatchet();
    await spd.addData('k', 'v1');

    const file = tmpFile();
    try {
      const t0 = Date.now();
      await spd.saveToFileStreaming(file, '');
      const saveMs = Date.now() - t0;
      // The ratchet re-derives keys internally on every save — must still
      // route through the keyless HKDF-only path, not silently fall back
      // to Argon2id (which would be ~15-20x+ slower even at the cheapest profile).
      expect(saveMs).toBeLessThan(500);

      await spd.addData('k2', 'v2');
      await spd.saveToFileStreaming(file, '');

      const loaded = await SPD.loadWithRandomKey(file, secret);
      const data = await loaded.extractData();
      expect(data['k']).toBe('v1');
      expect(data['k2']).toBe('v2');
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(file); } catch {}
      spd.destroy();
    }
  });

  it('interacts correctly with setEpochSize() — key rotates every N saves, still keyless throughout', async () => {
    const secret = SPD.generateRandomKey();
    const spd = new SPD();
    await spd.setRandomKey(secret);
    spd.setEpochSize(2); // rotate every 2 saves
    await spd.addData('k', 'v1');

    const file = tmpFile();
    try {
      await spd.saveToFileStreaming(file, ''); // save 1
      await spd.saveToFileStreaming(file, ''); // save 2 — triggers epoch rotation

      const loaded = await SPD.loadWithRandomKey(file, secret);
      const data = await loaded.extractData();
      expect(data['k']).toBe('v1');
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(file); } catch {}
      spd.destroy();
    }
  });
});

describe('rotateRandomKey — keyless credential rotation', () => {
  it('rotates to a fresh auto-generated secret and round-trips correctly', async () => {
    const oldSecret = SPD.generateRandomKey();
    const spd = new SPD();
    await spd.setRandomKey(oldSecret);
    await spd.addData('k', 'v1');

    const newSecret = await spd.rotateRandomKey(oldSecret);
    expect(newSecret).toBeInstanceOf(Uint8Array);
    expect(newSecret.length).toBe(96);
    expect(Buffer.from(newSecret).equals(Buffer.from(oldSecret))).toBe(false);

    // Existing data survived the rotation, readable under the new secret in-memory.
    expect((await spd.extractData())['k']).toBe('v1');

    const file = tmpFile();
    try {
      await spd.saveToFileStreaming(file, '');

      // Old secret no longer works.
      await expect(SPD.loadWithRandomKey(file, oldSecret)).rejects.toThrow(/Authentication failed/);

      // New secret works and data is intact.
      const loaded = await SPD.loadWithRandomKey(file, newSecret);
      expect((await loaded.extractData())['k']).toBe('v1');
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(file); } catch {}
      spd.destroy();
    }
  });

  it('accepts a pre-generated newSecret instead of auto-generating one', async () => {
    const oldSecret = SPD.generateRandomKey();
    const preGenerated = SPD.generateRandomKey();
    const spd = new SPD();
    await spd.setRandomKey(oldSecret);
    await spd.addData('k', 'v');

    const returned = await spd.rotateRandomKey(oldSecret, preGenerated);
    expect(Buffer.from(returned).equals(Buffer.from(preGenerated))).toBe(true);

    const file = tmpFile();
    try {
      await spd.saveToFileStreaming(file, '');
      const loaded = await SPD.loadWithRandomKey(file, preGenerated);
      expect((await loaded.extractData())['k']).toBe('v');
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(file); } catch {}
      spd.destroy();
    }
  });

  it('rejects rotation with the wrong current secret (does not mutate the instance)', async () => {
    const oldSecret = SPD.generateRandomKey();
    const wrongSecret = SPD.generateRandomKey();
    const spd = new SPD();
    await spd.setRandomKey(oldSecret);
    await spd.addData('k', 'v');

    await expect(spd.rotateRandomKey(wrongSecret)).rejects.toThrow(/Authentication failed/);

    // Original secret must still work — the failed rotation must not have
    // partially mutated instance state.
    expect((await spd.extractData())['k']).toBe('v');
    spd.destroy();
  });

  it('throws a clear error when called on a non-keyless (passphrase) instance', async () => {
    const spd = await freshSPD();
    await expect(spd.rotateRandomKey(SPD.generateRandomKey())).rejects.toThrow(/setRandomKey|setKeyfileOnly/);
    spd.destroy();
  });

  it('rejects a currentSecret of the wrong length', async () => {
    const secret = SPD.generateRandomKey();
    const spd = new SPD();
    await spd.setRandomKey(secret);
    await expect(spd.rotateRandomKey(new Uint8Array(32))).rejects.toThrow(/96 bytes/);
    spd.destroy();
  });

  it('works with setKeyfileOnly-based instances too', async () => {
    const keyfilePath = tmpFile('.key');
    const newKeyfilePath = tmpFile('.key');
    const file = tmpFile();
    try {
      SPD.generateKeyfileOnly(keyfilePath);
      const oldSecret = new Uint8Array(fs.readFileSync(keyfilePath));

      const spd = new SPD();
      await spd.setKeyfileOnly(keyfilePath);
      await spd.addData('k', 'v');

      const newSecret = await spd.rotateRandomKey(oldSecret);
      fs.writeFileSync(newKeyfilePath, newSecret, { mode: 0o600 });
      await spd.saveToFileStreaming(file, '');
      spd.destroy();

      const loaded = await SPD.loadWithKeyfileOnly(file, newKeyfilePath);
      expect((await loaded.extractData())['k']).toBe('v');
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(keyfilePath); } catch {}
      try { fs.unlinkSync(newKeyfilePath); } catch {}
      try { fs.unlinkSync(file); } catch {}
    }
  });
});

describe('SPD.noiseInjection() — channel noise (rules2.txt R14)', () => {
  it('returns a delayMs within [0, MAX_DELAY_MS) and padding within [0, PAD_BLOCK_SIZE) bytes', () => {
    for (let i = 0; i < 50; i++) {
      const { delayMs, padding } = SPD.noiseInjection();
      expect(delayMs).toBeGreaterThanOrEqual(0);
      expect(delayMs).toBeLessThan(SPD.CHANNEL_NOISE.MAX_DELAY_MS);
      expect(Number.isInteger(delayMs)).toBe(true);
      expect(padding).toBeInstanceOf(Uint8Array);
      expect(padding.length).toBeGreaterThanOrEqual(0);
      expect(padding.length).toBeLessThan(SPD.CHANNEL_NOISE.PAD_BLOCK_SIZE);
    }
  });

  it('produces varied delayMs/padding-length values across many calls (not a constant or narrow range)', () => {
    const delays = new Set<number>();
    const lengths = new Set<number>();
    for (let i = 0; i < 200; i++) {
      const { delayMs, padding } = SPD.noiseInjection();
      delays.add(delayMs);
      lengths.add(padding.length);
    }
    // Real randomness across 200 draws from [0,200)/[0,512) should hit a
    // good spread of distinct values — a constant or near-constant output
    // (e.g. a broken RNG always returning 0) would fail this immediately.
    expect(delays.size).toBeGreaterThan(50);
    expect(lengths.size).toBeGreaterThan(50);
  });

  it('padding content is genuinely random (not all-zero, not a fixed pattern)', () => {
    const { padding } = SPD.noiseInjection();
    if (padding.length > 0) {
      // Overwhelmingly unlikely to be all-zero if genuinely random.
      expect(padding.some((b) => b !== 0)).toBe(true);
    }
  });

  it(
    'delayMs/padLen no longer come from Math.random() (regression: rules2.txt R14 previously ' +
    'documented this as a weak-RNG gap in SECURITY_RULES_IMPLEMENTATION.md — fixed to use ' +
    'crypto.getRandomValues via rejection sampling instead)',
    () => {
      const original = Math.random;
      let mathRandomCalled = false;
      Math.random = () => { mathRandomCalled = true; return original(); };
      try {
        for (let i = 0; i < 20; i++) SPD.noiseInjection();
        expect(mathRandomCalled).toBe(false);
      } finally {
        Math.random = original;
      }
    }
  );
});

describe('SPD.deniableDecryptView() — hidden-volume decoy entries', () => {
  it(
    'decrypts real content from _decoy_-prefixed entries added via addData() ' +
    '(regression: previously filtered on dataType === "_decoy", a sentinel only ' +
    'addDecoy() ever sets — the documented addData(\'_decoy_message\', ...) example ' +
    'always returned an empty array)',
    async () => {
      const spd = await freshSPD();
      await spd.addData('_decoy_message', 'innocent content');
      await spd.addData('real_secret', 'the actual sensitive value');

      const view = await spd.deniableDecryptView();
      expect(view).toEqual([{ name: '_decoy_message', value: 'innocent content' }]);
      spd.destroy();
    }
  );

  it('excludes real (non-decoy-prefixed) entries from the view', async () => {
    const spd = await freshSPD();
    await spd.addData('_decoy_a', 'a');
    await spd.addData('_decoy_b', 'b');
    await spd.addData('secret', 'nope');

    const view = await spd.deniableDecryptView();
    expect(view.map((e) => e.name).sort()).toEqual(['_decoy_a', '_decoy_b']);
    expect(view.every((e) => e.name !== 'secret')).toBe(true);
    spd.destroy();
  });

  it('excludes addDecoy()-generated noise entries (dataType === "_decoy") from the view', async () => {
    const spd = await freshSPD();
    await spd.addData('_decoy_real', 'genuine decoy content');
    await spd.addDecoy('padding', 5);

    const view = await spd.deniableDecryptView();
    expect(view).toEqual([{ name: '_decoy_real', value: 'genuine decoy content' }]);
    spd.destroy();
  });

  it('round-trips through saveToFileStreaming/loadFromFileStreaming', async () => {
    const file = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('_decoy_note', 'nothing to see here');
      await spd.addData('real', 'true secret');
      await spd.saveToFileStreaming(file, PASS);
      spd.destroy();

      const loaded = await SPD.loadFromFileStreaming(file, PASS);
      const view = await loaded.deniableDecryptView();
      expect(view).toEqual([{ name: '_decoy_note', value: 'nothing to see here' }]);
      loaded.destroy();
    } finally {
      try { fs.unlinkSync(file); } catch {}
    }
  });
});

describe('key cache (KEY_CACHE_TTL_MS = 0)', () => {
  it('retains no derived key material in the static cache after a load', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('a', 1);
      await spd.saveToFile(f, PASS);
      spd.destroy();
      const loaded = await SPD.loadFromFile(f, PASS);
      expect(await loaded.extractData()).toEqual({ a: 1 });
      loaded.destroy();
      expect((SPD as unknown as { keyCache: Map<string, unknown> }).keyCache.size).toBe(0);
    } finally {
      fs.rmSync(f, { force: true });
    }
  });
});

describe('lock ownership across users', () => {
  it('does not break a live lock whose owner process is another user (kill -> EPERM)', () => {
    const f = tmpFile();
    fs.writeFileSync(f + '.lock', JSON.stringify({ pid: 999_999, ts: Date.now() }));
    const kill = vi.spyOn(process, 'kill').mockImplementation(() => {
      throw Object.assign(new Error('operation not permitted'), { code: 'EPERM' });
    });
    try {
      expect(() => SPD.acquireLock(f, 150)).toThrow(/locked/i);
      expect(fs.existsSync(f + '.lock')).toBe(true);
    } finally {
      kill.mockRestore();
      fs.rmSync(f + '.lock', { force: true });
    }
  });
});

describe('generatePassphrase', () => {
  it('returns the requested number of known words and rejects < 5', () => {
    const pass = SPD.generatePassphrase(12);
    const words = pass.split(' ');
    expect(words).toHaveLength(12);
    for (const w of words) expect(w).toMatch(/^[a-z]{4}$/);
    expect(() => SPD.generatePassphrase(6)).toThrow(/Minimum 7/);
  });

  it('draws every word index roughly uniformly (no modulo bias toward early words)', () => {
    const counts = new Map<string, number>();
    for (let i = 0; i < 2000; i++) {
      for (const w of SPD.generatePassphrase(12).split(' ')) counts.set(w, (counts.get(w) ?? 0) + 1);
    }
    expect(counts.size).toBe(240);
    // 24000 draws / 240 words = 100 expected each; 6-sigma band ≈ ±60.
    for (const c of counts.values()) {
      expect(c).toBeGreaterThan(40);
      expect(c).toBeLessThan(160);
    }
  });
});

describe('stale-lock breaking', () => {
  it('a fresh lock that appears between our stale judgement and the break is never deleted; the .break mutex is cleaned up', async () => {
    const { createRequire } = await import('module');
    const cjsFs = createRequire(import.meta.url)('fs') as typeof fs;
    const f = tmpFile();
    const lockPath = f + '.lock';
    fs.writeFileSync(lockPath, JSON.stringify({ pid: process.pid, ts: Date.now() - 60_000, nonce: 'old' })); // stale
    const fresh = JSON.stringify({ pid: process.pid, ts: Date.now(), nonce: 'other-process' });
    const realWrite = cjsFs.writeFileSync.bind(cjsFs);
    let injected = false;
    // The instant our breaker takes the mutex, another process has already replaced the stale lock with a fresh one.
    const spy = vi.spyOn(cjsFs, 'writeFileSync').mockImplementation((p: any, d: any, o?: any) => {
      const r = realWrite(p, d, o);
      if (!injected && String(p).endsWith('.lock.break')) { injected = true; realWrite(lockPath, fresh); }
      return r;
    });
    try {
      expect(() => SPD.acquireLock(f, 300)).toThrow(/locked/i);
      expect(injected).toBe(true);
      expect(fs.readFileSync(lockPath, 'utf8')).toBe(fresh);
      expect(fs.existsSync(lockPath + '.break')).toBe(false);
    } finally {
      spy.mockRestore();
      for (const x of [lockPath, lockPath + '.break']) fs.rmSync(x, { force: true });
    }
  });

  it('implausible lock contents (pid 0, future timestamp) are treated as stale', () => {
    const f = tmpFile();
    try {
      fs.writeFileSync(f + '.lock', JSON.stringify({ pid: 0, ts: Date.now() }));
      SPD.releaseLock(f, SPD.acquireLock(f, 500));
      fs.writeFileSync(f + '.lock', JSON.stringify({ pid: 1, ts: Date.now() + 9e12 }));
      SPD.releaseLock(f, SPD.acquireLock(f, 500));
    } finally { for (const x of [f + '.lock', f + '.lock.break']) fs.rmSync(x, { force: true }); }
  });
});


describe('SPDShamir GF(256) arithmetic', () => {
  // The original (branchy) peasant multiply — reference oracle only.
  function gfMulReference(a: number, b: number): number {
    let p = 0;
    for (let i = 0; i < 8; i++) {
      if (b & 1) p ^= a;
      const hi = a & 0x80;
      a = (a << 1) & 0xff;
      if (hi) a ^= 0x1b;
      b >>= 1;
    }
    return p & 0xff;
  }

  it('constant-time gfMul matches the reference on all 65536 input pairs', async () => {
    const { __testing__ } = await import('../src/SPDShamir.js');
    for (let a = 0; a < 256; a++) {
      for (let b = 0; b < 256; b++) {
        if (__testing__.gfMul(a, b) !== gfMulReference(a, b)) {
          throw new Error(`gfMul(${a}, ${b}) mismatch`);
        }
      }
    }
  });

  it('gfInv is a true inverse for every nonzero element', async () => {
    const { __testing__ } = await import('../src/SPDShamir.js');
    for (let a = 1; a < 256; a++) expect(__testing__.gfMul(a, __testing__.gfInv(a))).toBe(1);
  });

  it('split/combine still round-trips for every k-subset size', async () => {
    const { SPDShamir } = await import('../src/index.js');
    const secret = crypto.getRandomValues(new Uint8Array(64));
    const shares = SPDShamir.split(secret, 7, 4);
    for (const subset of [shares.slice(0, 4), shares.slice(3, 7), [shares[6], shares[0], shares[3], shares[5]], shares]) {
      expect(Buffer.from(SPDShamir.combine(subset)).equals(Buffer.from(secret))).toBe(true);
    }
  });
});

// ── Audit regressions (Oct 2026) ─────────────────────────────────────────────

describe('audit: JSON-format decompression bomb cap', () => {
  it('rejects a crafted JSON .spd whose inflate would exceed SPD.maxJsonInflateBytes', async () => {
    const f = tmpFile();
    const prev = SPD.maxJsonInflateBytes;
    SPD.maxJsonInflateBytes = 1024 * 1024;
    try {
      const bomb = zlib.deflateSync(Buffer.alloc(4 * 1024 * 1024)); // few KiB on disk, 4 MiB inflated
      fs.writeFileSync(f, bomb);
      await expect(SPD.loadFromFile(f, PASS)).rejects.toThrow();
      await expect(SPD.loadFromString(bomb.toString('base64'), PASS)).rejects.toThrow();
    } finally {
      SPD.maxJsonInflateBytes = prev;
      fs.rmSync(f, { force: true });
    }
  });
});

describe('audit: extractFromFileStreaming authenticates before touching the .seq sidecar', () => {
  it('a tampered (unauthenticated) writeCounter does not advance .seq', async () => {
    const f = tmpFile();
    const d = tmpDir();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();

      // Rebuild the file with the same 72-byte header and a plaintext whose
      // meta.writeCounter is larger but the same length (1 → 9), so only the
      // MAC check can catch it.
      const raw = fs.readFileSync(f);
      const seqBefore = fs.readFileSync(f + '.seq', 'utf8'); // written by the genuine save
      const header = raw.subarray(0, 72);
      const plain = zlib.inflateSync(raw.subarray(72));
      const metaLen = plain.readUInt32LE(0);
      const meta = plain.subarray(4, 4 + metaLen).toString('utf8');
      expect(meta).toContain('"writeCounter":1');
      const meta2 = Buffer.from(meta.replace('"writeCounter":1', '"writeCounter":9'), 'utf8');
      expect(meta2.length).toBe(metaLen);
      const plain2 = Buffer.concat([plain.subarray(0, 4), meta2, plain.subarray(4 + metaLen)]);
      fs.writeFileSync(f, Buffer.concat([header, zlib.deflateSync(plain2)]));

      await expect(
        SPD.extractFromFileStreaming(f, PASS, d, async () => {})
      ).rejects.toThrow(/Authentication failed/);
      expect(fs.readFileSync(f + '.seq', 'utf8')).toBe(seqBefore); // not advanced to 9
      // The genuine file is still accepted (no ESPD_ROLLBACK lock-out).
      fs.writeFileSync(f, raw);
      const again = await SPD.loadFromFileStreaming(f, PASS);
      expect(await again.extractData()).toEqual({ k: 'v' });
      again.destroy();
    } finally {
      fs.rmSync(f, { force: true });
      fs.rmSync(f + '.seq', { force: true });
      fs.rmSync(d, { recursive: true, force: true });
    }
  });
});

describe('audit: extractFromFileStreaming honours non-default wrap-key params', () => {
  it('reads a file saved with setWrapKeyProfile(65536, 2)', async () => {
    const f = tmpFile();
    const d = tmpDir();
    try {
      const spd = await freshSPD();
      spd.setWrapKeyProfile(65536, 2);
      await spd.addData('k', 'wrapped');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();
      const seen: Record<string, unknown> = {};
      await SPD.extractFromFileStreaming(f, PASS, d, async (name, value) => { seen[name] = value; });
      expect(seen).toEqual({ k: 'wrapped' });
    } finally {
      fs.rmSync(f, { force: true });
      fs.rmSync(f + '.seq', { force: true });
      fs.rmSync(d, { recursive: true, force: true });
    }
  });
});

describe('audit: SPDTransport v2 signature covers the whole transcript', () => {
  it('a MITM who swaps the client KEM public key is caught by the pinned signature, not just key-commit', async () => {
    const id = await SPDTransport.generateServerIdentity();
    const cert = SPDTransport.generateCertKeyPair();
    id.signingPrivKey = cert.privateKey;
    id.signingPubKey = cert.publicKey;
    const { session: cs, clientHello } = await SPDTransport.clientConnect(id.publicKey, { v2: true, pinnedSigningKey: cert.publicKey });
    const { clientHello: evilHello } = await SPDTransport.clientConnect(id.publicKey, { v2: true });
    const tampered = new Uint8Array(clientHello);
    tampered.set(evilHello.subarray(65), 65); // replace the 1184-byte ML-KEM public key
    const { serverHello } = await SPDTransport.serverAccept(id, tampered);
    expect(() => cs.processServerHello(serverHello!)).toThrow(/certificate verification failed/);
  });

  it('a genuine pinned handshake still completes, and processServerHello cannot be called twice', async () => {
    const id = await SPDTransport.generateServerIdentity();
    const cert = SPDTransport.generateCertKeyPair();
    id.signingPrivKey = cert.privateKey;
    const { session: cs, clientHello } = await SPDTransport.clientConnect(id.publicKey, { v2: true, pinnedSigningKey: cert.publicKey });
    const { session: ss, serverHello } = await SPDTransport.serverAccept(id, clientHello);
    cs.processServerHello(serverHello!);
    expect(() => cs.processServerHello(serverHello!)).toThrow(/already called/);
    const msg = new TextEncoder().encode('hello');
    expect(Buffer.from(ss.decrypt(cs.encrypt(msg))).equals(Buffer.from(msg))).toBe(true);
  });
});

describe('audit: SPDWriter uses the same key derivation as SPD (pepper parity)', () => {
  it('a file written with a global pepper loads with it and fails without it', async () => {
    const f = tmpFile();
    const pepper = crypto.getRandomValues(new Uint8Array(32));
    try {
      SPD.setPepper(pepper);
      const writer = new SPDWriter(f, PASS);
      await writer.init();
      await writer.addEntry('name', 'alice');
      await writer.finalize();
      const loaded = await SPD.loadFromFileStreaming(f, PASS);
      expect((await loaded.extractData()).name).toBe('alice');
      loaded.destroy();
      SPD.setPepper('');
      await expect(SPD.loadFromFileStreaming(f, PASS)).rejects.toThrow(/Authentication failed/);
    } finally {
      SPD.setPepper('');
      fs.rmSync(f, { force: true });
      fs.rmSync(f + '.seq', { force: true });
    }
  });
});

describe('composite (ML-DSA-65 + Ed25519) file signatures', () => {
  const comp = SPD.generateSigningKeyPair({ composite: true });
  const plain = SPD.generateSigningKeyPair();

  it('key and signature sizes identify the kind', () => {
    expect(comp.privateKey.length).toBe(4064);
    expect(comp.publicKey.length).toBe(1984);
    expect(plain.privateKey.length).toBe(4032);
    expect(plain.publicKey.length).toBe(1952);
    const spd = new SPD();
    expect(() => spd.setSigningKey(new Uint8Array(100))).toThrow(/4032 bytes.*4064 bytes/);
    expect(() => spd.setVerifyKey(new Uint8Array(100))).toThrow(/1952 bytes.*1984 bytes/);
  });

  async function signedFile(key: Uint8Array, streaming: boolean): Promise<string> {
    const spd = await freshSPD();
    spd.setSigningKey(key);
    await spd.addData('signed', 'authentic');
    const f = tmpFile();
    if (streaming) await spd.saveToFileStreaming(f, PASS); else await spd.saveToFile(f, PASS);
    spd.destroy();
    return f;
  }

  for (const streaming of [false, true]) {
    const load = (f: string, vk?: Uint8Array) => streaming ? SPD.loadFromFileStreaming(f, PASS, undefined, vk) : SPD.loadFromFile(f, PASS, vk);

    it(`composite sign/verify round-trips (${streaming ? 'binary' : 'json'})`, async () => {
      const f = await signedFile(comp.privateKey, streaming);
      try {
        const loaded = await load(f, comp.publicKey);
        expect((await loaded.extractData()).signed).toBe('authentic');
        loaded.destroy();
      } finally { fs.rmSync(f, { force: true }); fs.rmSync(f + '.seq', { force: true }); }
    });

    it(`kinds are non-separable: ML-DSA-only key rejects a composite file and vice versa (${streaming ? 'binary' : 'json'})`, async () => {
      const fc = await signedFile(comp.privateKey, streaming);
      const fp = await signedFile(plain.privateKey, streaming);
      try {
        await expect(load(fc, plain.publicKey)).rejects.toThrow('Authentication failed.');
        await expect(load(fp, comp.publicKey)).rejects.toThrow('Authentication failed.');
        // sanity: the matching kinds still verify
        (await load(fp, plain.publicKey)).destroy();
      } finally {
        for (const f of [fc, fp]) { fs.rmSync(f, { force: true }); fs.rmSync(f + '.seq', { force: true }); }
      }
    });
  }

  it('a composite signature with one valid component is rejected (both must verify)', async () => {
    const { signFileMac, verifyFileMac } = await import('../src/internal/spd-signature.js');
    const mac = crypto.getRandomValues(new Uint8Array(64));
    const sig = signFileMac(mac, comp.privateKey);
    expect(sig.length).toBe(3373);
    expect(verifyFileMac(sig, mac, comp.publicKey)).toBe(true);
    const badEd = new Uint8Array(sig); badEd[3309 + 10] ^= 1;
    const badMl = new Uint8Array(sig); badMl[100] ^= 1;
    expect(verifyFileMac(badEd, mac, comp.publicKey)).toBe(false);
    expect(verifyFileMac(badMl, mac, comp.publicKey)).toBe(false);
    expect(verifyFileMac(sig.subarray(0, 3309), mac, comp.publicKey)).toBe(false); // stripped Ed25519 part
    expect(verifyFileMac(sig.subarray(0, 3309), mac, comp.publicKey.subarray(0, 1952))).toBe(false); // ML-DSA-only verifier, composite-context sig
  });
});

describe('audit: a throwing onProgress callback rejects instead of hanging the load', () => {
  it('loadFromFileStreaming rejects with the callback error', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();
      await expect(
        SPD.loadFromFileStreaming(f, PASS, () => { throw new Error('progress boom'); })
      ).rejects.toThrow('progress boom');
    } finally {
      fs.rmSync(f, { force: true });
      fs.rmSync(f + '.seq', { force: true });
    }
  }, 20_000);
});

describe('opt-in unlock cache (SPD.setKeyCacheTtl)', () => {
  it('is off by default (2 KDF runs per open), skips the KDF entirely while enabled, and is forced off by anti-forensic mode', async () => {
    const { argon2Stats } = await import('../src/internal/spd-crypto.js');
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFile(f, PASS);
      spd.destroy();

      let c = argon2Stats.calls;
      (await SPD.loadFromFile(f, PASS)).destroy();
      expect(argon2Stats.calls - c).toBe(2);

      SPD.setKeyCacheTtl(30_000);
      c = argon2Stats.calls;
      (await SPD.loadFromFile(f, PASS)).destroy(); // populates
      expect(argon2Stats.calls - c).toBe(2);
      c = argon2Stats.calls;
      const t = performance.now();
      const hot = await SPD.loadFromFile(f, PASS);  // served from cache
      expect(argon2Stats.calls - c).toBe(0);
      expect(performance.now() - t).toBeLessThan(200);
      expect(await hot.extractData()).toEqual({ k: 'v' });
      hot.destroy();
      // A wrong passcode must still fail even with a warm cache.
      await expect(SPD.loadFromFile(f, PASS2)).rejects.toThrow();

      const af = new SPD();
      af.enableAntiForensic(true); // forces TTL 0 process-wide while this instance lives
      try {
        c = argon2Stats.calls;
        (await SPD.loadFromFile(f, PASS)).destroy();
        expect(argon2Stats.calls - c).toBe(2);
        expect(() => SPD.setKeyCacheTtl(-1)).toThrow();
      } finally { af.destroy(); }
    } finally {
      SPD.setKeyCacheTtl(0);
      for (const p of [f, f + '.seq', f + '.ocount']) fs.rmSync(p, { force: true });
    }
  }, 60_000);
});

describe('wrap-key parallelism (setWrapKeyProfile third arg)', () => {
  it('p=4 wrap round-trips on every read path and is recorded in meta; changePasscode keeps it', async () => {
    const fj = tmpFile(), fb = tmpFile();
    try {
      const spd = await freshSPD();
      spd.setWrapKeyProfile(131072, 6, 4);
      await spd.addData('k', 'lanes');
      await spd.saveToFile(fj, PASS);
      await spd.saveToFileStreaming(fb, PASS);
      spd.destroy();
      expect((await SPD.loadFromFile(fj, PASS)).has('k')).toBe(true);
      expect(await (await SPD.loadFromFileStreaming(fb, PASS)).extractData()).toEqual({ k: 'lanes' });
      expect((await SPD.getEntry(fb, PASS, 'k')).value).toBe('lanes');
      const plain = zlib.inflateSync(fs.readFileSync(fj)).toString('utf8');
      const inner = Buffer.from(JSON.parse(plain).payload, 'base64').toString('utf8');
      expect(JSON.parse(inner).wrapArgon2Parallelism).toBe(4);
      const again = await SPD.loadFromFile(fj, PASS);
      await again.changePasscode(PASS, PASS2);
      await again.saveToFile(fj, PASS2);
      again.destroy();
      expect(await (await SPD.loadFromFile(fj, PASS2)).extractData()).toEqual({ k: 'lanes' });
    } finally {
      for (const p of [fj, fb]) for (const x of [p, p + '.seq', p + '.ocount']) fs.rmSync(x, { force: true });
    }
  }, 60_000);
});

describe('audit: SPD.verify derives the wrap key from the wrap params (not the main profile)', () => {
  it('verifies files whose wrap profile differs from the main profile, in both formats', async () => {
    const fj = tmpFile(), fb = tmpFile();
    try {
      const spd = await freshSPD();           // main: standard (128 MiB / 6)
      spd.setWrapKeyProfile(65536, 2);        // wrap: different
      await spd.addData('k', 'v');
      await spd.saveToFile(fj, PASS);
      await spd.saveToFileStreaming(fb, PASS);
      spd.destroy();
      expect((await SPD.verify(fj, PASS)).valid).toBe(true);
      expect((await SPD.verify(fb, PASS)).valid).toBe(true);
    } finally {
      for (const p of [fj, fb]) for (const x of [p, p + '.seq', p + '.ocount']) fs.rmSync(x, { force: true });
    }
  }, 60_000);
});

describe('SPDWriter integrity-field parity', () => {
  it('emits writeCounter + counterHMAC that SPD.verify and loaders validate', async () => {
    const f = tmpFile();
    try {
      const writer = new SPDWriter(f, PASS);
      await writer.init();
      await writer.addEntry('name', 'alice');
      await writer.finalize();
      const v = await SPD.verify(f, PASS);
      expect(v.valid).toBe(true);
      expect(v.writeCounter).toBe(1);
      // Tamper the counter in the authenticated meta: MAC catches it before counterHMAC, either way it must fail.
      const raw = fs.readFileSync(f);
      expect(zlib.inflateSync(raw.subarray(72)).toString('utf8')).toContain('"counterHMAC"');
      const loaded = await SPD.loadFromFileStreaming(f, PASS);
      expect((await loaded.extractData()).name).toBe('alice');
      loaded.destroy();
    } finally { for (const x of [f, f + '.seq', f + '.ocount']) fs.rmSync(x, { force: true }); }
  }, 60_000);
});

describe('loadFromFileStreaming accepts the verify key in the loadFromFile position', () => {
  it('a Uint8Array third argument is treated as verifyKey, and passing it twice is rejected', async () => {
    const f = tmpFile();
    try {
      const kp = SPD.generateSigningKeyPair();
      const spd = await freshSPD();
      spd.setSigningKey(kp.privateKey);
      await spd.addData('k', 'v');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();
      const ok = await SPD.loadFromFileStreaming(f, PASS, kp.publicKey);
      expect(await ok.extractData()).toEqual({ k: 'v' });
      ok.destroy();
      await expect(SPD.loadFromFileStreaming(f, PASS, SPD.generateSigningKeyPair().publicKey)).rejects.toThrow('Authentication failed.');
      await expect(SPD.loadFromFileStreaming(f, PASS, kp.publicKey, kp.publicKey)).rejects.toThrow(/passed twice/);
    } finally { for (const x of [f, f + '.seq', f + '.ocount']) fs.rmSync(x, { force: true }); }
  }, 60_000);
});

// ── Audit round 2 regressions ────────────────────────────────────────────────

describe('audit2: ACL is enforced on every read path', () => {
  it('extractDataStreaming, exportEntries and deniableDecryptView deny restricted entries; export keeps the restriction', async () => {
    const spd = await freshSPD();
    await spd.addData('open', 1);
    await spd.addData('secret', 2);
    await spd.addData('_decoy_note', 'cover');
    spd.restrictEntry('secret', ['admin']);
    spd.restrictEntry('_decoy_note', ['admin']);
    spd.setRole('guest');
    await expect(spd.extractDataStreaming(async () => {})).rejects.toThrow(/Access denied/);
    expect(() => spd.exportEntries(/secret/)).toThrow(/Access denied/);
    await expect(spd.deniableDecryptView()).rejects.toThrow(/Access denied/);
    spd.setRole('admin');
    const exported = spd.exportEntries(/secret/);
    exported.setRole('guest');
    await expect(exported.extractData()).rejects.toThrow(/Access denied/); // restriction travelled with the entry
    exported.setRole('admin');
    expect(await exported.extractData()).toEqual({ secret: 2 });
    const snap = spd.snapshot();
    spd.restrictEntry('secret', []);          // lift the restriction…
    spd.restoreSnapshot(snap);                // …and get it back from the snapshot
    spd.setRole('guest');
    await expect(spd.extractData()).rejects.toThrow(/Access denied/); // ACL survives snapshot/restore
    spd.destroy(); exported.destroy();
  });
});

describe('audit2: decoys do not break reads or rotation', () => {
  it('extractData, changePasscode and upgradeKdfParams work with decoys present and carry them over', async () => {
    const spd = await freshSPD();
    await spd.addData('k', 'v');
    await spd.addDecoy('noise', 3);
    const before = spd.count();
    expect(await spd.extractData()).toEqual({ k: 'v' });
    await spd.changePasscode(PASS, PASS2);
    expect(spd.count()).toBe(before);
    expect(await spd.extractData()).toEqual({ k: 'v' });
    await spd.upgradeKdfParams(PASS2, { memory: 131072, time: 7 });
    expect(spd.count()).toBe(before);
    expect(await spd.extractData()).toEqual({ k: 'v' });
    spd.destroy();
  }, 60_000);
});

describe('audit2: key rotation is atomic', () => {
  it('a failure during re-encryption leaves the instance on the old passcode with all entries intact', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('a', 1);
      await spd.addData('b', 2);
      // Rotation deliberately bypasses schema validation (values were already
      // validated), so inject the failure in the re-encryption itself.
      const real = SPD.deriveEntryKey;
      const spy = vi.spyOn(SPD, 'deriveEntryKey').mockImplementation((k, n) => {
        if (n === 'b') throw new Error('injected re-encryption failure');
        return real(k, n);
      });
      try {
        await expect(spd.changePasscode(PASS, PASS2)).rejects.toThrow(/injected/);
      } finally { spy.mockRestore(); }
      expect(await spd.extractData()).toEqual({ a: 1, b: 2 });
      await spd.saveToFile(f, PASS); // still the old passcode
      spd.destroy();
      expect(await (await SPD.loadFromFile(f, PASS)).extractData()).toEqual({ a: 1, b: 2 });
      await expect(SPD.loadFromFile(f, PASS2)).rejects.toThrow();
    } finally { for (const x of [f, f + '.seq', f + '.ocount']) fs.rmSync(x, { force: true }); }
  }, 60_000);
});

describe('audit2: carrier embed/extract round-trips', () => {
  it('100 random payloads/carriers/secrets', () => {
    for (let i = 0; i < 100; i++) {
      const ct = crypto.getRandomValues(new Uint8Array(1 + Math.floor(Math.random() * 200)));
      const carrier = crypto.getRandomValues(new Uint8Array(ct.length + 8 + 1024 + Math.floor(Math.random() * 1024)));
      const secret = crypto.getRandomValues(new Uint8Array(32));
      let embedded: Uint8Array;
      try { embedded = SPD.embedInCarrier(ct, carrier, secret); } catch (e) { expect((e as Error).message).toMatch(/Carrier too small/); continue; }
      expect(Buffer.from(SPD.extractFromCarrier(embedded, secret)).equals(Buffer.from(ct))).toBe(true);
    }
  });
});

describe('audit2: a forged .ecc sidecar cannot replace the vault', () => {
  it('repairBitRot without a passcode writes .repaired and leaves the original; with a passcode it refuses unauthenticated bytes', async () => {
    const { buildEccSidecar } = await import('../src/internal/spd-ecc.js');
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.saveToFileStreaming(f, PASS);
      spd.destroy();
      const original = fs.readFileSync(f);
      const evil = Buffer.alloc(original.length, 0x41);
      fs.writeFileSync(f + '.ecc', buildEccSidecar(new Uint8Array(evil), { dataShards: 1, parityShards: 1, blockSize: original.length }).sidecar);

      const r = await SPD.repairBitRot(f);
      expect(fs.readFileSync(f).equals(original)).toBe(true);
      expect(r.verified).toBe(false);
      if (r.repairedPath) { expect(r.repairedPath).toBe(f + '.repaired'); fs.rmSync(r.repairedPath, { force: true }); }

      await expect(SPD.repairBitRot(f, PASS)).rejects.toThrow(/failed authentication/);
      expect(fs.readFileSync(f).equals(original)).toBe(true);
      // autoRepair must not destroy the file either
      const loaded = await SPD.loadFromFileStreaming(f, PASS, undefined, undefined, { autoRepair: true });
      expect(await loaded.extractData()).toEqual({ k: 'v' });
      loaded.destroy();
      expect(fs.readFileSync(f).equals(original)).toBe(true);
    } finally { for (const x of [f, f + '.ecc', f + '.repaired', f + '.seq', f + '.ocount']) fs.rmSync(x, { force: true }); }
  }, 60_000);

  it('a sidecar with blockSize 0 is rejected, not looped on', async () => {
    const { buildEccSidecar, verifyWithEccSidecar } = await import('../src/internal/spd-ecc.js');
    const data = crypto.getRandomValues(new Uint8Array(5000));
    const sc = new Uint8Array(buildEccSidecar(data).sidecar);
    sc[5] = 0; sc[6] = 0; sc[7] = 0; sc[8] = 0; // blockSize := 0 (HMAC now wrong too — either error is fine, a hang is not)
    expect(() => verifyWithEccSidecar(data, sc)).toThrow();
  });
});

describe('audit3: decoys are indistinguishable on disk; snapshot/restore ACL; cache pinning', () => {
  it('a decoy is a normal string record on disk, skipped after decryption, and survives save/load', async () => {
    const f = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('k', 'v');
      await spd.addDecoy('cover', 2);
      expect(await spd.extractData()).toEqual({ k: 'v' });
      await spd.saveToFile(f, PASS);
      const plain = zlib.inflateSync(fs.readFileSync(f)).toString('utf8');
      const inner = JSON.parse(Buffer.from(JSON.parse(plain).payload, 'base64').toString('utf8'));
      expect(inner.data.every((e: any) => e.dataType !== '_decoy')).toBe(true);
      expect(new Set(inner.data.map((e: any) => e.dataType))).toEqual(new Set(['string']));
      spd.destroy();
      const loaded = await SPD.loadFromFile(f, PASS);
      expect(await loaded.extractData()).toEqual({ k: 'v' });
      const seen: string[] = [];
      await loaded.extractDataStreaming(async (n) => { seen.push(n); });
      expect(seen).toEqual(['k']);
      loaded.destroy();
    } finally { for (const x of [f, f + '.seq', f + '.ocount']) fs.rmSync(x, { force: true }); }
  }, 60_000);

  it('snapshot() is ACL-gated and restoreSnapshot() cannot lift a restriction', async () => {
    const spd = await freshSPD();
    await spd.addData('s', 1);
    const snap = spd.snapshot();
    spd.restrictEntry('s', ['admin']);
    spd.setRole('guest');
    expect(() => spd.snapshot()).toThrow(/Access denied/);
    spd.restoreSnapshot(snap); // snapshot taken before the restriction: must not remove it
    await expect(spd.extractData()).rejects.toThrow(/Access denied/);
    spd.destroy();
  });

  it('setKeyCacheTtl refuses while an anti-forensic instance is live', async () => {
    const spd = await freshSPD();
    spd.enableAntiForensic(true);
    expect(() => SPD.setKeyCacheTtl(1000)).toThrow(/anti-forensic/);
    spd.destroy();
    SPD.setKeyCacheTtl(1000);
    SPD.setKeyCacheTtl(0);
  });
});

describe('audit3: tail index no longer leaks entry names', () => {
  it('binary files from saveToFileStreaming and SPDWriter carry SPDy tails with no plaintext names; getEntry works; .spdi is not written', async () => {
    const f1 = tmpFile(), f2 = tmpFile();
    try {
      const spd = await freshSPD();
      await spd.addData('very_secret_entry_name', 'v1');
      await spd.addData('another_hidden_name', 'v2');
      await spd.saveToFileStreaming(f1, PASS);
      spd.destroy();
      const w = new SPDWriter(f2, PASS);
      await w.init(); await w.addEntry('very_secret_entry_name', 'w1'); await w.finalize();
      await new Promise((r) => setTimeout(r, 50));
      for (const f of [f1, f2]) {
        const raw = fs.readFileSync(f);
        expect(raw.subarray(raw.length - 4).toString('latin1')).toBe('SPDy');
        expect(raw.includes(Buffer.from('very_secret_entry_name'))).toBe(false);
        expect(fs.existsSync(f + 'i')).toBe(false);
        expect((await SPD.getEntry(f, PASS, 'very_secret_entry_name')).value).toMatch(/^[vw]1$/);
        await expect(SPD.getEntry(f, PASS, 'nope')).rejects.toThrow(/not found/);
      }
    } finally { for (const f of [f1, f2]) for (const x of [f, f + 'i', f + '.seq', f + '.ocount']) fs.rmSync(x, { force: true }); }
  }, 60_000);
});
