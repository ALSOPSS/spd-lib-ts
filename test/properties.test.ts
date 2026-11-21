/**
 * Property-based tests (fast-check). Where the fuzz suite asks "does a broken
 * input break us?", these ask "does EVERY valid input round-trip?" — across
 * all supported value types, share parameters, recipient counts, frame sizes
 * and codec inputs. Keyless mode keeps Argon2id out of the loop.
 */
import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { SPD, SPDRecipient, SPDShamir, SPDTransport } from '../src/index';
import { encodeWalRecord, replayWalRecords, walHeader } from '../src/internal/spd-wal';
import { bytesToBase64, base64ToBytes, bytesToBase64Url, base64UrlToBytes, bytesToHex, hexToBytes } from '../src/internal/portable-crypto';

const bytes = (min = 0, max = 512) => fc.uint8Array({ minLength: min, maxLength: max });
const eq = (a: Uint8Array, b: Uint8Array) => Buffer.from(a).equals(Buffer.from(b));
const name = fc.stringMatching(/^[a-z][a-z0-9_-]{0,40}$/);

// Every SupportedDataType, with the normalisation SPD applies on the way out.
const typedArrays = [
  fc.uint8Array().map((a) => ({ v: a, t: 'Uint8Array' })),
  fc.uint16Array().map((a) => ({ v: a, t: 'Uint16Array' })),
  fc.uint32Array().map((a) => ({ v: a, t: 'Uint32Array' })),
  fc.bigInt64Array().map((a) => ({ v: a, t: 'BigInt64Array' })),
  fc.bigUint64Array().map((a) => ({ v: a, t: 'BigUint64Array' })),
  fc.float32Array().map((a) => ({ v: a, t: 'Float32Array' })),
  fc.float64Array().map((a) => ({ v: a, t: 'Float64Array' })),
];
const jsonValue = fc.jsonValue({ maxDepth: 3 });
const plainValue = fc.oneof(
  fc.string().map((v) => ({ v, t: 'string' })),
  fc.double({ noNaN: true, noDefaultInfinity: true }).map((v) => ({ v, t: 'number' })),
  fc.boolean().map((v) => ({ v, t: 'boolean' })),
  fc.dictionary(fc.string(), jsonValue).map((v) => ({ v, t: 'object' })),
  fc.array(jsonValue).map((v) => ({ v, t: 'Array' })),
  fc.date({ noInvalidDate: true }).map((v) => ({ v, t: 'Date' })),
  fc.dictionary(fc.string(), fc.string()).map((o) => ({ v: new Map(Object.entries(o)), t: 'Map' })),
  fc.uniqueArray(fc.string()).map((a) => ({ v: new Set(a), t: 'Set' })),
  ...typedArrays,
);

describe('property: every supported value type round-trips through a keyless SPD (memory + string)', () => {
  it('addData → extractData and saveData → loadStringWithRandomKey preserve the value and its type', async () => {
    await fc.assert(fc.asyncProperty(fc.array(fc.tuple(name, plainValue), { minLength: 1, maxLength: 6 }), async (items) => {
      const secret = SPD.generateRandomKey();
      const spd = new SPD();
      await spd.setRandomKey(secret);
      const expected: Record<string, unknown> = {};
      for (const [n, { v }] of items) { await spd.addData(n, v); expected[n] = v; }
      const inMem = await spd.extractData();
      const s = await spd.saveData('');
      spd.destroy();
      const back = await SPD.loadStringWithRandomKey(s, secret);
      const fromString = await back.extractData();
      back.destroy();
      for (const out of [inMem, fromString]) {
        expect(Object.keys(out).sort()).toEqual(Object.keys(expected).sort());
        for (const k of Object.keys(expected)) {
          const e = expected[k] as any, o = out[k] as any;
          if (e instanceof Date) expect((o as Date).getTime()).toBe(e.getTime());
          else if (e instanceof Map) expect([...o.entries()]).toEqual([...e.entries()]);
          else if (e instanceof Set) expect([...o]).toEqual([...e]);
          else if (ArrayBuffer.isView(e)) {
            expect(o.constructor.name).toBe(e.constructor.name);
            const ea = Array.from(e as any), oa = Array.from(o as any);
            expect(oa.length).toBe(ea.length);
            for (let i = 0; i < ea.length; i++) expect(Object.is(oa[i], ea[i]) || (Number.isNaN(oa[i]) && Number.isNaN(ea[i]))).toBe(true);
          }
          else if (typeof e === 'number' && Object.is(e, -0)) expect(o === 0).toBe(true);
          else expect(o).toEqual(e);
        }
      }
    }), { numRuns: 25 });
  }, 120_000);
});

describe('property: Shamir', () => {
  it('any k-subset of n shares reconstructs; any (k-1)-subset is rejected', () => {
    fc.assert(fc.property(bytes(1, 64), fc.integer({ min: 2, max: 8 }), fc.integer({ min: 2, max: 8 }), fc.nat(), (secret, a, b, seed) => {
      const n = Math.max(a, b), k = Math.min(a, b);
      const shares = SPDShamir.split(secret, n, k);
      const idx = [...Array(n).keys()].sort(() => ((seed = (seed * 1103515245 + 12345) >>> 0) & 1) ? 1 : -1);
      expect(eq(SPDShamir.combine(idx.slice(0, k).map((i) => shares[i])), secret)).toBe(true);
      expect(() => SPDShamir.combine(idx.slice(0, k - 1).map((i) => shares[i]))).toThrow();
    }), { numRuns: 60 });
  });
});

describe('property: recipient envelopes', () => {
  it('every listed recipient opens, no unlisted one does, for 1..6 recipients', () => {
    const ids = Array.from({ length: 7 }, () => SPDRecipient.generateIdentity());
    fc.assert(fc.property(fc.integer({ min: 1, max: 6 }), (count) => {
      const master = SPD.generateRandomKey();
      const env = SPDRecipient.seal(master, ids.slice(0, count).map((i) => i.publicKey));
      for (let i = 0; i < count; i++) expect(eq(SPDRecipient.open(env, ids[i].secretKey), master)).toBe(true);
      expect(() => SPDRecipient.open(env, ids[6].secretKey)).toThrow();
    }), { numRuns: 12 });
  });
});

describe('property: WAL codec', () => {
  it('encode → replay yields the same entries, last write per name wins', () => {
    const entry = fc.record({ dataName: name, dataType: fc.constant('string' as const), hash: fc.stringMatching(/^[0-9a-f]{64}$/), nonce: bytes(24, 24), data: bytes(0, 300) });
    fc.assert(fc.property(fc.array(entry, { maxLength: 20 }), (entries) => {
      const parts = [walHeader(), ...entries.map(encodeWalRecord)];
      const buf = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
      let o = 0; for (const p of parts) { buf.set(p, o); o += p.length; }
      const target: typeof entries = [];
      expect(replayWalRecords(buf, target, (n) => n)).toBe(entries.length);
      const last = new Map(entries.map((e) => [e.dataName, e]));
      expect(target.length).toBe(last.size);
      for (const t of target) expect(eq(t.data, last.get(t.dataName)!.data)).toBe(true);
    }), { numRuns: 100 });
  });
});

describe('property: transport frames', () => {
  it('any payload (padded or not) round-trips and a replayed frame is rejected', async () => {
    for (const padding of [false, true]) {
      const id = await SPDTransport.generateServerIdentity();
      const { session: cs, clientHello } = await SPDTransport.clientConnect(id.publicKey, { v2: true, padding });
      const { session: ss, serverHello } = await SPDTransport.serverAccept(id, clientHello, undefined, padding);
      cs.processServerHello(serverHello!);
      await fc.assert(fc.asyncProperty(bytes(0, 4000), async (msg) => {
        const frame = cs.encrypt(msg);
        expect(eq(ss.decrypt(frame), msg)).toBe(true);
        expect(() => ss.decrypt(frame)).toThrow(); // replay
      }), { numRuns: 60 });
    }
  });
});

describe('property: encoding helpers agree with Node Buffer', () => {
  it('base64, base64url and hex', () => {
    fc.assert(fc.property(bytes(0, 2000), (b) => {
      expect(bytesToBase64(b)).toBe(Buffer.from(b).toString('base64'));
      expect(bytesToBase64Url(b)).toBe(Buffer.from(b).toString('base64url'));
      expect(bytesToHex(b)).toBe(Buffer.from(b).toString('hex'));
      expect(eq(base64ToBytes(bytesToBase64(b)), b)).toBe(true);
      expect(eq(base64UrlToBytes(bytesToBase64Url(b)), b)).toBe(true);
      expect(eq(hexToBytes(bytesToHex(b)), b)).toBe(true);
    }), { numRuns: 200 });
  });
});
