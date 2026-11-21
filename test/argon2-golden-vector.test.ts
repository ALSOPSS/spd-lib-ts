/**
 * Golden-vector test: proves the pure-JS Argon2id fallback (src/internal/spd-crypto.ts,
 * backed by @noble/hashes) AND the WASM tier (backed by hash-wasm) both produce
 * byte-identical output to the native `argon2` npm package for the same (password,
 * salt, memory, time, parallelism, hashLen). This is what the three-tier `argon2idRaw`
 * relies on: it prefers native argon2 when loadable, then hash-wasm's WASM
 * implementation, and only falls back to pure-JS if WASM itself can't instantiate —
 * all three paths must be interchangeable.
 *
 * Uses small, fast KDF cost parameters deliberately: measured on this machine, pure-JS
 * Argon2id (@noble/hashes) is ~15-20x slower than the native addon even at the
 * "standard" production profile (128 MiB/6 iter took ~13-17s pure-JS vs ~0.8s native;
 * hash-wasm's WASM tier measured ~840ms at the same profile — ~6x faster than pure-JS,
 * still real overhead worth avoiding in a fast test). Argon2id's byte-for-byte
 * behavior is a pure function of its parameters — cost parameters don't change
 * *correctness*, only *time* — so proving equality at cheap parameters is sufficient;
 * re-running the full production profiles here would only make this test slow
 * without adding confidence.
 */
import { describe, it, expect } from 'vitest';
import * as argon2 from 'argon2';
import { argon2idPureJs, argon2idWasmTier, argon2idNodeBuiltin, argon2idRaw } from '../src/internal/spd-crypto';

const PASSWORD = 'correct horse battery staple';
const SALT = Buffer.from('0123456789abcdef0123456789abcdef', 'utf8').subarray(0, 32);

async function nativeArgon2(memory: number, time: number, parallelism: number, hashLen: number): Promise<Buffer> {
  return argon2.hash(PASSWORD, {
    salt: Buffer.from(SALT),
    type: argon2.argon2id,
    raw: true,
    memoryCost: memory,
    timeCost: time,
    parallelism,
    hashLength: hashLen,
  });
}

describe('argon2idPureJs golden vectors (native argon2 vs @noble/hashes)', () => {
  // Cheap cost parameters (8 MiB, 1 iteration) — enough to exercise memory-hard
  // mixing and multi-lane logic without the ~15-20x pure-JS slowdown making the
  // test itself slow. Cost parameters don't affect byte-for-byte correctness.
  const memory = 8192; // 8 MiB
  const time = 1;
  const hashLens = [
    { label: 'v27+ (96B)', len: 96 },
    { label: 'v26 (64B)', len: 64 },
  ];
  const parallelisms = [1, 4];

  for (const hl of hashLens) {
    for (const p of parallelisms) {
      it(`${hl.label}, parallelism=${p}`, async () => {
        const [native, pureJs] = await Promise.all([
          nativeArgon2(memory, time, p, hl.len),
          argon2idPureJs(PASSWORD, new Uint8Array(SALT), { memory, time, parallelism: p, hashLen: hl.len }),
        ]);
        expect(Buffer.compare(native, pureJs)).toBe(0);
      }, 15_000);
    }
  }
});

describe('argon2idWasmTier golden vectors (native argon2 vs hash-wasm)', () => {
  const memory = 8192; // 8 MiB
  const time = 1;
  const hashLens = [
    { label: 'v27+ (96B)', len: 96 },
    { label: 'v26 (64B)', len: 64 },
  ];
  const parallelisms = [1, 4];

  for (const hl of hashLens) {
    for (const p of parallelisms) {
      it(`${hl.label}, parallelism=${p}`, async () => {
        const [native, wasm] = await Promise.all([
          nativeArgon2(memory, time, p, hl.len),
          argon2idWasmTier(PASSWORD, new Uint8Array(SALT), { memory, time, parallelism: p, hashLen: hl.len }),
        ]);
        expect(Buffer.compare(native, Buffer.from(wasm))).toBe(0);
      }, 15_000);
    }
  }
});

const HAS_NODE_ARGON2 = typeof (await import('node:crypto') as { argon2?: unknown }).argon2 === 'function';

describe.skipIf(!HAS_NODE_ARGON2)('argon2idNodeBuiltin golden vectors (native argon2 vs node:crypto)', () => {
  const memory = 8192;
  const time = 1;
  for (const len of [96, 64]) {
    for (const p of [1, 4]) {
      it(`hashLen=${len}, parallelism=${p}`, async () => {
        const opts = { memory, time, parallelism: p, hashLen: len };
        const [native, builtin, viaRaw] = await Promise.all([
          nativeArgon2(memory, time, p, len),
          argon2idNodeBuiltin(PASSWORD, new Uint8Array(SALT), opts),
          argon2idRaw(PASSWORD, new Uint8Array(SALT), opts),
        ]);
        expect(builtin).not.toBeNull();
        expect(Buffer.compare(native, builtin!)).toBe(0);
        expect(Buffer.compare(native, viaRaw)).toBe(0);
      }, 15_000);
    }
  }

  it('matches for binary (Uint8Array) passwords too', async () => {
    const pw = new Uint8Array([0, 255, 1, 254, 2, 253, 0xc3, 0x28]); // includes invalid UTF-8
    const opts = { memory, time, parallelism: 1, hashLen: 96 };
    const [builtin, wasm] = await Promise.all([
      argon2idNodeBuiltin(pw, new Uint8Array(SALT), opts),
      argon2idWasmTier(pw, new Uint8Array(SALT), opts),
    ]);
    expect(Buffer.compare(builtin!, wasm)).toBe(0);
  }, 15_000);
});
