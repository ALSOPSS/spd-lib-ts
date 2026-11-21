/**
 * Verifies the browser zlib module (native CompressionStream/DecompressionStream,
 * format 'deflate' = RFC 1950) is byte-compatible with real Node zlib in both
 * directions, so .spd data written by the Node build is readable by the
 * browser build and vice versa. Node >= 18 exposes the same Web Streams
 * codecs, which is what lets this run under vitest.
 */
import { describe, it, expect } from 'vitest';
import * as zlib from 'zlib';
import { randomBytes } from 'crypto';
import { deflate, inflate, deflateSync, inflateSync, createDeflate, createInflate } from '../src/internal/portable-zlib.browser';

const rnd = (n: number) => new Uint8Array(randomBytes(n)); // not getRandomValues: it caps at 64 KiB per call
const eq = (a: Uint8Array, b: Uint8Array) => Buffer.from(a).equals(Buffer.from(b));

describe('portable-zlib (browser): cross-compatibility with real Node zlib', () => {
  it('browser deflate output is readable by Node inflateSync and carries the zlib header', async () => {
    const data = new TextEncoder().encode('hello zlib '.repeat(200));
    const out = await deflate(data);
    expect(out[0]).toBe(0x78);
    expect(eq(zlib.inflateSync(out), data)).toBe(true);
  });

  it('Node deflateSync output (every level) is readable by browser inflate', async () => {
    const data = rnd(5000);
    for (const level of [1, 6, 9]) {
      expect(eq(await inflate(new Uint8Array(zlib.deflateSync(data, { level }))), data)).toBe(true);
    }
  });

  it('round-trips empty and binary input', async () => {
    for (const data of [new Uint8Array(0), rnd(1), rnd(70000)]) {
      expect(eq(await inflate(await deflate(data)), data)).toBe(true);
    }
  });

  it('rejects corrupt input with an Error (not a hang or a silent partial result)', async () => {
    const good = await deflate(rnd(2000));
    const bad = new Uint8Array(good); bad[5] ^= 0xff; bad[good.length - 3] ^= 0xff;
    await expect(inflate(bad)).rejects.toThrow(/invalid or corrupt/);
    await expect(inflate(rnd(40))).rejects.toThrow();
  });

  it('maxOutputLength aborts a decompression bomb early with RangeError and passes under the cap', async () => {
    const bomb = new Uint8Array(zlib.deflateSync(Buffer.alloc(8 * 1024 * 1024)));
    expect(bomb.length).toBeLessThan(64 * 1024);
    await expect(inflate(bomb, { maxOutputLength: 1024 * 1024 })).rejects.toThrow(RangeError);
    expect((await inflate(bomb, { maxOutputLength: 8 * 1024 * 1024 })).length).toBe(8 * 1024 * 1024);
  });

  it('Node-only sync/streaming entry points throw a clear "requires Node.js" error', () => {
    expect(() => deflateSync(new Uint8Array(1))).toThrow(/requires Node\.js/);
    expect(() => inflateSync(new Uint8Array(1))).toThrow(/requires Node\.js/);
    expect(() => createDeflate()).toThrow(/requires Node\.js/);
    expect(() => createInflate()).toThrow(/requires Node\.js/);
  });
});
