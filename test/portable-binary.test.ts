/**
 * portable-binary.ts's own header comment claims: "Verified byte-identical
 * to real Node Buffer output for every function here before any call site
 * was converted — see test/portable-binary.test.ts." That file never
 * actually existed until now — this codebase's entire binary file format
 * (the v29 `.spd` wire format: length prefixes, offsets, entry framing) is
 * built on these functions, exercised only indirectly through SPD.ts's own
 * tests, with no direct verification against the real Buffer semantics the
 * header comment claims. This file provides that real verification.
 */
import { describe, it, expect } from 'vitest';
import * as pb from '../src/internal/portable-binary';

describe('portable-binary: u8Alloc / u8Concat / u8Equals / u8CopyInto', () => {
  it('u8Alloc returns a zero-filled Uint8Array of the requested length', () => {
    const buf = pb.u8Alloc(16);
    expect(buf.length).toBe(16);
    expect(buf.every((b) => b === 0)).toBe(true);
  });

  it('u8Concat matches Buffer.concat byte-for-byte', () => {
    const parts = [new Uint8Array([1, 2]), new Uint8Array([3, 4, 5]), new Uint8Array([])];
    const got = pb.u8Concat(parts);
    const want = Buffer.concat(parts.map((p) => Buffer.from(p)));
    expect(Buffer.from(got)).toEqual(want);
  });

  it('u8Equals matches Buffer.prototype.equals', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3]);
    const c = new Uint8Array([1, 2, 4]);
    const d = new Uint8Array([1, 2]);
    expect(pb.u8Equals(a, b)).toBe(Buffer.from(a).equals(Buffer.from(b)));
    expect(pb.u8Equals(a, c)).toBe(Buffer.from(a).equals(Buffer.from(c)));
    expect(pb.u8Equals(a, d)).toBe(Buffer.from(a).equals(Buffer.from(d)));
    expect(pb.u8Equals(a, b)).toBe(true);
    expect(pb.u8Equals(a, c)).toBe(false);
  });

  it('u8CopyInto matches Buffer.prototype.copy(target, targetStart)', () => {
    const source = new Uint8Array([9, 9, 9]);
    const target1 = new Uint8Array(6);
    const target2 = Buffer.alloc(6);
    pb.u8CopyInto(source, target1, 2);
    Buffer.from(source).copy(target2, 2);
    expect(Buffer.from(target1)).toEqual(target2);
  });
});

describe('portable-binary: 8-bit read/write', () => {
  it('writeUInt8/readUInt8 matches Buffer.writeUInt8/readUInt8', () => {
    for (const value of [0, 1, 127, 255]) {
      const buf = pb.u8Alloc(4);
      const nodeBuf = Buffer.alloc(4);
      pb.writeUInt8(buf, value, 1);
      nodeBuf.writeUInt8(value, 1);
      expect(Buffer.from(buf)).toEqual(nodeBuf);
      expect(pb.readUInt8(buf, 1)).toBe(nodeBuf.readUInt8(1));
    }
  });
});

describe('portable-binary: 16-bit read/write', () => {
  it('writeUInt16LE/readUInt16LE matches Buffer LE variants', () => {
    for (const value of [0, 1, 256, 65535]) {
      const buf = pb.u8Alloc(4);
      const nodeBuf = Buffer.alloc(4);
      pb.writeUInt16LE(buf, value, 1);
      nodeBuf.writeUInt16LE(value, 1);
      expect(Buffer.from(buf)).toEqual(nodeBuf);
      expect(pb.readUInt16LE(buf, 1)).toBe(nodeBuf.readUInt16LE(1));
    }
  });

  it('writeUInt16BE/readUInt16BE matches Buffer BE variants', () => {
    for (const value of [0, 1, 256, 65535]) {
      const buf = pb.u8Alloc(4);
      const nodeBuf = Buffer.alloc(4);
      pb.writeUInt16BE(buf, value, 1);
      nodeBuf.writeUInt16BE(value, 1);
      expect(Buffer.from(buf)).toEqual(nodeBuf);
      expect(pb.readUInt16BE(buf, 1)).toBe(nodeBuf.readUInt16BE(1));
    }
  });

  it('defaults offset to 0', () => {
    const buf = pb.u8Alloc(2);
    pb.writeUInt16LE(buf, 258);
    expect(pb.readUInt16LE(buf)).toBe(258);
  });
});

describe('portable-binary: 32-bit read/write', () => {
  it('writeUInt32LE/readUInt32LE matches Buffer LE variants', () => {
    for (const value of [0, 1, 65536, 4294967295]) {
      const buf = pb.u8Alloc(8);
      const nodeBuf = Buffer.alloc(8);
      pb.writeUInt32LE(buf, value, 2);
      nodeBuf.writeUInt32LE(value, 2);
      expect(Buffer.from(buf)).toEqual(nodeBuf);
      expect(pb.readUInt32LE(buf, 2)).toBe(nodeBuf.readUInt32LE(2));
    }
  });

  it('readUInt32BE matches Buffer.readUInt32BE', () => {
    for (const value of [0, 1, 65536, 4294967295]) {
      const nodeBuf = Buffer.alloc(8);
      nodeBuf.writeUInt32BE(value, 2);
      const buf = new Uint8Array(nodeBuf);
      expect(pb.readUInt32BE(buf, 2)).toBe(nodeBuf.readUInt32BE(2));
    }
  });
});

describe('portable-binary: 3-byte LE (writeUIntLE3 / readUIntLE3)', () => {
  it('matches Buffer.writeUIntLE(value, offset, 3) / readUIntLE(offset, 3)', () => {
    for (const value of [0, 1, 255, 256, 65535, 65536, 0xffffff]) {
      const buf = pb.u8Alloc(5);
      const nodeBuf = Buffer.alloc(5);
      pb.writeUIntLE3(buf, value, 1);
      nodeBuf.writeUIntLE(value, 1, 3);
      expect(Buffer.from(buf)).toEqual(nodeBuf);
      expect(pb.readUIntLE3(buf, 1)).toBe(nodeBuf.readUIntLE(1, 3));
    }
  });
});

describe('portable-binary: 64-bit BigInt read/write', () => {
  it('writeBigUInt64LE/readBigUInt64LE matches Buffer LE variants', () => {
    for (const value of [0n, 1n, 4294967295n, 18446744073709551615n]) {
      const buf = pb.u8Alloc(16);
      const nodeBuf = Buffer.alloc(16);
      pb.writeBigUInt64LE(buf, value, 4);
      nodeBuf.writeBigUInt64LE(value, 4);
      expect(Buffer.from(buf)).toEqual(nodeBuf);
      expect(pb.readBigUInt64LE(buf, 4)).toBe(nodeBuf.readBigUInt64LE(4));
    }
  });

  it('writeBigUInt64BE/readBigUInt64BE matches Buffer BE variants', () => {
    for (const value of [0n, 1n, 4294967295n, 18446744073709551615n]) {
      const buf = pb.u8Alloc(16);
      const nodeBuf = Buffer.alloc(16);
      pb.writeBigUInt64BE(buf, value, 4);
      nodeBuf.writeBigUInt64BE(value, 4);
      expect(Buffer.from(buf)).toEqual(nodeBuf);
      expect(pb.readBigUInt64BE(buf, 4)).toBe(nodeBuf.readBigUInt64BE(4));
    }
  });

  it('round-trips a value at the exact width used for .spd file-size headers (8-byte LE)', () => {
    const bigFileSize = 3_000_000_000n; // > 2 GiB — exercises the "large file" streaming path's header
    const buf = pb.u8Alloc(8);
    pb.writeBigUInt64LE(buf, bigFileSize);
    expect(pb.readBigUInt64LE(buf)).toBe(bigFileSize);
  });
});
