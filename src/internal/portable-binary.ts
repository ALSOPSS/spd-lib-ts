/**
 * Portable replacements for the handful of Node `Buffer`-only instance
 * methods this codebase used for binary length-prefix framing
 * (`writeUInt*`/`readUInt*`, `equals`, `copy`) plus `Buffer.alloc`/`.from`/
 * `.concat` static equivalents — everything else (`.fill`, `.subarray`,
 * `.slice`) is already a native `Uint8Array` method and needs no wrapper.
 *
 * All integer read/write helpers operate in-place on a plain `Uint8Array`
 * via a `DataView`, matching Buffer's exact semantics (byte order, range,
 * truncation-on-overflow behavior is intentionally NOT replicated — every
 * call site in this codebase writes a length that's already validated to
 * fit, so Buffer's silent-truncation edge case was never relied upon).
 * Verified byte-identical to real Node Buffer output for every function
 * here before any call site was converted — see
 * test/portable-binary.test.ts.
 */

export function u8Alloc(len: number): Uint8Array {
  return new Uint8Array(len);
}

export function u8Concat(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

export function u8Equals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Buffer.prototype.copy(target, targetStart) equivalent (full-source-range only — the only form this codebase uses). */
export function u8CopyInto(source: Uint8Array, target: Uint8Array, targetStart: number): void {
  target.set(source, targetStart);
}

export function writeUInt8(buf: Uint8Array, value: number, offset = 0): void {
  buf[offset] = value & 0xff;
}

export function readUInt8(buf: Uint8Array, offset = 0): number {
  return buf[offset];
}

export function writeUInt16LE(buf: Uint8Array, value: number, offset = 0): void {
  new DataView(buf.buffer, buf.byteOffset, buf.byteLength).setUint16(offset, value, true);
}

export function readUInt16LE(buf: Uint8Array, offset = 0): number {
  return new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint16(offset, true);
}

export function writeUInt16BE(buf: Uint8Array, value: number, offset = 0): void {
  new DataView(buf.buffer, buf.byteOffset, buf.byteLength).setUint16(offset, value, false);
}

export function readUInt16BE(buf: Uint8Array, offset = 0): number {
  return new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint16(offset, false);
}

export function writeUInt32LE(buf: Uint8Array, value: number, offset = 0): void {
  new DataView(buf.buffer, buf.byteOffset, buf.byteLength).setUint32(offset, value, true);
}

export function readUInt32LE(buf: Uint8Array, offset = 0): number {
  return new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(offset, true);
}

export function readUInt32BE(buf: Uint8Array, offset = 0): number {
  return new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(offset, false);
}

/** Buffer.writeUIntLE(value, offset, 3) — always 3 bytes, the only byteLength this codebase uses. */
export function writeUIntLE3(buf: Uint8Array, value: number, offset = 0): void {
  buf[offset] = value & 0xff;
  buf[offset + 1] = (value >>> 8) & 0xff;
  buf[offset + 2] = (value >>> 16) & 0xff;
}

/** Buffer.readUIntLE(offset, 3) — always 3 bytes, the only byteLength this codebase uses. */
export function readUIntLE3(buf: Uint8Array, offset = 0): number {
  return buf[offset] | (buf[offset + 1] << 8) | (buf[offset + 2] << 16);
}

export function writeBigUInt64LE(buf: Uint8Array, value: bigint, offset = 0): void {
  new DataView(buf.buffer, buf.byteOffset, buf.byteLength).setBigUint64(offset, value, true);
}

export function readBigUInt64LE(buf: Uint8Array, offset = 0): bigint {
  return new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getBigUint64(offset, true);
}

export function writeBigUInt64BE(buf: Uint8Array, value: bigint, offset = 0): void {
  new DataView(buf.buffer, buf.byteOffset, buf.byteLength).setBigUint64(offset, value, false);
}

export function readBigUInt64BE(buf: Uint8Array, offset = 0): bigint {
  return new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getBigUint64(offset, false);
}
