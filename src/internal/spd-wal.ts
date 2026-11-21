/**
 * SPD write-ahead log (WAL) record codec — Node-only file I/O stays in SPD.ts;
 * this module only encodes/decodes bytes.
 *
 * File layout: [4B magic "SPDW"][1B version] followed by records:
 *   [1B nameLen][name][1B typeLen][type][2B hashLen][hash]
 *   [3B nonceLen][nonce][8B dataLen][data]
 */

import type { EncryptedDataEntry, SupportedDataType } from '../types.js';
import { utf8ToBytes, bytesToUtf8 } from './portable-crypto.js';
import {
  u8Alloc, u8Concat, u8Equals, u8CopyInto,
  writeUInt8, readUInt8, writeUInt16LE, readUInt16LE,
  writeUIntLE3, readUIntLE3, writeBigUInt64LE, readBigUInt64LE,
} from './portable-binary.js';

export const WAL_MAGIC   = new Uint8Array([0x53, 0x50, 0x44, 0x57]); // "SPDW"
export const WAL_VERSION = 1;

/** The 5-byte header an empty WAL file starts with. */
export function walHeader(): Uint8Array {
  const hdr = u8Alloc(5);
  u8CopyInto(WAL_MAGIC, hdr, 0);
  writeUInt8(hdr, WAL_VERSION, 4);
  return hdr;
}

export function encodeWalRecord(entry: EncryptedDataEntry): Uint8Array {
  const nameBytes  = utf8ToBytes(entry.dataName);
  const typeBytes  = utf8ToBytes(entry.dataType);
  const hashBytes  = utf8ToBytes(entry.hash);
  const nlBuf  = u8Alloc(1);  writeUInt8(nlBuf, nameBytes.length);
  const tlBuf  = u8Alloc(1);  writeUInt8(tlBuf, typeBytes.length);
  const hlBuf  = u8Alloc(2);  writeUInt16LE(hlBuf, hashBytes.length);
  const nolBuf = u8Alloc(3);  writeUIntLE3(nolBuf, entry.nonce.length);
  const dlBuf  = u8Alloc(8);  writeBigUInt64LE(dlBuf, BigInt(entry.data.length));
  return u8Concat([nlBuf, nameBytes, tlBuf, typeBytes, hlBuf, hashBytes, nolBuf, entry.nonce, dlBuf, entry.data]);
}

/**
 * Replays every complete record in `buf` into `data` (a later record for the
 * same name overwrites the earlier entry). Returns the number replayed.
 *
 * A WAL can end in a torn/incomplete record after a crash mid-append — the
 * exact case it exists to survive — so every length field and the payload it
 * describes is bounds-checked BEFORE being read, and the first incomplete or
 * malformed record (including a name `validateName` rejects) stops replay,
 * keeping what replayed cleanly before it.
 */
export function replayWalRecords(
  buf: Uint8Array,
  data: EncryptedDataEntry[],
  validateName: (name: string) => string
): number {
  if (buf.length < 5) return 0;
  if (!u8Equals(buf.subarray(0, 4), WAL_MAGIC)) return 0;

  let pos = 5; // skip magic + version byte
  let count = 0;
  // name->index map instead of a per-record findIndex: O(N+M), not O(N*M).
  const nameToIdx = new Map(data.map((e, i) => [e.dataName, i] as const));
  while (pos < buf.length) {
    try {
      if (pos + 1 > buf.length) break;
      const nameLen = readUInt8(buf, pos); pos += 1;
      if (pos + nameLen > buf.length) break;
      // WAL names are plaintext (no AEAD over the WAL file) — validate before
      // they can reach a downstream temp-file path.
      const dataName = validateName(bytesToUtf8(buf.subarray(pos, pos + nameLen))); pos += nameLen;

      if (pos + 1 > buf.length) break;
      const typeLen = readUInt8(buf, pos); pos += 1;
      if (pos + typeLen > buf.length) break;
      const dataType = bytesToUtf8(buf.subarray(pos, pos + typeLen)) as SupportedDataType; pos += typeLen;

      if (pos + 2 > buf.length) break;
      const hashLen = readUInt16LE(buf, pos); pos += 2;
      if (pos + hashLen > buf.length) break;
      const hash = bytesToUtf8(buf.subarray(pos, pos + hashLen)); pos += hashLen;

      if (pos + 3 > buf.length) break;
      const nonceLen = readUIntLE3(buf, pos); pos += 3;
      if (pos + nonceLen > buf.length) break;
      const nonce = buf.subarray(pos, pos + nonceLen); pos += nonceLen;

      if (pos + 8 > buf.length) break;
      const dataLen = Number(readBigUInt64LE(buf, pos)); pos += 8;
      if (dataLen < 0 || pos + dataLen > buf.length) break;
      const payload = buf.subarray(pos, pos + dataLen); pos += dataLen;

      const entry: EncryptedDataEntry = { dataName, nonce, data: payload, hash, dataType };
      const existing = nameToIdx.get(dataName);
      if (existing !== undefined) {
        data[existing] = entry;
      } else {
        nameToIdx.set(dataName, data.length);
        data.push(entry);
      }
      count++;
    } catch {
      break;
    }
  }
  return count;
}
