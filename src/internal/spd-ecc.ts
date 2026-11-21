/**
 * Bit-rot / silent-corruption resilience for `.spd` files — a `<file>.spd.ecc`
 * sidecar carrying Reed-Solomon parity data.
 *
 * Design principle (deliberate, not incidental): parity is computed over the
 * `.spd` file's raw on-disk bytes as an opaque blob, AFTER encryption/framing
 * is already final. It never touches plaintext. This matters for two
 * independent reasons:
 *   1. Security — adding structured, predictable redundancy to plaintext
 *      before encryption risks leaking plaintext structure through the
 *      ciphertext depending on the AEAD mode's properties. Wrapping already-
 *      encrypted bytes (which are indistinguishable from random) carries no
 *      such risk — the parity data is just as opaque as the ciphertext it
 *      protects.
 *   2. Compatibility — `saveToFileStreaming` embeds a byte-offset tail index
 *      (see SPD.ts's embedIndexInFile) and `getEntry()`/the `.spdi` sidecar
 *      do fixed-offset random-access reads into the `.spd` file. Any encoding
 *      that reflows or interleaves the file's own bytes would break that
 *      random access. Keeping parity entirely in a separate sidecar file
 *      means the `.spd` format, its offset index, and every existing
 *      read/write path are completely unmodified — this feature is 100%
 *      additive and opt-in.
 *
 * Sidecar format `<path>.ecc`:
 *   [4B magic "SPDE"][1B version=1][4B blockSize LE][1B dataShards][1B parityShards]
 *   [8B originalFileSize LE][32B random integrity key]
 *   [32B HMAC-SHA3-256 of everything from blockSize through the last block record]
 *   per block:
 *     [4B actualBlockLen LE]  (last block may be shorter than blockSize; a
 *      full block's length can equal blockSize itself — e.g. the default
 *      64 KiB block size is exactly 65536, which overflows a 16-bit field —
 *      so this must be wide enough to hold blockSize itself, not blockSize-1)
 *     per shard (dataShards + parityShards):
 *       [32B SHA3-256 checksum of this shard's bytes]
 *       [shardLen bytes of parity data]  (only for the parity shards — data
 *        shard bytes are NOT duplicated here, they live in the original file;
 *        only their checksum is stored, to detect which shard rotted)
 *
 * The integrity key/HMAC protect the parity file itself from corruption —
 * unrelated to the `.spd` file's own passcode/MAC. This sidecar carries no
 * secrets (it's parity over already-encrypted bytes) so it needs no passcode.
 */
import { u8Alloc, u8Concat, writeUInt32LE, readUInt32LE, writeBigUInt64LE, readBigUInt64LE } from './portable-binary.js';
import { createHash, createHmac, randomBytes, timingSafeEqual } from './portable-crypto.js';
import { rsEncode, rsReconstruct } from './reed-solomon.js';

const ECC_MAGIC = new Uint8Array([0x53, 0x50, 0x44, 0x45]); // "SPDE"
const ECC_VERSION = 1;

export const DEFAULT_BLOCK_SIZE = 64 * 1024; // 64 KiB per block
export const DEFAULT_DATA_SHARDS = 16;
export const DEFAULT_PARITY_SHARDS = 4; // tolerates up to 4 of 20 shards (20%) corrupted per block

export interface EccOptions {
  blockSize?: number;
  dataShards?: number;
  parityShards?: number;
}

export interface EccBuildResult {
  sidecar: Uint8Array;
  blockCount: number;
}

interface BlockLayout {
  actualLen: number;
  shardLen: number;
}

function sha256(data: Uint8Array): Uint8Array {
  return createHash('sha3-256').update(data).digest();
}

function splitIntoShards(block: Uint8Array, dataShards: number): { shards: Uint8Array[]; shardLen: number } {
  const shardLen = Math.ceil(block.length / dataShards) || 1;
  const shards: Uint8Array[] = [];
  for (let i = 0; i < dataShards; i++) {
    const shard = u8Alloc(shardLen); // zero-padded — deterministic given actualLen is stored separately
    const start = i * shardLen;
    const end = Math.min(start + shardLen, block.length);
    if (end > start) shard.set(block.subarray(start, end));
    shards.push(shard);
  }
  return { shards, shardLen };
}

/**
 * Builds a parity sidecar for `fileBytes`. Pure function — no file I/O —
 * so it's independently testable and usable from both Node and browser builds.
 */
export function buildEccSidecar(fileBytes: Uint8Array, options: EccOptions = {}): EccBuildResult {
  const blockSize = options.blockSize ?? DEFAULT_BLOCK_SIZE;
  const dataShards = options.dataShards ?? DEFAULT_DATA_SHARDS;
  const parityShards = options.parityShards ?? DEFAULT_PARITY_SHARDS;
  if (blockSize < dataShards) throw new Error('spd-ecc: blockSize must be >= dataShards');
  if (dataShards < 1 || parityShards < 1) throw new Error('spd-ecc: dataShards and parityShards must both be >= 1');
  if (dataShards + parityShards > 255) throw new Error('spd-ecc: dataShards + parityShards must be <= 255');

  const blockCount = Math.max(1, Math.ceil(fileBytes.length / blockSize));
  const blockRecords: Uint8Array[] = [];

  for (let b = 0; b < blockCount; b++) {
    const start = b * blockSize;
    const end = Math.min(start + blockSize, fileBytes.length);
    const block = fileBytes.subarray(start, end);
    const { shards, shardLen } = splitIntoShards(block, dataShards);
    const parity = rsEncode(shards, parityShards);

    const lenBuf = u8Alloc(4);
    writeUInt32LE(lenBuf, block.length);

    const parts: Uint8Array[] = [lenBuf];
    for (const s of shards) {
      parts.push(sha256(s)); // checksum only — data shard bytes live in the original file
    }
    for (const p of parity) {
      parts.push(sha256(p), p); // checksum + actual parity bytes
    }
    blockRecords.push(u8Concat(parts));
  }

  const blockSizeBuf = u8Alloc(4); writeUInt32LE(blockSizeBuf, blockSize);
  const dataShardsBuf = u8Alloc(1); dataShardsBuf[0] = dataShards;
  const parityShardsBuf = u8Alloc(1); parityShardsBuf[0] = parityShards;
  const fileSizeBuf = u8Alloc(8); writeBigUInt64LE(fileSizeBuf, BigInt(fileBytes.length));
  const integrityKey = randomBytes(32);

  const signedBody = u8Concat([blockSizeBuf, dataShardsBuf, parityShardsBuf, fileSizeBuf, integrityKey, ...blockRecords]);
  const hmac = createHmac('sha3-256', integrityKey).update(signedBody).digest();

  const sidecar = u8Concat([ECC_MAGIC, new Uint8Array([ECC_VERSION]), signedBody, hmac]);
  return { sidecar, blockCount };
}

interface ParsedBlockRecord {
  actualLen: number;
  shardLen: number;
  dataChecksums: Uint8Array[];
  parityChecksums: Uint8Array[];
  parityShards: Uint8Array[];
}

interface ParsedSidecar {
  blockSize: number;
  dataShards: number;
  parityShards: number;
  originalFileSize: number;
  blocks: ParsedBlockRecord[];
}

function parseEccSidecar(sidecar: Uint8Array): ParsedSidecar {
  if (sidecar.length < 4 + 1 + 4 + 1 + 1 + 8 + 32 + 32) {
    throw new Error('spd-ecc: parity file is too short / corrupt');
  }
  let offset = 0;
  const magic = sidecar.subarray(0, 4);
  if (magic[0] !== ECC_MAGIC[0] || magic[1] !== ECC_MAGIC[1] || magic[2] !== ECC_MAGIC[2] || magic[3] !== ECC_MAGIC[3]) {
    throw new Error('spd-ecc: not a valid .ecc parity file (bad magic)');
  }
  offset += 4;
  const version = sidecar[offset]; offset += 1;
  if (version !== ECC_VERSION) throw new Error(`spd-ecc: unsupported parity file version ${version}`);

  const signedBodyStart = offset;
  const blockSize = readUInt32LE(sidecar, offset); offset += 4;
  const dataShards = sidecar[offset]; offset += 1;
  const parityShardCount = sidecar[offset]; offset += 1;
  const originalFileSize = Number(readBigUInt64LE(sidecar, offset)); offset += 8;
  const integrityKey = sidecar.subarray(offset, offset + 32); offset += 32;
  if (blockSize === 0 || dataShards === 0 || parityShardCount === 0 || !Number.isSafeInteger(originalFileSize)) {
    throw new Error('spd-ecc: parity file header is invalid');
  }

  const hmacStart = sidecar.length - 32;
  const signedBody = sidecar.subarray(signedBodyStart, hmacStart);
  const storedHmac = sidecar.subarray(hmacStart);
  const expectedHmac = createHmac('sha3-256', integrityKey).update(signedBody).digest();
  if (!timingSafeEqual(expectedHmac, storedHmac)) {
    throw new Error('spd-ecc: parity file integrity check failed — .ecc sidecar itself is corrupted');
  }

  const blocks: ParsedBlockRecord[] = [];
  const blockCount = Math.max(1, Math.ceil(originalFileSize / blockSize));
  const need = (n: number): void => {
    if (offset + n > hmacStart) throw new Error('spd-ecc: parity file is truncated');
  };
  for (let b = 0; b < blockCount; b++) {
    need(4);
    const actualLen = readUInt32LE(sidecar, offset); offset += 4;
    if (actualLen > blockSize) throw new Error('spd-ecc: parity block record is invalid');
    const shardLen = Math.ceil((actualLen || 1) / dataShards) || 1;
    need(dataShards * 32 + parityShardCount * (32 + shardLen));

    const dataChecksums: Uint8Array[] = [];
    for (let i = 0; i < dataShards; i++) {
      dataChecksums.push(sidecar.subarray(offset, offset + 32)); offset += 32;
    }
    const parityChecksums: Uint8Array[] = [];
    const parityShards: Uint8Array[] = [];
    for (let i = 0; i < parityShardCount; i++) {
      parityChecksums.push(sidecar.subarray(offset, offset + 32)); offset += 32;
      parityShards.push(sidecar.subarray(offset, offset + shardLen)); offset += shardLen;
    }
    blocks.push({ actualLen, shardLen, dataChecksums, parityChecksums, parityShards });
  }

  return { blockSize, dataShards, parityShards: parityShardCount, originalFileSize, blocks };
}

export interface EccVerifyResult {
  ok: boolean;
  /** true if fileBytes.length didn't match what the sidecar was built for — repair is impossible. */
  sizeMismatch: boolean;
  corruptedBlocks: number[];
  /** Corrupted blocks where MORE shards rotted than parityShards can recover — unrecoverable. */
  unrecoverableBlocks: number[];
}

/** Checks `fileBytes` against a previously-built sidecar without modifying anything. */
export function verifyWithEccSidecar(fileBytes: Uint8Array, sidecar: Uint8Array): EccVerifyResult {
  const parsed = parseEccSidecar(sidecar);
  if (fileBytes.length !== parsed.originalFileSize) {
    return { ok: false, sizeMismatch: true, corruptedBlocks: [], unrecoverableBlocks: [] };
  }

  const corruptedBlocks: number[] = [];
  const unrecoverableBlocks: number[] = [];

  for (let b = 0; b < parsed.blocks.length; b++) {
    const rec = parsed.blocks[b];
    const start = b * parsed.blockSize;
    const end = start + rec.actualLen;
    const block = fileBytes.subarray(start, end);
    const { shards } = splitIntoShards(block, parsed.dataShards);

    let badShardCount = 0;
    for (let i = 0; i < parsed.dataShards; i++) {
      if (!timingSafeEqual(sha256(shards[i]), rec.dataChecksums[i])) badShardCount++;
    }
    if (badShardCount > 0) {
      corruptedBlocks.push(b);
      if (badShardCount > parsed.parityShards) unrecoverableBlocks.push(b);
    }
  }

  return { ok: corruptedBlocks.length === 0, sizeMismatch: false, corruptedBlocks, unrecoverableBlocks };
}

export interface EccRepairResult {
  repaired: boolean;
  blocksChecked: number;
  blocksCorrupted: number;
  blocksRepaired: number;
  unrecoverableBlocks: number[];
  /** Present only when repaired === true. */
  repairedBytes?: Uint8Array;
}

/**
 * Attempts to repair `fileBytes` using `sidecar`. Returns the repaired bytes
 * (only the corrupted blocks are actually rewritten; everything else is
 * copied through unchanged) when every corrupted block was within the
 * parity budget. Never mutates the input array.
 */
export function repairWithEccSidecar(fileBytes: Uint8Array, sidecar: Uint8Array): EccRepairResult {
  const parsed = parseEccSidecar(sidecar);
  if (fileBytes.length !== parsed.originalFileSize) {
    throw new Error(
      `spd-ecc: file size (${fileBytes.length}) does not match the size the parity file was built for ` +
      `(${parsed.originalFileSize}) — the file was likely replaced, not just bit-rotted. Cannot repair.`
    );
  }

  const out = new Uint8Array(fileBytes); // copy — never mutate caller's buffer
  let blocksCorrupted = 0;
  let blocksRepaired = 0;
  const unrecoverableBlocks: number[] = [];

  for (let b = 0; b < parsed.blocks.length; b++) {
    const rec = parsed.blocks[b];
    const start = b * parsed.blockSize;
    const end = start + rec.actualLen;
    const block = out.subarray(start, end);
    const { shards, shardLen } = splitIntoShards(block, parsed.dataShards);

    const badDataShardIdx: number[] = [];
    for (let i = 0; i < parsed.dataShards; i++) {
      if (!timingSafeEqual(sha256(shards[i]), rec.dataChecksums[i])) badDataShardIdx.push(i);
    }
    // Also check parity shards themselves for rot — a corrupted parity shard
    // just means "don't use this one for reconstruction," not "block is unrecoverable"
    // as long as enough OTHER shards (data + remaining parity) still total >= dataShards.
    const goodParityIdx: number[] = [];
    for (let i = 0; i < parsed.parityShards; i++) {
      if (timingSafeEqual(sha256(rec.parityShards[i]), rec.parityChecksums[i])) goodParityIdx.push(i);
    }

    if (badDataShardIdx.length === 0) continue; // block is fine

    blocksCorrupted++;

    const survivingIndices: number[] = [];
    const survivingShards: Uint8Array[] = [];
    for (let i = 0; i < parsed.dataShards; i++) {
      if (!badDataShardIdx.includes(i)) { survivingIndices.push(i); survivingShards.push(shards[i]); }
    }
    for (const i of goodParityIdx) {
      survivingIndices.push(parsed.dataShards + i);
      survivingShards.push(rec.parityShards[i]);
    }

    if (survivingIndices.length < parsed.dataShards) {
      unrecoverableBlocks.push(b);
      continue;
    }

    const recovered = rsReconstruct(parsed.dataShards, parsed.parityShards, survivingIndices, survivingShards);
    const rebuiltBlock = u8Concat(recovered).subarray(0, rec.actualLen);

    // Verify the repair actually reproduces the expected checksums before
    // trusting it — belt-and-suspenders against a logic error silently
    // writing wrong bytes back to disk.
    const { shards: verifyShards } = splitIntoShards(rebuiltBlock, parsed.dataShards);
    let verifyOk = true;
    for (let i = 0; i < parsed.dataShards; i++) {
      if (!timingSafeEqual(sha256(verifyShards[i]), rec.dataChecksums[i])) { verifyOk = false; break; }
    }
    if (!verifyOk) {
      unrecoverableBlocks.push(b);
      continue;
    }

    out.set(rebuiltBlock, start);
    blocksRepaired++;
    void shardLen;
  }

  return {
    repaired: blocksRepaired > 0 && unrecoverableBlocks.length === 0,
    blocksChecked: parsed.blocks.length,
    blocksCorrupted,
    blocksRepaired,
    unrecoverableBlocks,
    repairedBytes: unrecoverableBlocks.length === 0 ? out : undefined,
  };
}
