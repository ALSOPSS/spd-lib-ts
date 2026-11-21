import { describe, it, expect } from 'vitest';
import { rsEncode, rsReconstruct } from '../src/internal/reed-solomon';
import {
  buildEccSidecar, verifyWithEccSidecar, repairWithEccSidecar,
  DEFAULT_DATA_SHARDS, DEFAULT_PARITY_SHARDS,
} from '../src/internal/spd-ecc';

function randomBytes(len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = Math.floor(Math.random() * 256);
  return out;
}

describe('reed-solomon (GF(256) erasure coding)', () => {
  it('encodes and reconstructs with no loss (identity check)', () => {
    const data = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6]), new Uint8Array([7, 8, 9])];
    const parity = rsEncode(data, 2);
    expect(parity.length).toBe(2);

    const recovered = rsReconstruct(3, 2, [0, 1, 2], [...data]);
    for (let i = 0; i < 3; i++) expect(recovered[i]).toEqual(data[i]);
  });

  it('reconstructs data shards from parity when data shards are missing', () => {
    const data = [
      new Uint8Array([10, 20, 30, 40]),
      new Uint8Array([50, 60, 70, 80]),
      new Uint8Array([90, 100, 110, 120]),
      new Uint8Array([130, 140, 150, 160]),
    ];
    const parity = rsEncode(data, 2); // k=4, m=2

    // Simulate losing data shards 1 and 3 — reconstruct from shards 0,2 + both parity shards.
    const survivingIndices = [0, 2, 4, 5]; // data[0], data[2], parity[0], parity[1]
    const survivingShards = [data[0], data[2], parity[0], parity[1]];
    const recovered = rsReconstruct(4, 2, survivingIndices, survivingShards);
    expect(recovered).toEqual(data);
  });

  it('throws when fewer than k shards survive', () => {
    const data = [new Uint8Array([1]), new Uint8Array([2]), new Uint8Array([3])];
    const parity = rsEncode(data, 1);
    expect(() => rsReconstruct(3, 1, [0, 1], [data[0], data[1]])).toThrow(/unrecoverable/);
    void parity;
  });

  it('works with random data across many trials (fuzz-style correctness check)', () => {
    for (let trial = 0; trial < 20; trial++) {
      const k = 2 + (trial % 8);
      const m = 1 + (trial % 4);
      const shardLen = 1 + (trial % 37);
      const data = Array.from({ length: k }, () => randomBytes(shardLen));
      const parity = rsEncode(data, m);

      // Drop up to m shards (mix of data and parity), keep the rest.
      const allIdx = Array.from({ length: k + m }, (_, i) => i);
      const allShards = [...data, ...parity];
      const dropCount = m;
      const dropped = new Set<number>();
      while (dropped.size < dropCount) dropped.add(Math.floor(Math.random() * (k + m)));

      const survivingIndices = allIdx.filter((i) => !dropped.has(i));
      const survivingShards = survivingIndices.map((i) => allShards[i]);
      const recovered = rsReconstruct(k, m, survivingIndices, survivingShards);
      expect(recovered).toEqual(data);
    }
  });
});

describe('spd-ecc sidecar (.spd bit-rot resilience)', () => {
  it('verifies clean (uncorrupted) file as ok', () => {
    const file = randomBytes(500_000); // spans multiple blocks at default 64 KiB block size
    const { sidecar } = buildEccSidecar(file);
    const result = verifyWithEccSidecar(file, sidecar);
    expect(result.ok).toBe(true);
    expect(result.corruptedBlocks).toEqual([]);
  });

  it('detects a single flipped byte', () => {
    const file = randomBytes(200_000);
    const { sidecar } = buildEccSidecar(file);
    const corrupted = new Uint8Array(file);
    corrupted[123_456] ^= 0xff;
    const result = verifyWithEccSidecar(corrupted, sidecar);
    expect(result.ok).toBe(false);
    expect(result.corruptedBlocks.length).toBeGreaterThan(0);
  });

  it('repairs a single flipped byte back to the exact original bytes', () => {
    const file = randomBytes(200_000);
    const { sidecar } = buildEccSidecar(file);
    const corrupted = new Uint8Array(file);
    corrupted[50_000] ^= 0xff;

    const result = repairWithEccSidecar(corrupted, sidecar);
    expect(result.repaired).toBe(true);
    expect(result.repairedBytes).toBeDefined();
    expect(result.repairedBytes).toEqual(file);
  });

  it('repairs multiple scattered single-byte corruptions across different blocks', () => {
    const file = randomBytes(1_000_000);
    const { sidecar } = buildEccSidecar(file);
    const corrupted = new Uint8Array(file);
    // Corrupt one byte in each of several distinct 64 KiB blocks.
    const positions = [1000, 70_000, 140_000, 500_000, 900_000];
    for (const p of positions) corrupted[p] ^= 0xaa;

    const result = repairWithEccSidecar(corrupted, sidecar);
    expect(result.repaired).toBe(true);
    expect(result.blocksCorrupted).toBe(positions.length);
    expect(result.repairedBytes).toEqual(file);
  });

  it('repairs corruption up to the parity budget within a single block, using default params', () => {
    const file = randomBytes(64 * 1024); // exactly one default-sized block
    const { sidecar } = buildEccSidecar(file, { dataShards: DEFAULT_DATA_SHARDS, parityShards: DEFAULT_PARITY_SHARDS });
    const corrupted = new Uint8Array(file);
    const shardLen = Math.ceil(file.length / DEFAULT_DATA_SHARDS);
    // Corrupt exactly `parityShards` worth of distinct data shards (the max recoverable).
    for (let i = 0; i < DEFAULT_PARITY_SHARDS; i++) {
      corrupted[i * shardLen] ^= 0xff;
    }
    const result = repairWithEccSidecar(corrupted, sidecar);
    expect(result.repaired).toBe(true);
    expect(result.repairedBytes).toEqual(file);
  });

  it('reports unrecoverable when corruption exceeds the parity budget', () => {
    const file = randomBytes(64 * 1024);
    const { sidecar } = buildEccSidecar(file, { dataShards: DEFAULT_DATA_SHARDS, parityShards: DEFAULT_PARITY_SHARDS });
    const corrupted = new Uint8Array(file);
    const shardLen = Math.ceil(file.length / DEFAULT_DATA_SHARDS);
    // Corrupt one more shard than parityShards can recover.
    for (let i = 0; i < DEFAULT_PARITY_SHARDS + 1; i++) {
      corrupted[i * shardLen] ^= 0xff;
    }
    const result = repairWithEccSidecar(corrupted, sidecar);
    expect(result.repaired).toBe(false);
    expect(result.unrecoverableBlocks.length).toBeGreaterThan(0);
    expect(result.repairedBytes).toBeUndefined();
  });

  it('throws a clear error when file size no longer matches what the sidecar was built for', () => {
    const file = randomBytes(10_000);
    const { sidecar } = buildEccSidecar(file);
    const wrongSizeFile = randomBytes(20_000);
    expect(() => repairWithEccSidecar(wrongSizeFile, sidecar)).toThrow(/does not match/);
  });

  it('rejects a corrupted .ecc sidecar itself (integrity HMAC check)', () => {
    const file = randomBytes(10_000);
    const { sidecar } = buildEccSidecar(file);
    const corruptedSidecar = new Uint8Array(sidecar);
    corruptedSidecar[10] ^= 0xff;
    expect(() => verifyWithEccSidecar(file, corruptedSidecar)).toThrow(/integrity check failed/);
  });

  it('handles a file smaller than one block', () => {
    const file = randomBytes(100);
    const { sidecar } = buildEccSidecar(file);
    expect(verifyWithEccSidecar(file, sidecar).ok).toBe(true);
    const corrupted = new Uint8Array(file);
    corrupted[50] ^= 0xff;
    const result = repairWithEccSidecar(corrupted, sidecar);
    expect(result.repaired).toBe(true);
    expect(result.repairedBytes).toEqual(file);
  });

  it('handles an empty file', () => {
    const file = new Uint8Array(0);
    const { sidecar } = buildEccSidecar(file);
    expect(verifyWithEccSidecar(file, sidecar).ok).toBe(true);
  });
});
