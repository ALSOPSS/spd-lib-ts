/**
 * Reed-Solomon erasure/error coding over GF(256) — from-spec, zero dependencies.
 *
 * Same field construction used by QR codes, CDs, and RAID6 (primitive polynomial
 * 0x11D, generator 2). A from-spec implementation was chosen over a third-party
 * package deliberately, matching this library's existing precedent for
 * security/portability-critical primitives (see internal/spd-crypto.ts's
 * hand-rolled AEAD/KX): the alternatives were a native addon (reintroduces the
 * exact portability problem this library has been removing elsewhere), a
 * single-release unmaintained port, or a toy with one published version — all
 * worse than ~150 lines of well-specified, independently-verifiable math with
 * no new supply-chain surface.
 *
 * This module implements systematic Reed-Solomon ERASURE coding: given k data
 * shards, produce m parity shards (k+m total), such that ANY k of the k+m
 * shards suffice to reconstruct the original k data shards. This is the
 * classic "erasure code" formulation (used by RAID6/Reed-Solomon storage
 * systems) rather than the polynomial-error-locator formulation used for
 * blind error correction without knowing which bytes are bad — SPD's use case
 * always knows which shard(s) look wrong first (a checksum mismatch, computed
 * per-shard by the caller), then asks this module to reconstruct using the
 * remaining good shards. That's a strictly simpler and easier-to-verify
 * problem than general Berlekamp-Massey-style decoding, while covering
 * exactly the "some bytes silently rotted, self-heal on load" use case.
 */

// ─── GF(256) field tables ────────────────────────────────────────────────
// Primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D), generator element 2.
const GF_EXP = new Uint8Array(512); // exp[i] = 2^i mod poly, doubled length avoids wraparound checks
const GF_LOG = new Uint8Array(256);

(function initTables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function gfDiv(a: number, b: number): number {
  if (a === 0) return 0;
  if (b === 0) throw new Error('Reed-Solomon: division by zero in GF(256)');
  return GF_EXP[(GF_LOG[a] + 255 - GF_LOG[b]) % 255];
}

/**
 * Builds the Cauchy-matrix generator rows used for systematic RS encoding.
 *
 * IMPORTANT, found via exhaustive testing (not assumed from a writeup): a
 * plain power-based Vandermonde matrix (row i, col j = (i+1)^j) does NOT
 * guarantee that every square submatrix of the full systematic generator
 * matrix `[I | V]` is invertible — only that V itself, and certain specific
 * combinations, are. Reconstructing from a mix of identity-block (surviving
 * data shard) rows and Vandermonde parity rows can produce a genuinely
 * singular submatrix for specific index combinations (confirmed by
 * exhaustive enumeration: e.g. k=4,m=3 with surviving indices [2,4,5,6] —
 * one data shard + all three parity shards — hits a real singular matrix,
 * not a flaky/random failure). This is a known subtlety of naive Vandermonde
 * constructions for systematic MDS codes; real implementations either
 * post-process the Vandermonde matrix (row-reduce it against the identity
 * block) or use a Cauchy matrix instead, which has the needed property
 * unconditionally: over a field, a Cauchy matrix C[i][j] = 1/(x_i XOR y_j)
 * built from two disjoint sets {x_i}, {y_j} has EVERY square submatrix
 * invertible, which is exactly the guarantee erasure coding needs (any k of
 * k+m shards, in any combination, must be enough to reconstruct).
 *
 * x_i = dataShards + i (i = 0..parityShards-1), y_j = j (j = 0..dataShards-1)
 * — disjoint as long as dataShards + parityShards <= 256, already enforced
 * by the field-size check in rsEncode/rsReconstruct.
 */
function buildEncodeMatrix(dataShards: number, parityShards: number): number[][] {
  const matrix: number[][] = [];
  for (let i = 0; i < parityShards; i++) {
    const x = dataShards + i;
    const row: number[] = [];
    for (let j = 0; j < dataShards; j++) {
      const y = j;
      row.push(gfDiv(1, x ^ y)); // x !== y always holds — disjoint sets by construction
    }
    matrix.push(row);
  }
  return matrix;
}

/**
 * Encodes `dataShards` equal-length Uint8Arrays into `parityShards` parity
 * shards of the same length. Any `dataShards` of the resulting
 * `dataShards + parityShards` total shards suffice to reconstruct the
 * originals via `reconstruct()`.
 */
export function rsEncode(data: Uint8Array[], parityShardCount: number): Uint8Array[] {
  const k = data.length;
  if (k === 0) throw new Error('Reed-Solomon: at least one data shard required');
  const shardLen = data[0].length;
  for (const d of data) {
    if (d.length !== shardLen) throw new Error('Reed-Solomon: all data shards must be the same length');
  }
  if (parityShardCount < 1) throw new Error('Reed-Solomon: parityShardCount must be >= 1');
  if (k + parityShardCount > 255) {
    throw new Error('Reed-Solomon: k + parity shards must be <= 255 (GF(256) field limit)');
  }

  const matrix = buildEncodeMatrix(k, parityShardCount);
  const parity: Uint8Array[] = [];
  for (let p = 0; p < parityShardCount; p++) {
    const out = new Uint8Array(shardLen);
    for (let byteIdx = 0; byteIdx < shardLen; byteIdx++) {
      let acc = 0;
      for (let col = 0; col < k; col++) {
        acc ^= gfMul(matrix[p][col], data[col][byteIdx]);
      }
      out[byteIdx] = acc;
    }
    parity.push(out);
  }
  return parity;
}

/**
 * Reconstructs the original `dataShardCount` data shards given any surviving
 * subset of shards (data and/or parity), identified by their original index
 * in the conceptual `[...data, ...parity]` array (data indices are
 * `0..dataShardCount-1`, parity indices are `dataShardCount..dataShardCount+parityShardCount-1`).
 *
 * @param survivingIndices Index (in the full data+parity numbering) of each shard in `survivingShards`, same order/length.
 * @param survivingShards  The actual shard bytes, one per entry in `survivingIndices`.
 * @throws if fewer than `dataShardCount` shards survive — reconstruction is impossible.
 */
export function rsReconstruct(
  dataShardCount: number,
  parityShardCount: number,
  survivingIndices: number[],
  survivingShards: Uint8Array[]
): Uint8Array[] {
  if (survivingIndices.length !== survivingShards.length) {
    throw new Error('Reed-Solomon: survivingIndices and survivingShards length mismatch');
  }
  if (survivingIndices.length < dataShardCount) {
    throw new Error(
      `Reed-Solomon: unrecoverable — only ${survivingIndices.length} of ${dataShardCount} required shards survived`
    );
  }
  const shardLen = survivingShards[0]?.length ?? 0;
  for (const s of survivingShards) {
    if (s.length !== shardLen) throw new Error('Reed-Solomon: all surviving shards must be the same length');
  }

  // Full generator matrix: identity rows for data shards (row i = e_i), then
  // the Vandermonde parity rows — this is exactly the matrix such that
  // fullMatrix * data = [...data, ...parity].
  const encodeMatrix = buildEncodeMatrix(dataShardCount, parityShardCount);
  const fullMatrix: number[][] = [];
  for (let i = 0; i < dataShardCount; i++) {
    const row = new Array(dataShardCount).fill(0);
    row[i] = 1;
    fullMatrix.push(row);
  }
  for (const row of encodeMatrix) fullMatrix.push(row);

  // Take the first `dataShardCount` surviving shards/rows, invert that
  // sub-matrix, and multiply through to recover the original data shards.
  const usedIndices = survivingIndices.slice(0, dataShardCount);
  const usedShards = survivingShards.slice(0, dataShardCount);
  const subMatrix = usedIndices.map((idx) => fullMatrix[idx]);

  const inverse = invertMatrix(subMatrix);

  const recovered: Uint8Array[] = [];
  for (let row = 0; row < dataShardCount; row++) {
    const out = new Uint8Array(shardLen);
    for (let byteIdx = 0; byteIdx < shardLen; byteIdx++) {
      let acc = 0;
      for (let col = 0; col < dataShardCount; col++) {
        acc ^= gfMul(inverse[row][col], usedShards[col][byteIdx]);
      }
      out[byteIdx] = acc;
    }
    recovered.push(out);
  }
  return recovered;
}

/** Gauss-Jordan matrix inversion over GF(256). */
function invertMatrix(matrix: number[][]): number[][] {
  const n = matrix.length;
  // Augment with identity
  const aug: number[][] = matrix.map((row, i) => {
    const idRow = new Array(n).fill(0);
    idRow[i] = 1;
    return [...row, ...idRow];
  });

  for (let col = 0; col < n; col++) {
    // Find a pivot row with non-zero entry in this column
    let pivotRow = -1;
    for (let row = col; row < n; row++) {
      if (aug[row][col] !== 0) { pivotRow = row; break; }
    }
    if (pivotRow === -1) {
      throw new Error('Reed-Solomon: singular matrix — chosen shard combination cannot reconstruct (should not happen with a Vandermonde matrix and valid indices)');
    }
    if (pivotRow !== col) {
      const tmp = aug[col]; aug[col] = aug[pivotRow]; aug[pivotRow] = tmp;
    }

    const pivotVal = aug[col][col];
    const pivotInv = gfDiv(1, pivotVal);
    for (let c = 0; c < 2 * n; c++) aug[col][c] = gfMul(aug[col][c], pivotInv);

    for (let row = 0; row < n; row++) {
      if (row === col) continue;
      const factor = aug[row][col];
      if (factor === 0) continue;
      for (let c = 0; c < 2 * n; c++) {
        aug[row][c] ^= gfMul(factor, aug[col][c]);
      }
    }
  }

  return aug.map((row) => row.slice(n));
}
