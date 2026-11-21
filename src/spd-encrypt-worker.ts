/**
 * Worker thread for parallel entry encryption in addMany().
 * Receives a batch of { name, serialized, dataType } items and the master AEAD key,
 * encrypts each one, and posts back the encrypted EncryptedDataEntry array.
 *
 * Isolation: the worker never sees the passcode — only the already-derived aeadKey.
 * Key material is zeroed before the worker exits.
 */
import { workerData, parentPort } from 'worker_threads';
import * as crypto from './internal/portable-crypto.js';
import { utf8ToBytes } from './internal/portable-crypto.js';
import * as zlib from './internal/portable-zlib.js';
import { deriveEntryKey, padForCompression, aeadEncrypt } from './internal/spd-crypto.js';

interface WorkerInput {
  items: Array<{ name: string; serialized: string; dataType: string }>;
  aeadKeyBytes: Uint8Array;   // aeadKey, structured-cloned (not copied via a plain number[])
  hashAlgorithm: string;
  compressionLevel: number;
}

interface WorkerResult {
  entries: Array<{
    dataName: string;
    nonce: number[];
    data: number[];
    hash: string;
    dataType: string;
  }>;
  error?: string;
}

async function main() {
  const { items, aeadKeyBytes, hashAlgorithm, compressionLevel } = workerData as WorkerInput;
  // `new Uint8Array(aeadKeyBytes)` COPIES into a fresh, independent
  // ArrayBuffer (verified directly — it does not create a view over
  // aeadKeyBytes's own buffer). That means the original aeadKeyBytes,
  // holding the real structured-cloned master key, was never zeroed by the
  // old code below (only the copy, `aeadKey`, was) — real, unzeroed key
  // material left sitting in this worker's memory for its whole lifetime.
  // Fixed: zero aeadKeyBytes too, in the same finally block.
  const aeadKey = new Uint8Array(aeadKeyBytes);

  const result: WorkerResult = { entries: [] };
  try {
    for (const { name, serialized, dataType } of items) {
      const padded     = padForCompression(utf8ToBytes(serialized));
      const compressed = zlib.deflateSync(padded, { level: compressionLevel });
      const entryKey   = deriveEntryKey(aeadKey, name);
      const nonce      = crypto.randomBytes(24);
      const encrypted  = aeadEncrypt(compressed, utf8ToBytes(name), nonce, entryKey);
      (entryKey).fill(0);
      const hash = crypto.createHash(hashAlgorithm).update(encrypted).digest('hex');
      result.entries.push({
        dataName: name,
        nonce:    Array.from(nonce),
        data:     Array.from(encrypted),
        hash,
        dataType,
      });
    }
  } catch (e: any) {
    result.error = e?.message ?? String(e);
  } finally {
    (aeadKey).fill(0);
    (aeadKeyBytes).fill(0);
  }

  parentPort!.postMessage(result);
}

main();
