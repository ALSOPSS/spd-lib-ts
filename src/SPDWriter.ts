/**
 * SPDWriter — streaming, disk-backed binary SPD writer.
 *
 * Writes entries one at a time to disk as they are encrypted, so the full
 * plaintext never exists in RAM simultaneously. Works on any device regardless
 * of available memory.
 *
 * Usage:
 *   const writer = new SPDWriter('./output.spd', 'MyStr0ng!Passphrase#2024');
 *   await writer.init();
 *   await writer.addEntry('username', 'alice');
 *   await writer.addEntry('config', { theme: 'dark' });
 *   await writer.finalize();
 *
 * After finalize(), an index tail is embedded in the file itself so that
 * `SPD.getEntry()` can locate entries without a full scan (no sidecar file).
 */

import * as zlib from './internal/portable-zlib.js';
import * as crypto from './internal/portable-crypto.js';
import type { PortableHmac } from './internal/portable-crypto.js';
import { utf8ToBytes } from './internal/portable-crypto.js';
import {
  u8Alloc, u8Concat,
  writeUInt8, writeUInt16LE, writeUInt32LE, writeUIntLE3, writeBigUInt64LE,
} from './internal/portable-binary.js';
import { SPD } from './SPD.js';
import type { HashAlgorithm, SupportedDataType, SPDWriterOptions, SPDIndexEntry } from './types.js';
import type * as fs from 'fs';
import { getFs } from './internal/node-platform.js';
import {
  aeadEncrypt,
  padForCompression,
  checkPassphraseStrength,
} from './internal/spd-crypto.js';

// Constants — must match SPD.ts v29
const SPD_VERSION     = 29;
const ARGON2_MEMORY   = 131072;
const ARGON2_TIME     = 6;
const ARGON2_HASH_LEN = 96;
const ARGON2_SALT_LEN = 32;     // 256-bit salt — rainbow-table proof at universal-adversary scale
const HMAC_KEY_LEN    = 64;
// SPDI_MAGIC removed — SPDWriter now uses embedded tail index (SPDX) not sidecar

export class SPDWriter {
  private outputPath: string;
  private passcode: string;
  private opts: Required<SPDWriterOptions>;

  private aeadKey?: Uint8Array;
  private macKey?: Uint8Array;
  private salt?: Uint8Array;

  private deflate?: ReturnType<typeof zlib.createDeflate>;
  private outStream?: fs.WriteStream;
  private hmac?: PortableHmac;
  // Resolved lazily in init() — SPDWriter is 100% disk-backed by design
  // (streaming writer), so this is where the class throws a clear
  // "requires Node.js" error in an environment without `fs`, rather than
  // failing confusingly deep inside a later write call.
  private _fs!: typeof import('fs');

  private plaintextOffset = 0;
  private entryCount      = 0;
  private indexEntries: SPDIndexEntry[] = [];

  private finalized = false;
  private initialized = false;

  constructor(outputPath: string, passcode: string, opts: SPDWriterOptions = {}) {
    // Found via direct audit: this class previously had NO entropy
    // validation at all on the passcode it derives keys from — every
    // other passcode-accepting entry point in this codebase enforces a
    // real (not just length-based) 60-bit-ish minimum via
    // checkPassphraseStrength, but SPDWriter silently accepted anything,
    // however guessable. No amount of Argon2id cost protects a passphrase
    // an attacker can just guess directly.
    checkPassphraseStrength(passcode);
    this.outputPath = outputPath;
    this.passcode   = passcode;
    this.opts = {
      compressionLevel: opts.compressionLevel ?? 9,
      hashAlgorithm:    opts.hashAlgorithm    ?? 'sha3-512',
      argon2Memory:     opts.argon2Memory     ?? ARGON2_MEMORY,
      argon2Time:       opts.argon2Time       ?? ARGON2_TIME,
    };
  }

  /**
   * Derives keys, opens the output file, and writes the meta block.
   * Must be called before addEntry().
   */
  async init(): Promise<void> {
    if (this.initialized) throw new Error('SPDWriter already initialized.');
    this._fs = getFs();

    // Derive keys
    this.salt = crypto.getRandomValues(new Uint8Array(ARGON2_SALT_LEN));

    // Same derivation as SPD.setPassKey / loadFromFileStreaming — including
    // the global pepper, keyfile and machine binding — so SPDWriter output is
    // never silently weaker than SPD's, and always readable by it.
    const keys = await SPD.deriveKeys(this.passcode, this.salt, this.opts.argon2Memory, this.opts.argon2Time);
    this.aeadKey = keys.aeadKey;
    this.macKey  = keys.macKey;

    // Salt wrapped with the standard, profile-independent wrap params every
    // reader assumes when `wrapArgon2Memory/Time` are absent from meta.
    const { encryptedSalt, saltNonce, wrapSalt } = await SPD.encryptSalt(this.salt, this.passcode);

    // Build meta JSON — entryCount=0 sentinel; true count in index + tail
    const metaJSON = JSON.stringify({
      encryptedSalt: Array.from(encryptedSalt),
      saltNonce:     Array.from(saltNonce),
      wrapSalt:      Array.from(wrapSalt),
      version:       SPD_VERSION,
      entryCount:    0,  // sentinel — reader scans to EOF or uses .spdi index
      hashAlgorithm: this.opts.hashAlgorithm,
      argon2Memory:  this.opts.argon2Memory,
      argon2Time:    this.opts.argon2Time,
      argon2HashLen: ARGON2_HASH_LEN,
      hashKeyLen:    HMAC_KEY_LEN,
      keyCommitment: SPD.computeKeyCommitment(this.aeadKey),
      // Same signed write counter SPD emits, so readers apply the rollback
      // and counter-HMAC checks to SPDWriter files too (a fresh file is write 1).
      writeCounter:  1,
      counterHMAC:   SPD.computeCounterHMAC(this.macKey, 1),
    });
    const metaPayload  = utf8ToBytes(metaJSON);
    const metaLenBuf   = u8Alloc(4);
    writeUInt32LE(metaLenBuf, metaPayload.length);
    const metaBlock    = u8Concat([metaLenBuf, metaPayload]);

    // Open output file — write 72-byte placeholder header (filled in at finalize)
    this.outStream = this._fs.createWriteStream(this.outputPath, { mode: 0o600 });
    await new Promise<void>((res, rej) => {
      // 'open' passes the new fd to its listener — res() takes no meaningful
      // argument (Promise<void>), so wrap rather than pass res directly;
      // TypeScript's listener-assignability check treats these as distinct
      // signatures even though passing extra args to res() is harmless at runtime.
      this.outStream!.once('open', () => res());
      this.outStream!.once('error', rej);
    });

    const placeholder = u8Alloc(72);
    this.outStream.write(placeholder);

    // Start deflate stream piped to output
    this.deflate = zlib.createDeflate({ level: this.opts.compressionLevel });
    this.deflate.on('data', (chunk: Uint8Array) => this.outStream!.write(chunk));

    // Start HMAC
    this.hmac = crypto.createHmac('sha3-512', this.macKey);

    // Write meta block into the deflate stream (and update HMAC)
    this.writeToPlaintext(metaBlock);

    this.initialized = true;
  }

  /**
   * Encrypts one entry and streams it to disk.
   */
  async addEntry(name: string, value: unknown): Promise<void> {
    if (!this.initialized) throw new Error('Call init() before addEntry().');
    if (this.finalized)    throw new Error('SPDWriter already finalized.');

    // Use SPD's static helpers for type detection / serialization
    const sanitized = (SPD as any).prototype.sanitizeName.call({ }, name) as string;
    const [serialized, dataType] = await (SPD as any).prototype.convertInputToString.call({
      detectType: (SPD as any).prototype.detectType,
      isTypedArray: (SPD as any).prototype.isTypedArray,
      isCollectionType: (SPD as any).prototype.isCollectionType,
    }, value) as [string, SupportedDataType];

    // v29: pad → compress → CMT-4 AEAD
    const padded     = padForCompression(utf8ToBytes(serialized));
    const compressed = zlib.deflateSync(padded, { level: this.opts.compressionLevel });

    const entryKey  = SPD.deriveEntryKey(this.aeadKey!, sanitized);
    const nonce     = crypto.randomBytes(24);
    const encrypted = aeadEncrypt(compressed, utf8ToBytes(sanitized), nonce, entryKey);
    (entryKey).fill(0);

    const hash = crypto.createHash(this.opts.hashAlgorithm).update(encrypted).digest('hex');

    // v29 encrypted name: [24B nonce || CMT-4 ciphertext]
    const nameKey     = SPD.deriveNameKey(this.aeadKey!);
    const nameNonce   = crypto.randomBytes(24);
    const encNameCt   = aeadEncrypt(utf8ToBytes(sanitized), null, nameNonce, nameKey);
    const encName     = u8Concat([nameNonce, encNameCt]);
    (nameKey).fill(0);
    const typeBytes  = utf8ToBytes(dataType);
    const hashBytes  = utf8ToBytes(hash);
    const encBuf     = encrypted;
    const nonceBuf   = nonce;

    // v29+ interleaved format: [2B encNameLen][encName][1B typeLen][type][2B hashLen][hash][3B nonceLen][nonce][8B dataLen][data]
    const enlBuf = u8Alloc(2);  writeUInt16LE(enlBuf, encName.length);
    const tlBuf  = u8Alloc(1);  writeUInt8(tlBuf, typeBytes.length);
    const hlBuf  = u8Alloc(2);  writeUInt16LE(hlBuf, hashBytes.length);
    const nolBuf = u8Alloc(3);  writeUIntLE3(nolBuf, nonceBuf.length);
    const dlBuf  = u8Alloc(8);  writeBigUInt64LE(dlBuf, BigInt(encBuf.length));

    const entryStart = this.plaintextOffset;
    this.writeToPlaintext(u8Concat([enlBuf, encName, tlBuf, typeBytes, hlBuf, hashBytes, nolBuf, nonceBuf, dlBuf, encBuf]));

    // A same-named entry written earlier in this stream can't be replaced
    // in the body (each entry is appended to the compressed stream as it's
    // written — that's the point of streaming, never holding the full
    // plaintext in memory to rewrite). But the tail INDEX can and should
    // still point at the latest write, matching SPD.addData's overwrite
    // semantics (see that method's own comment) — SPD.readIndexFile's
    // `map.set(name, offset)` would resolve duplicate index records to
    // whichever parses last anyway, so tracking that explicitly here keeps
    // the index consistent with a full-scan read instead of leaving the
    // earlier record as silent, unreachable-via-index dead weight.
    const existingIdx = this.indexEntries.findIndex((e) => e.name === sanitized);
    const indexEntry = { name: sanitized, decompressedOffset: BigInt(entryStart) };
    if (existingIdx === -1) this.indexEntries.push(indexEntry);
    else this.indexEntries[existingIdx] = indexEntry;
    this.entryCount++;
  }

  /**
   * Flushes the deflate stream, computes the HMAC, patches the file header,
   * and writes the `.spdi` index sidecar.
   */
  async finalize(): Promise<void> {
    if (!this.initialized) throw new Error('Call init() before finalize().');
    if (this.finalized)    throw new Error('SPDWriter already finalized.');
    this.finalized = true;

    // Finish deflate + wait for output stream to flush
    await new Promise<void>((res, rej) => {
      this.deflate!.once('end', () => {
        this.outStream!.once('finish', res);
        this.outStream!.once('error', rej);
        this.outStream!.end();
      });
      this.deflate!.once('error', rej);
      this.deflate!.end();
    });

    // Compute final MAC (append content-type domain separator)
    this.hmac!.update(utf8ToBytes('application/spd-binary'));
    const mac = this.hmac!.digest();

    // Patch the 72-byte placeholder at the top of the file:
    //   [0..8)   = plaintextLen as LE uint64
    //   [8..72)  = 64-byte MAC
    const sizeBuf = u8Alloc(8);
    writeBigUInt64LE(sizeBuf, BigInt(this.plaintextOffset));

    const patchFd = this._fs.openSync(this.outputPath, 'r+');
    try {
      this._fs.writeSync(patchFd, sizeBuf, 0, 8,  0);
      this._fs.writeSync(patchFd, mac,     0, 64, 8);
    } finally {
      this._fs.closeSync(patchFd);
    }

    // Embed index tail in the file itself (no sidecar)
    this.embedIndexTail();

    // Zero key material
    if (this.aeadKey) { (this.aeadKey).fill(0); this.aeadKey = undefined; }
    if (this.macKey)  { (this.macKey).fill(0);  this.macKey  = undefined; }
    if (this.salt)    { (this.salt).fill(0);     this.salt    = undefined; }
  }

  /**
   * Zero keys and remove the partial output file if finalize() was never
   * called. Best-effort only: `deflate`/`outStream` are destroyed and the
   * unlink is attempted in the same synchronous tick, with no wait for the
   * underlying file descriptor to actually finish closing. On most
   * platforms this is fine (Node's own stream.destroy() doesn't require
   * waiting for 'close' before a subsequent unlink succeeds), but on a
   * platform where an open fd can block unlink/rename (Windows, or an
   * unusual filesystem), this ordering can make the unlink silently fail —
   * swallowed by the catch below — leaving the partial file behind despite
   * this method's intent to clean it up. `destroy()` is kept synchronous
   * (matching Node's own Writable.destroy() convention and this class's
   * existing call sites) rather than becoming async just to await 'close'.
   */
  destroy(): void {
    if (this.aeadKey) { try { (this.aeadKey).fill(0); } catch {} this.aeadKey = undefined; }
    if (this.macKey)  { try { (this.macKey).fill(0);  } catch {} this.macKey  = undefined; }
    if (this.salt)    { try { (this.salt).fill(0);    } catch {} this.salt    = undefined; }

    if (!this.finalized) {
      try { this.deflate?.destroy(); } catch {}
      try { this.outStream?.destroy(); } catch {}
      try { this._fs?.unlinkSync(this.outputPath); } catch {}
    }
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  /** Write bytes to the deflate stream and update the rolling HMAC + offset. */
  private writeToPlaintext(buf: Uint8Array): void {
    this.hmac!.update(buf);
    this.deflate!.write(buf);
    this.plaintextOffset += buf.length;
  }

  /**
   * Appends the entry offset index to the end of the output file.
   * Format (v2): [32B HMAC-SHA3-256 of body][body: (16B name tag ‖ 8B offset)*][8B indexStart][4B "SPDy"] — see SPD.buildIndexTail.
   * NOTE: macKey is still valid here — zeroed by finalize() AFTER this call.
   */
  private embedIndexTail(): void {
    if (!this.macKey) return;
    const indexStart = BigInt(this._fs.statSync(this.outputPath).size);
    this._fs.appendFileSync(this.outputPath, SPD.buildIndexTail(this.indexEntries, this.macKey, indexStart));
  }
}
