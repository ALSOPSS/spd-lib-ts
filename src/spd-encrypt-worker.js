// GENERATED DEV/TEST SHIM — do not hand-edit.
//
// worker_threads.Worker uses Node's native module loader, which can't parse
// spd-encrypt-worker.ts directly. In the published package, `npm run build`
// (tsup) compiles it to dist/spd-encrypt-worker.js and SPD.ts's worker-spawn
// logic picks that up automatically. Under ts-node/vitest (running from
// source, no dist/), SPD.ts falls back to this checked-in copy instead.
//
// Regenerate after any change to spd-encrypt-worker.ts or its
// internal/spd-crypto.ts / internal/portable-crypto.ts / internal/portable-zlib.ts / internal/portable-aead.ts imports:
//   npm run build && cp dist/spd-encrypt-worker.js src/spd-encrypt-worker.js
// (then re-add this header, since the build overwrites it)
//
// src/spd-encrypt-worker.ts
import { workerData, parentPort } from "worker_threads";

// src/internal/portable-crypto.ts
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { sha3_256, sha3_512 } from "@noble/hashes/sha3.js";
import { hmac as nobleHmac } from "@noble/hashes/hmac.js";
import { scryptAsync } from "@noble/hashes/scrypt.js";
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from "@noble/hashes/utils.js";
var HASHES = {
  sha256,
  sha512,
  "sha3-256": sha3_256,
  "sha3-512": sha3_512
};
function resolveHash(algo) {
  const h = HASHES[algo];
  if (!h) throw new Error(`Unsupported hash algorithm: ${algo}`);
  return h;
}
var PortableHash = class {
  constructor(algo) {
    this.inner = resolveHash(algo).create();
  }
  update(data) {
    this.inner.update(typeof data === "string" ? utf8ToBytes(data) : data);
    return this;
  }
  digest(encoding) {
    const out = this.inner.digest();
    return encoding === "hex" ? bytesToHex(out) : out;
  }
};
function createHash(algo) {
  return new PortableHash(algo);
}
var GET_RANDOM_VALUES_MAX_BYTES = 65536;
function randomBytes(len) {
  const buf = new Uint8Array(len);
  for (let offset = 0; offset < len; offset += GET_RANDOM_VALUES_MAX_BYTES) {
    const end = Math.min(offset + GET_RANDOM_VALUES_MAX_BYTES, len);
    globalThis.crypto.getRandomValues(buf.subarray(offset, end));
  }
  return buf;
}

// src/internal/portable-zlib.ts
import { deflateSync, inflateSync, createDeflate, createInflate } from "zlib";

// src/internal/spd-crypto.ts
import { argon2idAsync } from "@noble/hashes/argon2.js";
import { sha3_256 as sha3_2562, sha3_512 as sha3_5122 } from "@noble/hashes/sha3.js";
import { hmac } from "@noble/hashes/hmac.js";

// src/internal/portable-aead.ts
var CHACHA20_CONSTANTS = [1634760805, 857760878, 2036477234, 1797285236];
function rotl32(x, n) {
  return x << n | x >>> 32 - n;
}
function quarterRound(s, a, b, c, d) {
  s[a] = s[a] + s[b] | 0;
  s[d] = rotl32(s[d] ^ s[a], 16);
  s[c] = s[c] + s[d] | 0;
  s[b] = rotl32(s[b] ^ s[c], 12);
  s[a] = s[a] + s[b] | 0;
  s[d] = rotl32(s[d] ^ s[a], 8);
  s[c] = s[c] + s[d] | 0;
  s[b] = rotl32(s[b] ^ s[c], 7);
}
function chacha20Block(key, counter, nonce) {
  const state = new Int32Array(16);
  state[0] = CHACHA20_CONSTANTS[0];
  state[1] = CHACHA20_CONSTANTS[1];
  state[2] = CHACHA20_CONSTANTS[2];
  state[3] = CHACHA20_CONSTANTS[3];
  const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
  for (let i = 0; i < 8; i++) state[4 + i] = keyView.getUint32(i * 4, true);
  state[12] = counter | 0;
  const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  for (let i = 0; i < 3; i++) state[13 + i] = nonceView.getUint32(i * 4, true);
  const working = new Int32Array(state);
  for (let round = 0; round < 10; round++) {
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }
  const out = new Uint8Array(64);
  const outView = new DataView(out.buffer);
  for (let i = 0; i < 16; i++) {
    outView.setUint32(i * 4, working[i] + state[i] | 0, true);
  }
  return out;
}
function chacha20Xor(key, initialCounter, nonce, data) {
  const out = new Uint8Array(data.length);
  const baseState = new Int32Array(16);
  baseState[0] = CHACHA20_CONSTANTS[0];
  baseState[1] = CHACHA20_CONSTANTS[1];
  baseState[2] = CHACHA20_CONSTANTS[2];
  baseState[3] = CHACHA20_CONSTANTS[3];
  const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
  for (let i = 0; i < 8; i++) baseState[4 + i] = keyView.getUint32(i * 4, true);
  const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  for (let i = 0; i < 3; i++) baseState[13 + i] = nonceView.getUint32(i * 4, true);
  const working = new Int32Array(16);
  const blockBytes = new Uint8Array(64);
  const blockView = new DataView(blockBytes.buffer);
  let counter = initialCounter;
  for (let offset = 0; offset < data.length; offset += 64) {
    baseState[12] = counter | 0;
    working.set(baseState);
    for (let round = 0; round < 10; round++) {
      quarterRound(working, 0, 4, 8, 12);
      quarterRound(working, 1, 5, 9, 13);
      quarterRound(working, 2, 6, 10, 14);
      quarterRound(working, 3, 7, 11, 15);
      quarterRound(working, 0, 5, 10, 15);
      quarterRound(working, 1, 6, 11, 12);
      quarterRound(working, 2, 7, 8, 13);
      quarterRound(working, 3, 4, 9, 14);
    }
    for (let i = 0; i < 16; i++) {
      blockView.setUint32(i * 4, working[i] + baseState[i] | 0, true);
    }
    const end = Math.min(offset + 64, data.length);
    for (let i = offset; i < end; i++) out[i] = data[i] ^ blockBytes[i - offset];
    counter = counter + 1 | 0;
  }
  return out;
}
var P1305 = (1n << 130n) - 5n;
var MASK_128 = (1n << 128n) - 1n;
function le_bytes_to_bigint(bytes) {
  let x = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) x = x << 8n | BigInt(bytes[i]);
  return x;
}
function le_bytes_to_bigint_range(bytes, start, end) {
  let x = 0n;
  for (let i = end - 1; i >= start; i--) x = x << 8n | BigInt(bytes[i]);
  return x;
}
function bigint_to_le_bytes(x, len) {
  const out = new Uint8Array(len);
  let v = x;
  for (let i = 0; i < len; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}
var Poly1305 = class {
  constructor(key) {
    this.acc = 0n;
    this.carry = new Uint8Array(16);
    this.carryLen = 0;
    const rBytes = new Uint8Array(key.subarray(0, 16));
    rBytes[3] &= 15;
    rBytes[7] &= 15;
    rBytes[11] &= 15;
    rBytes[15] &= 15;
    rBytes[4] &= 252;
    rBytes[8] &= 252;
    rBytes[12] &= 252;
    this.r = le_bytes_to_bigint(rBytes);
    this.s = le_bytes_to_bigint(key.subarray(16, 32));
  }
  absorbBlock(bytes, start, end) {
    const chunkLen = end - start;
    const n = le_bytes_to_bigint_range(bytes, start, end) + (1n << BigInt(8 * chunkLen));
    this.acc = (this.acc + n) * this.r % P1305;
  }
  update(data) {
    let offset = 0;
    if (this.carryLen > 0) {
      const need = 16 - this.carryLen;
      const take = Math.min(need, data.length);
      this.carry.set(data.subarray(0, take), this.carryLen);
      this.carryLen += take;
      offset += take;
      if (this.carryLen === 16) {
        this.absorbBlock(this.carry, 0, 16);
        this.carryLen = 0;
      } else {
        return;
      }
    }
    while (data.length - offset >= 16) {
      this.absorbBlock(data, offset, offset + 16);
      offset += 16;
    }
    const remaining = data.length - offset;
    if (remaining > 0) {
      this.carry.set(data.subarray(offset), 0);
      this.carryLen = remaining;
    }
  }
  digest() {
    if (this.carryLen > 0) {
      this.absorbBlock(this.carry, 0, this.carryLen);
      this.carryLen = 0;
    }
    const tag = this.acc + this.s & MASK_128;
    return bigint_to_le_bytes(tag, 16);
  }
};
function poly1305KeyGen(key, nonce) {
  const block = chacha20Block(key, 0, nonce);
  return block.subarray(0, 32);
}
function pad16(len) {
  const rem = len % 16;
  return rem === 0 ? new Uint8Array(0) : new Uint8Array(16 - rem);
}
function concatBytes2(...parts) {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}
function u64le(n) {
  const out = new Uint8Array(8);
  const view = new DataView(out.buffer);
  view.setBigUint64(0, BigInt(n), true);
  return out;
}
var ZERO_PAD16 = new Uint8Array(16);
function macAadAndCiphertext(p, aad, ciphertext) {
  p.update(aad);
  p.update(ZERO_PAD16.subarray(0, pad16(aad.length).length));
  p.update(ciphertext);
  p.update(ZERO_PAD16.subarray(0, pad16(ciphertext.length).length));
  p.update(u64le(aad.length));
  p.update(u64le(ciphertext.length));
}
function chacha20poly1305Encrypt(key, nonce, plaintext, aad) {
  const otk = poly1305KeyGen(key, nonce);
  const ciphertext = chacha20Xor(key, 1, nonce, plaintext);
  const p = new Poly1305(otk);
  macAadAndCiphertext(p, aad, ciphertext);
  const tag = p.digest();
  const out = new Uint8Array(ciphertext.length + 16);
  out.set(ciphertext, 0);
  out.set(tag, ciphertext.length);
  return out;
}
function hchacha20(key, nonceInput) {
  const state = new Int32Array(16);
  state[0] = CHACHA20_CONSTANTS[0];
  state[1] = CHACHA20_CONSTANTS[1];
  state[2] = CHACHA20_CONSTANTS[2];
  state[3] = CHACHA20_CONSTANTS[3];
  const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
  for (let i = 0; i < 8; i++) state[4 + i] = keyView.getUint32(i * 4, true);
  const nonceView = new DataView(nonceInput.buffer, nonceInput.byteOffset, nonceInput.byteLength);
  for (let i = 0; i < 4; i++) state[12 + i] = nonceView.getUint32(i * 4, true);
  for (let round = 0; round < 10; round++) {
    quarterRound(state, 0, 4, 8, 12);
    quarterRound(state, 1, 5, 9, 13);
    quarterRound(state, 2, 6, 10, 14);
    quarterRound(state, 3, 7, 11, 15);
    quarterRound(state, 0, 5, 10, 15);
    quarterRound(state, 1, 6, 11, 12);
    quarterRound(state, 2, 7, 8, 13);
    quarterRound(state, 3, 4, 9, 14);
  }
  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, state[0], true);
  outView.setUint32(4, state[1], true);
  outView.setUint32(8, state[2], true);
  outView.setUint32(12, state[3], true);
  outView.setUint32(16, state[12], true);
  outView.setUint32(20, state[13], true);
  outView.setUint32(24, state[14], true);
  outView.setUint32(28, state[15], true);
  return out;
}
var XCHACHA20_POLY1305_KEY_BYTES = 32;
var XCHACHA20_POLY1305_NONCE_BYTES = 24;
function xchacha20poly1305Encrypt(key, nonce, plaintext, aad = new Uint8Array(0)) {
  if (key.length !== XCHACHA20_POLY1305_KEY_BYTES) throw new Error("xchacha20poly1305: key must be 32 bytes");
  if (nonce.length !== XCHACHA20_POLY1305_NONCE_BYTES) throw new Error("xchacha20poly1305: nonce must be 24 bytes");
  const subkey = hchacha20(key, nonce.subarray(0, 16));
  const innerNonce = concatBytes2(new Uint8Array(4), nonce.subarray(16, 24));
  return chacha20poly1305Encrypt(subkey, innerNonce, plaintext, aad);
}

// src/internal/portable-binary.ts
function u8Alloc(len) {
  return new Uint8Array(len);
}
function writeUInt32LE(buf, value, offset = 0) {
  new DataView(buf.buffer, buf.byteOffset, buf.byteLength).setUint32(offset, value, true);
}

// src/internal/spd-crypto.ts
function sha3_256Concat(...parts) {
  const h = sha3_2562.create();
  for (const p of parts) h.update(p);
  return h.digest();
}
function randomBytes2(len) {
  const buf = new Uint8Array(len);
  globalThis.crypto.getRandomValues(buf);
  return buf;
}
var AEAD_KEY_LEN = 32;
var CMT_BLOCK_BYTES = 32;
var COMPRESS_PAD_BLOCK = 256;
function aeadEncrypt(plaintext, aad, nonce, key) {
  const cmt = sha3_256Concat(key, nonce);
  const ct = xchacha20poly1305Encrypt(key, nonce, plaintext, aad ?? new Uint8Array(0));
  const out = new Uint8Array(CMT_BLOCK_BYTES + ct.length);
  out.set(cmt, 0);
  out.set(ct, CMT_BLOCK_BYTES);
  return out;
}
function padForCompression(data) {
  const origLen = data.length;
  const lenBuf = u8Alloc(4);
  writeUInt32LE(lenBuf, origLen, 0);
  const combined = concatBytes(lenBuf, data);
  const rem = combined.length % COMPRESS_PAD_BLOCK;
  if (rem === 0) return combined;
  const pad = randomBytes2(COMPRESS_PAD_BLOCK - rem);
  return concatBytes(combined, pad);
}
function deriveEntryKey(masterAeadKey, entryName) {
  const prk = hmac(sha3_5122, utf8ToBytes(entryName), masterAeadKey);
  const info = utf8ToBytes("spd-entry-v27");
  const okm = hmac(sha3_5122, prk, concatBytes(info, new Uint8Array([1])));
  return okm.subarray(0, AEAD_KEY_LEN);
}

// src/spd-encrypt-worker.ts
async function main() {
  const { items, aeadKeyBytes, hashAlgorithm, compressionLevel } = workerData;
  const aeadKey = new Uint8Array(aeadKeyBytes);
  const result = { entries: [] };
  try {
    for (const { name, serialized, dataType } of items) {
      const padded = padForCompression(utf8ToBytes(serialized));
      const compressed = deflateSync(padded, { level: compressionLevel });
      const entryKey = deriveEntryKey(aeadKey, name);
      const nonce = randomBytes(24);
      const encrypted = aeadEncrypt(compressed, utf8ToBytes(name), nonce, entryKey);
      entryKey.fill(0);
      const hash = createHash(hashAlgorithm).update(encrypted).digest("hex");
      result.entries.push({
        dataName: name,
        nonce: Array.from(nonce),
        data: Array.from(encrypted),
        hash,
        dataType
      });
    }
  } catch (e) {
    result.error = e?.message ?? String(e);
  } finally {
    aeadKey.fill(0);
    aeadKeyBytes.fill(0);
  }
  parentPort.postMessage(result);
}
main();
