#!/usr/bin/env node
/**
 * spd-inspect — interactive SPD file inspector
 *
 * Breaks open a .spd (or streaming .spd) file layer by layer:
 *
 *   Layer 0 — raw file bytes (hex dump + size)
 *   Layer 1 — outer container (after zlib inflate + JSON parse)
 *   Layer 2 — payload JSON (MAC verified, salt decrypted, Argon2 keys derived)
 *   Layer 3 — per-entry details (encrypted blobs, nonces, hashes)
 *   Layer 4 — decrypted values (full round-trip, prints actual data)
 *
 * Usage (installed via `npm install spd-lib`, exposed as the `spd-inspect` bin):
 *   npx spd-inspect <file.spd> [--pass <passcode>] [--layer <0-4>] [--entry <name>]
 *   npx spd-inspect <file.spd> --streaming [--pass <passcode>]
 *
 * From within this repo (before publishing): `npm run build && npm run inspect -- <file.spd> ...`
 */

import * as fs from 'fs';
import { SPDRecipient } from './SPDRecipient.js';
import * as path from 'path';
import * as zlib from './internal/portable-zlib.js';
import * as crypto from './internal/portable-crypto.js';
import { bytesToUtf8, bytesToHex } from './internal/portable-crypto.js';
import { u8Alloc, u8Concat, readBigUInt64LE, readUInt32LE, readUInt16LE, readUInt8, readUIntLE3 } from './internal/portable-binary.js';
import * as readline from 'readline';
import { SPD } from './SPD.js';
import { base64ToBytes } from './internal/portable-crypto.js';

// ─── CLI argument parsing ────────────────────────────────────────────────────

const args = process.argv.slice(2);

/**
 * Validate a file path from the command line.
 * Rejects null bytes, path traversal sequences, and disallowed characters.
 */
function sanitizeInspectPath(raw: string): string {
  if (!raw) return raw;
  if (raw.includes('\0')) throw new Error('invalid path: null byte');
  if (raw.includes('..'))  throw new Error('invalid path: traversal sequence (..)');
  if (!/^[A-Za-z0-9.\-_/~ ]+$/.test(raw)) throw new Error('invalid path: disallowed characters');
  return path.resolve(raw);
}

const _rawPath = args.find((a) => !a.startsWith('--')) ?? '';
// Validate immediately: reject null bytes, traversal, and disallowed chars.
// (sanitizeInspectPath does the same three checks; calling it here instead
// of duplicating them inline avoids the two copies silently drifting out
// of sync if one is ever edited and not the other.)
if (_rawPath) {
  try {
    sanitizeInspectPath(_rawPath);
  } catch {
    console.error('Error: invalid file path');
    process.exit(1);
  }
}
// Resolve to canonical real path via the filesystem (resolves symlinks, normalises separators).
// fs.realpathSync terminates the taint chain — the result is a filesystem-verified absolute path.
const filePath = _rawPath ? fs.realpathSync(path.resolve(_rawPath)) : '';

const passFlag  = args.indexOf('--pass');
const layerFlag = args.indexOf('--layer');
const entryFlag = args.indexOf('--entry');
const streaming = args.includes('--streaming');
const noColor   = args.includes('--no-color');

let passcode    = passFlag  !== -1 ? args[passFlag  + 1] : '';
let targetLayer = layerFlag !== -1 ? parseInt(args[layerFlag + 1], 10) : -1; // -1 = interactive
let targetEntry = entryFlag !== -1 ? args[entryFlag + 1] : '';

// ─── Colours ─────────────────────────────────────────────────────────────────

const C = noColor ? {
  reset: '', bold: '', dim: '', red: '', green: '', yellow: '', cyan: '', magenta: '', blue: '',
} : {
  reset:   '\x1b[0m',
  bold:    '\x1b[1m',
  dim:     '\x1b[2m',
  red:     '\x1b[31m',
  green:   '\x1b[32m',
  yellow:  '\x1b[33m',
  cyan:    '\x1b[36m',
  magenta: '\x1b[35m',
  blue:    '\x1b[34m',
};

function header(text: string) {
  const bar = '─'.repeat(60);
  console.log(`\n${C.bold}${C.cyan}${bar}${C.reset}`);
  console.log(`${C.bold}${C.cyan}  ${text}${C.reset}`);
  console.log(`${C.bold}${C.cyan}${bar}${C.reset}`);
}

function label(k: string, v: string | number | boolean) {
  console.log(`  ${C.yellow}${k}:${C.reset} ${v}`);
}

function hexDump(buf: Uint8Array, maxBytes = 256) {
  const slice = buf.slice(0, maxBytes);
  const lines: string[] = [];
  for (let i = 0; i < slice.length; i += 16) {
    const chunk = slice.slice(i, i + 16);
    const hex  = [...chunk].map((b) => b.toString(16).padStart(2, '0')).join(' ');
    const asc  = [...chunk].map((b) => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.').join('');
    lines.push(`  ${C.dim}${i.toString(16).padStart(6, '0')}${C.reset}  ${hex.padEnd(48)}  ${C.dim}${asc}${C.reset}`);
  }
  if (buf.length > maxBytes) lines.push(`  ${C.dim}… (${buf.length - maxBytes} more bytes)${C.reset}`);
  console.log(lines.join('\n'));
}

function printValue(v: unknown, indent = 2) {
  const pad = ' '.repeat(indent);
  if (v === null || v === undefined) {
    console.log(`${pad}${C.dim}null${C.reset}`);
  } else if (v instanceof Uint8Array) {
    console.log(`${pad}${C.magenta}[Buffer ${v.length}B]${C.reset} ${bytesToHex(v.slice(0, 32))}${v.length > 32 ? '…' : ''}`);
  } else if (v instanceof Map) {
    console.log(`${pad}${C.magenta}Map(${(v as Map<unknown, unknown>).size})${C.reset}`);
    for (const [mk, mv] of v as Map<unknown, unknown>) {
      console.log(`${pad}  ${C.yellow}${String(mk)}${C.reset} =>`);
      printValue(mv, indent + 4);
    }
  } else if (v instanceof Set) {
    console.log(`${pad}${C.magenta}Set(${(v as Set<unknown>).size})${C.reset} [ ${[...(v as Set<unknown>)].slice(0, 8).map(String).join(', ')}${(v as Set<unknown>).size > 8 ? ', …' : ''} ]`);
  } else if (v instanceof Date) {
    console.log(`${pad}${C.magenta}Date${C.reset} ${(v as Date).toISOString()}`);
  } else if (v instanceof RegExp) {
    console.log(`${pad}${C.magenta}RegExp${C.reset} ${v}`);
  } else if (v instanceof Error) {
    console.log(`${pad}${C.red}Error${C.reset} ${(v as Error).message}`);
  } else if (Array.isArray(v)) {
    console.log(`${pad}${C.magenta}Array[${(v as unknown[]).length}]${C.reset}`);
    (v as unknown[]).slice(0, 10).forEach((item, i) => {
      process.stdout.write(`${pad}  [${i}] `);
      printValue(item, 0);
    });
    if ((v as unknown[]).length > 10) console.log(`${pad}  … (${(v as unknown[]).length - 10} more)`);
  } else if (typeof v === 'object') {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj);
    console.log(`${pad}${C.magenta}Object{${keys.length}}${C.reset}`);
    keys.slice(0, 20).forEach((k) => {
      process.stdout.write(`${pad}  ${C.yellow}${k}${C.reset}: `);
      printValue(obj[k], 0);
    });
    if (keys.length > 20) console.log(`${pad}  … (${keys.length - 20} more keys)`);
  } else {
    const str = String(v);
    const display = str.length > 200 ? str.slice(0, 200) + `… (${str.length} chars)` : str;
    console.log(`${pad}${C.green}${display}${C.reset}`);
  }
}

// ─── Password prompt ─────────────────────────────────────────────────────────

async function promptPass(): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    process.stdout.write(`${C.yellow}Passcode: ${C.reset}`);
    // hide input
    const stdin = process.stdin as NodeJS.ReadStream & { setRawMode?: (m: boolean) => NodeJS.ReadStream };
    if (stdin.setRawMode) {
      let buf = '';
      stdin.setRawMode(true);
      stdin.resume();
      stdin.setEncoding('utf8');
      stdin.on('data', function onData(ch: string) {
        if (ch === '\r' || ch === '\n') {
          stdin.setRawMode!(false);
          stdin.removeListener('data', onData);
          process.stdout.write('\n');
          rl.close();
          resolve(buf);
        } else if (ch === '\u0003') {
          process.exit(0);
        } else if (ch === '\u007f') {
          buf = buf.slice(0, -1);
        } else {
          buf += ch;
        }
      });
    } else {
      rl.question('', (ans) => { rl.close(); resolve(ans); });
    }
  });
}

// ─── Argon2 / key helpers ────────────────────────────────────────────────────


/** `.spd` fields are base64 strings (2.0.1+) or legacy `number[]`. */
function fieldBytes(v: unknown): Uint8Array {
  return typeof v === 'string' ? base64ToBytes(v) : new Uint8Array(v as number[]);
}

/** Decrypted values come from the library itself, so this tool can never drift from the real key schedule again. */
async function printDecrypted(file: string, pass: string, streaming: boolean, only?: string): Promise<void> {
  const loaded = streaming ? await SPD.loadFromFileStreaming(file, pass) : await SPD.loadFromFile(file, pass);
  try {
    const data = await loaded.extractData();
    for (const [name, val] of Object.entries(data)) {
      if (only && only !== '*' && name !== only) continue;
      console.log(`\n  ${C.bold}${C.cyan}${name}${C.reset}`);
      printValue(val, 4);
    }
  } finally {
    loaded.destroy();
  }
}

async function pickLayer(maxLayer: number): Promise<number> {
  return new Promise((resolve) => {
    console.log(`\n${C.bold}Select layer to inspect:${C.reset}`);
    for (let i = 0; i <= maxLayer; i++) {
      const names = ['Raw bytes', 'Outer container', 'Payload + keys', 'Entry details', 'Decrypted values'];
      console.log(`  ${C.cyan}${i}${C.reset}  ${names[i] ?? `Layer ${i}`}`);
    }
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(`\n${C.yellow}Layer (0-${maxLayer}): ${C.reset}`, (ans) => {
      rl.close();
      const n = parseInt(ans, 10);
      resolve(isNaN(n) ? 0 : Math.max(0, Math.min(n, maxLayer)));
    });
  });
}

async function pickEntry(names: string[]): Promise<string> {
  return new Promise((resolve) => {
    console.log(`\n${C.bold}Entries:${C.reset}`);
    names.forEach((n, i) => console.log(`  ${C.cyan}${i}${C.reset}  ${n}`));
    console.log(`  ${C.cyan}*${C.reset}  all entries`);
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(`\n${C.yellow}Entry (0-${names.length - 1} or *): ${C.reset}`, (ans) => {
      rl.close();
      if (ans.trim() === '*') return resolve('*');
      const n = parseInt(ans, 10);
      resolve(isNaN(n) ? '*' : (names[n] ?? '*'));
    });
  });
}

// ─── Streaming binary inspector ───────────────────────────────────────────────

async function inspectStreaming(file: string, pass: string) {
  header('STREAMING BINARY FILE INSPECTOR');

  // `file` is already fs.realpathSync-resolved by the caller (see top-level filePath).
  const safeFile = path.resolve(file);
  // Confinement check: path must stay within its own directory (Snyk-recognized PT guard).
  const allowedDir = path.resolve(path.dirname(safeFile));
  if (!safeFile.startsWith(allowedDir + path.sep) && safeFile !== allowedDir) {
    throw new Error('invalid path: outside allowed directory');
  }
  const stat = fs.statSync(safeFile);
  label('File', safeFile);
  label('Size on disk', `${stat.size.toLocaleString()} bytes`);

  const headerBuf = u8Alloc(72);
  const fd = fs.openSync(safeFile, 'r');
  fs.readSync(fd, headerBuf, 0, 72, 0);
  fs.closeSync(fd);

  header('LAYER 0 — File header (72 bytes)');
  label('Plaintext length field (LE uint64)', readBigUInt64LE(headerBuf, 0).toLocaleString() + ' bytes');
  label('HMAC-SHA3-512 (hex, first 32B shown)', bytesToHex(headerBuf.slice(8, 40)) + '…');
  hexDump(headerBuf);

  header('LAYER 1 — Inflating compressed body…');
  const plaintext = await new Promise<Uint8Array>((res, rej) => {
    const chunks: Uint8Array[] = [];
    const inflate = zlib.createInflate();
    inflate.on('data', (c: Uint8Array) => chunks.push(c));
    inflate.once('end', () => res(u8Concat(chunks)));
    inflate.once('error', rej);
    const rs = fs.createReadStream(safeFile, { start: 72 });
    // rs never has .setEncoding() called on it, so every 'data' chunk is
    // genuinely always a Buffer — Node's own stream types allow `string`
    // too (since .setEncoding() CAN make that happen on some other stream),
    // so this narrows explicitly rather than widening the callback's type.
    rs.on('data', (chunk) => {
      if (typeof chunk === 'string') throw new Error('spd-inspect: unexpected string chunk from read stream');
      inflate.write(new Uint8Array(chunk));
    });
    rs.once('end', () => inflate.end());
    rs.once('error', rej);
  });
  const expected = Number(readBigUInt64LE(headerBuf, 0));
  label('Inflated plaintext size', `${plaintext.length.toLocaleString()} bytes`);
  label('Length check', plaintext.length === expected ? `${C.green}PASS${C.reset}` : `${C.red}FAIL${C.reset}`);

  header('LAYER 2 — Metadata block');
  const metaLen = readUInt32LE(plaintext, 0);
  const metaBuf = plaintext.slice(4, 4 + metaLen);
  const meta = JSON.parse(bytesToUtf8(metaBuf));
  label('Meta block size', metaLen + ' bytes');
  label('SPD version', meta.version);
  label('Entry count', meta.entryCount);
  label('Hash algorithm', meta.hashAlgorithm ?? 'sha3-512');
  label('Argon2 memory', (meta.argon2Memory ?? 131072) / 1024 + ' MiB');
  label('Argon2 time cost', meta.argon2Time ?? 6);

  if (!pass) {
    console.log(`\n${C.dim}(No passcode provided — skipping MAC verification and decryption)${C.reset}`);
    return;
  }

  header('LAYER 3 — Key derivation + MAC verification');
  console.log(`  ${C.dim}Deriving Argon2id keys (library key schedule)…${C.reset}`);
  const v = await SPD.verify(safeFile, pass);
  label('MAC verification', v.valid ? `${C.green}PASS ✓${C.reset}` : `${C.red}FAIL ✗ — authentication failed (file integrity or credentials)${C.reset}`);
  label('Entry count (verified)', v.entryCount);
  label('Write counter', v.writeCounter);
  if (!v.valid) return;

  header('LAYER 4 — Entry structure');
  if ((meta.version ?? 0) >= 29) {
    // v29 records carry encrypted names and a different record layout; the
    // authoritative parse lives in the library (used for layer 5 below).
    console.log(`  ${C.dim}(structural per-entry scan is shown for pre-v29 files only; see layer 5)${C.reset}`);
  } else {
  const checkLen = (len: number, remaining: number, field: string): number => {
    if (len < 0 || len > remaining) {
      throw new Error(`malformed ${field} length: ${len} (only ${remaining} bytes remain)`);
    }
    return len;
  };
  let offset = 4 + metaLen;
  for (let i = 0; offset < plaintext.length && (meta.entryCount === 0 || i < meta.entryCount); i++) {
    const nameLen   = checkLen(readUInt8(plaintext, offset), plaintext.length - offset - 1, 'nameLen'); offset += 1;
    const nameBytes = plaintext.slice(offset, offset + nameLen); offset += nameLen;
    const typeLen   = checkLen(readUInt8(plaintext, offset), plaintext.length - offset - 1, 'typeLen'); offset += 1;
    const dataType  = bytesToUtf8(plaintext.slice(offset, offset + typeLen)); offset += typeLen;
    const hashLen   = checkLen(readUInt16LE(plaintext, offset), plaintext.length - offset - 2, 'hashLen'); offset += 2;
    const entryHash = bytesToUtf8(plaintext.slice(offset, offset + hashLen)); offset += hashLen;
    const nonceLen  = checkLen(readUIntLE3(plaintext, offset), plaintext.length - offset - 3, 'nonceLen'); offset += 3;
    const nonce     = plaintext.slice(offset, offset + nonceLen); offset += nonceLen;
    const dataLen   = checkLen(Number(readBigUInt64LE(plaintext, offset)), plaintext.length - offset - 8, 'dataLen'); offset += 8;
    const encData   = plaintext.slice(offset, offset + dataLen); offset += dataLen;
    const computedHash = crypto.createHash(meta.hashAlgorithm ?? 'sha3-512').update(encData).digest('hex');
    const nameShown = (meta.version ?? 0) >= 29 ? `${C.dim}(encrypted name, ${nameLen} B)${C.reset}` : `${C.cyan}${bytesToUtf8(nameBytes)}${C.reset}`;
    console.log(`\n  ${C.bold}[${i}]${C.reset} ${nameShown}  ${C.dim}(${dataType})${C.reset}`);
    label('  Encrypted size',  dataLen + ' bytes');
    label('  Nonce (hex)',      bytesToHex(nonce));
    label('  Integrity check', computedHash === entryHash ? `${C.green}PASS ✓${C.reset}` : `${C.red}FAIL ✗${C.reset}`);
    if (plaintext.length - offset < 4) break; // index tail / padding follows
  }
  }

  header('LAYER 5 — Decrypted values');
  await printDecrypted(safeFile, pass, true, targetEntry);
}

// ─── Standard JSON payload inspector ─────────────────────────────────────────

async function inspectStandard(file: string, pass: string, layer: number) {

  // ── Layer 0 ──────────────────────────────────────────────────────────────
  header('LAYER 0 — Raw file bytes');
  // `file` is already fs.realpathSync-resolved by the caller (see top-level filePath).
  const safeFile = path.resolve(file);
  // Confinement check: path must stay within its own directory (Snyk-recognized PT guard).
  const allowedDir = path.resolve(path.dirname(safeFile));
  if (!safeFile.startsWith(allowedDir + path.sep) && safeFile !== allowedDir) {
    throw new Error('invalid path: outside allowed directory');
  }
  const raw = fs.readFileSync(safeFile);
  label('File', file);
  label('Size on disk', `${raw.length.toLocaleString()} bytes`);
  hexDump(raw);
  if (layer === 0) return;

  // ── Layer 1 ──────────────────────────────────────────────────────────────
  header('LAYER 1 — Outer container (zlib inflate → JSON)');
  let outer: { payload: string | number[]; mac: number[] };
  try {
    outer = JSON.parse(bytesToUtf8(zlib.inflateSync(new Uint8Array(raw))));
  } catch {
    console.log(`${C.red}  Failed to inflate/parse outer container — is this a streaming file? Try --streaming${C.reset}`);
    return;
  }
  const payloadBuf = fieldBytes(outer.payload);
  const macBuf     = new Uint8Array(outer.mac);
  label('Payload bytes', payloadBuf.length.toLocaleString());
  label('MAC bytes', macBuf.length.toLocaleString());
  label('MAC (hex)', bytesToHex(macBuf));
  if (layer === 1) return;

  // ── Layer 2 ──────────────────────────────────────────────────────────────
  header('LAYER 2 — Payload JSON + key derivation');
  const parsed = JSON.parse(bytesToUtf8(payloadBuf));
  label('SPD version',    parsed.version);
  label('Entry count',    parsed.data?.length ?? 0);
  label('Hash algorithm', parsed.hashAlgorithm ?? 'sha3-512');
  label('Argon2 memory',  (parsed.argon2Memory ?? 131072) / 1024 + ' MiB');
  label('Argon2 time',    parsed.argon2Time ?? 6);
  label('wrapSalt (hex)', bytesToHex(new Uint8Array(parsed.wrapSalt).slice(0, 8)) + '…');
  label('File signature', parsed.fileSignature ? `${parsed.fileSignature.length} bytes` : 'none');

  if (!pass) {
    console.log(`\n${C.dim}(No passcode provided — skipping MAC verification and layers 3–4)${C.reset}`);
    return;
  }

  console.log(`\n  ${C.dim}Deriving Argon2id keys (library key schedule)…${C.reset}`);
  const v = await SPD.verify(safeFile, pass);
  label('MAC verification', v.valid ? `${C.green}PASS ✓${C.reset}` : `${C.red}FAIL ✗ — authentication failed (file integrity or credentials)${C.reset}`);
  if (!v.valid) return;
  if (layer === 2) return;

  // ── Layer 3 ──────────────────────────────────────────────────────────────
  header('LAYER 3 — Encrypted entry details');
  const entries: Array<{ dataName: string; dataType: string; hash: string; nonce: string | number[]; data: string | number[] }> = parsed.data;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    const encBuf = fieldBytes(e.data);
    const nonce  = fieldBytes(e.nonce);
    const computedHash = crypto.createHash(parsed.hashAlgorithm ?? 'sha3-512').update(encBuf).digest('hex');
    console.log(`\n  ${C.bold}[${i}] ${C.cyan}${e.dataName}${C.reset}  ${C.dim}(${e.dataType})${C.reset}`);
    label('  Encrypted size',  encBuf.length + ' bytes');
    label('  Nonce (hex)',      bytesToHex(nonce));
    label('  Stored hash',     e.hash.slice(0, 32) + '…');
    label('  Integrity check', computedHash === e.hash ? `${C.green}PASS ✓${C.reset}` : `${C.red}FAIL ✗${C.reset}`);
    console.log(`  ${C.dim}Encrypted blob (first 32B):${C.reset}`);
    hexDump(encBuf, 32);
  }
  if (layer === 3) return;

  // ── Layer 4 ──────────────────────────────────────────────────────────────
  header('LAYER 4 — Decrypted values');
  const filterEntry = targetEntry || (entries.length > 1 && process.stdin.isTTY ? await pickEntry(entries.map((e) => e.dataName)) : '*');
  await printDecrypted(safeFile, pass, false, filterEntry);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  if (!filePath || !fs.existsSync(filePath)) {
    console.error(`${C.red}Usage: spd-inspect <file.spd> [--pass <passcode> | SPD_PASSCODE=…] [--layer <0-4>] [--streaming]${C.reset}`);
    process.exit(1);
  }

  console.log(`\n${C.bold}${C.magenta}SPD Inspector${C.reset}  ${C.dim}v1.0${C.reset}`);

  // Recipient envelopes ("SPDR"): standalone, or the `<file>.spdr` sidecar
  // written by saveToFileSealed(). Neither needs a passcode to describe.
  const head = Buffer.alloc(4);
  const hfd = fs.openSync(filePath, 'r');
  try { fs.readSync(hfd, head, 0, 4, 0); } finally { fs.closeSync(hfd); }
  if (head.toString('latin1') === 'SPDR') {
    header('RECIPIENT ENVELOPE');
    const info = SPDRecipient.inspect(new Uint8Array(fs.readFileSync(filePath)));
    label('Format', `SPDR v${info.version}`);
    label('KEM', info.kem);
    label('Recipients', info.recipientCount);
    console.log(`${C.dim}Open with a recipient secret key: SPD.loadFromFileSealed(file, secretKey)${C.reset}\n`);
    return;
  }
  if (fs.existsSync(filePath + '.spdr')) {
    try {
      const info = SPDRecipient.inspect(new Uint8Array(fs.readFileSync(filePath + '.spdr')));
      label('Recipient envelope', `${path.basename(filePath)}.spdr — ${info.kem}, ${info.recipientCount} recipient(s) (keyless file)`);
    } catch { label('Recipient envelope', 'present but unreadable'); }
  }

  // `--pass` is visible in `ps` and shell history; SPD_PASSCODE avoids that in scripts.
  if (!passcode && process.env.SPD_PASSCODE) passcode = process.env.SPD_PASSCODE;
  if (!passcode) {
    passcode = await promptPass();
  }

  if (streaming) {
    await inspectStreaming(filePath, passcode);
    return;
  }

  const layer = targetLayer !== -1 ? targetLayer : (process.stdin.isTTY ? await pickLayer(4) : 4);
  await inspectStandard(filePath, passcode, layer);
}

main().catch((e) => {
  console.error(`${C.red}Error: ${(e as Error).message}${C.reset}`);
  process.exit(1);
});
