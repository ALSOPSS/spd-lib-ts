/**
 * SPD Performance Benchmark
 * Measures throughput and latency of core operations.
 *
 * Run: npx ts-node bench/spd-bench.ts
 */

import { SPD } from '../src/index.js';
import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';
import * as zlib from 'zlib';
import * as crypto from 'crypto';

const PASS = 'MyStr0ng!Passphrase#2024';

function tmpFile(): string {
  return path.join(os.tmpdir(), `spd-bench-${Date.now()}-${Math.random().toString(36).slice(2)}.spd`);
}

function fmt(ms: number): string {
  if (ms < 1) return `${(ms * 1000).toFixed(0)} µs`;
  if (ms < 1000) return `${ms.toFixed(1)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

function fmtThroughput(ops: number, ms: number): string {
  const ops_s = (ops / ms) * 1000;
  if (ops_s >= 1000) return `${(ops_s / 1000).toFixed(1)}k ops/s`;
  return `${ops_s.toFixed(0)} ops/s`;
}

async function bench(label: string, fn: () => Promise<void>, iterations = 1): Promise<number> {
  await fn(); // warmup

  const start = performance.now();
  for (let i = 0; i < iterations; i++) await fn();
  const elapsed = performance.now() - start;
  const avg = elapsed / iterations;
  const throughput = iterations > 1 ? `  ${fmtThroughput(iterations, elapsed)}` : '';
  console.log(`  ${label.padEnd(52)} ${fmt(avg)}${throughput}`);
  return avg;
}

async function main() {
  console.log('\n══════════════════════════════════════════════════════');
  console.log('  SPD v29 Performance Benchmark');
  console.log(`  Node ${process.version}  Platform: ${process.platform}/${process.arch}`);
  console.log('══════════════════════════════════════════════════════\n');

  // ── Key derivation ─────────────────────────────────────────────────────────
  console.log('▶ Key Derivation');
  await bench('setPassKey (standard, no KDF-chain)', async () => {
    const s = new SPD(); s.setKeyProfile('standard');
    await s.setPassKey(PASS);
    s.destroy();
  });
  console.log();

  // ── In-memory encrypt/decrypt ──────────────────────────────────────────────
  console.log('▶ In-Memory Encrypt / Decrypt (standard profile)');
  const spd = new SPD();
  spd.setKeyProfile('standard');
  await spd.setPassKey(PASS);

  const small  = 'Hello, World! This is a 36-byte string.';
  const med    = 'x'.repeat(10_000);
  const large  = 'x'.repeat(100_000);
  const huge   = 'x'.repeat(1_000_000);

  await bench('addData  ~36 B', async () => {
    spd['data'] = [];
    await spd.addData('k', small);
  }, 200);

  await bench('addData  10 KB', async () => {
    spd['data'] = [];
    await spd.addData('k', med);
  }, 100);

  await bench('addData 100 KB', async () => {
    spd['data'] = [];
    await spd.addData('k', large);
  }, 30);

  await bench('addData   1 MB', async () => {
    spd['data'] = [];
    await spd.addData('k', huge);
  }, 10);

  spd['data'] = [];
  await spd.addData('small', small);
  await spd.addData('med', med);
  await bench('extractData (2 entries ~10 KB)', async () => {
    await spd.extractData();
  }, 100);

  console.log();

  // ── File operations ────────────────────────────────────────────────────────
  console.log('▶ File Save / Load  (standard profile, no KDF-chain)');

  // Prepare 10-entry SPD with 10 KB entries
  const spd10 = new SPD();
  spd10.setKeyProfile('standard');
  await spd10.setPassKey(PASS);
  for (let i = 0; i < 10; i++) await spd10.addData(`entry${i}`, med);

  // saveToFile = JSON format; saveToFileStreaming = binary format
  const f10j = tmpFile();
  await bench('saveToFile (JSON) 10 × 10 KB', async () => {
    await spd10.saveToFile(f10j, PASS);
  }, 3);
  await bench('loadFromFile (JSON) 10 × 10 KB', async () => {
    const s = await SPD.loadFromFile(f10j, PASS); s.destroy();
  }, 3);

  const f10s = tmpFile();  // binary streaming format — required by getEntry
  await bench('saveToFileStreaming 10 × 10 KB', async () => {
    await spd10.saveToFileStreaming(f10s, PASS);
  }, 3);
  await bench('loadFromFileStreaming 10×10 KB', async () => {
    const s = await SPD.loadFromFileStreaming(f10s, PASS); s.destroy();
  }, 3);

  // 100-entry file
  const spd100 = new SPD();
  spd100.setKeyProfile('standard');
  await spd100.setPassKey(PASS);
  for (let i = 0; i < 100; i++) await spd100.addData(`entry${i}`, small);
  const f100s = tmpFile();  // binary streaming format
  await bench('saveToFileStreaming 100 × 36 B', async () => {
    await spd100.saveToFileStreaming(f100s, PASS);
  }, 3);
  await bench('loadFromFileStreaming 100 × 36 B', async () => {
    const s = await SPD.loadFromFileStreaming(f100s, PASS); s.destroy();
  }, 3);

  console.log();

  // ── getEntry (requires binary streaming format) ────────────────────────────
  console.log('▶ getEntry  (on-demand lookup, MAC-verified, binary format)');
  await bench('getEntry  first   (10 × 10 KB file)', async () => {
    await SPD.getEntry(f10s, PASS, 'entry0');
  }, 3);
  await bench('getEntry  last    (10 × 10 KB file)', async () => {
    await SPD.getEntry(f10s, PASS, 'entry9');
  }, 3);
  await bench('getEntry  entry50 (100 × 36 B file)', async () => {
    await SPD.getEntry(f100s, PASS, 'entry50');
  }, 3);

  console.log();

  // ── addMany batch ──────────────────────────────────────────────────────────
  console.log('▶ addMany  (parallel worker encryption)');
  const spdBatch = new SPD();
  spdBatch.setKeyProfile('standard');
  await spdBatch.setPassKey(PASS);

  for (const n of [64, 256, 1000]) {
    const items = Array.from({ length: n }, (_, i) => ({ name: `b${i}`, data: `value_${i}` }));
    await bench(`addMany ${n.toString().padStart(4)} items`, async () => {
      spdBatch['data'] = [];
      await spdBatch.addMany(items);
    }, 3);
  }

  console.log();

  // ── Crypto primitive microbenchmarks ──────────────────────────────────────
  console.log('▶ Crypto Primitive Overhead (per-call)');
  const k32   = crypto.randomBytes(32);
  const n24   = crypto.randomBytes(24);
  const buf1k = Buffer.alloc(1024, 0x42);

  await bench('SHA3-256(key || nonce)  — CMT block', async () => {
    crypto.createHash('sha3-256').update(k32).update(n24).digest();
  }, 50_000);

  await bench('HMAC-SHA3-512  — HKDF-Expand 1 block', async () => {
    crypto.createHmac('sha3-512', k32).update(n24).update(Buffer.from('spd-aead-key-v1')).update(Buffer.from([1])).digest();
  }, 50_000);

  await bench('padForCompression  1 KB', async () => {
    const origLen = buf1k.length;
    const lenBuf = Buffer.alloc(4); lenBuf.writeUInt32LE(origLen, 0);
    const combined = Buffer.concat([lenBuf, buf1k]);
    const rem = combined.length % 256;
    if (rem !== 0) { const pad = crypto.randomBytes(256 - rem); Buffer.concat([combined, pad]); }
  }, 50_000);

  await bench('deflateSync 1 KB (level 6)', async () => {
    zlib.deflateSync(buf1k, { level: 6 });
  }, 5_000);

  const deflated = zlib.deflateSync(buf1k, { level: 6 });
  await bench('inflateSync 1 KB', async () => {
    zlib.inflateSync(deflated);
  }, 20_000);

  await bench('HMAC-SHA3-512 100 KB (MAC verification)', async () => {
    crypto.createHmac('sha3-512', k32).update(Buffer.alloc(100_000)).digest();
  }, 1_000);

  console.log();

  // ── File sizes ─────────────────────────────────────────────────────────────
  console.log('▶ Generated File Sizes');
  const files: [string, string][] = [
    ['10-entry  10 KB each (JSON)',     f10j],
    ['10-entry  10 KB each (binary)',   f10s],
    ['100-entry 36 B each (binary)',    f100s],
  ];
  for (const [label, file] of files) {
    try {
      const stat = fs.statSync(file);
      console.log(`  ${label.padEnd(52)} ${(stat.size / 1024).toFixed(1)} KB`);
    } catch {}
  }

  // Cleanup
  spd.destroy(); spd10.destroy(); spd100.destroy(); spdBatch.destroy();
  [f10j, f10s, f100s].forEach(f => {
    try { fs.unlinkSync(f); } catch {}
    try { fs.unlinkSync(f + 'i'); } catch {}
    try { fs.unlinkSync(f + '.seq'); } catch {}
  });

  console.log('\n══════════════════════════════════════════════════════\n');
}

main().catch(console.error);
