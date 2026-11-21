/**
 * Advisory file locking (`<file>.lock`) and rollback protection
 * (`<file>.seq` sidecar) for SPD files. Node-only (uses the real fs).
 */

import { getFs } from './node-platform.js';
import { bytesToHex } from './portable-crypto.js';

const STALE_MS = 30_000;
const POLL_MS  = 50;
const BREAK_STALE_MS = 10_000; // a crashed breaker's mutex is ignored after this

/**
 * True if `pid` is a live process. `kill(pid, 0)` throws EPERM for a live
 * process owned by another user — that is "alive", not "dead"; treating it
 * as dead would let any user break another user's live lock.
 */
function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException)?.code === 'EPERM';
  }
}

/**
 * Acquires an advisory lock for `filePath` by exclusively creating
 * `filePath.lock` containing {pid, ts}. Stale locks (dead process or older
 * than 30 s) are broken. Polls every 50 ms until `lockTimeoutMs`, then
 * throws `ESPD_LOCKED`.
 *
 * Returns the token written to the lock file; pass it to `releaseLock` so
 * release only deletes the lock if it is still this caller's (a lock broken
 * as stale and re-acquired by another process must not be deleted by the
 * original, slow holder).
 */
export function acquireLock(filePath: string, lockTimeoutMs = 5_000): string {
  const fs = getFs();
  const lockPath = filePath + '.lock';
  const breakPath = lockPath + '.break';
  const deadline = Date.now() + lockTimeoutMs;

  /** A lock file is stale when its owner is dead, it is older than STALE_MS, or its content is not a plausible token. */
  const isStale = (raw: string): boolean => {
    try {
      const { pid, ts } = JSON.parse(raw) as { pid?: unknown; ts?: unknown };
      if (!Number.isInteger(pid) || (pid as number) <= 1) return true;          // pid 0 / negatives would signal our own group
      if (!Number.isFinite(ts) || (ts as number) > Date.now() + 1000) return true; // future timestamps never age out
      return !isProcessAlive(pid as number) || Date.now() - (ts as number) >= STALE_MS;
    } catch {
      return true; // unreadable/corrupt
    }
  };

  /**
   * Break a stale lock. Breaking is serialised through a second exclusively
   * created file so two processes can never both judge the same lock stale
   * and have the slower one delete the faster one's FRESH lock (the
   * rename-aside scheme this replaces had exactly that window). Under the
   * mutex the lock is re-read and re-judged before the unlink. A breaker that
   * dies holding the mutex is covered by its own age limit.
   */
  const breakStale = (): void => {
    try {
      const st = fs.statSync(breakPath);
      if (Date.now() - st.mtimeMs > BREAK_STALE_MS) { try { fs.unlinkSync(breakPath); } catch { /* raced */ } }
    } catch { /* no break mutex present */ }
    try {
      fs.writeFileSync(breakPath, String(process.pid), { mode: 0o600, flag: 'wx' });
    } catch {
      return; // another breaker is at work; retry the normal loop
    }
    try {
      let raw: string;
      try { raw = fs.readFileSync(lockPath, 'utf8'); } catch { return; } // already gone
      if (isStale(raw)) { try { fs.unlinkSync(lockPath); } catch { /* raced */ } }
    } finally {
      try { fs.unlinkSync(breakPath); } catch { /* ignore */ }
    }
  };

  // Synchronous sleep via Atomics.wait on a SharedArrayBuffer.
  const ia = new Int32Array(new SharedArrayBuffer(4));

  for (;;) {
    // 'wx' (exclusive create) so only one of two racing acquirers wins; the
    // loser retries instead of believing it holds the lock. The nonce makes
    // every token unique, so releaseLock's content check cannot confuse two
    // locks taken by the same pid in the same millisecond.
    const nonce = bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(8)));
    const token = JSON.stringify({ pid: process.pid, ts: Date.now(), nonce });
    try {
      fs.writeFileSync(lockPath, token, { mode: 0o600, flag: 'wx' });
      return token;
    } catch (e) {
      if ((e as NodeJS.ErrnoException)?.code !== 'EEXIST') throw e;
    }
    let raw: string | undefined;
    try { raw = fs.readFileSync(lockPath, 'utf8'); } catch { continue; } // vanished between create and read
    if (isStale(raw)) breakStale();
    if (Date.now() >= deadline) {
      throw Object.assign(
        new Error(`SPD file "${filePath}" is locked. Timed out after ${lockTimeoutMs} ms.`),
        { code: 'ESPD_LOCKED' }
      );
    }
    Atomics.wait(ia, 0, 0, POLL_MS);
  }
}

/**
 * Releases the lock for `filePath`. With `token`, only deletes the lock file
 * if it still contains exactly that token; without it, best-effort delete.
 */
export function releaseLock(filePath: string, token?: string): void {
  const fs = getFs();
  const lockPath = filePath + '.lock';
  try {
    if (token !== undefined && fs.readFileSync(lockPath, 'utf8') !== token) return;
    fs.unlinkSync(lockPath);
  } catch { /* already gone, or unreadable */ }
}

// ─── Rollback protection ────────────────────────────────────────────────────

/** Last-seen write counter from the `.seq` sidecar, or -1 if none (first load). */
function readSeqCounter(filePath: string): number {
  const fs = getFs();
  try {
    const n = parseInt(fs.readFileSync(filePath + '.seq', 'utf8').trim(), 10);
    return isNaN(n) ? -1 : n;
  } catch { return -1; }
}

/** Writes the write counter to the `.seq` sidecar (atomic rename). */
export function writeSeqCounter(filePath: string, counter: number): void {
  const fs = getFs();
  const seqFile = filePath + '.seq';
  const tmp = seqFile + '.tmp';
  fs.writeFileSync(tmp, String(counter), { mode: 0o600 });
  fs.renameSync(tmp, seqFile);
}

/**
 * Throws `ESPD_ROLLBACK` if `fileCounter` is below the last-seen counter in
 * the `.seq` sidecar; otherwise advances the sidecar (skipping the write when
 * unchanged).
 */
export function checkRollback(filePath: string, fileCounter: number): void {
  const lastSeen = readSeqCounter(filePath);
  if (fileCounter < lastSeen) {
    throw Object.assign(
      new Error(
        `Rollback detected for "${filePath}": ` +
        `file counter ${fileCounter} < last seen ${lastSeen}.`
      ),
      { code: 'ESPD_ROLLBACK' }
    );
  }
  if (fileCounter !== lastSeen) writeSeqCounter(filePath, fileCounter);
}
