import * as crypto from './internal/portable-crypto.js';
import { utf8ToBytes } from './internal/portable-crypto.js';

/**
 * Zero a Uint8Array. Previously tried sodium.memzero first — that exists in
 * C to defeat compiler dead-store elimination on stack buffers, a concern
 * that doesn't have a documented, proven JS-engine equivalent (or
 * mitigation); .fill(0) is the actual industry-standard practice for this
 * in managed languages.
 */
function zero(buf: Uint8Array): void {
  buf.fill(0);
}

/**
 * In-memory key vault with automatic expiration.
 * Keys are automatically deleted after the specified timeout.
 *
 * NOTE on the string-based API (genKey/pushKey/pullKey/updateKey/destroyKey):
 * "expiration" here only drops this vault's own `Map` reference to the key —
 * it cannot wipe the underlying string data from the JS heap/string table,
 * since JS strings are immutable and have no memzero equivalent. A string
 * returned by `pullKey` may remain resident in memory indefinitely after
 * expiry, regardless of this vault's internal cleanup. Callers that need an
 * actual memory-safety guarantee (the key bytes provably overwritten on
 * expiry/destroy) should use the byte-based API instead
 * (genKeyBytes/pushKeyBytes/pullKeyBytes/destroyKeyBytes), which stores
 * `Uint8Array`s and zeroes them via `sodium.memzero` on expiry, destroy, and
 * `updateKeyBytes`'s old-value comparison failing.
 */
export class SPDVault {
  private keys: Map<string, string> = new Map();
  private keyBytes: Map<string, Uint8Array> = new Map();
  private timers: Map<string, NodeJS.Timeout> = new Map();
  private byteTimers: Map<string, NodeJS.Timeout> = new Map();
  private timeoutMs: number;

  constructor(timeoutMs: number = 300000) {
    this.timeoutMs = timeoutMs;
  }

  /**
   * Generate a random key string.
   */
  private generateRandomKey(length: number): string {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`~!@#$%^&*()[]{}\\|;:\'",./? ';
    const cs = charset.length; // 91
    // Rejection sampling: discard any uint32 above the last clean multiple of
    // cs so every character has exactly equal probability.
    const limit = Math.floor(0x100000000 / cs) * cs;
    const result: string[] = [];
    while (result.length < length) {
      const batch = new Uint32Array(length - result.length);
      crypto.getRandomValues(batch);
      for (const v of batch) {
        if (v < limit) {
          result.push(charset[v % cs]);
        }
      }
    }
    return result.join('');
  }

  /**
   * Reset the expiration timer for a key.
   */
  private resetTimer(keyId: string): void {
    if (this.timers.has(keyId)) {
      clearTimeout(this.timers.get(keyId)!);
    }

    const timer = setTimeout(() => {
      this.keys.delete(keyId);
      this.timers.delete(keyId);
    }, this.timeoutMs);
    // Expiry must not keep the process alive (a script would otherwise hang
    // for up to timeoutMs after its last vault call).
    timer.unref?.();

    this.timers.set(keyId, timer);
  }

  /**
   * Generate and store a new random key.
   */
  genKey(keyId: string = ''): void {
    if (!this.keys.has(keyId)) {
      // Use CSPRNG for length jitter so even the length is unpredictable
      const jitter = new Uint32Array(1);
      crypto.getRandomValues(jitter);
      const length = 500 + (jitter[0] % 200);
      const key = this.generateRandomKey(length);
      this.keys.set(keyId, key);
      this.resetTimer(keyId);
    }
  }

  /**
   * Store a custom key.
   */
  pushKey(keyId: string = '', key: string = ''): void {
    if (!this.keys.has(keyId)) {
      this.keys.set(keyId, key);
      this.resetTimer(keyId);
    }
  }

  /**
   * Retrieve a key by ID.
   * Returns undefined if the key doesn't exist.
   */
  pullKey(keyId: string = ''): string | undefined {
    if (this.keys.has(keyId)) {
      this.resetTimer(keyId);
      return this.keys.get(keyId);
    }
    return undefined;
  }

  /**
   * Delete a key by ID.
   */
  destroyKey(keyId: string = ''): void {
    this.keys.delete(keyId);
    if (this.timers.has(keyId)) {
      clearTimeout(this.timers.get(keyId)!);
      this.timers.delete(keyId);
    }
  }

  /**
   * Update a key if the old value matches.
   * Uses a timing-safe comparison — `oldValue` is caller-supplied secret
   * material, and a plain `===` string comparison short-circuits on the
   * first differing character, leaking timing information about the
   * stored key.
   */
  updateKey(keyId: string, oldValue: string = '', newValue: string = ''): void {
    if (this.keys.has(keyId)) {
      const stored = this.keys.get(keyId)!;
      const storedBytes = utf8ToBytes(stored);
      const oldBytes = utf8ToBytes(oldValue);
      if (storedBytes.length === oldBytes.length && crypto.timingSafeEqual(storedBytes, oldBytes)) {
        this.keys.set(keyId, newValue);
      }
      this.resetTimer(keyId);
    }
  }

  /**
   * Reset the expiration timer for a byte-based key.
   */
  private resetByteTimer(keyId: string): void {
    if (this.byteTimers.has(keyId)) {
      clearTimeout(this.byteTimers.get(keyId)!);
    }
    const timer = setTimeout(() => {
      const existing = this.keyBytes.get(keyId);
      if (existing) zero(existing);
      this.keyBytes.delete(keyId);
      this.byteTimers.delete(keyId);
    }, this.timeoutMs);
    timer.unref?.();
    this.byteTimers.set(keyId, timer);
  }

  /**
   * Generate and store a new random key as raw bytes. Unlike `genKey`, the
   * stored value can be actually zeroed (via `.fill(0)`) on expiry,
   * `destroyKeyBytes`, or `destroy`.
   */
  genKeyBytes(keyId: string = '', length: number = 32): void {
    if (!this.keyBytes.has(keyId)) {
      const key = crypto.randomBytes(length); // chunked: getRandomValues caps at 64 KiB per call
      this.keyBytes.set(keyId, key);
      this.resetByteTimer(keyId);
    }
  }

  /**
   * Store a custom key as raw bytes. Takes ownership of `key` — the caller
   * should not reuse or zero it independently afterward.
   */
  pushKeyBytes(keyId: string = '', key: Uint8Array = new Uint8Array(0)): void {
    if (!this.keyBytes.has(keyId)) {
      this.keyBytes.set(keyId, key);
      this.resetByteTimer(keyId);
    }
  }

  /**
   * Retrieve a byte-based key by ID. Returns undefined if the key doesn't
   * exist. The returned `Uint8Array` aliases the vault's own storage —
   * zero it yourself with `sodium.memzero` once you're done with it if you
   * need it gone before the vault's own timeout/destroy would clear it.
   */
  pullKeyBytes(keyId: string = ''): Uint8Array | undefined {
    if (this.keyBytes.has(keyId)) {
      this.resetByteTimer(keyId);
      return this.keyBytes.get(keyId);
    }
    return undefined;
  }

  /**
   * Delete a byte-based key by ID, zeroing it first.
   */
  destroyKeyBytes(keyId: string = ''): void {
    const existing = this.keyBytes.get(keyId);
    if (existing) zero(existing);
    this.keyBytes.delete(keyId);
    if (this.byteTimers.has(keyId)) {
      clearTimeout(this.byteTimers.get(keyId)!);
      this.byteTimers.delete(keyId);
    }
  }

  /**
   * Update a byte-based key if the old value matches (timing-safe
   * comparison). The replaced old value is zeroed either way once no
   * longer needed.
   */
  updateKeyBytes(keyId: string, oldValue: Uint8Array = new Uint8Array(0), newValue: Uint8Array = new Uint8Array(0)): void {
    if (this.keyBytes.has(keyId)) {
      const stored = this.keyBytes.get(keyId)!;
      if (stored.length === oldValue.length && crypto.timingSafeEqual(stored, oldValue)) {
        zero(stored);
        this.keyBytes.set(keyId, newValue);
      }
      this.resetByteTimer(keyId);
    }
  }

  /**
   * Stop all expiration timers (the underlying keys are NOT removed — only
   * their scheduled auto-expiry is cancelled; call `destroy()` instead to
   * also clear/zero the stored keys).
   */
  stop(): void {
    this.timers.forEach((timer) => clearTimeout(timer));
    this.timers.clear();
    this.byteTimers.forEach((timer) => clearTimeout(timer));
    this.byteTimers.clear();
  }

  /**
   * Clear all keys and timers. Byte-based keys are zeroed before being
   * dropped; string-based keys cannot be (see class doc comment).
   */
  destroy(): void {
    this.stop();
    this.keys.clear();
    this.timers.clear();
    this.keyBytes.forEach((key) => zero(key));
    this.keyBytes.clear();
    this.byteTimers.clear();
  }
}
