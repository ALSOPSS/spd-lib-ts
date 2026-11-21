import { describe, it, expect } from 'vitest';
import { getRandomValues, randomBytes } from '../src/internal/portable-crypto';

describe('portable-crypto: getRandomValues', () => {
  it('fills a Uint8Array with random bytes', () => {
    const buf = new Uint8Array(32);
    getRandomValues(buf);
    // Overwhelmingly unlikely to still be all-zero if it actually ran.
    expect(buf.some((b) => b !== 0)).toBe(true);
  });

  it(
    'does not throw ReferenceError when the SharedArrayBuffer global does not exist ' +
    '(the common case in a real browser without COOP/COEP cross-origin-isolation headers ' +
    '— confirmed via a real headless-Chrome run with no isolation headers set, which crashed ' +
    'on setPassKey() before this fix)',
    () => {
      const hadOwnProperty = Object.prototype.hasOwnProperty.call(globalThis, 'SharedArrayBuffer');
      const original = (globalThis as any).SharedArrayBuffer;
      try {
        // Simulate a browser with SharedArrayBuffer genuinely absent from
        // the global scope (not just falsy) — matches what a real
        // non-cross-origin-isolated page actually has.
        delete (globalThis as any).SharedArrayBuffer;
        expect(typeof (globalThis as any).SharedArrayBuffer).toBe('undefined');

        const buf = new Uint8Array(16);
        expect(() => getRandomValues(buf)).not.toThrow();
        expect(buf.some((b) => b !== 0)).toBe(true);
      } finally {
        if (hadOwnProperty) (globalThis as any).SharedArrayBuffer = original;
      }
    }
  );

  it('still correctly rejects a genuine SharedArrayBuffer-backed view when the global IS present', () => {
    if (typeof SharedArrayBuffer === 'undefined') return; // nothing to test in this environment
    const sab = new SharedArrayBuffer(16);
    const view = new Uint8Array(sab);
    expect(() => getRandomValues(view)).toThrow(/SharedArrayBuffer/);
  });
});

describe('portable-crypto: randomBytes', () => {
  it('returns the requested length', () => {
    expect(randomBytes(32).length).toBe(32);
  });

  it('chunks correctly past the 65536-byte getRandomValues single-call limit', () => {
    const buf = randomBytes(100_000);
    expect(buf.length).toBe(100_000);
    expect(buf.some((b) => b !== 0)).toBe(true);
  });
});
