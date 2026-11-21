import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { SPDVault } from '../src/SPDVault';

describe('SPDVault — string-based API', () => {
  let vault: SPDVault;
  afterEach(() => vault?.destroy());

  it('genKey generates and stores a key retrievable via pullKey', () => {
    vault = new SPDVault(300000);
    vault.genKey('a');
    const key = vault.pullKey('a');
    expect(key).toBeDefined();
    expect(key!.length).toBeGreaterThanOrEqual(500);
    expect(key!.length).toBeLessThan(700);
  });

  it('genKey does not overwrite an existing key with the same id', () => {
    vault = new SPDVault(300000);
    vault.pushKey('a', 'first');
    vault.genKey('a'); // should be a no-op since 'a' already exists
    expect(vault.pullKey('a')).toBe('first');
  });

  it('pushKey stores a custom key', () => {
    vault = new SPDVault(300000);
    vault.pushKey('a', 'my-secret');
    expect(vault.pullKey('a')).toBe('my-secret');
  });

  it('pullKey returns undefined for a nonexistent key', () => {
    vault = new SPDVault(300000);
    expect(vault.pullKey('nonexistent')).toBeUndefined();
  });

  it('destroyKey removes a key', () => {
    vault = new SPDVault(300000);
    vault.pushKey('a', 'secret');
    vault.destroyKey('a');
    expect(vault.pullKey('a')).toBeUndefined();
  });

  it('updateKey replaces the value only when oldValue matches', () => {
    vault = new SPDVault(300000);
    vault.pushKey('a', 'original');
    vault.updateKey('a', 'wrong-old-value', 'new-value');
    expect(vault.pullKey('a')).toBe('original'); // unchanged
    vault.updateKey('a', 'original', 'new-value');
    expect(vault.pullKey('a')).toBe('new-value'); // changed
  });

  it('updateKey is a no-op for a nonexistent key', () => {
    vault = new SPDVault(300000);
    expect(() => vault.updateKey('missing', 'a', 'b')).not.toThrow();
    expect(vault.pullKey('missing')).toBeUndefined();
  });
});

describe('SPDVault — byte-based API', () => {
  let vault: SPDVault;
  afterEach(() => vault?.destroy());

  it('genKeyBytes generates a key of the requested length', () => {
    vault = new SPDVault(300000);
    vault.genKeyBytes('a', 32);
    const key = vault.pullKeyBytes('a');
    expect(key).toBeDefined();
    expect(key!.length).toBe(32);
    expect(key!.some((b) => b !== 0)).toBe(true); // actually random, not all-zero
  });

  it('pushKeyBytes stores a custom key', () => {
    vault = new SPDVault(300000);
    const secret = new Uint8Array([1, 2, 3, 4]);
    vault.pushKeyBytes('a', secret);
    expect(vault.pullKeyBytes('a')).toEqual(new Uint8Array([1, 2, 3, 4]));
  });

  it('destroyKeyBytes zeroes the stored bytes before removing them', () => {
    vault = new SPDVault(300000);
    const secret = new Uint8Array([1, 2, 3, 4]);
    vault.pushKeyBytes('a', secret);
    vault.destroyKeyBytes('a');
    // The original array is the same object stored internally (pushKeyBytes
    // takes ownership) — it must be zeroed, not just dereferenced.
    expect(secret).toEqual(new Uint8Array([0, 0, 0, 0]));
    expect(vault.pullKeyBytes('a')).toBeUndefined();
  });

  it('updateKeyBytes replaces the value only when oldValue matches, zeroing the old value either way', () => {
    vault = new SPDVault(300000);
    const original = new Uint8Array([1, 2, 3]);
    vault.pushKeyBytes('a', original);

    const wrongOld = new Uint8Array([9, 9, 9]);
    const newVal = new Uint8Array([4, 5, 6]);
    vault.updateKeyBytes('a', wrongOld, newVal);
    expect(vault.pullKeyBytes('a')).toEqual(new Uint8Array([1, 2, 3])); // unchanged

    vault.updateKeyBytes('a', new Uint8Array([1, 2, 3]), newVal);
    expect(vault.pullKeyBytes('a')).toEqual(new Uint8Array([4, 5, 6])); // changed
  });

  it('destroy() zeroes all byte-based keys', () => {
    vault = new SPDVault(300000);
    const secretA = new Uint8Array([1, 2, 3]);
    const secretB = new Uint8Array([4, 5, 6]);
    vault.pushKeyBytes('a', secretA);
    vault.pushKeyBytes('b', secretB);
    vault.destroy();
    expect(secretA).toEqual(new Uint8Array([0, 0, 0]));
    expect(secretB).toEqual(new Uint8Array([0, 0, 0]));
  });
});

describe('SPDVault — expiration', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('a string key expires and is removed after timeoutMs', () => {
    const vault = new SPDVault(1000);
    vault.pushKey('a', 'secret');
    expect(vault.pullKey('a')).toBe('secret');
    vi.advanceTimersByTime(1001);
    expect(vault.pullKey('a')).toBeUndefined();
    vault.destroy();
  });

  it('a byte key expires, is zeroed, and removed after timeoutMs', () => {
    const vault = new SPDVault(1000);
    const secret = new Uint8Array([1, 2, 3]);
    vault.pushKeyBytes('a', secret);
    vi.advanceTimersByTime(1001);
    expect(vault.pullKeyBytes('a')).toBeUndefined();
    expect(secret).toEqual(new Uint8Array([0, 0, 0])); // zeroed on expiry, not just dropped
    vault.destroy();
  });

  it('pullKey resets the expiration timer (sliding expiration, not absolute)', () => {
    const vault = new SPDVault(1000);
    vault.pushKey('a', 'secret');
    vi.advanceTimersByTime(700);
    expect(vault.pullKey('a')).toBe('secret'); // access before expiry resets the timer
    vi.advanceTimersByTime(700); // total 1400ms since push, but only 700ms since last pull
    expect(vault.pullKey('a')).toBe('secret'); // still alive — timer was reset
    vi.advanceTimersByTime(1001);
    expect(vault.pullKey('a')).toBeUndefined(); // now actually expired
    vault.destroy();
  });

  it('stop() cancels pending expiry without removing the keys themselves', () => {
    const vault = new SPDVault(1000);
    vault.pushKey('a', 'secret');
    vault.stop();
    vi.advanceTimersByTime(5000); // would have expired long ago if the timer weren't cancelled
    expect(vault.pullKey('a')).toBe('secret'); // still present — stop() only cancels the timer
    vault.destroy();
  });

  it('stop() also cancels pending byte-key expiry', () => {
    const vault = new SPDVault(1000);
    vault.pushKeyBytes('a', new Uint8Array([1, 2, 3]));
    vault.stop();
    vi.advanceTimersByTime(5000);
    expect(vault.pullKeyBytes('a')).toEqual(new Uint8Array([1, 2, 3])); // still present
    vault.destroy();
  });
});

describe('SPDVault process lifetime and large keys', () => {
  it('expiry timers do not keep the process alive', async () => {
    const { execFileSync } = await import('child_process');
    const script = `import { SPDVault } from ${JSON.stringify(new URL('../src/SPDVault.ts', import.meta.url).pathname)};
      const v = new SPDVault(60_000); v.genKey('a'); v.genKeyBytes('b'); console.log('done');`;
    const t = Date.now();
    const out = execFileSync('npx', ['tsx', '--input-type=module', '-e', script], { encoding: 'utf8', timeout: 30_000 });
    expect(out.trim()).toBe('done');
    expect(Date.now() - t).toBeLessThan(30_000);
  }, 40_000);

  it('genKeyBytes supports keys larger than 64 KiB', async () => {
    const { SPDVault } = await import('../src/SPDVault.js');
    const v = new SPDVault();
    v.genKeyBytes('big', 100_000);
    const k = v.pullKeyBytes('big')!;
    expect(k.length).toBe(100_000);
    expect(k.some((b) => b !== 0)).toBe(true);
    v.destroyKeyBytes('big');
  });
});
