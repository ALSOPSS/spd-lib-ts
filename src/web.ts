/**
 * SPD Web adapter — browser / Deno / Bun compatible.
 *
 * @deprecated The main `SPD` class is now portable everywhere (Node, browsers,
 * Deno, Bun, Cloudflare Workers) — its Argon2id KDF, XChaCha20-Poly1305 AEAD,
 * hashing, and zlib-compatible compression all run on pure-JS implementations
 * (`@noble/hashes`, `@noble/curves`, `@noble/ciphers`, native CompressionStream — see
 * internal/portable-aead.ts / internal/portable-kx.ts) with no native
 * addons or Node-only built-ins in the core encrypt/decrypt path.
 * Prefer `SPD` for new code — it uses stronger primitives (Argon2id instead of
 * PBKDF2, XChaCha20-Poly1305 instead of AES-GCM) and its file format is the
 * one real `.spd` files use. `SPDWeb` is kept only for existing consumers of
 * its (format-incompatible) JSON payload shape and will not gain new features.
 *
 * Provides a stripped-down `SPDWeb` class that encrypts and decrypts entries
 * using only platform-agnostic Web Crypto APIs (SubtleCrypto + getRandomValues).
 * No Node.js built-ins (fs, zlib, worker_threads, crypto module, argon2) are used.
 *
 * Limitations vs the full SPD class:
 *  - Key derivation uses PBKDF2-SHA-256 (weaker than SPD's Argon2id).
 *    PBKDF2 iterations default to 600 000 (OWASP 2023 recommendation for SHA-256).
 *  - Encryption uses AES-GCM-256 (weaker than SPD's XChaCha20-Poly1305).
 *  - No file I/O, WAL, streaming, worker threads, or machine binding.
 *  - The payload format is JSON (base64url-encoded ciphertext) and is NOT compatible
 *    with files produced by the main SPD class.
 *
 * Compatible runtimes: Chrome 91+, Firefox 90+, Safari 15+, Deno 1.x, Bun 1.x,
 * Edge 91+, Node.js 18+ (globalThis.crypto.subtle).
 */

// ─── Utilities ────────────────────────────────────────────────────────────────

const subtle: SubtleCrypto = (() => {
  if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle) {
    return globalThis.crypto.subtle;
  }
  throw new Error('SPDWeb: SubtleCrypto is not available in this environment.');
})();

function getRandomBytes(n: number): Uint8Array<ArrayBuffer> {
  const buf = new Uint8Array(new ArrayBuffer(n));
  globalThis.crypto.getRandomValues(buf);
  return buf;
}

function b64uEncode(buf: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < buf.length; i++) bin += String.fromCharCode(buf[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function b64uDecode(s: string): Uint8Array<ArrayBuffer> {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = (4 - (padded.length % 4)) % 4;
  const bin = atob(padded + '='.repeat(pad));
  const buf = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

// ─── Types ────────────────────────────────────────────────────────────────────

export interface SPDWebEntry {
  name:     string;
  iv:       string; // base64url AES-GCM IV (12 bytes)
  ct:       string; // base64url ciphertext + GCM tag
  dataType: string;
}

export interface SPDWebPayload {
  version:    number;
  pbkdf2Iter: number;
  salt:       string; // base64url PBKDF2 salt (16 bytes)
  entries:    SPDWebEntry[];
}

// ─── SPDWeb ───────────────────────────────────────────────────────────────────

/**
 * Lightweight encrypted key-value store for browser / Deno / Bun environments.
 *
 * ```ts
 * const spd = await SPDWeb.create('my-passphrase');
 * await spd.set('apiKey', 'sk-secret-123');
 * const val = await spd.get('apiKey'); // → 'sk-secret-123'
 *
 * // Serialize to JSON string for localStorage / IndexedDB
 * const json = await spd.export('my-passphrase');
 * const restored = await SPDWeb.import(json, 'my-passphrase');
 * ```
 *
 * @deprecated Use the main `SPD` class instead — it now runs portably in
 * browsers too, with stronger primitives (Argon2id, XChaCha20-Poly1305) and
 * a format that matches real `.spd` files. See the module-level doc comment.
 */
export class SPDWeb {
  static readonly VERSION = 1;
  static readonly PBKDF2_ITER_DEFAULT = 600_000;
  /** Lowest work factor accepted on import (a tampered payload cannot weaken future re-keys below this). */
  static readonly PBKDF2_ITER_MIN = 100_000;

  private readonly _aesKey: CryptoKey;
  private readonly _salt: Uint8Array<ArrayBuffer>;
  private readonly _pbkdf2Iter: number;
  private readonly _entries: Map<string, SPDWebEntry> = new Map();

  private constructor(aesKey: CryptoKey, salt: Uint8Array<ArrayBuffer>, pbkdf2Iter: number) {
    this._aesKey     = aesKey;
    this._salt       = salt;
    this._pbkdf2Iter = pbkdf2Iter;
  }

  // ── Factory ────────────────────────────────────────────────────────────────

  /**
   * Create a new, empty `SPDWeb` instance with a freshly derived key.
   *
   * @param passphrase  The passphrase to derive the AES key from.
   * @param pbkdf2Iter  PBKDF2 iteration count (default 600 000).
   */
  static async create(
    passphrase: string,
    pbkdf2Iter = SPDWeb.PBKDF2_ITER_DEFAULT
  ): Promise<SPDWeb> {
    const salt   = getRandomBytes(16);
    const aesKey = await SPDWeb._deriveKey(passphrase, salt, pbkdf2Iter);
    return new SPDWeb(aesKey, salt, pbkdf2Iter);
  }

  /**
   * Import a payload previously produced by `spd.export()`.
   *
   * @param json        JSON string produced by `SPDWeb.prototype.export`.
   * @param passphrase  The passphrase used during `export`.
   */
  static async import(json: string, passphrase: string): Promise<SPDWeb> {
    const payload: SPDWebPayload = JSON.parse(json);
    if (payload.version !== SPDWeb.VERSION) {
      throw new Error(`SPDWeb: unsupported payload version ${payload.version}`);
    }
    const salt       = b64uDecode(payload.salt);
    const pbkdf2Iter = payload.pbkdf2Iter ?? SPDWeb.PBKDF2_ITER_DEFAULT;
    // The payload is unauthenticated JSON: refuse a tampered-down work factor
    // or a short salt rather than re-keying future saves with them.
    if (!Number.isInteger(pbkdf2Iter) || pbkdf2Iter < SPDWeb.PBKDF2_ITER_MIN) {
      throw new Error(`SPDWeb: pbkdf2Iter must be an integer >= ${SPDWeb.PBKDF2_ITER_MIN}`);
    }
    if (salt.length < 16) throw new Error('SPDWeb: salt must be at least 16 bytes');
    const aesKey     = await SPDWeb._deriveKey(passphrase, salt, pbkdf2Iter);

    const instance = new SPDWeb(aesKey, salt, pbkdf2Iter);
    for (const entry of payload.entries) {
      instance._entries.set(entry.name, entry);
    }
    return instance;
  }

  // ── Key derivation ─────────────────────────────────────────────────────────

  private static async _deriveKey(
    passphrase: string,
    salt: Uint8Array<ArrayBuffer>,
    iterations: number
  ): Promise<CryptoKey> {
    const baseKey = await subtle.importKey(
      'raw',
      enc.encode(passphrase),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
    return subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // ── Mutation ───────────────────────────────────────────────────────────────

  /**
   * Encrypt and store a value under `name`.
   * Supported value types: string, number, boolean, object (JSON-serializable).
   */
  async set(name: string, value: unknown): Promise<void> {
    const dataType = Array.isArray(value) ? 'Array'
                   : value === null       ? 'object'
                   : typeof value;
    const plaintext = enc.encode(JSON.stringify(value));
    const iv        = getRandomBytes(12);
    const ctBuf     = await subtle.encrypt(
      { name: 'AES-GCM', iv },
      this._aesKey,
      plaintext
    );
    this._entries.set(name, {
      name,
      iv:       b64uEncode(iv),
      ct:       b64uEncode(new Uint8Array(ctBuf)),
      dataType,
    });
  }

  /** Remove an entry by name. Returns `true` if it existed. */
  delete(name: string): boolean {
    return this._entries.delete(name);
  }

  // ── Access ─────────────────────────────────────────────────────────────────

  /**
   * Decrypt and return the value stored under `name`.
   * Returns `undefined` if the name does not exist.
   */
  async get(name: string): Promise<unknown> {
    const entry = this._entries.get(name);
    if (!entry) return undefined;
    const iv         = b64uDecode(entry.iv);
    const ct         = b64uDecode(entry.ct);
    const plainBuf   = await subtle.decrypt({ name: 'AES-GCM', iv }, this._aesKey, ct);
    return JSON.parse(dec.decode(plainBuf));
  }

  /** Returns `true` if an entry with `name` exists. */
  has(name: string): boolean {
    return this._entries.has(name);
  }

  /** List all entry names. */
  keys(): string[] {
    return [...this._entries.keys()];
  }

  /** Number of stored entries. */
  get size(): number {
    return this._entries.size;
  }

  /**
   * Async generator that yields `{ name, value }` for every entry.
   * Entries are decrypted lazily one at a time.
   */
  async *entries(): AsyncGenerator<{ name: string; value: unknown; dataType: string }> {
    for (const entry of this._entries.values()) {
      const value = await this.get(entry.name);
      yield { name: entry.name, value, dataType: entry.dataType };
    }
  }

  // ── Serialization ──────────────────────────────────────────────────────────

  /**
   * Serialize all entries to a JSON string. Entries are already encrypted
   * under the key derived at `create()`/`import()` time, so no passphrase is
   * needed; the parameter is accepted and ignored for API compatibility.
   */
  async export(_passphrase?: string): Promise<string> {
    const payload: SPDWebPayload = {
      version:    SPDWeb.VERSION,
      pbkdf2Iter: this._pbkdf2Iter,
      salt:       b64uEncode(this._salt),
      entries:    [...this._entries.values()],
    };
    return JSON.stringify(payload);
  }

  // ── Passphrase change ──────────────────────────────────────────────────────

  /**
   * Re-encrypt all entries under a new passphrase.
   * Returns a new `SPDWeb` instance; the old one is unaffected.
   */
  async changePassphrase(
    oldPassphrase: string,
    newPassphrase: string
  ): Promise<SPDWeb> {
    // Verify the old passphrase: derive its key and prove it decrypts an
    // existing entry (if any). Deriving alone never fails, so without this
    // check `oldPassphrase` was never actually verified.
    const oldKey = await SPDWeb._deriveKey(oldPassphrase, this._salt, this._pbkdf2Iter);
    const probe = this._entries.values().next().value;
    if (probe) {
      try {
        await subtle.decrypt({ name: 'AES-GCM', iv: b64uDecode(probe.iv) }, oldKey, b64uDecode(probe.ct));
      } catch {
        throw new Error('SPDWeb: old passphrase is incorrect');
      }
    }

    const newSalt   = getRandomBytes(16);
    const newAesKey = await SPDWeb._deriveKey(newPassphrase, newSalt, this._pbkdf2Iter);
    const next      = new SPDWeb(newAesKey, newSalt, this._pbkdf2Iter);

    // Decrypt each entry with the old key, re-encrypt with the new key.
    for (const entry of this._entries.values()) {
      const iv       = b64uDecode(entry.iv);
      const ct       = b64uDecode(entry.ct);
      const plainBuf = await subtle.decrypt({ name: 'AES-GCM', iv }, this._aesKey, ct);
      const newIv    = getRandomBytes(12);
      const newCt    = await subtle.encrypt({ name: 'AES-GCM', iv: newIv }, newAesKey, plainBuf);
      next._entries.set(entry.name, {
        name:     entry.name,
        iv:       b64uEncode(newIv),
        ct:       b64uEncode(new Uint8Array(newCt)),
        dataType: entry.dataType,
      });
    }

    return next;
  }
}
