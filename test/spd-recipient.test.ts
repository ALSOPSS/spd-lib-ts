/**
 * SPDRecipient — PQ/T hybrid (MLKEM768-X25519) public-key recipients that
 * seal SPD's 96-byte keyless master secret.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SPD, SPDRecipient } from '../src/index';

const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const eq = (a: Uint8Array, b: Uint8Array) => Buffer.from(a).equals(Buffer.from(b));

describe('SPDRecipient identities and encoding', () => {
  it('generates 1216-byte public / 32-byte secret keys and re-derives the public key', () => {
    const id = SPDRecipient.generateIdentity();
    expect(id.publicKey.length).toBe(1216);
    expect(id.secretKey.length).toBe(32);
    expect(eq(SPDRecipient.publicKeyFromSecret(id.secretKey), id.publicKey)).toBe(true);
  });

  it('encodes/decodes public keys with the spdpq1. prefix and rejects junk', () => {
    const id = SPDRecipient.generateIdentity();
    const s = SPDRecipient.encodePublicKey(id.publicKey);
    expect(s.startsWith('spdpq1.')).toBe(true);
    expect(eq(SPDRecipient.decodePublicKey(s), id.publicKey)).toBe(true);
    expect(() => SPDRecipient.decodePublicKey('age1pq1abc')).toThrow(/spdpq1/);
    expect(() => SPDRecipient.decodePublicKey('spdpq1.AAAA')).toThrow(/1216-byte/);
  });
});

describe('SPDRecipient seal / open', () => {
  const alice = SPDRecipient.generateIdentity();
  const bob = SPDRecipient.generateIdentity();
  const eve = SPDRecipient.generateIdentity();

  it('single recipient round-trips; a stranger cannot open', () => {
    const master = SPD.generateRandomKey();
    const env = SPDRecipient.seal(master, [alice.publicKey]);
    expect(SPDRecipient.inspect(env)).toEqual({ version: 1, kem: 'MLKEM768-X25519', recipientCount: 1 });
    expect(eq(SPDRecipient.open(env, alice.secretKey), master)).toBe(true);
    expect(() => SPDRecipient.open(env, eve.secretKey)).toThrow(/no stanza could be opened/);
  });

  it('multi-recipient: every listed recipient opens, order independent', () => {
    const { masterSecret, envelope } = SPDRecipient.newSealedKey([bob.publicKey, alice.publicKey]);
    expect(SPDRecipient.inspect(envelope).recipientCount).toBe(2);
    expect(eq(SPDRecipient.open(envelope, alice.secretKey), masterSecret)).toBe(true);
    expect(eq(SPDRecipient.open(envelope, bob.secretKey), masterSecret)).toBe(true);
    expect(() => SPDRecipient.open(envelope, eve.secretKey)).toThrow();
  });

  it('two seals of the same secret to the same key produce different envelopes (fresh encapsulation)', () => {
    const master = SPD.generateRandomKey();
    const a = SPDRecipient.seal(master, [alice.publicKey]);
    const b = SPDRecipient.seal(master, [alice.publicKey]);
    expect(eq(a, b)).toBe(false);
  });

  it('any tampered byte (header, KEM ciphertext, or body) is rejected', () => {
    const master = SPD.generateRandomKey();
    const env = SPDRecipient.seal(master, [alice.publicKey, bob.publicKey]);
    const stanza = 1120 + 32 + 96 + 16;
    const positions = [
      5,                       // kem id (header)
      7 + 10,                  // alice's KEM ct
      7 + 1120 + 3,            // alice's commitment block
      7 + 1120 + 32 + 40,      // alice's ciphertext
    ];
    for (const pos of positions) {
      const bad = new Uint8Array(env);
      bad[pos] ^= 0x01;
      expect(() => SPDRecipient.open(bad, alice.secretKey), `pos ${pos}`).toThrow();
    }
    // Damage confined to bob's stanza: bob fails, alice is unaffected.
    const bobBad = new Uint8Array(env);
    bobBad[7 + stanza + 1120 + 143] ^= 0x01; // bob's tag byte
    expect(() => SPDRecipient.open(bobBad, bob.secretKey)).toThrow();
    expect(eq(SPDRecipient.open(bobBad, alice.secretKey), master)).toBe(true);
    // Header tamper that keeps the version but breaks the count/length relation
    const short = env.subarray(0, env.length - 1);
    expect(() => SPDRecipient.inspect(short)).toThrow(/length/);
  });

  it('a stanza cannot be transplanted into another envelope (header is AAD)', () => {
    const m1 = SPD.generateRandomKey();
    const m2 = SPD.generateRandomKey();
    const e1 = SPDRecipient.seal(m1, [alice.publicKey]);            // count = 1
    const e2 = SPDRecipient.seal(m2, [alice.publicKey, bob.publicKey]); // count = 2
    const frank = new Uint8Array(e2);
    frank.set(e1.subarray(7), 7); // put e1's stanza (sealed under count=1 header) into slot 0 of a count=2 envelope
    // Slot 0 fails (sealed under a count=1 header, AAD mismatch); slot 1 is bob's — alice gets nothing.
    expect(() => SPDRecipient.open(frank, alice.secretKey)).toThrow();
    // Bob's own stanza in the untouched slot still opens m2.
    expect(eq(SPDRecipient.open(frank, bob.secretKey), m2)).toBe(true);
  });

  it('validates inputs', () => {
    expect(() => SPDRecipient.seal(new Uint8Array(32), [alice.publicKey])).toThrow(/96 bytes/);
    expect(() => SPDRecipient.seal(SPD.generateRandomKey(), [])).toThrow(/1–255/);
    expect(() => SPDRecipient.seal(SPD.generateRandomKey(), [rnd(10)])).toThrow(/1216-byte/);
    expect(() => SPDRecipient.open(new Uint8Array(3), alice.secretKey)).toThrow(/not an SPD recipient envelope/);
    expect(() => SPDRecipient.open(SPDRecipient.seal(SPD.generateRandomKey(), [alice.publicKey]), rnd(31))).toThrow(/32 bytes/);
  });
});

describe('SPDRecipient end-to-end with SPD keyless mode', () => {
  it('sender seals to two recipients; each loads the file, a third cannot', async () => {
    const alice = SPDRecipient.generateIdentity();
    const bob = SPDRecipient.generateIdentity();
    const eve = SPDRecipient.generateIdentity();
    const f = path.join(os.tmpdir(), `spd-recipient-${Date.now()}-${Math.random().toString(36).slice(2)}.spd`);
    try {
      const { masterSecret, envelope } = SPDRecipient.newSealedKey([alice.publicKey, bob.publicKey]);
      const spd = new SPD();
      await spd.setRandomKey(masterSecret);
      masterSecret.fill(0);
      await spd.addData('report', { q: 3, ok: true });
      await spd.saveToFile(f, '');
      spd.destroy();

      for (const who of [alice, bob]) {
        const master = SPDRecipient.open(envelope, who.secretKey);
        const loaded = await SPD.loadWithRandomKey(f, master, undefined, { streaming: false });
        expect(await loaded.extractData()).toEqual({ report: { q: 3, ok: true } });
        loaded.destroy();
        master.fill(0);
      }
      expect(() => SPDRecipient.open(envelope, eve.secretKey)).toThrow();
    } finally {
      fs.rmSync(f, { force: true });
    }
  });
});

describe('SPD.createSealed / saveToFileSealed / loadFromFileSealed', () => {
  for (const streaming of [false, true]) {
    it(`one-call sealed workflow round-trips (${streaming ? 'binary' : 'json'}); strangers and passcode users cannot open`, async () => {
      const alice = SPDRecipient.generateIdentity();
      const bob = SPDRecipient.generateIdentity();
      const eve = SPDRecipient.generateIdentity();
      const f = path.join(os.tmpdir(), `spd-sealed-${Date.now()}-${Math.random().toString(36).slice(2)}.spd`);
      try {
        const { spd } = await SPD.createSealed([alice.publicKey, bob.publicKey]);
        await spd.addData('doc', { v: 42 });
        await spd.saveToFileSealed(f, [alice.publicKey, bob.publicKey], { streaming });
        spd.destroy();
        expect(fs.existsSync(f + '.spdr')).toBe(true);
        expect(SPDRecipient.inspect(new Uint8Array(fs.readFileSync(f + '.spdr'))).recipientCount).toBe(2);

        for (const who of [alice, bob]) {
          const loaded = await SPD.loadFromFileSealed(f, who.secretKey, { streaming });
          expect(await loaded.extractData()).toEqual({ doc: { v: 42 } });
          loaded.destroy();
        }
        await expect(SPD.loadFromFileSealed(f, eve.secretKey, { streaming })).rejects.toThrow(/no stanza/);
        // The envelope can also be supplied explicitly (delivered out of band).
        const env = new Uint8Array(fs.readFileSync(f + '.spdr'));
        fs.rmSync(f + '.spdr');
        const viaOpt = await SPD.loadFromFileSealed(f, alice.secretKey, { streaming, envelope: env });
        expect(await viaOpt.extractData()).toEqual({ doc: { v: 42 } });
        viaOpt.destroy();
      } finally {
        for (const p of [f, f + '.spdr', f + '.seq', f + '.ocount']) fs.rmSync(p, { force: true });
      }
    });
  }

  it('saveToFileSealed refuses a passcode-keyed instance', async () => {
    const spd = new SPD();
    spd.setKeyProfile('standard');
    await spd.setPassKey(SPD.generatePassphrase());
    await expect(spd.saveToFileSealed('/nonexistent/x.spd', [SPDRecipient.generateIdentity().publicKey])).rejects.toThrow(/keyless/);
    spd.destroy();
  });
});

describe('keyless in-memory persistence (strings / chunks)', () => {
  it('saveData + loadStringWithRandomKey and saveDataChunked + loadChunksWithRandomKey round-trip; wrong secret and empty passcode fail clearly', async () => {
    const secret = SPD.generateRandomKey();
    const spd = new SPD();
    await spd.setRandomKey(secret);
    const kp = SPD.generateSigningKeyPair({ composite: true });
    spd.setSigningKey(kp.privateKey);
    await spd.addData('k', { v: 'in-memory keyless' });
    const s = await spd.saveData('');
    const chunks = await spd.saveDataChunked('');
    spd.destroy();

    const a = await SPD.loadStringWithRandomKey(s, secret, kp.publicKey);
    expect(await a.extractData()).toEqual({ k: { v: 'in-memory keyless' } });
    a.destroy();
    const b = await SPD.loadChunksWithRandomKey(chunks, secret);
    expect(await b.extractData()).toEqual({ k: { v: 'in-memory keyless' } });
    b.destroy();

    await expect(SPD.loadStringWithRandomKey(s, SPD.generateRandomKey())).rejects.toThrow('Authentication failed.');
    await expect(SPD.loadStringWithRandomKey(s, secret, SPD.generateSigningKeyPair().publicKey)).rejects.toThrow('Authentication failed.');
    await expect(SPD.loadStringWithRandomKey(s, new Uint8Array(5))).rejects.toThrow(/96-byte/);
    await expect(SPD.loadFromString(s, '')).rejects.toThrow(/loadStringWithRandomKey/);
  });

  it('a recipient can open sealed data delivered as a string (browser-style flow, no files)', async () => {
    const alice = SPDRecipient.generateIdentity();
    const { spd, envelope } = await SPD.createSealed([alice.publicKey]);
    await spd.addData('note', 'string transport');
    const s = await spd.saveData('');
    spd.destroy();
    const master = SPDRecipient.open(envelope, alice.secretKey);
    const loaded = await SPD.loadStringWithRandomKey(s, master);
    expect(await loaded.extractData()).toEqual({ note: 'string transport' });
    loaded.destroy();
  });
});
