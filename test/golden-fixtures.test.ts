/**
 * Golden fixtures: files written by this library at a fixed point in time,
 * committed, and read back by every future version. If any of these stop
 * loading, the on-disk format has changed — that must be a deliberate
 * version bump with a NEW fixture set, never a silent incompatibility.
 * Regenerate (only for an intentional format change): npx tsx test/fixtures/generate-v29.mts
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { SPD, SPDShamir } from '../src/index';

const dir = path.join(__dirname, 'fixtures', 'v29');
const PASS = 'golden-fixture-passphrase-Tr0ub4dor&3';
const RECIPIENT_SEED = new Uint8Array(Buffer.from('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', 'hex'));
const MASTER = new Uint8Array(Buffer.from('f0'.repeat(96), 'hex'));

function expectPayload(d: Record<string, unknown>) {
  expect(d.greeting).toBe('hello from the v29 golden fixture');
  expect(d.n).toBe(42);
  expect((d.when as Date).toISOString()).toBe('2026-10-24T00:00:00.000Z');
  expect(Array.from(d.bytes as Uint8Array)).toEqual([1, 2, 3, 250]);
  expect(d.nested).toEqual({ a: [1, 'two', null], b: true });
}

describe('v29 golden fixtures still load', () => {
  it('passphrase JSON and binary files', async () => {
    const j = await SPD.loadFromFile(path.join(dir, 'passphrase-json.spd'), PASS);
    expectPayload(await j.extractData()); j.destroy();
    const b = await SPD.loadFromFileStreaming(path.join(dir, 'passphrase-binary.spd'), PASS);
    expectPayload(await b.extractData()); b.destroy();
    expect((await SPD.getEntry(path.join(dir, 'passphrase-binary.spd'), PASS, 'n')).value).toBe(42);
  }, 60_000);

  it('composite-signed file verifies with the committed public key and rejects another', async () => {
    const pk = new Uint8Array(Buffer.from(fs.readFileSync(path.join(dir, 'composite-signed.pub.hex'), 'utf8').trim(), 'hex'));
    const s = await SPD.loadFromFile(path.join(dir, 'composite-signed.spd'), PASS, pk);
    expectPayload(await s.extractData()); s.destroy();
    await expect(SPD.loadFromFile(path.join(dir, 'composite-signed.spd'), PASS, SPD.generateSigningKeyPair({ composite: true }).publicKey)).rejects.toThrow('Authentication failed.');
  }, 60_000);

  it('keyless file opens via the recipient envelope, the raw master secret, and the saveData string', async () => {
    const viaEnvelope = await SPD.loadFromFileSealed(path.join(dir, 'keyless-json.spd'), RECIPIENT_SEED, { streaming: false });
    expectPayload(await viaEnvelope.extractData()); viaEnvelope.destroy();
    const viaMaster = await SPD.loadWithRandomKey(path.join(dir, 'keyless-json.spd'), MASTER, undefined, { streaming: false });
    expectPayload(await viaMaster.extractData()); viaMaster.destroy();
    const viaString = await SPD.loadStringWithRandomKey(fs.readFileSync(path.join(dir, 'keyless.saveData.txt'), 'utf8'), MASTER);
    expectPayload(await viaString.extractData()); viaString.destroy();
  });

  it('Shamir v2 shares reconstruct the master secret', () => {
    const shares = (JSON.parse(fs.readFileSync(path.join(dir, 'shamir-5of3.json'), 'utf8')) as string[]).map((s) => SPDShamir.decodeShare(s));
    expect(Buffer.from(SPDShamir.combine([shares[4], shares[1], shares[2]])).equals(Buffer.from(MASTER))).toBe(true);
    expect(() => SPDShamir.combine([shares[0], shares[1]])).toThrow();
  });
});
