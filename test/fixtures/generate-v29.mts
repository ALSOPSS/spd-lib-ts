/**
 * Regenerates the v29 golden fixtures. Run ONLY when the on-disk format
 * intentionally changes (then also bump SPEC.md and add a NEW fixture set —
 * old sets must keep reading forever):  npx tsx test/fixtures/generate-v29.mts
 * Secrets here are test-only and committed on purpose.
 */
import * as fs from 'fs';
import * as path from 'path';
import { SPD, SPDRecipient, SPDShamir } from '../../src/index.ts';

const dir = path.dirname(new URL(import.meta.url).pathname) + '/v29';
const PASS = 'golden-fixture-passphrase-Tr0ub4dor&3';
const RECIPIENT_SEED = Buffer.from('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', 'hex');
const MASTER = Buffer.from('f0'.repeat(96), 'hex');
const payload = { greeting: 'hello from the v29 golden fixture', n: 42, when: new Date('2026-10-24T00:00:00Z'), bytes: new Uint8Array([1, 2, 3, 250]), nested: { a: [1, 'two', null], b: true } };

async function filled(spd: SPD) { for (const [k, v] of Object.entries(payload)) await spd.addData(k, v); }

const p1 = new SPD(); p1.setKeyProfile('standard'); await p1.setPassKey(PASS); await filled(p1);
await p1.saveToFile(path.join(dir, 'passphrase-json.spd'), PASS);
await p1.saveToFileStreaming(path.join(dir, 'passphrase-binary.spd'), PASS);
p1.destroy();

const kp = SPD.generateSigningKeyPair({ composite: true });
const p2 = new SPD(); p2.setKeyProfile('standard'); await p2.setPassKey(PASS); p2.setSigningKey(kp.privateKey); await filled(p2);
await p2.saveToFile(path.join(dir, 'composite-signed.spd'), PASS);
fs.writeFileSync(path.join(dir, 'composite-signed.pub.hex'), Buffer.from(kp.publicKey).toString('hex'));
p2.destroy();

const id = SPDRecipient.generateIdentity(); // seed below is what matters; derive deterministically instead:
const recipientPk = SPDRecipient.publicKeyFromSecret(new Uint8Array(RECIPIENT_SEED));
void id;
const p3 = new SPD(); await p3.setRandomKey(new Uint8Array(MASTER)); await filled(p3);
await p3.saveToFile(path.join(dir, 'keyless-json.spd'), '');
fs.writeFileSync(path.join(dir, 'keyless-json.spd.spdr'), SPDRecipient.seal(new Uint8Array(MASTER), [recipientPk]));
fs.writeFileSync(path.join(dir, 'keyless.saveData.txt'), await p3.saveData(''));
p3.destroy();

const shares = SPDShamir.split(new Uint8Array(MASTER), 5, 3);
fs.writeFileSync(path.join(dir, 'shamir-5of3.json'), JSON.stringify(shares.map((s) => SPDShamir.encodeShare(s)), null, 2));
for (const side of ['.seq', '.ocount']) for (const f of fs.readdirSync(dir)) if (f.endsWith(side)) fs.unlinkSync(path.join(dir, f));
console.log('fixtures written to', dir, fs.readdirSync(dir));
