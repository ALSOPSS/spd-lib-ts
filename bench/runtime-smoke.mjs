/**
 * Cross-runtime smoke test for the BUILT package: node / bun / deno.
 *   node bench/runtime-smoke.mjs
 *   bunx bun bench/runtime-smoke.mjs      (or: npx -y bun bench/runtime-smoke.mjs)
 *   deno run -A bench/runtime-smoke.mjs   (or: npx -y deno run -A bench/runtime-smoke.mjs)
 * Exercises the in-memory keyless path (no fs, no Argon2id), recipients and Shamir.
 */
const { SPD, SPDRecipient, SPDShamir } = await import(new URL('../dist/index.js', import.meta.url).href);
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const secret = SPD.generateRandomKey();
const spd = new SPD(); await spd.setRandomKey(secret);
await spd.addData('k', { hello: 'runtime' });
const s = await spd.saveData('');
const back = await SPD.loadStringWithRandomKey(s, secret);
const roundtrip = (await back.extractData()).k?.hello === 'runtime';
const id = SPDRecipient.generateIdentity();
const recipient = same(SPDRecipient.open(SPDRecipient.seal(secret, [id.publicKey]), id.secretKey), secret);
const sh = SPDShamir.split(secret, 3, 2);
const shamir = same(SPDShamir.combine([sh[0], sh[2]]), secret);
const ok = roundtrip && recipient && shamir;
console.log('RESULT', JSON.stringify({ runtime: globalThis.Deno ? 'deno' : globalThis.Bun ? 'bun' : 'node', roundtrip, recipient, shamir, PASS: ok }));
if (!ok) { globalThis.process?.exit?.(1); globalThis.Deno?.exit?.(1); }
