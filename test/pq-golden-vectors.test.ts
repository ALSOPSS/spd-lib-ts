/**
 * Golden-vector tests for the post-quantum primitives (@noble/post-quantum,
 * ML-KEM-768 / FIPS 203 and ML-DSA-65 / FIPS 204) this library depends on.
 *
 * package.json pins `"@noble/post-quantum": "^0.5.4"` — a pre-1.0 package.
 * npm's caret range on a 0.x version only allows patch bumps (0.5.5, 0.5.99,
 * ...), never an unexpected 0.6.0, so a silent breaking install is already
 * guarded against at the dependency-resolution level. But every existing
 * test of these primitives in this repo is a round-trip test (sign then
 * verify, encapsulate then decapsulate, all within the same test run) —
 * that style of test would keep passing even if the ENTIRE algorithm
 * implementation silently changed behavior (a bug in a patch release, or a
 * manual version bump someone makes years from now), because both sides of
 * the round trip use the same, possibly-changed code. It would not catch
 * the one failure mode that actually matters for "can I still open a file
 * I encrypted years ago": the byte-level output no longer matching what an
 * OLDER install of this same dependency produced.
 *
 * These tests hardcode real output produced by the currently-installed
 * 0.5.4 and assert it never changes — a genuine regression/drift detector,
 * not a correctness proof of the crypto itself (that's NIST's and noble's
 * job, not this library's). If one of these ever fails after a dependency
 * update, that is the signal to investigate whether old on-disk files
 * (ML-DSA-65 file signatures, ML-KEM-768 transport handshakes) are still
 * verifiable before shipping the update — NOT something to "fix" by just
 * updating the hardcoded hex here.
 *
 * ML-KEM-768: keygen(seed) and encapsulate(pub, msg) both accept an
 * explicit deterministic input (confirmed directly against the installed
 * package), so the full chain is reproducible byte-for-byte.
 *
 * ML-DSA-65: keygen(seed) is deterministic, but sign() is randomized by
 * FIPS 204 design (uses fresh internal randomness even for the same
 * message + key, confirmed directly — two signatures of the same input
 * are different byte strings). So the sign-side golden vector is a fixed,
 * pre-generated signature checked into this test — proving a signature
 * produced by THIS install still verifies, not that signing itself is
 * deterministic (it isn't, and shouldn't be "fixed" to be so).
 */
import { describe, it, expect } from 'vitest';
import * as crypto from 'crypto';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

function sha256hex(data: Uint8Array): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

describe('ML-KEM-768 golden vectors (regression: dependency drift detector)', () => {
  const seed = new Uint8Array(64).fill(0x42);
  const msg  = new Uint8Array(32).fill(0x24);

  it('keygen(fixedSeed) produces the expected, unchanged keypair', () => {
    const { secretKey, publicKey } = ml_kem768.keygen(seed);
    expect(publicKey.length).toBe(1184);
    expect(secretKey.length).toBe(2400);
    expect(sha256hex(publicKey)).toBe('8cde1b49992415b527e361f52465634978fcc488d6f541c4a1fec97fd14b4661');
    expect(sha256hex(secretKey)).toBe('32cd78a5f245c9e9f922e02e87714ac58f188f205a093480043b1573a18ad5df');
  });

  it('encapsulate(pub, fixedMsg) produces the expected, unchanged ciphertext + shared secret', () => {
    const { publicKey } = ml_kem768.keygen(seed);
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey, msg);
    expect(cipherText.length).toBe(1088);
    expect(sha256hex(cipherText)).toBe('5e40353f41f38f77fecf2a005e927051c1be746e157a4531f2bac07a8c5a1dec');
    expect(Buffer.from(sharedSecret).toString('hex')).toBe('bcf2af3bd39ae7ab59ce584a3731e1b93fdefba36d30a828275d1aabf5d27d1e');
  });

  it('decapsulate recovers the exact same shared secret encapsulate produced', () => {
    const { secretKey, publicKey } = ml_kem768.keygen(seed);
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey, msg);
    const decapped = ml_kem768.decapsulate(cipherText, secretKey);
    expect(Buffer.from(decapped).equals(Buffer.from(sharedSecret))).toBe(true);
  });
});

describe('ML-DSA-65 golden vectors (regression: dependency drift detector)', () => {
  const seed = new Uint8Array(32).fill(0x37);
  const msg  = new TextEncoder().encode('spd-lib-ts golden vector fixed message');
  // Pre-generated once against the currently-pinned 0.5.4 install (see this
  // file's header) — a fixed signature that must keep verifying under the
  // fixed keypair below. Signing itself is NOT deterministic (FIPS 204,
  // confirmed directly) so this is checked in as data, not regenerated.
  const HARDCODED_SIG_HEX =
    'c7b9a97be46cf34b280047087598fa79450d0f36f52bee2fe62ab41f0cc06036979d296322266c7475fd8cedbd2d134424eb0f749127710f0270be48' +
    'd5d54e3e9c23ad9f05f594a7fe0240b7174c3a62e9beeaddad9220bbab77da1574b1d9c60c7b8b0736ccc73bbe5aef4462345790214b9dc6696d078f' +
    '59da607a46c35d323148aa57c4a41989b90bf4932e5f4165f84d88b5a631a1d786d927950f848de8bf26f9480ce0b6f209dd7b7d7aaa6e50d1f71c7d' +
    '6c31005d16458bb56dfc30affc9cd72d7c4a7c115a8e840acc0878e08030741c88cdd6491ddb8eba0fd32415522afce61ea7b6dbfbfdc78795d4ac45' +
    'b5c52ccea7d55904fb2ead837511814ad6c793660e45afd770f4ef1a6e5f6a89e57d260914df9e4057ec609139edf49d99805192d83bd1c2bc4f36fd' +
    '65969fb127ebd24643ac6bdb6e0289e3b6d68fc047f11f94aaba79f377e97d6d9ed703a5a9d239a629770e8cb4e1548c0a7e66fdb07fdb2989d3704b' +
    'ecdcbdfaa1dd933ef593e5296f935da030ce068c9e2fdf10054e84779903e01a42ef33c9a9e27b412bb8c06704e6ec3fdf851976f52ae34702e80f0e' +
    '67e1b542c2bfe6c2e7ea520efab09d070d0b0339863a9c25f1847979bbee700e038f3cbcd33be1057ffb1d64ddf2b0582c4fe3314085f449eab08681' +
    'ac5429f83e1eb6825bfbc40a546f98f6cf227fd598cf6c812268605da49cb8ead5f7f5c39cdccb974b5d5c832205c9a6c107a8b4b5db9e92947b04a2' +
    'efc1deda357fbd385a7a1a8e16766e201329b5e915433ecf5308015610c2665445e3204be63c87a51ea1b0dfdcd155caa00e9d28f2d84f2d627d4540' +
    '343794259242494e186068e66e66654c12bf84e70e4d812ac74adfabfacf136239f925705994adbce7cd905924aad5981130fd0d93f1666e12331b75' +
    'b209d3449f6222e2a93d241eb9e44c48febb54ac31f487f146e855334d8ad8a58d7fa4de2a39abcba7feb935e395eca79befb136b8ca28d38a573435' +
    'e60cae517ca880e82c37094f12844beb15aaf41594889bee10a1a36d3bfe2d3f6055caaa709556b1b41451b8468fad92fd3c93fe89addcf19a0bbca0' +
    '946c56d97690cbdf53073f8d93893bef46a16d5c4a0ac3489d7f394196d87f664e1a7152a59687101bbd0129bbd93432f6e704844b34d40c2e203bca' +
    'ce4bb495ddf314f2ab23edcdd859494acc40e628e6e5ca050af015c864d7ec47161e2f39f919811ea1d966b6121de259d1e647527e06814e40eac258' +
    '971386eb0218b391aecc800162be4d2e75ff75e488b43393066d02269349a7b772928cf051819008ae6573e5ae5c853af53f9031b9c2faa88564d9b3' +
    '4a3ba29ebce6eac53bb82c26761a579b7e3e1dd8d3b6db544908538908223b1045444106d5dfb4cc84ed38ce8f9397dfd9be796de468a9b326d2d968' +
    '201a945236d0167d173d1eb53dc0da6cf822e328946c9f30ffb5e2d84e72a2ca51cbdff4db719131b5a3c8371522bd31ef4d412daa73f257b06628d1' +
    'ecb1eddf402242137bf6c77f1fb63d4b5a3ba4a58267fe4912322dd7a0947a00388905b7b98d7044ea75467d4836d5ba81c11b5a47da079d18807f4a' +
    '840c73ef3dd4d5b26bc5fb5ab2e1c801cdd954bbca27dfc1d773985efc3d707ccfcc8ff3026f68041fe3606ce441f5f35d717cbf32ff0bdeeebd29c5' +
    '8a7d421908729def472412cc8d70a85431f83178e94e84834546acaaba76dce040b1f91ec43d03a5c7d4dc9eed6e6ff93b0e134de2fb925135639695' +
    '704438f233f7d2737ee21859bcb5f350338bfa5f56e052caef5efb59ad271da6f59d9e1b1cd314c6b71c2ac1e5240aaf1ac178d873cce01de0e60216' +
    '38fdb0aa6e3941afb84395fe7899bec85be4e198a469460d8737592be678c89c2a5222e7128ca5035fa3a443a8c50f182c25ef896e48d91e4b7cbbcd' +
    '60ec43cef274e567a23a9a456368ffdd19f78199c4c0744f3608139054e50a3d59b20efad59c9cd74545e7ab619218bd3f1d4c50a360ddf1ea9a1da7' +
    '15cc37dbd1d614fca02d1220d0537fbb3cdbf055b0ef29cc401a7be67e587f224a8e2eed543a49d5d398a491f47e468ac3b1cb73a64ef944e5a2c1b5' +
    'ac6086d052b4c57bacf8eb187af644be55e34cc226403378b7d1a77f0a755492237ee55d3405135dad41bfca65627b3957c5910fa55cf18462ffdd19' +
    '58e8b3553aa919195b3bb76362ca69f25d165f43667e622d086a1d81d573ca712f9798d200823757a47e25083e604de262660eb07e7e407ce43a83ee' +
    '5eca8a25a8849d1e7df32e6686b262aea54e89e509ac5086ad1c25bdb977efb8c09e4e8067b3744beeb0d07898bc254c72dcc9d1d015e23e900a3f98' +
    'b7563e7880596cb5307e76a533134b8e74ad47ecf19a375ba197c9e42b2d9aee1f53067b9af29d2fda1cc4de87a827182f97cdd56c09be03ed9acf44' +
    '717d24308a3a1b53ccd7f6fef4a410e63dcd03d84944be4dcac261dba9db3b79ed18b12586732eb5a7c762cb2262fd35228ad02776009532090a71a2' +
    '772e1de6ec8410ce1aa0b63d0f404f7561833ec38f6eb20104efc338e4f2328db53e17e7aecb22272ad5fbaa97e6848cda37ab28f2f69ea76a5d9f62' +
    'c63cde7a5de5ee0c6009075a1eefde602b0d57236356148dbd82068b1e832cd360c25cfcd40790481a5ec7109318b310747ef3e998fb6dfca7eebb27' +
    'b0c80de50ee066519d88786b6ba1f1f2496e8359c609b24d8cdc99d27cd4302c300daa904c784a3133f4418ae6a4a2e8825fd0424070a6533a1596c2' +
    '48090f971df56663058add7b970f7fed84b123a38ed50a561e47fb3baaac3cbb38a37a5653fb9ad90234151a7be8faf353129c949ba43690eadd1c9b' +
    'd7b91b7a5540dcdd928b3ab7455abb2fe2f0ebdc2d547c5dc09b2dd1416ee1a423e0f97859d038f4b5a9fb32195373cb9575cc86f8299eb53892cc72' +
    'bad4ad6c6b361f89a6951f7a596e756f5bca815028785eccce69d1d808eebf62a2199d4bb1eb65254ffd7295e2e343fa7f6a734209171d5450c0e465' +
    'c55628d7050ec101cb3fa779cd1944cd9c5232dc7b0e0e00276fcbd91b68ea8f76dcf2a0d0fd2920bf6633938119dcadae278a01ee7146929c88edcc' +
    '2af17008c208614b7ed8cf18f64cf1263de41394ac961a638bf07daadc461b725e317bfcc27d90857e6354d982b919adc15eb1315035f4ad0a4d7b6f' +
    'ba7e62890d86ffbf4d885ba332571b09a64bfedeaedb240d29ee76e97f552f5e968baf1ccef00cc0944fa367bf6a22e31d7656d4aee730786ec9ede7' +
    'c468a78a902f68582dcff7e994f1695a339a46634cbf92dc321142958ca17cea0ca1f5502f18e2b0c098870bc58b61dc0ae91309a7d4d51010991653' +
    '7ba2e473761dda213881769bd4aecdc7970583fbe7dc284cd583c55fd21033fdb47699ee6369f83d8ead0cfec29312e78a7ba01e945af7dd2105c49e' +
    'f5ccaf59e3ba8ab1bf9571f2ba3205a59c71c17994d2e657c426d7dcd31ce92a45c996ec36cb6063fa1ad275f190b74c38677beea40ce5e8d517158e' +
    '9dd9382de26055ea3c2bfedac118ebd61d42aee9bed7c1ab38c16e4fd48313e3aa6ce0b050ac0aa55847ffe50e1cc870783ff5c85709ad76e0e9ab95' +
    'f49482e4e5d54a93c0142ee8147603b593657ff60c8e80b1f59c7e264aa99c4ecb3f6d80495dc1cefcea235c12e61df782239da3df5528cda2edd799' +
    '4476b41f9b6747f078dc70126d90c7450ae6ffff383c5efd879ef0e8f1ad07858ae3b051ae4f41ad6d5d5cde9ea11e19b0bb95170fccca133bc639e0' +
    '07d582e30d58402370da2ce0b3890e35ebe58d9c750df8ade63ce41bd03c58dee579c7ceef56d6eef06ba49d020c1b8cbdf95c6c7b63c7666816ae5d' +
    '8a76b45c433d528dac2898d90942a68717d4fa6923ab7c7c25a576095cae7b2a6704e988167512e5377ec1b4194a434ad2751cd0e538321f199aae8d' +
    '9a7c9d609f815a3d7f960e8f23cc595ea6b8e13fced4ee551170378f64cb73e4a88dccd586a0a17e9c68c6cf4fd18782b1d90d5cb10df1b77979ebd6' +
    'f05e336dcf9c6a8b5bd88c3f7ac656e079469017b7b40ffadbc7e7ff33717bdeb98bb0c13f7439eeec0d48a5648be1ccd9d0669dc23d13da8c9d1f47' +
    '4fa10da5d4e1bf23048482bc5f4815d06b16c4e2ff9f92af62a20eb0d9d0698ca083e0ac7403c65bdf60349a39d3af3dcc4cea1c56f04d8e4681ab7a' +
    'a9b325b32e630bddc8cf1a7c61602975bfe61c8cfe45acd7349664a31ac6071e7073c741eca47487a9db4f3b7c1ae2e62aa9503fd6c945a381905642' +
    '35b52308beeb1cbe0d1e839b41347c6391652fe689c4fe293043f79159ac10c3a02c68955d1080d99a44014f822c2334f33c8aef8fdef01454d84e68' +
    '99a839bb12724eb8d48b46419f0d8a52e27b327db0dd6376e26320d5b254f3bd986f6028dc7dbbf560cb0dcfd456421582c16a3c7a824d4348371f21' +
    '6547e0dc8141ea7bc4e3b9b38fe34688eb7c0e1feb7c40faada5aead5771b7624260a5d48a2239083b8bd608968ad363f7d2c1ccf864622ee73ad250' +
    '3bbce04d12e6e0940c0d42526d6e8ff8073f51f4fa020c16a0eaedfb18666ba0a6e6ec0c18203c6b93f22d304ab6bacad3d7fe000000000000000000' +
    '000000080d141b222b';

  it('keygen(fixedSeed) produces the expected, unchanged keypair', () => {
    const { secretKey, publicKey } = ml_dsa65.keygen(seed);
    expect(publicKey.length).toBe(1952);
    expect(secretKey.length).toBe(4032);
    expect(sha256hex(publicKey)).toBe('61b6a6f3f64dd2d17e80147a46ceff27332e10c0a13969a17071aec8b70f8518');
    expect(sha256hex(secretKey)).toBe('05557ca87c929fd21d86c2547d4dcfe10a80e38b9a33b4384d8135db241c44a6');
  });

  it('sign() is randomized (FIPS 204 by design) — two signatures of the same message differ', () => {
    const { secretKey } = ml_dsa65.keygen(seed);
    const sigA = ml_dsa65.sign(msg, secretKey);
    const sigB = ml_dsa65.sign(msg, secretKey);
    expect(Buffer.from(sigA).equals(Buffer.from(sigB))).toBe(false);
  });

  it('a hardcoded, pre-generated signature still verifies under the fixed keypair (regression: dependency drift detector)', () => {
    const { publicKey } = ml_dsa65.keygen(seed);
    const sig = new Uint8Array(Buffer.from(HARDCODED_SIG_HEX, 'hex'));
    expect(sig.length).toBe(3309);
    expect(ml_dsa65.verify(sig, msg, publicKey)).toBe(true);
  });

  it('the hardcoded signature is correctly rejected for a different message (sanity check on the fixture itself)', () => {
    const { publicKey } = ml_dsa65.keygen(seed);
    const sig = new Uint8Array(Buffer.from(HARDCODED_SIG_HEX, 'hex'));
    const wrongMsg = new TextEncoder().encode('a different message entirely');
    expect(ml_dsa65.verify(sig, wrongMsg, publicKey)).toBe(false);
  });
});
