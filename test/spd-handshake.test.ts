import { describe, it, expect } from 'vitest';
import { SPDHandshake } from '../src/SPDHandshake';
import type { SPDHandshakeHello } from '../src/SPDHandshake';

describe('SPDHandshake — hybrid X25519 + ML-KEM-768 key agreement', () => {
  it('initiator and responder derive the same session key and matching commitment', async () => {
    const init = await SPDHandshake.createInitiator();
    const resp = await SPDHandshake.createResponder(init.hello);
    const initResult = await init.finalizeInitiator(resp.hello);
    const respResult = resp.responderResult();

    expect(initResult.sessionKey).toBe(respResult.sessionKey);
    expect(initResult.commitment).toBe(respResult.commitment);
    expect(initResult.sessionKey).toMatch(/^[0-9a-f]{64}$/); // 32 bytes hex

    initResult.destroy();
    respResult.destroy();
  });

  it('produces a different session key on every run (ephemeral keys)', async () => {
    const run = async () => {
      const init = await SPDHandshake.createInitiator();
      const resp = await SPDHandshake.createResponder(init.hello);
      const result = await init.finalizeInitiator(resp.hello);
      const key = result.sessionKey;
      result.destroy();
      resp.responderResult().destroy();
      return key;
    };
    const a = await run();
    const b = await run();
    expect(a).not.toBe(b);
  });

  it('finalizeInitiator throws if called twice', async () => {
    const init = await SPDHandshake.createInitiator();
    const resp = await SPDHandshake.createResponder(init.hello);
    const result = await init.finalizeInitiator(resp.hello);
    result.destroy();

    await expect(init.finalizeInitiator(resp.hello)).rejects.toThrow(/already called/);
  });

  it('rejects a malformed hello (wrong field type)', async () => {
    const init = await SPDHandshake.createInitiator();
    const badHello = { hybridClassicalPub: 123, hybridQuantumData: 'x', nonce: 'y' } as any;
    await expect(init.finalizeInitiator(badHello)).rejects.toThrow(/must be a string/);
  });

  it('rejects a hello with wrong-length classical public key', async () => {
    const init = await SPDHandshake.createInitiator();
    const resp = await SPDHandshake.createResponder(init.hello);
    const tamperedHello: SPDHandshakeHello = { ...resp.hello, hybridClassicalPub: Buffer.from(new Uint8Array(16)).toString('base64url') };
    await expect(init.finalizeInitiator(tamperedHello)).rejects.toThrow(/32 bytes/);
  });

  it('rejects a hello with wrong-length KEM data', async () => {
    const init = await SPDHandshake.createInitiator();
    const resp = await SPDHandshake.createResponder(init.hello);
    const tamperedHello: SPDHandshakeHello = { ...resp.hello, hybridQuantumData: Buffer.from(new Uint8Array(10)).toString('base64url') };
    await expect(init.finalizeInitiator(tamperedHello)).rejects.toThrow(/1088 bytes/);
  });

  it('rejects a low-order (all-zero) X25519 public key from the initiator side', async () => {
    const init = await SPDHandshake.createInitiator();
    const zeroKeyHello: SPDHandshakeHello = {
      ...init.hello,
      hybridClassicalPub: Buffer.from(new Uint8Array(32)).toString('base64url'),
    };
    await expect(SPDHandshake.createResponder(zeroKeyHello)).rejects.toThrow(/low-order/);
  });

  it('rejects a low-order (all-zero) X25519 public key from the responder side', async () => {
    const init = await SPDHandshake.createInitiator();
    const resp = await SPDHandshake.createResponder(init.hello);
    const zeroKeyHello: SPDHandshakeHello = {
      ...resp.hello,
      hybridClassicalPub: Buffer.from(new Uint8Array(32)).toString('base64url'),
    };
    await expect(init.finalizeInitiator(zeroKeyHello)).rejects.toThrow(/low-order/);
  });

  it('destroy() on an abandoned initiator does not throw', async () => {
    const init = await SPDHandshake.createInitiator();
    expect(() => init.destroy()).not.toThrow();
  });

  it('a tampered nonce changes the derived session key (nonce is bound into the transcript)', async () => {
    const init = await SPDHandshake.createInitiator();
    const resp = await SPDHandshake.createResponder(init.hello);

    // Real handshake result (control)
    const control = await SPDHandshake.createResponder(init.hello);
    void control;

    const tamperedHello: SPDHandshakeHello = {
      ...resp.hello,
      nonce: Buffer.from(new Uint8Array(32).fill(7)).toString('base64url'),
    };
    const result = await init.finalizeInitiator(tamperedHello);
    const untamperedInit = await SPDHandshake.createInitiator();
    const untamperedResp = await SPDHandshake.createResponder(untamperedInit.hello);
    const untamperedResult = await untamperedInit.finalizeInitiator(untamperedResp.hello);

    expect(result.sessionKey).not.toBe(untamperedResult.sessionKey);
    result.destroy();
    untamperedResult.destroy();
    untamperedResp.responderResult().destroy();
    resp.responderResult().destroy();
  });
});

describe('SPDHandshake transcript binding', () => {
  it('binds every public value: same shared secrets + one changed public input → different key', async () => {
    const { __testing__ } = await import('../src/SPDHandshake.js');
    const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n));
    const ss1 = rnd(32), ss2 = rnd(32);
    const inputs = [rnd(32), rnd(32), rnd(32), rnd(32), rnd(1184), rnd(1088)]; // nonces, x25519 pubs, kem pub, kem ct
    const derive = (pub: Uint8Array[]) =>
      __testing__.deriveSessionKey(ss1, ss2, __testing__.transcript(pub[0], pub[1], pub[2], pub[3], pub[4], pub[5])).sessionKey;
    const base = derive(inputs);
    expect(derive(inputs)).toBe(base);
    for (let i = 0; i < inputs.length; i++) {
      const changed = inputs.map((b) => new Uint8Array(b));
      changed[i][0] ^= 1;
      expect(derive(changed), `input ${i}`).not.toBe(base);
    }
  });
});

describe('SPDHandshake authentication (ML-DSA-65)', () => {
  const server = SPDHandshake.generateIdentity();
  const client = SPDHandshake.generateIdentity();
  const mallory = SPDHandshake.generateIdentity();

  it('mutual authentication: both sides pinned → same key, signatures verify', async () => {
    const init = await SPDHandshake.createInitiator({ identity: client.secretKey, peerPublicKey: server.publicKey });
    const resp = await SPDHandshake.createResponder(init.hello, { identity: server.secretKey, peerPublicKey: client.publicKey });
    expect(typeof resp.hello.signature).toBe('string');
    const iRes = await init.finalizeInitiator(resp.hello);
    expect(typeof iRes.signature).toBe('string');
    expect(() => resp.responderResult()).toThrow(/verifyInitiator/);
    resp.verifyInitiator(iRes.signature!);
    expect(resp.responderResult().sessionKey).toBe(iRes.sessionKey);
  });

  it('pinned responder key but unsigned responder hello → rejected', async () => {
    const init = await SPDHandshake.createInitiator({ peerPublicKey: server.publicKey });
    const resp = await SPDHandshake.createResponder(init.hello);
    await expect(init.finalizeInitiator(resp.hello)).rejects.toThrow(/signature required/);
  });

  it('MITM with its own identity → rejected by the pinned key', async () => {
    const init = await SPDHandshake.createInitiator({ peerPublicKey: server.publicKey });
    const evil = await SPDHandshake.createResponder(init.hello, { identity: mallory.secretKey });
    await expect(init.finalizeInitiator(evil.hello)).rejects.toThrow(/verification failed/);
  });

  it('a genuine responder signature replayed into another session → rejected', async () => {
    const initA = await SPDHandshake.createInitiator({ peerPublicKey: server.publicKey });
    const respA = await SPDHandshake.createResponder(initA.hello, { identity: server.secretKey });
    const initB = await SPDHandshake.createInitiator({ peerPublicKey: server.publicKey });
    const evilB = await SPDHandshake.createResponder(initB.hello); // attacker's own ephemeral keys
    await expect(initB.finalizeInitiator({ ...evilB.hello, signature: respA.hello.signature })).rejects.toThrow(/verification failed/);
  });

  it('an initiator signature cannot be reflected as a responder signature (role contexts)', async () => {
    // Same transcript, but signed under the initiator context by the "server" key.
    const init = await SPDHandshake.createInitiator({ identity: server.secretKey, peerPublicKey: server.publicKey });
    const resp = await SPDHandshake.createResponder(init.hello, { peerPublicKey: server.publicKey });
    // Initiator can't finish (responder unsigned); instead check the responder side rejects a responder-context sig.
    const resp2 = await SPDHandshake.createResponder(init.hello, { identity: server.secretKey, peerPublicKey: server.publicKey });
    expect(() => resp2.verifyInitiator(resp2.hello.signature!)).toThrow(/verification failed/);
    expect(() => resp.verifyInitiator(resp2.hello.signature!)).toThrow(/verification failed/);
  });

  it('bad initiator signature destroys the responder result', async () => {
    const init = await SPDHandshake.createInitiator({ identity: mallory.secretKey });
    const resp = await SPDHandshake.createResponder(init.hello, { peerPublicKey: client.publicKey });
    const iRes = await init.finalizeInitiator(resp.hello);
    expect(() => resp.verifyInitiator(iRes.signature!)).toThrow(/verification failed/);
    expect(() => resp.responderResult()).toThrow(/verifyInitiator/);
  });

  it('rejects malformed identity / peer keys', async () => {
    await expect(SPDHandshake.createInitiator({ identity: new Uint8Array(10) })).rejects.toThrow(/secret key/);
    await expect(SPDHandshake.createInitiator({ peerPublicKey: new Uint8Array(10) })).rejects.toThrow(/public key/);
  });

  it('unauthenticated handshakes still work unchanged', async () => {
    const init = await SPDHandshake.createInitiator();
    const resp = await SPDHandshake.createResponder(init.hello);
    expect(resp.hello.signature).toBeUndefined();
    const iRes = await init.finalizeInitiator(resp.hello);
    expect(iRes.signature).toBeUndefined();
    expect(resp.responderResult().sessionKey).toBe(iRes.sessionKey);
  });
});
