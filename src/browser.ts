/**
 * Browser entry point — `import { SPD } from 'spd-lib/browser'`.
 *
 * Identical API and `.spd` binary format to the main `spd-lib` entry —
 * this is the SAME SPD class, not a weaker/format-incompatible variant like
 * the older `SPDWeb`. A file saved from the desktop (`spd-lib`) build
 * opens correctly here, and vice versa.
 *
 * The only difference from the main entry is a build-time swap of
 * `internal/node-platform.ts` for `internal/node-platform.browser.ts` (see
 * tsup.config.ts's `alias` option) — the Node-only accessors (`fs`, `path`,
 * `os`, `worker_threads`) are replaced with stubs that throw a clear
 * "requires Node.js" error instead of trying to resolve Node's `module`
 * built-in, which is what broke bundling of the main entry in a browser.
 *
 * File-I/O methods (`saveToFile`, `loadFromFileStreaming`, WAL, locking,
 * `addMany`'s worker-thread path, machine-binding, and every `SPDWriter`
 * method) throw that error if called here — by nature, they need a real
 * filesystem/OS. `SPDWriter` itself is exported (it already routes through
 * the same lazy `node-platform` accessors `SPD` uses) so importing it here
 * fails the same way calling a file-I/O method does — a clear "requires
 * Node.js" error at the point of use — rather than a module-resolution
 * error just for importing the class. Everything else (in-memory
 * encrypt/decrypt, `addData`/`getData`/`extractData`, key derivation,
 * `SPDTransport` sessions, `SPDVault`, `SPDShamir`, `SPDHandshake`) works
 * identically to the desktop build: Argon2id, XChaCha20-Poly1305, ML-KEM-768,
 * ML-DSA-65 are all pure-JS/WASM already — verified running correctly in a
 * real headless-browser engine.
 */
export { SPD, ARGON2_MEMORY_HIGH, ARGON2_TIME_HIGH, ARGON2_MEMORY_PARANOID, ARGON2_TIME_PARANOID } from './SPD.js';
export type { SPDKeyProfile } from './SPD.js';
export { SPDVault, SPDVault as SPD_Vault } from './SPDVault.js';
export { SPDWriter } from './SPDWriter.js';
export * from './types.js';
export { SPDTransport } from './SPDTransport.js';
export type { SPDServerIdentity, SPDSession, SPDClientHandshake, SPDClientConnectOptions, SPDTransportIo } from './SPDTransport.js';
export { SPDShamir } from './SPDShamir.js';
export type { SPDShamirShare } from './SPDShamir.js';
export { SPDHandshake, SPDHandshakeInitiator, SPDHandshakeResponder, SPDHandshakeResult } from './SPDHandshake.js';
export type { SPDHandshakeHello, SPDHandshakeAuthOptions, SPDHandshakeIdentity } from './SPDHandshake.js';
export { SPDRecipient } from './SPDRecipient.js';
export type { SPDRecipientIdentity, SPDRecipientEnvelopeInfo } from './SPDRecipient.js';
