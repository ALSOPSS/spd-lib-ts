/**
 * SPD security scoring subpath — `spd-lib/score`.
 *
 * `spd-score.ts` reads files from disk (`fs`/`path`/`readline`) to analyze a
 * project's crypto posture — genuinely Node-only tooling, unlike the rest of
 * the library's in-memory encrypt/decrypt path. Kept out of the main
 * `spd-lib` barrel so importing the core `SPD` class never pulls in Node
 * built-ins, matching the library's cross-platform (browser + server) goal.
 *
 * Import from here explicitly if you need the scorer:
 * ```ts
 * import { scoreSPD, analyzeGenericDir } from 'spd-lib/score';
 * ```
 */
export {
  scoreSPD,
  scoreGenericSystem,
  scoreNpmLibrary,
  listKnownLibraries,
  analyzeGenericDir,
} from './spd-score.js';
export type {
  GenericCryptoObservable,
  GenericScoreResult,
  LibraryProfile,
} from './spd-score.js';
