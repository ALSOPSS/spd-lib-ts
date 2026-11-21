#!/usr/bin/env node
/**
 * Dedicated CLI executable for `spd-score` (see package.json's `bin` field).
 *
 * This file's only job is calling `main()` unconditionally — it is never
 * imported by library consumers of `spd-lib`/`spd-lib/score`, so there
 * is no bundling scenario where importing this codebase could accidentally
 * run the CLI or call `process.exit()`. See spd-score.ts's own comment
 * (right where the old, unreliable "was this file run directly?" guard used
 * to live) for why that detection approach was removed instead of patched
 * further — it's fundamentally unfixable from inside a module that might be
 * bundled into someone else's entry point.
 */
import { main } from './spd-score.js';

main().catch((err) => {
  console.error('spd-score error:', err.message ?? err);
  process.exit(2);
});
