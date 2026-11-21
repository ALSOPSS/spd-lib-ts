/**
 * End-to-end check of the spd-inspect CLI against files written by the
 * current library. It used to carry its own (drifted) key schedule and failed
 * on every current-format file; it now delegates to the library.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SPD } from '../src/index';

const PASS = 'Tr0ub4dor&3-horse-battery-staple-99';

describe('spd-inspect CLI', () => {
  it('verifies the MAC and prints decrypted values for JSON and binary files', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'spd-inspect-'));
    try {
      const spd = new SPD();
      spd.setKeyProfile('standard');
      await spd.setPassKey(PASS);
      await spd.addData('greeting', 'hello inspector');
      await spd.addData('n', 42);
      await spd.saveToFile(path.join(dir, 'j.spd'), PASS);
      await spd.saveToFileStreaming(path.join(dir, 'b.spd'), PASS);
      spd.destroy();
      const run = (...args: string[]) =>
        execFileSync('npx', ['tsx', 'src/spd-inspect.ts', ...args], { encoding: 'utf8', timeout: 120_000 }).replace(/\x1b\[[0-9;]*m/g, '');
      const j = run(path.join(dir, 'j.spd'), '--pass', PASS, '--layer', '4', '--entry', 'greeting');
      expect(j).toMatch(/MAC verification:\s+PASS/);
      expect(j).toContain('hello inspector');
      const b = run(path.join(dir, 'b.spd'), '--pass', PASS, '--streaming');
      expect(b).toMatch(/MAC verification:\s+PASS/);
      expect(b).toContain('hello inspector');
      expect(b).toContain('42');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, 180_000);
});
