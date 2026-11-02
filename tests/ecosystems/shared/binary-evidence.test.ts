import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  binaryFindingsDelta,
  EVIDENCE_MAX_BYTES,
  scanBinaries,
} from '../../../src/ecosystems/shared/binary-scan.js';
import { buildElf } from './binary-fixtures.js';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'lockscan-evidence-test-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('scanBinaries evidence', () => {
  it('writes strings and imports files next to a binary that has a signal', async () => {
    const buf = buildElf([{ name: 'socket', undefined: true }]);
    const scans = await scanBinaries(new Map([['lib/evil.so', buf]]), dir);

    const evidence = scans.get('lib/evil.so')?.evidence;
    expect(evidence?.imports).toBe(join(dir, 'lib', 'evil.so.lockscan-imports.txt'));
    expect(await readFile(evidence?.imports ?? '', 'utf8')).toContain('socket');
    expect(await readFile(evidence?.strings ?? '', 'utf8')).toMatch(/^\d+: /m);
  });

  it('attaches the evidence to the findings of that binary', async () => {
    const buf = buildElf([{ name: 'socket', undefined: true }]);
    const newScans = await scanBinaries(new Map([['evil.so', buf]]), dir);

    const [finding] = binaryFindingsDelta(new Map(), newScans);

    expect(finding.label).toBe('native:socket');
    expect(finding.evidence?.strings).toBe(join(dir, 'evil.so.lockscan-strings.txt'));
  });

  it('writes nothing without an evidence dir, for quiet binaries, or for escaping names', async () => {
    const noisy = buildElf([{ name: 'socket', undefined: true }]);
    const quiet = Buffer.from('plain bytes');

    expect((await scanBinaries(new Map([['a.so', noisy]]))).get('a.so')?.evidence).toBeUndefined();
    expect(
      (await scanBinaries(new Map([['q.so', quiet]]), dir)).get('q.so')?.evidence,
    ).toBeUndefined();
    expect(
      (await scanBinaries(new Map([['../escape.so', noisy]]), dir)).get('../escape.so')?.evidence,
    ).toBeUndefined();
    await expect(stat(join(dir, '..', 'escape.so.lockscan-strings.txt'))).rejects.toThrow();
  });

  it('caps the evidence file size', async () => {
    const text = `${'A'.repeat(2000)}\0`.repeat(300);
    const buf = Buffer.concat([
      buildElf([{ name: 'socket', undefined: true }]),
      Buffer.from(text, 'latin1'),
    ]);
    const evidence = (await scanBinaries(new Map([['big.so', buf]]), dir)).get('big.so')?.evidence;

    const written = await readFile(evidence?.strings ?? '', 'utf8');
    expect(written.length).toBeLessThanOrEqual(EVIDENCE_MAX_BYTES + 32);
    expect(written).toContain('[truncated]');
  });
});
