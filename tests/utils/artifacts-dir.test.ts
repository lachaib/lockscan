import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import AdmZip from 'adm-zip';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { prepareArtifactsDir } from '../../src/utils/artifacts-dir.js';
import { extractZipToDir } from '../../src/utils/extract.js';

let base: string;

beforeEach(async () => {
  base = await mkdtemp(join(tmpdir(), 'lockscan-artifacts-test-'));
});

afterEach(async () => {
  await rm(base, { recursive: true, force: true });
});

describe('prepareArtifactsDir', () => {
  it('creates a missing parent and a unique lockscan-* subdirectory', async () => {
    const path = await prepareArtifactsDir('out/art', base);
    expect(dirname(path)).toBe(join(base, 'out', 'art'));
    expect(basename(path)).toMatch(/^lockscan-/);
    expect((await stat(path)).isDirectory()).toBe(true);
  });

  it('leaves existing content in the parent untouched and returns distinct dirs', async () => {
    await mkdir(join(base, 'used'));
    await writeFile(join(base, 'used', 'keep.txt'), 'x');
    const first = await prepareArtifactsDir('used', base);
    const second = await prepareArtifactsDir('used', base);
    expect(first).not.toBe(second);
    expect(await readFile(join(base, 'used', 'keep.txt'), 'utf8')).toBe('x');
  });
});

describe('extractZipToDir', () => {
  it('writes entries and skips ones escaping the destination', async () => {
    const zip = new AdmZip();
    zip.addFile('pkg/mod.py', Buffer.from('print(1)'));
    zip.addFile('../escape.txt', Buffer.from('nope'));
    const dest = join(base, 'wheel');

    await extractZipToDir(zip.toBuffer(), dest);

    expect(await readFile(join(dest, 'pkg', 'mod.py'), 'utf8')).toBe('print(1)');
    await expect(stat(join(base, 'escape.txt'))).rejects.toThrow();
  });
});
