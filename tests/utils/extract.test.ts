import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import AdmZip from 'adm-zip';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { extractTarballBinaries, extractZipBinaries } from '../../src/utils/extract.js';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'lockscan-extract-test-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('extractTarballBinaries', () => {
  it('collects .node files as raw buffers from an already-extracted directory', async () => {
    await mkdir(join(dir, 'build', 'Release'), { recursive: true });
    await writeFile(join(dir, 'build', 'Release', 'addon.node'), Buffer.from([0x01, 0x02, 0x03]));
    await writeFile(
      join(dir, 'index.js'),
      'module.exports = require("./build/Release/addon.node");',
    );

    const binaries = await extractTarballBinaries(dir);

    expect([...binaries.keys()]).toEqual(['build/Release/addon.node']);
    expect(binaries.get('build/Release/addon.node')).toEqual(Buffer.from([0x01, 0x02, 0x03]));
  });

  it('skips node_modules when walking for binaries', async () => {
    await mkdir(join(dir, 'node_modules', 'dep'), { recursive: true });
    await writeFile(join(dir, 'node_modules', 'dep', 'bundled.node'), Buffer.from([0xff]));
    await writeFile(join(dir, 'own.node'), Buffer.from([0x42]));

    const binaries = await extractTarballBinaries(dir);

    expect([...binaries.keys()]).toEqual(['own.node']);
  });

  it('returns an empty map when no binary extensions are present', async () => {
    await writeFile(join(dir, 'index.js'), 'console.log("hi");');

    const binaries = await extractTarballBinaries(dir);

    expect(binaries.size).toBe(0);
  });
});

describe('extractZipBinaries', () => {
  it('extracts .node entries from a zip archive alongside .so/.dylib/.dll', () => {
    const zip = new AdmZip();
    zip.addFile('addon.node', Buffer.from([0x01]));
    zip.addFile('lib.so', Buffer.from([0x02]));
    zip.addFile('README.md', Buffer.from('hello'));

    const binaries = extractZipBinaries(zip.toBuffer());

    expect(new Set(binaries.keys())).toEqual(new Set(['addon.node', 'lib.so']));
  });
});
