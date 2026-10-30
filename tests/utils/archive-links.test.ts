import { lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import AdmZip from 'adm-zip';
import * as tar from 'tar';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { linkFindings } from '../../src/ecosystems/shared/scan.js';
import {
  type ArchiveLink,
  extractTarball,
  extractZip,
  extractZipToDir,
  zipLinks,
} from '../../src/utils/extract.js';

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'lockscan-links-test-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function buildTarball(): Promise<Buffer> {
  const src = join(dir, 'src');
  await mkdir(join(src, 'package', 'lib'), { recursive: true });
  await writeFile(join(src, 'package', 'index.js'), 'module.exports = 1;');
  await symlink('/etc/passwd', join(src, 'package', 'abs.js'));
  await symlink('../../outside.js', join(src, 'package', 'lib', 'up.js'));
  await symlink('index.js', join(src, 'package', 'lib', 'same.js'));
  const file = join(dir, 'pkg.tgz');
  await tar.c({ file, cwd: src, gzip: true }, ['package']);
  return readFile(file);
}

describe('extractTarball links', () => {
  it('does not create symlinks and reports them with their escape status', async () => {
    const dest = join(dir, 'out');
    const links: ArchiveLink[] = [];

    const files = await extractTarball(await buildTarball(), dest, new Set(['.js']), links);

    expect([...files.keys()]).toEqual(['index.js']);
    await expect(lstat(join(dest, 'abs.js'))).rejects.toThrow();
    expect(links.sort((a, b) => a.name.localeCompare(b.name))).toEqual([
      { name: 'abs.js', target: '/etc/passwd', escapes: true },
      { name: 'lib/same.js', target: 'index.js', escapes: false },
      { name: 'lib/up.js', target: '../../outside.js', escapes: true },
    ]);
  });
});

describe('zip symlinks', () => {
  function zipWithLink(): Buffer {
    const zip = new AdmZip();
    zip.addFile('pkg/mod.py', Buffer.from('print(1)'));
    zip.addFile('pkg/link.py', Buffer.from('/etc/shadow'));
    const entry = zip.getEntry('pkg/link.py');
    if (!entry) throw new Error('fixture entry missing');
    entry.header.made = (3 << 8) | 20;
    entry.attr = (0o120777 << 16) >>> 0;
    return zip.toBuffer();
  }

  it('reports symlink entries and skips them when extracting', async () => {
    const data = zipWithLink();

    expect(zipLinks(data)).toEqual([{ name: 'pkg/link.py', target: '/etc/shadow', escapes: true }]);
    expect([...extractZip(data, new Set(['.py'])).keys()]).toEqual(['pkg/mod.py']);

    await extractZipToDir(data, join(dir, 'wheel'));
    await expect(lstat(join(dir, 'wheel', 'pkg', 'link.py'))).rejects.toThrow();
  });
});

describe('linkFindings', () => {
  it('labels escaping links separately and keeps the target as detail', () => {
    expect(
      linkFindings([
        { name: 'a', target: '/x', escapes: true },
        { name: 'b', target: 'c', escapes: false },
      ]),
    ).toEqual([
      { file: 'a', line: 0, label: 'archive:symlink-escape', detail: '/x' },
      { file: 'b', line: 0, label: 'archive:symlink', detail: 'c' },
    ]);
  });
});
