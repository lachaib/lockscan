import { mkdir, readdir, readFile, stat, unlink, writeFile } from 'node:fs/promises';
import { extname, join, relative } from 'node:path';
import AdmZip from 'adm-zip';
import * as tar from 'tar';

export type FileMap = Map<string, string>;

const SKIP_DIRS = new Set([
  '__pycache__',
  '.git',
  'node_modules',
  '.mypy_cache',
  'dist',
  'build',
  '.pytest_cache',
  '.ruff_cache',
]);

/**
 * Extracts a .tgz or .tar.gz archive, stripping the top-level directory
 * (works for both npm tarballs `package/` and Python sdists `pkg-1.0/`).
 */
export async function extractTarball(
  data: Buffer,
  destDir: string,
  fileExtensions: Set<string>,
): Promise<FileMap> {
  await mkdir(destDir, { recursive: true });
  const tmpFile = `${destDir}.__archive.tgz`;
  await writeFile(tmpFile, data);
  try {
    await tar.x({ file: tmpFile, cwd: destDir, strip: 1 });
  } finally {
    await unlink(tmpFile).catch(() => {});
  }
  return collectFiles(destDir, fileExtensions);
}

const BINARY_EXTENSIONS = new Set(['.so', '.pyd', '.dylib', '.dll']);

/**
 * Extracts compiled binary extensions from a .whl (zip) archive in-memory.
 * Returns a map of entry name → raw bytes for .so/.pyd/.dylib/.dll files.
 */
export function extractZipBinaries(data: Buffer): Map<string, Buffer> {
  const files = new Map<string, Buffer>();
  const zip = new AdmZip(data);
  for (const entry of zip.getEntries()) {
    if (entry.isDirectory) continue;
    if (!BINARY_EXTENSIONS.has(extname(entry.entryName))) continue;
    files.set(entry.entryName, entry.getData());
  }
  return files;
}

/**
 * Extracts a .zip / .whl archive in-memory (synchronous via adm-zip).
 * Wheel files have no top-level container directory so no stripping is needed.
 */
export function extractZip(data: Buffer, fileExtensions: Set<string>): FileMap {
  const files: FileMap = new Map();
  const zip = new AdmZip(data);
  for (const entry of zip.getEntries()) {
    if (entry.isDirectory) continue;
    if (!fileExtensions.has(extname(entry.entryName))) continue;
    try {
      files.set(entry.entryName, entry.getData().toString('utf8'));
    } catch {
      // skip non-UTF-8 entries
    }
  }
  return files;
}

async function collectFiles(dir: string, extensions: Set<string>): Promise<FileMap> {
  const files: FileMap = new Map();
  await walkDir(dir, dir, extensions, files);
  return files;
}

async function walkDir(
  baseDir: string,
  currentDir: string,
  extensions: Set<string>,
  files: FileMap,
): Promise<void> {
  let entries: string[];
  try {
    entries = await readdir(currentDir);
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = join(currentDir, entry);
    let s: Awaited<ReturnType<typeof stat>>;
    try {
      s = await stat(fullPath);
    } catch {
      continue;
    }

    if (s.isDirectory()) {
      if (!SKIP_DIRS.has(entry)) {
        await walkDir(baseDir, fullPath, extensions, files);
      }
    } else if (extensions.has(extname(entry))) {
      const rel = relative(baseDir, fullPath);
      try {
        files.set(rel, await readFile(fullPath, 'utf8'));
      } catch {
        // skip unreadable files
      }
    }
  }
}
