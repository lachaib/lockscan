import { mkdir, readdir, readFile, stat, unlink, writeFile } from 'node:fs/promises';
import { dirname, extname, isAbsolute, join, posix, relative, resolve, sep } from 'node:path';
import AdmZip from 'adm-zip';
import * as tar from 'tar';
import { isNativeBinary } from '../ecosystems/shared/binary-formats.js';

export type FileMap = Map<string, string>;

/** A symlink or hardlink entry found in an archive; never created on disk. */
export interface ArchiveLink {
  /** Entry path relative to the package root. */
  name: string;
  target: string;
  /** Absolute target, or one that resolves outside the package root. */
  escapes: boolean;
}

function classifyLink(name: string, target: string, relativeToEntry: boolean): ArchiveLink {
  if (target.startsWith('/') || isAbsolute(target)) return { name, target, escapes: true };
  const base = relativeToEntry ? posix.dirname(name) : '';
  const resolved = posix.normalize(posix.join(base, target.replace(/\\/g, '/')));
  return { name, target, escapes: resolved === '..' || resolved.startsWith('../') };
}

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

// 'build' and 'dist' are excluded above to skip duplicated/transpiled source when
// pattern-scanning text files, but 'build/Release' (node-gyp) and 'build/<platform>'
// (prebuild/napi-rs) are exactly where compiled .node addons live — never skip them
// when walking for binaries.
const BINARY_SKIP_DIRS = new Set(['.git', 'node_modules']);

/**
 * Extracts a .tgz or .tar.gz archive, stripping the top-level directory
 * (works for both npm tarballs `package/` and Python sdists `pkg-1.0/`).
 */
export async function extractTarball(
  data: Buffer,
  destDir: string,
  fileExtensions: Set<string>,
  links: ArchiveLink[] = [],
): Promise<FileMap> {
  await mkdir(destDir, { recursive: true });
  const tmpFile = `${destDir}.__archive.tgz`;
  await writeFile(tmpFile, data);
  try {
    await tar.x({
      file: tmpFile,
      cwd: destDir,
      strip: 1,
      filter: (path, entry) => {
        const type = (entry as tar.ReadEntry).type;
        if (type !== 'SymbolicLink' && type !== 'Link') return true;
        const name = path.split('/').slice(1).join('/');
        const raw = String((entry as tar.ReadEntry).linkpath ?? '');
        // Hardlink targets are archive-root relative and include the top-level directory.
        const isHard = type === 'Link' && !raw.startsWith('/');
        const target = isHard ? raw.split('/').slice(1).join('/') || '.' : raw;
        links.push(classifyLink(name, target, !isHard));
        return false;
      },
    });
  } finally {
    await unlink(tmpFile).catch(() => {});
  }
  return collectFiles(destDir, fileExtensions);
}

const UNIX_SYMLINK = 0o120000;
const UNIX_TYPE_MASK = 0o170000;

function isZipSymlink(entry: AdmZip.IZipEntry): boolean {
  return ((entry.header.attr >>> 16) & UNIX_TYPE_MASK) === UNIX_SYMLINK;
}

/** Symlink entries of a .whl / .zip archive; they are skipped by the zip extractors. */
export function zipLinks(data: Buffer): ArchiveLink[] {
  return new AdmZip(data)
    .getEntries()
    .filter(isZipSymlink)
    .map((e) => classifyLink(e.entryName, e.getData().toString('utf8'), true));
}

/** Writes every entry of a .whl / .zip archive under destDir, refusing entries that escape it. */
export async function extractZipToDir(data: Buffer, destDir: string): Promise<void> {
  const root = resolve(destDir);
  for (const entry of new AdmZip(data).getEntries()) {
    if (entry.isDirectory || isZipSymlink(entry)) continue;
    const target = resolve(root, entry.entryName);
    if (!target.startsWith(root + sep)) continue;
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, entry.getData());
  }
}

/** Compiled native extensions — structurally ELF/Mach-O/PE regardless of the ecosystem's own extension convention. */
const BINARY_EXTENSIONS = new Set(['.so', '.pyd', '.dylib', '.dll', '.node', '.exe']);

/** Extensionless files below this size are never native executables; skip reading them. */
const MIN_EXECUTABLE_SIZE = 1024;

/** Wheel `<name>-<version>.data/` directories embed the version; normalize so old/new entries line up. */
const WHEEL_DATA_DIR = /^[^/]+\.data\//;

/**
 * Extracts compiled binary extensions from a .whl (zip) archive in-memory.
 * Returns a map of entry name → raw bytes for native extensions and extensionless executables
 * (e.g. `*.data/scripts/ruff`), detected by header magic.
 */
export function extractZipBinaries(data: Buffer): Map<string, Buffer> {
  const files = new Map<string, Buffer>();
  const zip = new AdmZip(data);
  for (const entry of zip.getEntries()) {
    if (entry.isDirectory) continue;
    const ext = extname(entry.entryName);
    const isExtensionlessCandidate = ext === '' && entry.header.size >= MIN_EXECUTABLE_SIZE;
    if (!BINARY_EXTENSIONS.has(ext) && !isExtensionlessCandidate) continue;
    const content = entry.getData();
    if (isExtensionlessCandidate && !isNativeBinary(content)) continue;
    files.set(entry.entryName.replace(WHEEL_DATA_DIR, '.data/'), content);
  }
  return files;
}

/**
 * Collects compiled binary extensions from a directory previously extracted by
 * `extractTarball` (e.g. npm native addons shipped as `.node` files).
 * Returns a map of relative path → raw bytes.
 */
export async function extractTarballBinaries(
  destDir: string,
  extensions: Set<string> = BINARY_EXTENSIONS,
): Promise<Map<string, Buffer>> {
  const files = new Map<string, Buffer>();
  await walkDir(destDir, destDir, extensions, files, (path) => readFile(path), BINARY_SKIP_DIRS);
  await walkDir(
    destDir,
    destDir,
    new Set(['']),
    files,
    (path) => readFile(path),
    BINARY_SKIP_DIRS,
    (content) => content.length >= MIN_EXECUTABLE_SIZE && isNativeBinary(content),
  );
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
    if (entry.isDirectory || isZipSymlink(entry)) continue;
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
  await walkDir(dir, dir, extensions, files, (path) => readFile(path, 'utf8'), SKIP_DIRS);
  return files;
}

async function walkDir<T>(
  baseDir: string,
  currentDir: string,
  extensions: Set<string>,
  files: Map<string, T>,
  readAs: (path: string) => Promise<T>,
  skipDirs: Set<string>,
  accept: (content: T) => boolean = () => true,
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
      if (!skipDirs.has(entry)) {
        await walkDir(baseDir, fullPath, extensions, files, readAs, skipDirs, accept);
      }
    } else if (extensions.has(extname(entry))) {
      const rel = relative(baseDir, fullPath);
      try {
        const content = await readAs(fullPath);
        if (accept(content)) files.set(rel, content);
      } catch {
        // skip unreadable files
      }
    }
  }
}
