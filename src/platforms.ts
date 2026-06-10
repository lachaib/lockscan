import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

export type PlatformOS = 'linux' | 'macos' | 'windows';
export type PlatformArch = 'x86_64' | 'arm64';

export interface Platform {
  os: PlatformOS;
  arch: PlatformArch;
  /** Python version string, e.g. "3.12". Omit to match any version. */
  python?: string;
}

export function parsePlatform(spec: string): Platform {
  const parts = spec.trim().split('/');
  if (parts.length < 2) {
    throw new Error(
      `Invalid platform spec "${spec}" — expected os/arch[/python], e.g. linux/arm64/3.12`,
    );
  }
  const [os, arch, python] = parts;
  if (os !== 'linux' && os !== 'macos' && os !== 'windows') {
    throw new Error(`Unknown OS "${os}" — expected linux, macos, or windows`);
  }
  if (arch !== 'x86_64' && arch !== 'arm64') {
    throw new Error(`Unknown arch "${arch}" — expected x86_64 or arm64`);
  }
  return { os, arch, python };
}

export function parsePlatforms(csv: string): Platform[] {
  return csv
    .split(',')
    .map((s) => parsePlatform(s.trim()))
    .filter(Boolean);
}

export function detectHostPlatform(): Platform {
  const os: PlatformOS =
    process.platform === 'darwin' ? 'macos' : process.platform === 'win32' ? 'windows' : 'linux';
  const arch: PlatformArch = process.arch === 'arm64' ? 'arm64' : 'x86_64';
  return { os, arch };
}

/** Best-effort read of Python version from pyproject.toml or .python-version in `dir`. */
export async function detectPythonVersion(dir: string): Promise<string | undefined> {
  try {
    const toml = await readFile(join(dir, 'pyproject.toml'), 'utf8');
    const m = toml.match(/requires-python\s*=\s*["'][><=!~ ]*(\d+)\.(\d+)/);
    if (m) return `${m[1]}.${m[2]}`;
  } catch {
    // not found
  }
  try {
    const pv = await readFile(join(dir, '.python-version'), 'utf8');
    const m = pv.trim().match(/^(\d+)\.(\d+)/);
    if (m) return `${m[1]}.${m[2]}`;
  } catch {
    // not found
  }
  return undefined;
}

export function platformLabel(p: Platform): string {
  return `${p.os}/${p.arch}${p.python ? `/${p.python}` : ''}`;
}
