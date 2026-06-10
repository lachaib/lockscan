import type { Platform } from '../../platforms.js';
import type { ArtifactInfo, RegistryMetadata } from '../../types.js';
import { verifySha256 } from '../../utils/crypto.js';
import { downloadBuffer, fetchJson } from '../../utils/http.js';

interface PyPIFile {
  filename: string;
  url: string;
  digests: { sha256: string };
  upload_time?: string;
}

export interface PyPIVersion {
  info: {
    summary?: string;
    author?: string;
    author_email?: string;
    home_page?: string;
    license?: string;
    version?: string;
    requires_dist?: string[] | null;
    project_urls?: Record<string, string> | null;
  };
  urls: PyPIFile[];
  releases?: Record<string, PyPIFile[]>;
}

export async function fetchPyPI(name: string, version: string): Promise<PyPIVersion> {
  return fetchJson<PyPIVersion>(`https://pypi.org/pypi/${name}/${version}/json`);
}

export interface PyPIArtifact extends ArtifactInfo {
  isSdist: boolean;
  /** Platforms this artifact was selected for. */
  platforms: Platform[];
}

/**
 * Scores a wheel filename against a target platform.
 * Returns -1 for incompatible, higher = better match.
 *
 * Wheel filename format: {name}-{version}-{python_tag}-{abi_tag}-{platform_tag}.whl
 * Tags can be dot-separated lists (e.g. cp312.cp311-abi3-linux_x86_64).
 */
export function wheelScore(filename: string, platform: Platform): number {
  if (!filename.endsWith('.whl')) return -1;
  const stem = filename.slice(0, -4);
  const parts = stem.split('-');
  if (parts.length < 5) return -1;

  // Split from the right to handle package names containing hyphens
  const pyTag = parts[parts.length - 3];
  const platTag = parts[parts.length - 1];

  const pyTags = pyTag.split('.');
  const platTags = platTag.split('.');
  const pyver = platform.python?.replace('.', '') ?? ''; // "3.12" → "312"

  // --- Python version compatibility ---
  let pyScore: number;
  const cpTag = `cp${pyver}`;

  if (pyver && pyTags.includes(cpTag)) {
    pyScore = 4; // exact CPython match
  } else if (pyTags.some((t) => t === 'py3' || t === 'py2.py3')) {
    pyScore = 2; // generic Python 3
  } else if (pyver && pyTags.some((t) => t.startsWith('cp') && t !== cpTag)) {
    return -1; // wrong CPython version
  } else if (pyTags.some((t) => t.startsWith('pp'))) {
    return -1; // PyPy
  } else {
    pyScore = 1;
  }

  // --- Platform compatibility ---
  if (platTags.includes('any')) return pyScore + 2; // pure Python, always compatible

  const { os, arch } = platform;

  if (os === 'linux') {
    const linuxTags = platTags.filter((t) => t.includes('linux'));
    if (linuxTags.length === 0) return -1;
    // arm64 on Linux is called aarch64
    const targetArch = arch === 'arm64' ? 'aarch64' : 'x86_64';
    return linuxTags.some((t) => t.includes(targetArch)) ? pyScore + 4 : -1;
  }

  if (os === 'macos') {
    const macTags = platTags.filter((t) => t.startsWith('macosx'));
    if (macTags.length === 0) return -1;
    if (arch === 'arm64') {
      if (macTags.some((t) => t.endsWith('arm64'))) return pyScore + 4;
      if (macTags.some((t) => t.endsWith('universal2'))) return pyScore + 3;
    } else {
      if (macTags.some((t) => t.endsWith('x86_64'))) return pyScore + 4;
      if (macTags.some((t) => t.endsWith('universal2'))) return pyScore + 3;
    }
    return -1;
  }

  if (os === 'windows') {
    const winTags = platTags.filter((t) => t.startsWith('win'));
    if (winTags.length === 0) return -1;
    if (arch === 'arm64') return winTags.some((t) => t.includes('arm64')) ? pyScore + 4 : -1;
    return winTags.some((t) => t.includes('amd64')) ? pyScore + 4 : -1;
  }

  return -1;
}

/**
 * For each platform in the matrix, find the best matching wheel.
 * Returns unique artifacts (by sha256), each annotated with the platforms it serves.
 * Falls back to sdist if no wheel matches any platform.
 */
export function selectArtifacts(meta: PyPIVersion, platforms: Platform[]): PyPIArtifact[] {
  const wheels = meta.urls.filter((u) => u.filename.endsWith('.whl'));

  const sha256ToPlatforms = new Map<string, Platform[]>();
  const sha256ToFile = new Map<string, PyPIFile>();

  for (const platform of platforms) {
    let best: PyPIFile | null = null;
    let bestScore = -1;

    for (const w of wheels) {
      const score = wheelScore(w.filename, platform);
      if (score > bestScore) {
        bestScore = score;
        best = w;
      }
    }

    if (best && bestScore >= 0) {
      const sha256 = best.digests.sha256;
      sha256ToFile.set(sha256, best);
      sha256ToPlatforms.set(sha256, [...(sha256ToPlatforms.get(sha256) ?? []), platform]);
    }
  }

  if (sha256ToPlatforms.size > 0) {
    return [...sha256ToPlatforms.entries()].map(([sha256, plats]) => {
      const f = sha256ToFile.get(sha256)!;
      return { filename: f.filename, url: f.url, sha256, isSdist: false, platforms: plats };
    });
  }

  // Fallback: sdist
  const sdist = meta.urls.find((u) => u.filename.endsWith('.tar.gz'));
  if (sdist) {
    return [
      {
        filename: sdist.filename,
        url: sdist.url,
        sha256: sdist.digests.sha256,
        isSdist: true,
        platforms,
      },
    ];
  }

  return [];
}

export async function downloadAndVerify(artifact: PyPIArtifact): Promise<Buffer> {
  const data = await downloadBuffer(artifact.url);
  verifySha256(data, artifact.sha256);
  return data;
}

const REPO_URL_KEYS = ['source', 'source code', 'repository', 'code', 'github', 'gitlab'];

export function extractRepoUrl(meta: PyPIVersion): string | undefined {
  const urls = meta.info.project_urls;
  if (!urls) return meta.info.home_page ?? undefined;
  // Prefer explicit source/repo labels over home_page
  for (const [key, url] of Object.entries(urls)) {
    if (REPO_URL_KEYS.includes(key.toLowerCase())) return url;
  }
  return meta.info.home_page ?? undefined;
}

export function extractRegistryInfo(meta: PyPIVersion): RegistryMetadata {
  const { info, releases } = meta;
  let firstUpload: string | undefined;
  let ageDays: number | undefined;

  let versionUpload: string | undefined;
  let versionAgeDays: number | undefined;

  if (releases) {
    for (const files of Object.values(releases)) {
      for (const f of files) {
        if (f.upload_time && (!firstUpload || f.upload_time < firstUpload)) {
          firstUpload = f.upload_time;
        }
      }
    }
    if (firstUpload) {
      ageDays = Math.floor((Date.now() - new Date(firstUpload).getTime()) / 86_400_000);
    }
  }

  // Version-specific freshness: earliest upload_time among this version's files
  const thisVersionUpload = meta.urls[0]?.upload_time;
  if (thisVersionUpload) {
    versionUpload = thisVersionUpload;
    versionAgeDays = Math.floor((Date.now() - new Date(thisVersionUpload).getTime()) / 86_400_000);
  }

  return {
    summary: info.summary,
    author: info.author,
    authorEmail: info.author_email,
    homepage: info.home_page,
    license: info.license,
    numReleases: releases ? Object.keys(releases).length : undefined,
    firstUpload,
    ageDays,
    versionUpload,
    versionAgeDays,
    latestVersion: info.version,
    requiresDist: info.requires_dist ?? [],
  };
}

export function computeMetadataDelta(
  oldMeta: PyPIVersion,
  newMeta: PyPIVersion,
): {
  authorChanged: boolean;
  homepageChanged: boolean;
  depsAdded: string[];
  depsRemoved: string[];
  licenseChanged: boolean;
} {
  const oldDeps = new Set(oldMeta.info.requires_dist ?? []);
  const newDeps = new Set(newMeta.info.requires_dist ?? []);
  return {
    authorChanged: (oldMeta.info.author_email ?? '') !== (newMeta.info.author_email ?? ''),
    homepageChanged: (oldMeta.info.home_page ?? '') !== (newMeta.info.home_page ?? ''),
    depsAdded: [...newDeps].filter((d) => !oldDeps.has(d)),
    depsRemoved: [...oldDeps].filter((d) => !newDeps.has(d)),
    licenseChanged: (oldMeta.info.license ?? '') !== (newMeta.info.license ?? ''),
  };
}
