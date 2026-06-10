import type { ArtifactInfo, RegistryMetadata } from '../../types.js';
import { downloadBuffer, fetchJson } from '../../utils/http.js';

interface NpmAuthor {
  name?: string;
  email?: string;
}

export interface NpmVersion {
  name: string;
  version: string;
  description?: string;
  author?: NpmAuthor | string;
  homepage?: string;
  license?: string | { type: string };
  repository?: { type?: string; url?: string } | string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  dist: {
    tarball: string;
    shasum: string;
    integrity?: string;
  };
  /** Who published this specific version to the npm registry. */
  _npmUser?: { name: string; email?: string };
}

interface NpmPackage {
  name: string;
  time?: Record<string, string>;
}

export async function fetchNpmVersion(name: string, version: string): Promise<NpmVersion> {
  const encoded = encodeNpmName(name);
  return fetchJson<NpmVersion>(`https://registry.npmjs.org/${encoded}/${version}`);
}

async function fetchNpmPackage(name: string): Promise<NpmPackage> {
  const encoded = encodeNpmName(name);
  // Accept-header selects the abbreviated manifest — much lighter than the full registry doc
  const res = await fetch(`https://registry.npmjs.org/${encoded}`, {
    headers: { Accept: 'application/vnd.npm.install-v1+json' },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}: registry.npmjs.org/${encoded}`);
  return res.json() as Promise<NpmPackage>;
}

function encodeNpmName(name: string): string {
  // Scoped packages: @scope/pkg → @scope%2Fpkg
  return name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : name;
}

export function extractRepoUrl(meta: NpmVersion): string | undefined {
  if (!meta.repository) return undefined;
  return typeof meta.repository === 'string' ? meta.repository : meta.repository.url;
}

export function getArtifactInfo(meta: NpmVersion): ArtifactInfo {
  const filename = meta.dist.tarball.split('/').pop() ?? `${meta.name}-${meta.version}.tgz`;
  return { filename, url: meta.dist.tarball, sha256: meta.dist.shasum };
}

export async function downloadNpmTarball(url: string): Promise<Buffer> {
  return downloadBuffer(url);
}

export async function extractRegistryInfo(meta: NpmVersion): Promise<RegistryMetadata> {
  const authorName = typeof meta.author === 'string' ? meta.author : meta.author?.name;
  const authorEmail = typeof meta.author === 'object' ? meta.author?.email : undefined;
  const license = typeof meta.license === 'string' ? meta.license : meta.license?.type;

  let firstUpload: string | undefined;
  let ageDays: number | undefined;
  let numReleases: number | undefined;

  let versionUpload: string | undefined;
  let versionAgeDays: number | undefined;

  try {
    const pkg = await fetchNpmPackage(meta.name);
    if (pkg.time) {
      const versionTimes = Object.entries(pkg.time)
        .filter(([k]) => !['created', 'modified'].includes(k))
        .map(([, v]) => v)
        .sort();
      numReleases = versionTimes.length;
      firstUpload = versionTimes[0];
      if (firstUpload) {
        ageDays = Math.floor((Date.now() - new Date(firstUpload).getTime()) / 86_400_000);
      }
      versionUpload = pkg.time[meta.version];
      if (versionUpload) {
        versionAgeDays = Math.floor((Date.now() - new Date(versionUpload).getTime()) / 86_400_000);
      }
    }
  } catch {
    // registry metadata is best-effort
  }

  return {
    summary: meta.description,
    author: authorName,
    authorEmail,
    homepage: meta.homepage,
    license,
    numReleases,
    firstUpload,
    ageDays,
    versionUpload,
    versionAgeDays,
    latestVersion: meta.version,
    requiresDist: [
      ...Object.keys(meta.dependencies ?? {}),
      ...Object.keys(meta.devDependencies ?? {}).map((k) => `${k} (dev)`),
    ],
  };
}

function licenseString(m: NpmVersion): string {
  if (!m.license) return '';
  return typeof m.license === 'string' ? m.license : m.license.type;
}

export function computeMetadataDelta(
  oldMeta: NpmVersion,
  newMeta: NpmVersion,
): {
  authorChanged: boolean;
  homepageChanged: boolean;
  depsAdded: string[];
  depsRemoved: string[];
  licenseChanged: boolean;
  publisherChanged?: boolean;
} {
  const getEmail = (m: NpmVersion) => (typeof m.author === 'object' ? (m.author?.email ?? '') : '');

  const oldDeps = new Set([
    ...Object.keys(oldMeta.dependencies ?? {}),
    ...Object.keys(oldMeta.devDependencies ?? {}).map((k) => `${k} (dev)`),
  ]);
  const newDeps = new Set([
    ...Object.keys(newMeta.dependencies ?? {}),
    ...Object.keys(newMeta.devDependencies ?? {}).map((k) => `${k} (dev)`),
  ]);

  const oldPublisher = oldMeta._npmUser?.name ?? oldMeta._npmUser?.email;
  const newPublisher = newMeta._npmUser?.name ?? newMeta._npmUser?.email;
  const publisherChanged =
    oldPublisher !== undefined && newPublisher !== undefined && oldPublisher !== newPublisher
      ? true
      : undefined;

  return {
    authorChanged: getEmail(oldMeta) !== getEmail(newMeta),
    homepageChanged: (oldMeta.homepage ?? '') !== (newMeta.homepage ?? ''),
    depsAdded: [...newDeps].filter((d) => !oldDeps.has(d)),
    depsRemoved: [...oldDeps].filter((d) => !newDeps.has(d)),
    licenseChanged: licenseString(oldMeta) !== licenseString(newMeta),
    ...(publisherChanged !== undefined && { publisherChanged }),
  };
}
