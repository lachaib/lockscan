import type { ArtifactInfo, RegistryMetadata } from '../../types.js';
import { downloadBuffer, fetchJson } from '../../utils/http.js';

interface PackagistAuthor {
  name?: string;
  email?: string;
  homepage?: string;
}

interface PackagistDist {
  type: string;
  url: string;
  reference?: string;
  shasum?: string;
}

interface PackagistSource {
  type: string;
  url: string;
  reference?: string;
}

export interface PackagistVersion {
  name: string;
  version: string;
  description?: string;
  homepage?: string;
  license?: string[];
  authors?: PackagistAuthor[];
  require?: Record<string, string>;
  'require-dev'?: Record<string, string>;
  dist?: PackagistDist;
  source?: PackagistSource;
  time?: string;
}

interface PackagistPackageResponse {
  package: {
    name: string;
    description?: string;
    time?: string;
    versions: Record<string, PackagistVersion>;
    repository?: string;
    abandoned?: boolean | string;
  };
}

export async function fetchPackagist(name: string, version: string): Promise<PackagistVersion> {
  const [vendor, pkg] = name.split('/');
  if (!vendor || !pkg) throw new Error(`Invalid Composer package name: ${name}`);

  const data = await fetchJson<PackagistPackageResponse>(
    `https://packagist.org/packages/${vendor}/${pkg}.json`,
  );

  const versions = data.package.versions;

  // Composer lock files may use version strings with or without a leading "v".
  // Try the exact string first, then with/without the prefix.
  const candidates = [version, version.startsWith('v') ? version.slice(1) : `v${version}`];
  for (const v of candidates) {
    if (versions[v]) return versions[v];
  }

  // Fall back to a case-insensitive search for unusual normalizations
  const lower = version.toLowerCase();
  for (const [k, v] of Object.entries(versions)) {
    if (k.toLowerCase() === lower || k.toLowerCase() === `v${lower}`) return v;
  }

  throw new Error(`Version ${version} of ${name} not found on Packagist`);
}

export function getArtifactInfo(meta: PackagistVersion): ArtifactInfo | undefined {
  if (!meta.dist?.url) return undefined;
  const url = meta.dist.url;
  const filename = url.split('/').pop() ?? `${meta.name}-${meta.version}.zip`;
  return {
    filename,
    url,
    // Packagist provides SHA-1 shasum (same treatment as npm's shasum field)
    sha256: meta.dist.shasum ?? '',
  };
}

export async function downloadArtifact(url: string): Promise<Buffer> {
  return downloadBuffer(url);
}

export function extractRepoUrl(meta: PackagistVersion): string | undefined {
  return meta.source?.url ?? undefined;
}

export function extractRegistryInfo(
  meta: PackagistVersion,
  allVersions: Record<string, PackagistVersion>,
): RegistryMetadata {
  const author = meta.authors?.[0];
  const license = meta.license?.join(', ');

  const uploadTimes = Object.values(allVersions)
    .map((v) => v.time)
    .filter((t): t is string => !!t)
    .sort();

  const firstUpload = uploadTimes[0];
  const ageDays = firstUpload
    ? Math.floor((Date.now() - new Date(firstUpload).getTime()) / 86_400_000)
    : undefined;

  const versionUpload = meta.time;
  const versionAgeDays = versionUpload
    ? Math.floor((Date.now() - new Date(versionUpload).getTime()) / 86_400_000)
    : undefined;

  const require = { ...meta.require, ...meta['require-dev'] };
  const requiresDist = Object.entries(require)
    .filter(([k]) => !k.startsWith('php') && !k.startsWith('ext-') && !k.startsWith('lib-'))
    .map(([k, v]) => `${k}:${v}`);

  return {
    summary: meta.description,
    author: author?.name,
    authorEmail: author?.email,
    homepage: meta.homepage,
    license,
    numReleases: Object.keys(allVersions).length,
    firstUpload,
    ageDays,
    versionUpload,
    versionAgeDays,
    requiresDist,
  };
}

export function computeMetadataDelta(
  oldMeta: PackagistVersion,
  newMeta: PackagistVersion,
): {
  authorChanged: boolean;
  homepageChanged: boolean;
  depsAdded: string[];
  depsRemoved: string[];
  licenseChanged: boolean;
} {
  const oldAuthorEmail = oldMeta.authors?.[0]?.email ?? '';
  const newAuthorEmail = newMeta.authors?.[0]?.email ?? '';

  const deps = (meta: PackagistVersion) =>
    new Set(
      Object.keys({ ...meta.require, ...meta['require-dev'] }).filter(
        (k) => !k.startsWith('php') && !k.startsWith('ext-') && !k.startsWith('lib-'),
      ),
    );

  const oldDeps = deps(oldMeta);
  const newDeps = deps(newMeta);

  return {
    authorChanged: oldAuthorEmail !== newAuthorEmail,
    homepageChanged: (oldMeta.homepage ?? '') !== (newMeta.homepage ?? ''),
    depsAdded: [...newDeps].filter((d) => !oldDeps.has(d)),
    depsRemoved: [...oldDeps].filter((d) => !newDeps.has(d)),
    licenseChanged:
      (oldMeta.license ?? []).sort().join(',') !== (newMeta.license ?? []).sort().join(','),
  };
}

/** Fetch the raw versions map alongside the specific version (used for registry info). */
export async function fetchPackagistWithVersions(
  name: string,
  version: string,
): Promise<{ meta: PackagistVersion; allVersions: Record<string, PackagistVersion> }> {
  const [vendor, pkg] = name.split('/');
  if (!vendor || !pkg) throw new Error(`Invalid Composer package name: ${name}`);

  const data = await fetchJson<PackagistPackageResponse>(
    `https://packagist.org/packages/${vendor}/${pkg}.json`,
  );

  const allVersions = data.package.versions;
  const candidates = [version, version.startsWith('v') ? version.slice(1) : `v${version}`];
  for (const v of candidates) {
    if (allVersions[v]) return { meta: allVersions[v], allVersions };
  }

  const lower = version.toLowerCase();
  for (const [k, v] of Object.entries(allVersions)) {
    if (k.toLowerCase() === lower || k.toLowerCase() === `v${lower}`) {
      return { meta: v, allVersions };
    }
  }

  throw new Error(`Version ${version} of ${name} not found on Packagist`);
}
