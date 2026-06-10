import type { RegistryMetadata } from '../../types.js';
import { fetchJson } from '../../utils/http.js';
import type { NpmVersion } from '../javascript/npm.js';
import { extractRepoUrl } from '../javascript/npm.js';

/**
 * Transform a JSR package name to its npm.jsr.io scoped name.
 * @std/http → @jsr/std__http
 */
export function jsrToNpmName(jsrName: string): string {
  if (!jsrName.startsWith('@')) throw new Error(`Invalid JSR name: ${jsrName}`);
  const withoutAt = jsrName.slice(1);
  const slash = withoutAt.indexOf('/');
  if (slash < 0) throw new Error(`Invalid JSR name (missing scope separator): ${jsrName}`);
  return `@jsr/${withoutAt.slice(0, slash)}__${withoutAt.slice(slash + 1)}`;
}

function encodeJsrNpmName(npmName: string): string {
  return npmName.startsWith('@') ? `@${encodeURIComponent(npmName.slice(1))}` : npmName;
}

/**
 * Fetch version metadata for a JSR package via the npm compatibility registry.
 * The response shape is compatible with NpmVersion, so all npm helpers apply.
 */
export async function fetchJsrVersion(jsrName: string, version: string): Promise<NpmVersion> {
  const npmName = jsrToNpmName(jsrName);
  return fetchJson<NpmVersion>(`https://npm.jsr.io/${encodeJsrNpmName(npmName)}/${version}`);
}

interface JsrApiPackage {
  githubRepository?: { owner: string; name: string };
  total?: number;
}

interface JsrVersionsResponse {
  total?: number;
}

/**
 * Attempt to resolve the GitHub repo URL for a JSR package from the JSR API.
 * Falls back to the npm compat metadata's repository field if the API is unavailable.
 */
export async function resolveJsrRepoUrl(
  jsrName: string,
  npmMeta: NpmVersion,
): Promise<string | undefined> {
  // Try npm compat metadata first — it's already in hand
  const fromNpm = extractRepoUrl(npmMeta);
  if (fromNpm) return fromNpm;

  // Fall back to the JSR API structured field
  try {
    const info = await fetchJson<JsrApiPackage>(`https://api.jsr.io/packages/${jsrName}`);
    if (info.githubRepository) {
      return `https://github.com/${info.githubRepository.owner}/${info.githubRepository.name}`;
    }
  } catch {
    // best-effort
  }
  return undefined;
}

export async function extractJsrRegistryInfo(
  jsrName: string,
  npmMeta: NpmVersion,
): Promise<RegistryMetadata> {
  const license =
    typeof npmMeta.license === 'string'
      ? npmMeta.license
      : (npmMeta.license as { type?: string } | undefined)?.type;

  let numReleases: number | undefined;
  try {
    const data = await fetchJson<JsrVersionsResponse>(
      `https://api.jsr.io/packages/${jsrName}/versions?limit=1`,
    );
    numReleases = data.total;
  } catch {
    // best-effort
  }

  return {
    summary: npmMeta.description,
    homepage: npmMeta.homepage,
    license,
    numReleases,
    latestVersion: npmMeta.version,
  };
}

export function computeJsrMetadataDelta(
  oldMeta: NpmVersion,
  newMeta: NpmVersion,
): { homepageChanged: boolean; licenseChanged: boolean } {
  const lic = (m: NpmVersion) =>
    typeof m.license === 'string' ? m.license : (m.license as { type?: string } | undefined)?.type ?? '';
  return {
    homepageChanged: (oldMeta.homepage ?? '') !== (newMeta.homepage ?? ''),
    licenseChanged: lic(oldMeta) !== lic(newMeta),
  };
}
