import type { KnownVuln } from '../../types.js';

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns';

const OSV_ECOSYSTEM: Record<string, string> = {
  javascript: 'npm',
  python: 'PyPI',
  php: 'Packagist',
};

interface OsvBatchVulnRef {
  id: string;
}

interface OsvFullVuln {
  id: string;
  summary?: string;
  aliases?: string[];
  database_specific?: Record<string, unknown>;
  references?: Array<{ type: string; url: string }>;
}

function toKnownVuln(v: OsvFullVuln): KnownVuln {
  const db = v.database_specific;
  const severity =
    typeof db?.severity === 'string' ? (db.severity as string).toUpperCase() : undefined;
  const url = v.references?.find((r) => r.type === 'ADVISORY' || r.type === 'WEB')?.url;
  return {
    id: v.id,
    summary: v.summary ?? '(no summary)',
    severity,
    aliases: v.aliases ?? [],
    url,
  };
}

/**
 * Query OSV (osv.dev) for known vulnerabilities affecting the given package versions.
 *
 * Uses a two-step strategy: one batch call to get affected vuln IDs per package,
 * then parallel fetches for unique vuln details (avoids re-fetching the same advisory
 * when it affects multiple packages).
 *
 * Returns a Map keyed by "name@version" → list of vulnerabilities.
 * On network failure, logs a warning and returns an empty Map.
 */
export async function queryOsv(
  packages: Array<{ name: string; version: string; ecosystem: string }>,
): Promise<Map<string, KnownVuln[]>> {
  const supported = packages
    .filter((p) => OSV_ECOSYSTEM[p.ecosystem] && p.version)
    .map((p) => ({ ...p, osvEcosystem: OSV_ECOSYSTEM[p.ecosystem] }));

  if (supported.length === 0) return new Map();

  // Step 1: batch call to get vuln IDs per package (lightweight, single round-trip)
  let batchResults: Array<{ vulns?: OsvBatchVulnRef[] }>;
  try {
    const res = await fetch(OSV_BATCH_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        queries: supported.map((p) => ({
          package: { name: p.name, ecosystem: p.osvEcosystem },
          version: p.version,
        })),
      }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as { results: Array<{ vulns?: OsvBatchVulnRef[] }> };
    batchResults = data.results;
  } catch (err) {
    process.stderr.write(`[WARN] OSV batch query failed: ${err}\n`);
    return new Map();
  }

  // Collect unique IDs and map back to package keys
  const uniqueIds = new Set<string>();
  const pkgToIds = new Map<string, string[]>();

  for (let i = 0; i < supported.length; i++) {
    const ids = batchResults[i]?.vulns?.map((v) => v.id) ?? [];
    if (ids.length === 0) continue;
    const key = `${supported[i].name}@${supported[i].version}`;
    pkgToIds.set(key, ids);
    for (const id of ids) uniqueIds.add(id);
  }

  if (uniqueIds.size === 0) return new Map();

  // Step 2: fetch full advisory details for each unique vuln ID in parallel
  const fetched = await Promise.all(
    [...uniqueIds].map(async (id) => {
      try {
        const res = await fetch(`${OSV_VULN_URL}/${id}`);
        if (!res.ok) return null;
        return (await res.json()) as OsvFullVuln;
      } catch {
        return null;
      }
    }),
  );

  const vulnById = new Map<string, KnownVuln>();
  for (const v of fetched) {
    if (v) vulnById.set(v.id, toKnownVuln(v));
  }

  // Build result map
  const result = new Map<string, KnownVuln[]>();
  for (const [key, ids] of pkgToIds) {
    const vulns = ids.map((id) => vulnById.get(id)).filter((v): v is KnownVuln => v !== undefined);
    if (vulns.length > 0) result.set(key, vulns);
  }

  return result;
}
