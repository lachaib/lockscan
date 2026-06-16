import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { DiffReport } from 'lockdelta';
import { getAnalyzer } from '../ecosystems/index.js';
import { queryOsv } from '../ecosystems/shared/vuln-check.js';
import type { AnalyzeOptions } from '../index.js';
import type { Platform } from '../platforms.js';
import { detectHostPlatform, detectPythonVersion, platformLabel } from '../platforms.js';
import type { LockfileAnalysis, PackageAnalysis, SecurityReport } from '../types.js';

const DEFAULT_CHANGE_TYPES = new Set(['added', 'updated', 'removed']);

export async function analyze(
  report: DiffReport,
  options: AnalyzeOptions,
): Promise<SecurityReport> {
  const onlyTypes = options.onlyTypes ? new Set(options.onlyTypes) : DEFAULT_CHANGE_TYPES;
  const platforms = await resolvePlatforms(options.platforms);

  process.stderr.write(`Platforms: ${platforms.map(platformLabel).join(', ')}\n`);

  const tmpDir = await mkdtemp(join(tmpdir(), 'lockscan-'));
  try {
    const lockfileAnalyses: LockfileAnalysis[] = [];

    for (const lf of report.lockfiles) {
      const analyzer = getAnalyzer(lf.ecosystem);
      if (!analyzer) {
        process.stderr.write(
          `[SKIP] ${lf.path ?? 'lockfile'} — ecosystem '${lf.ecosystem}' not supported\n`,
        );
        continue;
      }

      const changes = lf.changes.filter((c) => onlyTypes.has(c.change_type));

      if (changes.length === 0) {
        lockfileAnalyses.push({
          lockfilePath: lf.path,
          workspace: lf.workspace,
          type: lf.type,
          ecosystem: lf.ecosystem,
          packages: [],
        });
        continue;
      }

      process.stderr.write(
        `\nAnalyzing ${lf.path ?? 'lockfile'} (${lf.ecosystem}): ${changes.length} change(s)...\n`,
      );

      // Batch OSV lookup for all new/updated versions in this lockfile
      const osvResults = await queryOsv(
        changes
          .filter((c) => c.change_type !== 'removed')
          .map((c) => ({ name: c.name, version: c.new_version!, ecosystem: lf.ecosystem })),
      );

      const packages: PackageAnalysis[] = [];
      for (let i = 0; i < changes.length; i++) {
        const change = changes[i];
        process.stderr.write(
          `  [${i + 1}/${changes.length}] ${change.name} (${change.change_type})\n`,
        );
        try {
          const analysis = await analyzer.analyzeChange(change, {
            platforms,
            tmpDir: join(tmpDir, lf.ecosystem),
          });
          const vulns = change.new_version
            ? osvResults.get(`${change.name}@${change.new_version}`)
            : undefined;
          packages.push(vulns?.length ? { ...analysis, knownVulns: vulns } : analysis);
        } catch (err) {
          packages.push({
            name: change.name,
            changeType: change.change_type,
            oldVersion: change.old_version,
            newVersion: change.new_version,
            isDirect: change.is_direct,
            isDev: change.is_dev,
            ecosystem: lf.ecosystem,
            error: String(err),
          });
        }
      }

      lockfileAnalyses.push({
        lockfilePath: lf.path,
        workspace: lf.workspace,
        type: lf.type,
        ecosystem: lf.ecosystem,
        packages,
      });
    }

    return buildReport(report, lockfileAnalyses, platforms);
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
}

async function resolvePlatforms(explicit: Platform[] | undefined): Promise<Platform[]> {
  if (explicit && explicit.length > 0) return explicit;

  const host = detectHostPlatform();

  // Try to fill in the Python version from the working directory
  const python = await detectPythonVersion(process.cwd());
  if (python) {
    process.stderr.write(`Detected Python ${python} from project config\n`);
    return [{ ...host, python }];
  }

  return [host];
}

function buildReport(
  input: DiffReport,
  lockfiles: LockfileAnalysis[],
  platforms: Platform[],
): SecurityReport {
  const analyzed = lockfiles.reduce((s, lf) => s + lf.packages.length, 0);
  const errors = lockfiles.reduce((s, lf) => s + lf.packages.filter((p) => p.error).length, 0);
  const newSecurityFindings = lockfiles.reduce(
    (s, lf) => s + lf.packages.reduce((ps, p) => ps + (p.securityFindings?.delta.length ?? 0), 0),
    0,
  );
  const platformDivergences = lockfiles.reduce(
    (s, lf) => s + lf.packages.filter((p) => p.securityFindings?.platformDivergence).length,
    0,
  );
  const binaryAnomalies = lockfiles.reduce(
    (s, lf) => s + lf.packages.filter((p) => (p.binaryFindings?.delta.length ?? 0) > 0).length,
    0,
  );
  const knownVulns = lockfiles.reduce(
    (s, lf) => s + lf.packages.reduce((ps, p) => ps + (p.knownVulns?.length ?? 0), 0),
    0,
  );
  const releaseDropped = lockfiles.reduce(
    (s, lf) => s + lf.packages.filter((p) => p.repoCheck?.releaseDropped).length,
    0,
  );
  const installHooksAdded = lockfiles.reduce(
    (s, lf) => s + lf.packages.filter((p) => p.installHooks?.some((h) => h.isNew)).length,
    0,
  );
  const registryChanges = lockfiles.reduce(
    (s, lf) =>
      s +
      lf.packages.filter(
        (p) => p.registryCheck?.registryChanged || p.registryCheck?.potentialConfusion,
      ).length,
    0,
  );
  const freshnessWarnings = lockfiles.reduce(
    (s, lf) =>
      s + lf.packages.filter((p) => (p.registryInfo?.versionAgeDays ?? Infinity) < 1).length,
    0,
  );
  const publisherChanges = lockfiles.reduce(
    (s, lf) => s + lf.packages.filter((p) => p.metadataDelta?.publisherChanged).length,
    0,
  );
  const licenseChanges = lockfiles.reduce(
    (s, lf) => s + lf.packages.filter((p) => p.metadataDelta?.licenseChanged).length,
    0,
  );
  const ecosystems = [...new Set(lockfiles.map((lf) => lf.ecosystem))];

  return {
    schemaVersion: '1',
    generatedAt: new Date().toISOString(),
    baseRef: input.base_ref,
    headRef: input.head_ref,
    summary: {
      analyzed,
      errors,
      newSecurityFindings,
      platformDivergences,
      binaryAnomalies,
      knownVulns,
      releaseDropped,
      installHooksAdded,
      registryChanges,
      freshnessWarnings,
      publisherChanges,
      licenseChanges,
      ecosystems,
    },
    lockfiles,
  };
}
