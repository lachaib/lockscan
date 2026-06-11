import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import * as core from '@actions/core';
import type { SecurityReport } from '../types.js';
import { annotationLevel, packageMaxSeverity } from './severity.js';

/**
 * Knows how to find the human-readable dependency manifest for a given ecosystem
 * (e.g. package.json for npm, pyproject.toml for Python) and locate a specific
 * package name within it.
 *
 * Register new resolvers via registerManifestResolver when lockdelta gains new
 * ecosystem support (Cargo, Go modules, etc.).
 */
export interface ManifestResolver {
  readonly ecosystem: string;
  /** Absolute paths to candidate manifests, in priority order. */
  manifestCandidates(lockfilePath: string | null, workspace: string): string[];
  /** 1-based line number where packageName appears, or null if not found. */
  findPackageLine(content: string, packageName: string): number | null;
}

const npmResolver: ManifestResolver = {
  ecosystem: 'javascript',
  manifestCandidates(lockfilePath, workspace) {
    const dir = lockfilePath ? join(workspace, dirname(lockfilePath)) : workspace;
    return [join(dir, 'package.json')];
  },
  findPackageLine(content, packageName) {
    const escaped = packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`"${escaped}"\\s*:`);
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (re.test(lines[i])) return i + 1;
    }
    return null;
  },
};

const pythonResolver: ManifestResolver = {
  ecosystem: 'python',
  manifestCandidates(lockfilePath, workspace) {
    const dir = lockfilePath ? join(workspace, dirname(lockfilePath)) : workspace;
    return [
      join(dir, 'pyproject.toml'),
      join(dir, 'requirements.txt'),
      join(dir, 'setup.py'),
      join(dir, 'setup.cfg'),
    ];
  },
  findPackageLine(content, packageName) {
    // Normalize: Python package names are case-insensitive and treat - and _ as equivalent.
    const normalized = packageName.toLowerCase().replace(/[-_]/g, '[-_]');
    const re = new RegExp(`\\b${normalized}\\b`, 'i');
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (re.test(lines[i])) return i + 1;
    }
    return null;
  },
};

const denoResolver: ManifestResolver = {
  ecosystem: 'deno',
  manifestCandidates(lockfilePath, workspace) {
    const dir = lockfilePath ? join(workspace, dirname(lockfilePath)) : workspace;
    return [join(dir, 'deno.json'), join(dir, 'deno.jsonc')];
  },
  findPackageLine(content, packageName) {
    // packageName is either a bare npm name ("chalk") or a JSR name ("jsr:@std/http").
    // In deno.json the import values contain the full specifier, e.g.:
    //   "chalk": "npm:chalk@^5",  "std/http": "jsr:@std/http@^0.224"
    // Search within the import values rather than the alias keys.
    const specifier = packageName.startsWith('jsr:') ? packageName : `npm:${packageName}`;
    const escaped = specifier.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`"${escaped}`);
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (re.test(lines[i])) return i + 1;
    }
    return null;
  },
};

const resolvers = new Map<string, ManifestResolver>([
  ['javascript', npmResolver],
  ['python', pythonResolver],
  ['deno', denoResolver],
]);

export function registerManifestResolver(resolver: ManifestResolver): void {
  resolvers.set(resolver.ecosystem, resolver);
}

export interface ResolvedManifest {
  /** Path relative to the workspace root. */
  relativePath: string;
  /** 1-based line number where the package is declared, or null. */
  line: number | null;
}

export function resolveManifest(
  ecosystem: string,
  lockfilePath: string | null,
  packageName: string,
  workspace: string,
): ResolvedManifest | null {
  const resolver = resolvers.get(ecosystem);
  if (!resolver) return null;

  for (const candidate of resolver.manifestCandidates(lockfilePath, workspace)) {
    let content: string;
    try {
      content = readFileSync(candidate, 'utf-8');
    } catch {
      continue;
    }
    const line = resolver.findPackageLine(content, packageName);
    const relativePath = candidate.startsWith(workspace + '/')
      ? candidate.slice(workspace.length + 1)
      : candidate;
    return { relativePath, line };
  }
  return null;
}

function buildSignals(pkg: import('../types.js').PackageAnalysis): string[] {
  const signals: string[] = [];

  for (const v of pkg.knownVulns?.slice(0, 3) ?? []) {
    signals.push(`${v.id}${v.severity ? ` [${v.severity}]` : ''}`);
  }
  if ((pkg.knownVulns?.length ?? 0) > 3) {
    signals.push(`+${pkg.knownVulns!.length - 3} more CVEs`);
  }
  for (const f of pkg.securityFindings?.delta.slice(0, 3) ?? []) {
    signals.push(f.label);
  }
  if ((pkg.securityFindings?.delta.length ?? 0) > 3) {
    signals.push(`+${pkg.securityFindings!.delta.length - 3} more patterns`);
  }
  if ((pkg.binaryFindings?.delta.length ?? 0) > 0) {
    signals.push(`binary anomaly (${pkg.binaryFindings!.delta.length} change(s))`);
  }
  if (pkg.securityFindings?.platformDivergence) signals.push('platform divergence');
  if (pkg.metadataDelta?.publisherChanged) signals.push('publisher changed');
  if (pkg.metadataDelta?.buildSystemChanged) signals.push('build system changed');
  if (pkg.installHooks?.some((h) => h.isNew)) signals.push('new install hooks');
  if (pkg.registryCheck?.potentialConfusion) signals.push('dependency confusion');
  if (pkg.registryCheck?.registryChanged) signals.push('registry changed');
  if (pkg.repoCheck?.releaseDropped) signals.push('release tag dropped');
  if ((pkg.registryInfo?.versionAgeDays ?? Infinity) < 1) signals.push('fresh publish (<24h)');
  if (pkg.metadataDelta?.newBinaryWheels) signals.push('new binary wheels');
  if (pkg.metadataDelta?.licenseChanged) signals.push('license changed');

  return signals;
}

export function emitAnnotations(report: SecurityReport, workspace: string = process.cwd()): void {
  for (const lf of report.lockfiles) {
    for (const pkg of lf.packages) {
      const sev = packageMaxSeverity(pkg);
      if (!sev) continue;

      const level = annotationLevel(sev);
      const manifest = resolveManifest(lf.ecosystem, lf.lockfilePath, pkg.name, workspace);

      const filePath = manifest?.relativePath ?? lf.lockfilePath ?? 'package.json';
      const line = manifest?.line;

      const version =
        pkg.changeType === 'updated'
          ? `${pkg.oldVersion} → ${pkg.newVersion}`
          : (pkg.newVersion ?? pkg.oldVersion ?? '?');

      const signals = buildSignals(pkg);
      const title = `lockscan — ${pkg.name}`;
      const message = `${pkg.name} (${version}): ${signals.join(', ')}`;

      const props: core.AnnotationProperties = {
        title,
        file: filePath,
        ...(line != null ? { startLine: line } : {}),
      };

      if (level === 'error') core.error(message, props);
      else if (level === 'warning') core.warning(message, props);
      else core.notice(message, props);
    }
  }
}
