import type { PackageAnalysis, SecurityReport } from '../types.js';
import { resolveManifest } from './annotations.js';
import { packageMaxSeverity, patternSeverity, sarifLevel } from './severity.js';

// SARIF 2.1.0 — https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
// GitHub Code Scanning ingests this via actions/upload-sarif.

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string; uriBaseId: string };
    region?: { startLine: number };
  };
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: SarifLocation[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: 'error' | 'warning' | 'note' };
  helpUri?: string;
  properties: { tags: string[]; precision: string };
}

const RULES: Record<string, SarifRule> = {
  'lockscan/known-vuln': {
    id: 'lockscan/known-vuln',
    name: 'KnownVulnerability',
    shortDescription: { text: 'Known CVE or security advisory (OSV)' },
    fullDescription: {
      text: 'This package version has one or more known security advisories in the OSV database.',
    },
    defaultConfiguration: { level: 'error' },
    helpUri: 'https://osv.dev',
    properties: { tags: ['security', 'supply-chain'], precision: 'high' },
  },
  'lockscan/source-pattern': {
    id: 'lockscan/source-pattern',
    name: 'DangerousSourcePattern',
    shortDescription: { text: 'Dangerous API pattern introduced in updated version' },
    fullDescription: {
      text: 'A new version of this package introduced source code patterns associated with code execution, credential theft, or obfuscation.',
    },
    defaultConfiguration: { level: 'warning' },
    properties: { tags: ['security', 'supply-chain'], precision: 'medium' },
  },
  'lockscan/binary-anomaly': {
    id: 'lockscan/binary-anomaly',
    name: 'BinaryAnomaly',
    shortDescription: { text: 'Suspicious change in compiled binary extension' },
    fullDescription: {
      text: 'A compiled extension (.so/.pyd/.dll) in this package gained new dangerous native symbols, high-entropy regions, or suspicious embedded strings.',
    },
    defaultConfiguration: { level: 'error' },
    properties: { tags: ['security', 'supply-chain'], precision: 'medium' },
  },
  'lockscan/install-hook': {
    id: 'lockscan/install-hook',
    name: 'NewInstallHook',
    shortDescription: { text: 'New post-install script added' },
    fullDescription: {
      text: 'This package version added a new lifecycle script (npm postinstall, Python .pth file, or data script) that runs automatically at install time.',
    },
    defaultConfiguration: { level: 'error' },
    properties: { tags: ['security', 'supply-chain'], precision: 'high' },
  },
  'lockscan/publisher-change': {
    id: 'lockscan/publisher-change',
    name: 'PublisherChanged',
    shortDescription: { text: 'Package published by a different npm account' },
    fullDescription: {
      text: 'The npm account that published this version differs from all previous versions. This is the exact mechanism used in the event-stream (2018) supply-chain attack.',
    },
    defaultConfiguration: { level: 'error' },
    properties: { tags: ['security', 'supply-chain'], precision: 'high' },
  },
  'lockscan/registry-confusion': {
    id: 'lockscan/registry-confusion',
    name: 'DependencyConfusion',
    shortDescription: { text: 'Dependency confusion signal detected' },
    fullDescription: {
      text: 'This package shows hallmarks of a dependency confusion attack: implausibly high version number or a private-to-public registry switch.',
    },
    defaultConfiguration: { level: 'error' },
    properties: { tags: ['security', 'supply-chain'], precision: 'high' },
  },
  'lockscan/registry-change': {
    id: 'lockscan/registry-change',
    name: 'RegistryChanged',
    shortDescription: { text: 'Package registry source changed' },
    fullDescription: {
      text: 'This package is now resolved from a different registry than before.',
    },
    defaultConfiguration: { level: 'warning' },
    properties: { tags: ['security', 'supply-chain'], precision: 'high' },
  },
  'lockscan/release-dropped': {
    id: 'lockscan/release-dropped',
    name: 'ReleaseTagDropped',
    shortDescription: { text: 'Version has no corresponding source release tag' },
    fullDescription: {
      text: 'The previous version had a matching release tag in the source repository, but this version does not — suggesting the artifact was not built from tagged source.',
    },
    defaultConfiguration: { level: 'warning' },
    properties: { tags: ['security', 'supply-chain'], precision: 'medium' },
  },
  'lockscan/build-system-change': {
    id: 'lockscan/build-system-change',
    name: 'BuildSystemChanged',
    shortDescription: { text: 'Build configuration files modified (XZ-style injection risk)' },
    fullDescription: {
      text: 'Files that control the build process (Makefile.am, configure.ac, binding.gyp, …) were added or modified. This is the vector used in the XZ Utils backdoor (CVE-2024-3094).',
    },
    defaultConfiguration: { level: 'error' },
    properties: { tags: ['security', 'supply-chain'], precision: 'medium' },
  },
  'lockscan/platform-divergence': {
    id: 'lockscan/platform-divergence',
    name: 'PlatformDivergence',
    shortDescription: { text: 'Different security findings across platform wheels' },
    fullDescription: {
      text: 'This package version has different security findings in different platform-specific wheels, which may indicate a targeted platform attack.',
    },
    defaultConfiguration: { level: 'error' },
    properties: { tags: ['security', 'supply-chain'], precision: 'high' },
  },
  'lockscan/fresh-publish': {
    id: 'lockscan/fresh-publish',
    name: 'FreshPublish',
    shortDescription: { text: 'Package version published less than 24 hours ago' },
    fullDescription: {
      text: 'This version was published very recently, matching the "sniper" pattern where attackers publish just before a deployment window.',
    },
    defaultConfiguration: { level: 'note' },
    properties: { tags: ['security', 'supply-chain'], precision: 'low' },
  },
  'lockscan/license-change': {
    id: 'lockscan/license-change',
    name: 'LicenseChanged',
    shortDescription: { text: 'Package changed its declared license' },
    fullDescription: {
      text: 'The license field changed between versions. This may affect legal compliance or signal an ownership change.',
    },
    defaultConfiguration: { level: 'note' },
    properties: { tags: ['license', 'supply-chain'], precision: 'high' },
  },
  'lockscan/new-binary-wheels': {
    id: 'lockscan/new-binary-wheels',
    name: 'NewBinaryWheels',
    shortDescription: { text: 'Package switched from source distribution to binary wheels' },
    fullDescription: {
      text: 'This package previously shipped only source distributions; the new version adds compiled binary wheels that cannot be audited with source-level analysis.',
    },
    defaultConfiguration: { level: 'warning' },
    properties: { tags: ['security', 'supply-chain'], precision: 'high' },
  },
};

function locationFor(
  ecosystem: string,
  lockfilePath: string | null,
  packageName: string,
  workspace: string,
): SarifLocation {
  const manifest = resolveManifest(ecosystem, lockfilePath, packageName, workspace);
  const uri = manifest?.relativePath ?? lockfilePath ?? 'package.json';
  const region = manifest?.line != null ? { startLine: manifest.line } : undefined;
  return {
    physicalLocation: {
      artifactLocation: { uri, uriBaseId: '%SRCROOT%' },
      ...(region ? { region } : {}),
    },
  };
}

function resultsForPackage(
  pkg: PackageAnalysis,
  ecosystem: string,
  lockfilePath: string | null,
  workspace: string,
): SarifResult[] {
  const sev = packageMaxSeverity(pkg);
  if (!sev) return [];

  const results: SarifResult[] = [];
  const loc = locationFor(ecosystem, lockfilePath, pkg.name, workspace);
  const versionStr =
    pkg.changeType === 'updated'
      ? `${pkg.oldVersion} → ${pkg.newVersion}`
      : (pkg.newVersion ?? pkg.oldVersion ?? '?');

  // Known vulns — one result per advisory.
  for (const v of pkg.knownVulns ?? []) {
    const vulnSev = v.severity
      ? sarifLevel(v.severity.toLowerCase() as import('./severity.js').Severity)
      : 'warning';
    results.push({
      ruleId: 'lockscan/known-vuln',
      level: vulnSev,
      message: {
        text: `${pkg.name} (${versionStr}) has known advisory ${v.id}${v.severity ? ` [${v.severity}]` : ''}: ${v.summary}`,
      },
      locations: [loc],
    });
  }

  // Source pattern findings — one result per unique label.
  const seenLabels = new Set<string>();
  for (const f of pkg.securityFindings?.delta ?? []) {
    if (seenLabels.has(f.label)) continue;
    seenLabels.add(f.label);
    results.push({
      ruleId: 'lockscan/source-pattern',
      level: sarifLevel(patternSeverity(f.label)),
      message: {
        text: `${pkg.name} (${versionStr}) introduced dangerous pattern \`${f.label}\` (first seen in ${f.file}:${f.line})`,
      },
      locations: [loc],
    });
  }

  // Binary anomalies.
  if ((pkg.binaryFindings?.delta.length ?? 0) > 0) {
    const labels = [...new Set(pkg.binaryFindings!.delta.map((f) => f.label))].join(', ');
    results.push({
      ruleId: 'lockscan/binary-anomaly',
      level: 'error',
      message: {
        text: `${pkg.name} (${versionStr}) has ${pkg.binaryFindings!.delta.length} binary anomaly(ies): ${labels}`,
      },
      locations: [loc],
    });
  }

  // Platform divergence.
  if (pkg.securityFindings?.platformDivergence) {
    results.push({
      ruleId: 'lockscan/platform-divergence',
      level: 'error',
      message: {
        text: `${pkg.name} (${versionStr}) has different security findings across platform-specific wheels`,
      },
      locations: [loc],
    });
  }

  // New install hooks.
  if (pkg.installHooks?.some((h) => h.isNew)) {
    const newHooks = pkg.installHooks.filter((h) => h.isNew);
    results.push({
      ruleId: 'lockscan/install-hook',
      level: 'error',
      message: {
        text: `${pkg.name} (${versionStr}) added ${newHooks.length} new install hook(s): ${newHooks.map((h) => `${h.type}:${h.name}`).join(', ')}`,
      },
      locations: [loc],
    });
  }

  // Publisher change.
  if (pkg.metadataDelta?.publisherChanged) {
    results.push({
      ruleId: 'lockscan/publisher-change',
      level: 'error',
      message: {
        text: `${pkg.name} (${versionStr}) was published by a different npm account than previous versions`,
      },
      locations: [loc],
    });
  }

  // Build system changed.
  if (pkg.metadataDelta?.buildSystemChanged) {
    results.push({
      ruleId: 'lockscan/build-system-change',
      level: 'error',
      message: {
        text: `${pkg.name} (${versionStr}) has modifications to build configuration files (configure.ac, Makefile.am, binding.gyp, …)`,
      },
      locations: [loc],
    });
  }

  // Registry confusion.
  if (pkg.registryCheck?.potentialConfusion) {
    results.push({
      ruleId: 'lockscan/registry-confusion',
      level: 'error',
      message: {
        text: `${pkg.name} (${versionStr}) shows dependency confusion signals: ${pkg.registryCheck.confusionReasons.join('; ')}`,
      },
      locations: [loc],
    });
  }

  // Registry changed (but not confusion — that is already covered above).
  if (pkg.registryCheck?.registryChanged && !pkg.registryCheck?.potentialConfusion) {
    results.push({
      ruleId: 'lockscan/registry-change',
      level: 'warning',
      message: {
        text: `${pkg.name} (${versionStr}) registry changed: ${pkg.registryCheck.oldRegistry} → ${pkg.registryCheck.newRegistry}`,
      },
      locations: [loc],
    });
  }

  // Release tag dropped.
  if (pkg.repoCheck?.releaseDropped) {
    results.push({
      ruleId: 'lockscan/release-dropped',
      level: 'warning',
      message: {
        text: `${pkg.name} (${versionStr}) has no release tag in ${pkg.repoCheck.repoUrl} — the previous version did`,
      },
      locations: [loc],
    });
  }

  // New binary wheels.
  if (pkg.metadataDelta?.newBinaryWheels) {
    results.push({
      ruleId: 'lockscan/new-binary-wheels',
      level: 'warning',
      message: {
        text: `${pkg.name} (${versionStr}) switched from source-only distribution to compiled binary wheels`,
      },
      locations: [loc],
    });
  }

  // Fresh publish.
  if ((pkg.registryInfo?.versionAgeDays ?? Infinity) < 1) {
    results.push({
      ruleId: 'lockscan/fresh-publish',
      level: 'note',
      message: {
        text: `${pkg.name} (${versionStr}) was published less than 24 hours ago (sniper-pattern risk)`,
      },
      locations: [loc],
    });
  }

  // License changed.
  if (pkg.metadataDelta?.licenseChanged) {
    results.push({
      ruleId: 'lockscan/license-change',
      level: 'note',
      message: { text: `${pkg.name} (${versionStr}) changed its declared license` },
      locations: [loc],
    });
  }

  return results;
}

export function generateSarif(report: SecurityReport, workspace: string = process.cwd()): object {
  const results: SarifResult[] = [];

  for (const lf of report.lockfiles) {
    for (const pkg of lf.packages) {
      results.push(...resultsForPackage(pkg, lf.ecosystem, lf.lockfilePath, workspace));
    }
  }

  // Emit only the rules referenced by actual results to keep the output lean.
  const usedRuleIds = new Set(results.map((r) => r.ruleId));
  const rules = [...usedRuleIds].map((id) => RULES[id]).filter(Boolean);

  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'lockscan',
            informationUri: 'https://github.com/lachaib/lockscan',
            rules,
          },
        },
        results,
      },
    ],
  };
}
