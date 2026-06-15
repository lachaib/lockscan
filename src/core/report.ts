import { platformLabel } from '../platforms.js';
import type {
  BinaryFinding,
  InstallHook,
  KnownVuln,
  PackageAnalysis,
  RegistryCheck,
  RepoCheck,
  SecurityFinding,
  SecurityReport,
} from '../types.js';

const WIDE = '═'.repeat(62);
const THIN = '─'.repeat(62);
const MAX_FINDINGS_SHOWN = 30;

export function formatReport(report: SecurityReport): string {
  const { summary } = report;
  const divergenceNote =
    summary.platformDivergences > 0
      ? `\n⚠ PLATFORM DIVERGENCE: ${summary.platformDivergences} package(s) have different findings across wheels`
      : '';
  const binaryNote =
    summary.binaryAnomalies > 0
      ? `\n⚠ BINARY ANOMALIES: ${summary.binaryAnomalies} package(s) have suspicious changes in compiled extensions`
      : '';
  const vulnNote =
    summary.knownVulns > 0
      ? `\n⚠ KNOWN VULNERABILITIES: ${summary.knownVulns} known CVE/advisory across changed packages (OSV)`
      : '';
  const releaseNote =
    summary.releaseDropped > 0
      ? `\n⚠ RELEASE DROPPED: ${summary.releaseDropped} package(s) lost repo release tagging`
      : '';
  const hooksNote =
    summary.installHooksAdded > 0
      ? `\n⚠ NEW INSTALL HOOKS: ${summary.installHooksAdded} package(s) gained post-install scripts`
      : '';
  const registryNote =
    summary.registryChanges > 0
      ? `\n⚠ REGISTRY: ${summary.registryChanges} package(s) with registry change or dependency confusion signals`
      : '';
  const freshnessNote =
    summary.freshnessWarnings > 0
      ? `\n⚠ FRESH PUBLISH: ${summary.freshnessWarnings} package(s) published < 24 h ago — sniper-pattern risk`
      : '';
  const publisherNote =
    summary.publisherChanges > 0
      ? `\n⚠ PUBLISHER CHANGE: ${summary.publisherChanges} package(s) published by a different npm account than before`
      : '';
  const licenseNote =
    summary.licenseChanges > 0
      ? `\n⚠ LICENSE CHANGED: ${summary.licenseChanges} package(s) changed their declared license`
      : '';

  const blocks: string[] = [
    `=== LOCKSCAN SECURITY REPORT ===\n` +
      `Generated:   ${report.generatedAt}\n` +
      `Base ref:    ${report.baseRef}\n` +
      `Head ref:    ${report.headRef}\n` +
      `Analyzed:    ${summary.analyzed} package(s) — ${summary.errors} error(s)\n` +
      `New hits:    ${summary.newSecurityFindings} new security pattern hit(s)\n` +
      `Ecosystems:  ${summary.ecosystems.join(', ') || 'none'}` +
      divergenceNote +
      binaryNote +
      vulnNote +
      releaseNote +
      hooksNote +
      registryNote +
      freshnessNote +
      publisherNote +
      licenseNote,
  ];

  for (const lf of report.lockfiles) {
    const header =
      `\n${THIN}\n` +
      `LOCKFILE: ${lf.lockfilePath ?? '(unknown)'}  [workspace: ${lf.workspace}]  (${lf.type ?? '?'})\n` +
      `Ecosystem: ${lf.ecosystem}\n` +
      `Changes:  ${lf.packages.filter((p) => p.changeType === 'updated').length} updated, ` +
      `${lf.packages.filter((p) => p.changeType === 'added').length} added, ` +
      `${lf.packages.filter((p) => p.changeType === 'removed').length} removed\n` +
      `${THIN}`;

    if (lf.packages.length === 0) {
      blocks.push(header + '\nNo dependency changes.\n');
      continue;
    }

    const pkgBlocks = lf.packages.map((p, i) => formatPackage(p, i + 1, lf.packages.length));
    blocks.push(header + '\n' + pkgBlocks.join('\n'));
  }

  return blocks.join('\n');
}

function formatPackage(pkg: PackageAnalysis, idx: number, total: number): string {
  const direct = pkg.isDirect ? 'direct' : 'transitive';
  const devTag = pkg.isDev ? ' dev' : '';
  const lines: string[] = [];

  if (pkg.changeType === 'updated') {
    lines.push(
      `\n${WIDE}\n[${idx}/${total}] ${pkg.name}  UPDATED  ${pkg.oldVersion} → ${pkg.newVersion}  (${direct}${devTag})\n${WIDE}`,
    );
  } else if (pkg.changeType === 'added') {
    lines.push(
      `\n${WIDE}\n[${idx}/${total}] ${pkg.name}  ADDED  ${pkg.newVersion}  (${direct}${devTag})\n${WIDE}`,
    );
  } else {
    lines.push(
      `\n${WIDE}\n[${idx}/${total}] ${pkg.name}  REMOVED  ${pkg.oldVersion}  (${direct}${devTag})\n${WIDE}`,
    );
  }

  if (pkg.error) {
    lines.push(`\nERROR: ${pkg.error}\n`);
    return lines.join('');
  }

  // Verification
  if (pkg.verification) {
    const { platforms, oldArtifacts, newArtifacts } = pkg.verification;
    lines.push(`\nVERIFICATION\n  platforms: ${platforms.map(platformLabel).join(', ')}`);
    for (const a of oldArtifacts) {
      const plats = a.platforms?.map(platformLabel).join(', ');
      lines.push(
        `  old: ${a.filename}${plats ? `  [${plats}]` : ''}\n    sha256: ${a.sha256}  STATUS:VERIFIED`,
      );
    }
    for (const a of newArtifacts) {
      const plats = a.platforms?.map(platformLabel).join(', ');
      lines.push(
        `  new: ${a.filename}${plats ? `  [${plats}]` : ''}\n    sha256: ${a.sha256}  STATUS:VERIFIED`,
      );
    }
  }

  // Registry info (added packages)
  if (pkg.registryInfo) {
    const r = pkg.registryInfo;
    const ageStr = r.ageDays != null ? ` (${r.ageDays} days ago)` : '';
    const versionAgeStr =
      r.versionAgeDays != null
        ? r.versionAgeDays < 1
          ? '  ⚠ PUBLISHED < 24 H AGO'
          : ` (${r.versionAgeDays} days ago)`
        : '';
    lines.push(
      '\nREGISTRY INFO\n' +
        `  summary:        ${r.summary || '(none)'}\n` +
        `  author:         ${r.author ?? ''}${r.authorEmail ? ` <${r.authorEmail}>` : ''}\n` +
        `  homepage:       ${r.homepage || '(none)'}\n` +
        `  license:        ${r.license || '(none)'}\n` +
        `  num_releases:   ${r.numReleases ?? '?'}\n` +
        `  first_upload:   ${r.firstUpload ?? 'unknown'}${ageStr}\n` +
        `  version_upload: ${r.versionUpload ?? 'unknown'}${versionAgeStr}\n` +
        `  latest_ver:     ${r.latestVersion ?? '?'}\n` +
        `  requires:       ${
          r.requiresDist?.length
            ? r.requiresDist.slice(0, 5).join(', ') +
              (r.requiresDist.length > 5 ? ` ... +${r.requiresDist.length - 5} more` : '')
            : 'none'
        }`,
    );
  }

  // Metadata delta (updated packages)
  if (pkg.metadataDelta) {
    const d = pkg.metadataDelta;
    const flags: string[] = [];
    if (d.buildSystemChanged) flags.push('⚠ BUILD SYSTEM FILES CHANGED');
    if (d.newBinaryWheels) flags.push('⚠ NEW BINARY WHEELS (previously source-only)');
    if (d.publisherChanged) flags.push('⚠ PUBLISHER CHANGED (different npm account)');
    if (d.licenseChanged) flags.push('⚠ LICENSE CHANGED');
    lines.push(
      '\nMETADATA DELTA\n' +
        (flags.length ? `  ${flags.join('\n  ')}\n` : '') +
        `  author:       ${d.authorChanged ? 'CHANGED' : 'unchanged'}\n` +
        `  homepage:     ${d.homepageChanged ? 'CHANGED' : 'unchanged'}\n` +
        `  license:      ${d.licenseChanged ? 'CHANGED' : 'unchanged'}\n` +
        `  deps_added:   ${d.depsAdded.length ? d.depsAdded.join(', ') : 'none'}\n` +
        `  deps_removed: ${d.depsRemoved.length ? d.depsRemoved.join(', ') : 'none'}`,
    );
  }

  // Code delta
  if (pkg.codeDelta) {
    const c = pkg.codeDelta;
    lines.push(
      '\nCODE DELTA\n' +
        `  files_added: ${c.filesAdded}  removed: ${c.filesRemoved}  changed: ${c.filesChanged}\n` +
        `  diff:\n${c.diff}`,
    );
  }

  // Known vulnerabilities (OSV)
  if (pkg.knownVulns && pkg.knownVulns.length > 0) {
    lines.push('\nKNOWN VULNERABILITIES (OSV)');
    lines.push(formatKnownVulns(pkg.knownVulns));
  }

  // Registry check
  if (pkg.registryCheck) {
    lines.push('\nREGISTRY CHECK');
    lines.push(formatRegistryCheck(pkg.registryCheck));
  }

  // Install hooks
  if (pkg.installHooks && pkg.installHooks.length > 0) {
    lines.push('\nINSTALL HOOKS');
    lines.push(formatInstallHooks(pkg.installHooks));
  }

  // Repo release check
  if (pkg.repoCheck) {
    lines.push('\nREPO CHECK');
    lines.push(formatRepoCheck(pkg.repoCheck));
  }

  // Binary scan
  if (pkg.binaryFindings && pkg.binaryFindings.delta.length > 0) {
    lines.push('\nBINARY SCAN');
    lines.push(formatBinaryFindings(pkg.binaryFindings.delta));
  }

  // Security scan
  if (pkg.securityFindings) {
    const { old: oldF, new: newF, delta, platformDivergence } = pkg.securityFindings;

    const divergenceWarning = platformDivergence
      ? '\n  ⚠ PLATFORM DIVERGENCE DETECTED — security findings differ across wheels'
      : '';

    lines.push(
      '\nSECURITY SCAN' +
        divergenceWarning +
        '\n' +
        formatFindingsSummary(oldF, newF, delta) +
        '\n' +
        formatFindings(oldF, 'old_hits') +
        '\n' +
        formatFindings(newF, 'new_hits') +
        `\n  delta: +${delta.length} new hit(s) not in old version\n` +
        formatFindings(delta, 'new_hits'),
    );
  }

  return lines.join('\n');
}

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MODERATE: 2,
  MEDIUM: 2,
  LOW: 1,
};

function formatKnownVulns(vulns: KnownVuln[]): string {
  const sorted = [...vulns].sort(
    (a, b) => (SEVERITY_ORDER[b.severity ?? ''] ?? 0) - (SEVERITY_ORDER[a.severity ?? ''] ?? 0),
  );
  const lines = [`  ${vulns.length} known advisory(ies):`];
  for (const v of sorted) {
    const sev = v.severity ? ` [${v.severity}]` : '';
    const aliases = v.aliases.length ? `  aliases: ${v.aliases.join(', ')}` : '';
    lines.push(`  ${v.id}${sev} — ${v.summary}`);
    if (aliases) lines.push(`    ${aliases}`);
    if (v.url) lines.push(`    ${v.url}`);
  }
  return lines.join('\n');
}

function formatRegistryCheck(r: RegistryCheck): string {
  const lines: string[] = [];
  if (r.registryChanged) {
    lines.push(`  ⚠ REGISTRY CHANGED: ${r.oldRegistry} → ${r.newRegistry}`);
  }
  if (r.potentialConfusion) {
    for (const reason of r.confusionReasons) {
      lines.push(`  ⚠ DEPENDENCY CONFUSION: ${reason}`);
    }
  }
  if (!r.registryChanged && !r.potentialConfusion) {
    if (r.oldRegistry || r.newRegistry) {
      lines.push(`  registry: ${r.newRegistry ?? r.oldRegistry}`);
    }
  }
  return lines.join('\n');
}

function formatInstallHooks(hooks: InstallHook[]): string {
  const newCount = hooks.filter((h) => h.isNew).length;
  const changedCount = hooks.filter((h) => h.changed).length;
  const lines = [
    `  ${hooks.length} hook(s)${newCount > 0 ? ` — ${newCount} new` : ''}${changedCount > 0 ? `, ${changedCount} changed` : ''}`,
  ];
  for (const h of hooks) {
    const tag = h.isNew ? ' [NEW]' : h.changed ? ' [CHANGED]' : '';
    const cmd = h.command ? `  ${h.command.replace(/\n/g, ' ').slice(0, 120)}` : '';
    lines.push(`  ${h.type}:${h.name}${tag}${cmd}`);
  }
  return lines.join('\n');
}

function formatRepoCheck(r: RepoCheck): string {
  const lines = [`  repo: ${r.repoUrl}`];
  if (r.oldRelease) {
    lines.push(
      `  old:  ${r.oldRelease.found ? `✓ tag ${r.oldRelease.tag}` : '✗ no matching release'}`,
    );
  }
  if (r.newRelease) {
    const status = r.newRelease.found
      ? `✓ tag ${r.newRelease.tag}`
      : r.releaseDropped
        ? '✗ NO RELEASE — previously had one ⚠'
        : '✗ no matching release';
    lines.push(`  new:  ${status}`);
  }
  return lines.join('\n');
}

function formatBinaryFindings(findings: BinaryFinding[]): string {
  const byLabel = new Map<string, number>();
  for (const { label } of findings) byLabel.set(label, (byLabel.get(label) ?? 0) + 1);

  const lines = [`  delta: ${findings.length} anomaly(ies)`, '  by type:'];
  for (const [lbl, cnt] of [...byLabel.entries()].sort((a, b) => b[1] - a[1])) {
    lines.push(`    ${lbl}: ${cnt}`);
  }
  lines.push('  detail:');
  for (const f of findings.slice(0, MAX_FINDINGS_SHOWN)) {
    lines.push(`    ${f.file} — ${f.label}: ${f.detail}`);
  }
  if (findings.length > MAX_FINDINGS_SHOWN)
    lines.push(`    ...${findings.length - MAX_FINDINGS_SHOWN} more`);
  return lines.join('\n');
}

function formatFindingsSummary(
  oldF: SecurityFinding[],
  newF: SecurityFinding[],
  delta: SecurityFinding[],
): string {
  const oldCount = new Map<string, number>();
  for (const { label } of oldF) oldCount.set(label, (oldCount.get(label) ?? 0) + 1);

  const newCount = new Map<string, number>();
  for (const { label } of newF) newCount.set(label, (newCount.get(label) ?? 0) + 1);

  const deltaCount = new Map<string, number>();
  for (const { label } of delta) deltaCount.set(label, (deltaCount.get(label) ?? 0) + 1);

  const allLabels = new Set([...oldCount.keys(), ...newCount.keys()]);
  if (allLabels.size === 0) return '  by pattern (old → new): none';

  // Delta labels first (most new hits), then labels that only dropped
  const sorted = [...allLabels].sort((a, b) => {
    const dDiff = (deltaCount.get(b) ?? 0) - (deltaCount.get(a) ?? 0);
    if (dDiff !== 0) return dDiff;
    return (newCount.get(b) ?? 0) - (newCount.get(a) ?? 0);
  });

  const lines = ['  by pattern (old → new, net):'];
  for (const label of sorted) {
    const o = oldCount.get(label) ?? 0;
    const n = newCount.get(label) ?? 0;
    const net = n - o;
    const netStr = net > 0 ? `+${net}` : `${net}`;
    const d = deltaCount.get(label) ?? 0;
    const deltaStr = d > 0 ? `  [${d} in delta]` : '';
    lines.push(`    ${label}: ${o} → ${n}  (${netStr})${deltaStr}`);
  }
  return lines.join('\n');
}

function formatFindings(findings: SecurityFinding[], label: string): string {
  if (findings.length === 0) return `  ${label}: none`;

  const byLabel = new Map<string, number>();
  for (const { label: lbl } of findings) byLabel.set(lbl, (byLabel.get(lbl) ?? 0) + 1);

  const lines = [`  ${label}: ${findings.length} hit(s)`, '  by pattern:'];
  for (const [lbl, cnt] of [...byLabel.entries()].sort((a, b) => b[1] - a[1])) {
    lines.push(`    ${lbl}: ${cnt}`);
  }

  const shown = findings.slice(0, MAX_FINDINGS_SHOWN);
  lines.push(`  sample (${shown.length} of ${findings.length}):`);
  for (const f of shown) lines.push(`    ${f.file}:${f.line} — ${f.label}`);
  if (findings.length > MAX_FINDINGS_SHOWN)
    lines.push(`    ...${findings.length - MAX_FINDINGS_SHOWN} more`);

  return lines.join('\n');
}
