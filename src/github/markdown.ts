import type { PackageAnalysis, SecurityReport } from '../types.js';
import { packageMaxSeverity, type Severity } from './severity.js';

export const COMMENT_MARKER = '<!-- lockscan -->';

const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: '🔴',
  high: '🟠',
  moderate: '🟡',
  low: '🔵',
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  moderate: 'Moderate',
  low: 'Low',
};

function packageSignals(pkg: PackageAnalysis): string[] {
  const signals: string[] = [];

  for (const v of pkg.knownVulns?.slice(0, 2) ?? []) {
    signals.push(`${v.id}${v.severity ? ` [${v.severity}]` : ''}`);
  }
  if ((pkg.knownVulns?.length ?? 0) > 2) {
    signals.push(`+${pkg.knownVulns!.length - 2} more CVEs`);
  }
  for (const f of pkg.securityFindings?.delta.slice(0, 3) ?? []) {
    signals.push(`\`${f.label}\``);
  }
  if ((pkg.securityFindings?.delta.length ?? 0) > 3) {
    signals.push(`+${pkg.securityFindings!.delta.length - 3} more patterns`);
  }
  if ((pkg.binaryFindings?.delta.length ?? 0) > 0) {
    signals.push(`binary anomaly (${pkg.binaryFindings!.delta.length})`);
  }
  if (pkg.securityFindings?.platformDivergence) signals.push('platform divergence');
  if (pkg.metadataDelta?.publisherChanged) signals.push('publisher changed');
  if (pkg.metadataDelta?.buildSystemChanged) signals.push('build system changed');
  if (pkg.installHooks?.some((h) => h.isNew)) {
    const n = pkg.installHooks.filter((h) => h.isNew).length;
    signals.push(`${n} new install hook(s)`);
  }
  if (pkg.registryCheck?.potentialConfusion) signals.push('**dependency confusion**');
  if (pkg.registryCheck?.registryChanged) signals.push('registry changed');
  if (pkg.repoCheck?.releaseDropped) signals.push('release tag dropped');
  if ((pkg.registryInfo?.versionAgeDays ?? Infinity) < 1) signals.push('⚡ fresh publish');
  if (pkg.metadataDelta?.newBinaryWheels) signals.push('new binary wheels');
  if (pkg.metadataDelta?.licenseChanged) signals.push('license changed');

  return signals;
}

function packageRow(pkg: PackageAnalysis): string | null {
  const sev = packageMaxSeverity(pkg);
  if (!sev) return null;

  const badge = `${SEVERITY_EMOJI[sev]} ${SEVERITY_LABEL[sev]}`;
  const version =
    pkg.changeType === 'updated'
      ? `\`${pkg.oldVersion}\` → \`${pkg.newVersion}\``
      : `\`${pkg.newVersion ?? pkg.oldVersion ?? '?'}\``;
  const tag = pkg.isDev ? ' *(dev)*' : !pkg.isDirect ? ' *(transitive)*' : '';

  return `| ${badge} | \`${pkg.name}\`${tag} | ${version} | ${packageSignals(pkg).join(', ')} |`;
}

export function formatMarkdown(report: SecurityReport): string {
  const { summary } = report;

  const findingPkgs = report.lockfiles
    .flatMap((lf) => lf.packages)
    .filter((p) => packageMaxSeverity(p) !== null);

  const meta =
    `| | |\n|---|---|\n` +
    `| **Base** | \`${report.baseRef}\` |\n` +
    `| **Head** | \`${report.headRef}\` |\n` +
    `| **Analyzed** | ${summary.analyzed} package(s) |\n` +
    `| **Ecosystems** | ${summary.ecosystems.join(', ') || 'none'} |\n`;

  if (findingPkgs.length === 0) {
    return (
      `## 🔍 lockscan Security Report\n\n` +
      meta +
      '\n✅ **No security findings.** All dependency changes look clean.\n'
    );
  }

  // Count by severity for the summary line.
  const bySev: Record<Severity, number> = { critical: 0, high: 0, moderate: 0, low: 0 };
  for (const pkg of findingPkgs) {
    const s = packageMaxSeverity(pkg)!;
    bySev[s]++;
  }
  const summaryParts = (Object.entries(bySev) as [Severity, number][])
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${SEVERITY_EMOJI[s]} ${n} ${SEVERITY_LABEL[s]}`);

  const rows = findingPkgs.map(packageRow).filter(Boolean).join('\n');

  return (
    `## 🔍 lockscan Security Report\n\n` +
    meta +
    `\n> ${summaryParts.join(' · ')}\n\n` +
    `### Findings\n\n` +
    `| Severity | Package | Version | Signals |\n` +
    `|---|---|---|---|\n` +
    rows +
    '\n'
  );
}
