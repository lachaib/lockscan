import type { PackageAnalysis, SecurityReport } from '../types.js';

export type Severity = 'critical' | 'high' | 'moderate' | 'low';

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  moderate: 2,
  low: 1,
};

// Patterns that directly exfiltrate credentials — treat as critical regardless of context.
const CRITICAL_PATTERNS = new Set(['cred:ci-token']);

// Patterns that enable arbitrary code execution.
const HIGH_PATTERNS = new Set([
  'exec:eval',
  'exec:exec',
  'exec:compile',
  'exec:Function',
  'exec:vm',
  'exec:__import__',
  'exec:importlib',
  'obfusc:eval-decode',
  'deser:pickle',
  'deser:marshal',
]);

// Patterns that enable shell execution or unsafe deserialization.
const MODERATE_PATTERNS = new Set([
  'shell:require-child_process',
  'shell:execSync',
  'shell:spawnSync',
  'shell:execFileSync',
  'shell:os.system',
  'shell:os.popen',
  'shell:subprocess',
  'exec:dynamic-require',
  'exec:dynamic-load-path',
  'deser:yaml.load',
  'deser:generic',
]);

export function patternSeverity(label: string): Severity {
  if (CRITICAL_PATTERNS.has(label)) return 'critical';
  if (HIGH_PATTERNS.has(label)) return 'high';
  if (MODERATE_PATTERNS.has(label)) return 'moderate';
  return 'low';
}

function osvSeverity(s: string | undefined): Severity | null {
  switch (s?.toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MODERATE':
    case 'MEDIUM':
      return 'moderate';
    case 'LOW':
      return 'low';
    default:
      return null;
  }
}

export function higher(a: Severity | null, b: Severity): Severity {
  if (!a) return b;
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

export function packageMaxSeverity(pkg: PackageAnalysis): Severity | null {
  let s: Severity | null = null;

  for (const v of pkg.knownVulns ?? []) {
    const vs = osvSeverity(v.severity);
    if (vs) s = higher(s, vs);
  }
  for (const f of pkg.securityFindings?.delta ?? []) {
    s = higher(s, patternSeverity(f.label));
  }

  if ((pkg.binaryFindings?.delta.length ?? 0) > 0) s = higher(s, 'high');
  if (pkg.securityFindings?.platformDivergence) s = higher(s, 'high');
  if (pkg.metadataDelta?.publisherChanged) s = higher(s, 'high');
  if (pkg.metadataDelta?.buildSystemChanged) s = higher(s, 'high');
  if (pkg.installHooks?.some((h) => h.isNew)) s = higher(s, 'high');

  if (pkg.registryCheck?.potentialConfusion) s = higher(s, 'critical');
  if (pkg.registryCheck?.registryChanged) s = higher(s, 'moderate');
  if (pkg.repoCheck?.releaseDropped) s = higher(s, 'moderate');
  if (pkg.metadataDelta?.newBinaryWheels) s = higher(s, 'moderate');

  if ((pkg.registryInfo?.versionAgeDays ?? Infinity) < 1) s = higher(s, 'low');
  if (pkg.metadataDelta?.licenseChanged) s = higher(s, 'low');

  return s;
}

export function reportMaxSeverity(report: SecurityReport): Severity | null {
  let s: Severity | null = null;
  for (const lf of report.lockfiles) {
    for (const pkg of lf.packages) {
      const ps = packageMaxSeverity(pkg);
      if (ps) s = higher(s, ps);
    }
  }
  return s;
}

export function shouldFail(failOn: string, maxSev: Severity | null): boolean {
  if (failOn === 'never' || !maxSev) return false;
  if (failOn === 'any') return true;
  if (failOn === 'critical') return maxSev === 'critical';
  if (failOn === 'high') return SEVERITY_RANK[maxSev] >= SEVERITY_RANK.high;
  return false;
}

export function sarifLevel(sev: Severity): 'error' | 'warning' | 'note' {
  if (sev === 'critical' || sev === 'high') return 'error';
  if (sev === 'moderate') return 'warning';
  return 'note';
}

export function annotationLevel(sev: Severity): 'error' | 'warning' | 'notice' {
  if (sev === 'critical' || sev === 'high') return 'error';
  if (sev === 'moderate') return 'warning';
  return 'notice';
}
