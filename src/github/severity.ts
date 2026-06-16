import type { PackageAnalysis, SecurityFinding, SecurityReport } from '../types.js';

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

// Groups of labels that represent the same underlying capability. When the family's
// net hit count doesn't grow, a new delta hit is a lateral refactor rather than new
// attack surface and is downgraded to 'low'.
const PATTERN_FAMILIES: Record<string, string[]> = {
  'dynamic-import': [
    'exec:importlib',
    'exec:__import__',
    'exec:dynamic-require',
    'exec:dynamic-load-path',
  ],
  eval: ['exec:eval', 'exec:exec', 'exec:compile', 'exec:Function', 'exec:vm'],
  shell: [
    'shell:os.system',
    'shell:os.popen',
    'shell:subprocess',
    'shell:execSync',
    'shell:spawnSync',
    'shell:execFileSync',
    'shell:require-child_process',
  ],
  deser: ['deser:pickle', 'deser:marshal', 'deser:yaml.load', 'deser:generic'],
};

const LABEL_TO_FAMILY = new Map<string, string[]>();
for (const members of Object.values(PATTERN_FAMILIES)) {
  for (const label of members) LABEL_TO_FAMILY.set(label, members);
}

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

function countByLabel(findings: SecurityFinding[]): Map<string, number> {
  const m = new Map<string, number>();
  for (const { label } of findings) m.set(label, (m.get(label) ?? 0) + 1);
  return m;
}

function effectivePatternSeverity(
  label: string,
  oldCount: Map<string, number>,
  newCount: Map<string, number>,
): Severity {
  const base = patternSeverity(label);
  if (base === 'critical') return base;

  const family = LABEL_TO_FAMILY.get(label);
  if (!family) return base;

  const oldTotal = family.reduce((n, l) => n + (oldCount.get(l) ?? 0), 0);
  const newTotal = family.reduce((n, l) => n + (newCount.get(l) ?? 0), 0);

  // Family net count grew only marginally — treat as lateral refactor, not new attack surface.
  // Threshold: net increase must exceed 20% of the old count OR 3 absolute hits to escalate.
  const netIncrease = newTotal - oldTotal;
  const threshold = Math.max(3, Math.ceil(oldTotal * 0.2));
  if (netIncrease < threshold) return 'low';
  return base;
}

function binaryFindingSeverity(label: string): Severity {
  // Sensitive paths and non-HTTP schemes have no legitimate reason in a compiled lib.
  if (label === 'binary:sensitive-path' || label === 'binary:url-other-scheme') return 'high';
  // Entropy spikes and new dangerous native symbols are high-confidence signals.
  if (label === 'binary:high-entropy' || label.startsWith('native:')) return 'high';
  // HTTP URLs, IPv4/v6, and temp paths warrant attention but appear in legitimate packages.
  if (
    label === 'binary:url-http' ||
    label === 'binary:ip-v4' ||
    label === 'binary:ip-v6' ||
    label === 'binary:tmppath'
  )
    return 'moderate';
  // Long base64 blobs are expected in crypto/data libraries as constants and OIDs.
  if (label === 'binary:base64') return 'low';
  return 'high'; // unknown label — conservative fallback
}

export function packageMaxSeverity(pkg: PackageAnalysis): Severity | null {
  let s: Severity | null = null;

  for (const v of pkg.knownVulns ?? []) {
    const vs = osvSeverity(v.severity);
    if (vs) s = higher(s, vs);
  }

  if (pkg.securityFindings?.delta.length) {
    const { old: oldF, new: newF, delta } = pkg.securityFindings;
    const oldCount = countByLabel(oldF);
    const newCount = countByLabel(newF);
    for (const f of delta) {
      s = higher(s, effectivePatternSeverity(f.label, oldCount, newCount));
    }
  }

  for (const f of pkg.binaryFindings?.delta ?? []) {
    s = higher(s, binaryFindingSeverity(f.label));
  }
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
