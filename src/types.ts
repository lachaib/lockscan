import type { Platform } from './platforms.js';

export type { Platform } from './platforms.js';
export type ChangeType = 'added' | 'removed' | 'updated';

export type Severity = 'critical' | 'high' | 'moderate' | 'low';

/** A vulnerability record from the OSV database (osv.dev). */
export interface KnownVuln {
  id: string;
  summary: string;
  severity?: string;
  aliases: string[];
  url?: string;
}

/** Result of checking the source repository for a matching release tag. */
export interface RepoCheck {
  repoUrl: string;
  oldRelease?: { found: boolean; tag?: string };
  newRelease?: { found: boolean; tag?: string };
  /** Previous version had a matching release but the current version does not — highly suspect. */
  releaseDropped: boolean;
}

/** A post-install hook found inside the package. */
export interface InstallHook {
  type: 'npm-script' | 'pth-file' | 'data-script' | 'composer-script';
  name: string;
  command?: string;
  isNew: boolean;
  changed: boolean;
}

/** Build provenance of a published version (Sigstore / SLSA attestation, PyPI Trusted Publishing). */
export interface Provenance {
  attested: boolean;
  /** Source repository the attestation binds the build to. */
  source?: string;
  /** Build workflow file inside that repository. */
  workflow?: string;
}

/** A provenance regression between the old and new version of a package. */
export interface ProvenanceCheck {
  old: Provenance;
  new: Provenance;
  /** The previous version was attested; the new one is not. */
  dropped: boolean;
  /** The attested source repository differs between versions. */
  sourceChanged: boolean;
  /** Same repository, but a different build workflow. */
  workflowChanged: boolean;
}

/** Registry-level checks for dependency confusion and registry substitution. */
export interface RegistryCheck {
  oldRegistry?: string;
  newRegistry?: string;
  registryChanged: boolean;
  /**
   * True once a confusion signal is corroborated enough to act on: either the
   * registry/publish trail itself is anomalous (e.g. moved from a private
   * registry to a public one), or a weak version-shape signal (see
   * `versionShapeSuspicious`) is backed by an actual registry change or a
   * missing release tag in the source repository (`RepoCheck.releaseDropped`).
   */
  potentialConfusion: boolean;
  confusionReasons: string[];
  /**
   * True when the new version number alone looks like a classic dependency-confusion
   * pattern (comically high major, or a round major with no minor/patch — e.g.
   * `50.0.0`). Legitimate projects ship big round major bumps too (semver-major
   * releases, marketing versions, …), so this is a weak signal on its own: it does
   * not raise `potentialConfusion` unless corroborated by a registry change or a
   * dropped source release tag.
   */
  versionShapeSuspicious: boolean;
}

export interface BinaryFinding {
  file: string;
  label: string;
  detail: string;
  /** Stable rule id; equals `label` except for `native:<symbol>`, which is `binary:native-symbol`. */
  rule?: string;
  /** Dangerous symbol name, set for `native:<symbol>` findings. */
  symbol?: string;
  severity?: Severity;
}

export interface SecurityFinding {
  file: string;
  line: number;
  label: string;
  /** Extra context, e.g. the target of an archive symlink. */
  detail?: string;
  /** Stable rule id; equals `label`. Set on delta findings. */
  rule?: string;
  /** Severity of this finding in context (family downgrade applied). Set on delta findings. */
  severity?: Severity;
}

export interface ArtifactInfo {
  filename: string;
  url: string;
  sha256: string;
  /** Platforms this artifact was matched to. */
  platforms?: Platform[];
}

export interface RegistryMetadata {
  summary?: string;
  author?: string;
  authorEmail?: string;
  homepage?: string;
  license?: string;
  numReleases?: number;
  firstUpload?: string;
  ageDays?: number;
  /** ISO timestamp of when this specific version was published. */
  versionUpload?: string;
  /** Days since this specific version was published. < 1 is a sniper-pattern risk. */
  versionAgeDays?: number;
  latestVersion?: string;
  requiresDist?: string[];
}

export interface MetadataDelta {
  authorChanged: boolean;
  homepageChanged: boolean;
  depsAdded: string[];
  depsRemoved: string[];
  /** License field changed between versions (e.g. MIT → proprietary). */
  licenseChanged: boolean;
  /** npm only: the account that published the new version differs from the old one. */
  publisherChanged?: boolean;
  /** Build system configuration files were added or modified (XZ-style injection risk). */
  buildSystemChanged?: boolean;
  /** Python only: old version shipped only source distributions; new version includes binary wheels. */
  newBinaryWheels?: boolean;
}

export interface CodeDelta {
  filesAdded: number;
  filesRemoved: number;
  filesChanged: number;
  diff: string;
}

export interface PackageAnalysis {
  name: string;
  changeType: ChangeType;
  oldVersion: string | null;
  newVersion: string | null;
  isDirect: boolean;
  isDev: boolean;
  ecosystem: string;
  verification?: {
    platforms: Platform[];
    oldArtifacts: ArtifactInfo[];
    newArtifacts: ArtifactInfo[];
  };
  registryInfo?: RegistryMetadata;
  metadataDelta?: MetadataDelta;
  codeDelta?: CodeDelta;
  securityFindings?: {
    old: SecurityFinding[];
    new: SecurityFinding[];
    delta: SecurityFinding[];
    /** True when different wheels for the same version have different findings — supply-chain red flag. */
    platformDivergence: boolean;
  };
  binaryFindings?: {
    /** Changes in binary properties between old and new version (symbols, entropy, embedded strings). */
    delta: BinaryFinding[];
  };
  knownVulns?: KnownVuln[];
  repoCheck?: RepoCheck;
  provenanceCheck?: ProvenanceCheck;
  installHooks?: InstallHook[];
  registryCheck?: RegistryCheck;
  codebaseUsage?: string[];
  /** Highest severity across all signals for this package; null when it has none. */
  maxSeverity?: Severity | null;
  error?: string;
}

export interface LockfileAnalysis {
  lockfilePath: string | null;
  workspace: string;
  type: string | null;
  ecosystem: string;
  packages: PackageAnalysis[];
}

export interface SecurityReport {
  schemaVersion: '1';
  generatedAt: string;
  baseRef: string;
  headRef: string;
  summary: {
    analyzed: number;
    errors: number;
    newSecurityFindings: number;
    platformDivergences: number;
    binaryAnomalies: number;
    knownVulns: number;
    releaseDropped: number;
    installHooksAdded: number;
    registryChanges: number;
    freshnessWarnings: number;
    publisherChanges: number;
    licenseChanges: number;
    provenanceRegressions: number;
    /** Highest severity across all packages; null when the report is clean. */
    maxSeverity: Severity | null;
    /** Number of packages at each maximum severity. */
    bySeverity: Record<Severity, number>;
    /** Number of individual delta findings (pattern and binary) at each severity. */
    findingsBySeverity: Record<Severity, number>;
    ecosystems: string[];
  };
  lockfiles: LockfileAnalysis[];
}
