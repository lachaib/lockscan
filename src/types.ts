import type { Platform } from './platforms.js';

export type { Platform } from './platforms.js';
export type ChangeType = 'added' | 'removed' | 'updated';

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
}

export interface SecurityFinding {
  file: string;
  line: number;
  label: string;
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
  installHooks?: InstallHook[];
  registryCheck?: RegistryCheck;
  codebaseUsage?: string[];
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
    ecosystems: string[];
  };
  lockfiles: LockfileAnalysis[];
}
