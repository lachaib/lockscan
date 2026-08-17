import type { PackageChange } from 'lockdelta';
import type { RegistryCheck, RepoCheck } from '../../types.js';

const PUBLIC_REGISTRY_PREFIXES = [
  'https://registry.npmjs.org',
  'https://pypi.org',
  'https://pypi.python.org',
  'https://files.pythonhosted.org',
  'https://upload.pypi.org',
  // Packagist (PHP) distributes packages via GitHub zipballs
  'https://api.github.com',
  'https://codeload.github.com',
];

function isPublic(url?: string): boolean {
  return url !== undefined && PUBLIC_REGISTRY_PREFIXES.some((p) => url.startsWith(p));
}

function isPrivate(url?: string): boolean {
  return url !== undefined && !isPublic(url);
}

/** Parses a semver-ish version string and returns the numeric parts. */
function parseVersion(version: string): [number, number, number] {
  const clean = version.replace(/^[^0-9]*/, '');
  const [a, b, c] = clean.split(/[.\-+]/).map(Number);
  return [a ?? 0, b ?? 0, c ?? 0];
}

interface ConfusionSignals {
  reasons: string[];
  /** Weak, version-number-only pattern — needs corroboration, see `RegistryCheck.versionShapeSuspicious`. */
  versionShapeSuspicious: boolean;
  /** Strong, provenance-based pattern (actual registry move) — suspicious on its own. */
  registryAnomaly: boolean;
}

function confusionHeuristics(
  version: string,
  changeType: string,
  reg: Pick<PackageChange, 'old_registry_url' | 'new_registry_url'>,
): ConfusionSignals {
  const reasons: string[] = [];
  const [major, minor, patch] = parseVersion(version);
  let versionShapeSuspicious = false;
  let registryAnomaly = false;

  // Version-number-only patterns match classic dependency-confusion uploads (attackers
  // often publish a comically high version to win npm/pip's "highest version wins"
  // resolution), but legitimate projects also ship big round major bumps — semver-major
  // releases, marketing versions, etc. On their own these are a weak signal; they only
  // become meaningful when corroborated by an actual registry change or a source repo
  // release tag going missing (see `checkRegistry`/`reconcileConfusionSignal`).
  if (major >= 100) {
    versionShapeSuspicious = true;
    reasons.push(
      `suspiciously high major version (${version}) — classic dependency confusion pattern (weak signal unless corroborated)`,
    );
  } else if (major > 9 && minor === 0 && patch === 0) {
    versionShapeSuspicious = true;
    reasons.push(
      `round high version (${version}) with no minor/patch — possible confusion attempt (weak signal unless corroborated)`,
    );
  }

  // Package moved from a private registry to a public one — a genuine change in
  // provenance, and a strong signal on its own.
  if (isPrivate(reg.old_registry_url) && isPublic(reg.new_registry_url)) {
    registryAnomaly = true;
    reasons.push(
      `registry moved from private (${reg.old_registry_url}) to public (${reg.new_registry_url})`,
    );
  }

  // Newly added from a public registry with no prior (private) history. On its own this
  // just describes an ordinary first-time dependency addition — many legitimate packages
  // sit at major version >= 10 — so it's also a weak, version-shape-gated signal.
  if (changeType === 'added' && isPublic(reg.new_registry_url) && !reg.old_registry_url) {
    if (major >= 10) {
      versionShapeSuspicious = true;
      reasons.push(
        `package added directly from public registry with an unusually high version (${version}) (weak signal unless corroborated)`,
      );
    }
  }

  return { reasons, versionShapeSuspicious, registryAnomaly };
}

export function checkRegistry(
  change: Pick<
    PackageChange,
    'name' | 'change_type' | 'new_version' | 'old_registry_url' | 'new_registry_url'
  >,
): RegistryCheck | undefined {
  const { old_registry_url, new_registry_url, new_version } = change;

  // Nothing to check without at least one registry URL
  if (!old_registry_url && !new_registry_url) return undefined;

  const registryChanged =
    old_registry_url !== undefined &&
    new_registry_url !== undefined &&
    old_registry_url !== new_registry_url;

  const {
    reasons: confusionReasons,
    versionShapeSuspicious,
    registryAnomaly,
  } = new_version
    ? confusionHeuristics(new_version, change.change_type, change)
    : { reasons: [], versionShapeSuspicious: false, registryAnomaly: false };

  if (!registryChanged && confusionReasons.length === 0) return undefined;

  return {
    oldRegistry: old_registry_url,
    newRegistry: new_registry_url,
    registryChanged,
    // Only the strong, provenance-based signal stands on its own here. A weak
    // version-shape signal is reconciled against corroborating evidence (registry
    // change / dropped release tag) by `reconcileConfusionSignal` once the repo
    // check has run — see that function for the combined rule.
    potentialConfusion: registryAnomaly,
    confusionReasons,
    versionShapeSuspicious,
  };
}

/**
 * Reconciles a weak, version-shape-only confusion signal against corroborating evidence
 * before treating it as an actual dependency-confusion finding.
 *
 * A round/high version number alone (e.g. `50.0.0`) is not a reliable indicator by
 * itself — it becomes meaningful only when paired with a registry change or a version
 * that has no matching release tag in the package's source repository. Strong,
 * provenance-based signals (private → public registry move) already set
 * `potentialConfusion` and pass through unchanged.
 */
export function reconcileConfusionSignal(
  registryCheck: RegistryCheck | undefined,
  repoCheck: RepoCheck | undefined,
): RegistryCheck | undefined {
  if (!registryCheck) return registryCheck;
  if (registryCheck.potentialConfusion || !registryCheck.versionShapeSuspicious) {
    return registryCheck;
  }

  const corroborated = registryCheck.registryChanged || !!repoCheck?.releaseDropped;
  if (!corroborated) return registryCheck;

  return { ...registryCheck, potentialConfusion: true };
}
