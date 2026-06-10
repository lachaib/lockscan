import type { PackageChange } from 'lockdelta';
import type { RegistryCheck } from '../../types.js';

const PUBLIC_REGISTRY_PREFIXES = [
  'https://registry.npmjs.org',
  'https://pypi.org',
  'https://pypi.python.org',
  'https://files.pythonhosted.org',
  'https://upload.pypi.org',
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

function confusionHeuristics(version: string, changeType: string, reg: Pick<PackageChange, 'old_registry_url' | 'new_registry_url'>): string[] {
  const reasons: string[] = [];
  const [major, minor, patch] = parseVersion(version);

  // Classic dependency confusion: attacker publishes with a comically high version
  if (major >= 100) {
    reasons.push(
      `suspiciously high major version (${version}) — classic dependency confusion pattern`,
    );
  } else if (major > 9 && minor === 0 && patch === 0) {
    reasons.push(
      `round high version (${version}) with no minor/patch — possible confusion attempt`,
    );
  }

  // Package moved from a private registry to a public one
  if (isPrivate(reg.old_registry_url) && isPublic(reg.new_registry_url)) {
    reasons.push(
      `registry moved from private (${reg.old_registry_url}) to public (${reg.new_registry_url})`,
    );
  }

  // Newly added from public registry when old packages came from private
  if (changeType === 'added' && isPublic(reg.new_registry_url) && !reg.old_registry_url) {
    // Only flag if the version itself also looks suspicious
    if (major >= 10) {
      reasons.push(
        `package added directly from public registry with an unusually high version (${version})`,
      );
    }
  }

  return reasons;
}

export function checkRegistry(
  change: Pick<PackageChange, 'name' | 'change_type' | 'new_version' | 'old_registry_url' | 'new_registry_url'>,
): RegistryCheck | undefined {
  const { old_registry_url, new_registry_url, new_version } = change;

  // Nothing to check without at least one registry URL
  if (!old_registry_url && !new_registry_url) return undefined;

  const registryChanged =
    old_registry_url !== undefined &&
    new_registry_url !== undefined &&
    old_registry_url !== new_registry_url;

  const confusionReasons = new_version
    ? confusionHeuristics(new_version, change.change_type, change)
    : [];

  if (!registryChanged && confusionReasons.length === 0) return undefined;

  return {
    oldRegistry: old_registry_url,
    newRegistry: new_registry_url,
    registryChanged,
    potentialConfusion: confusionReasons.length > 0,
    confusionReasons,
  };
}
