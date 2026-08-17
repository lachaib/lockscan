import type { PackageChange } from 'lockdelta';
import { describe, expect, it } from 'vitest';
import {
  checkRegistry,
  reconcileConfusionSignal,
} from '../../../src/ecosystems/shared/registry-check.js';
import { packageMaxSeverity } from '../../../src/github/severity.js';
import type { PackageAnalysis, RepoCheck } from '../../../src/types.js';

function change(overrides: Partial<PackageChange>): PackageChange {
  return {
    name: 'some-package',
    change_type: 'updated',
    old_version: '41.0.7',
    new_version: '41.0.7',
    is_direct: true,
    is_dev: false,
    ...overrides,
  } as PackageChange;
}

function pkg(overrides: Partial<PackageAnalysis>): PackageAnalysis {
  return {
    name: 'some-package',
    changeType: 'updated',
    oldVersion: '41.0.7',
    newVersion: '50.0.0',
    isDirect: true,
    isDev: false,
    ecosystem: 'python',
    ...overrides,
  };
}

// lockdelta normalizes old_registry_url/new_registry_url down to the registry's
// *origin* (scheme+host) before handing us a PackageChange — never a full per-version
// tarball URL — so a same-registry bump always carries an identical origin on both sides.
const PYPI_ORIGIN = 'https://files.pythonhosted.org';
const NPM_ORIGIN = 'https://registry.npmjs.org';
const PRIVATE_ORIGIN = 'https://satis.internal.example.com';

describe('checkRegistry — round version number alone', () => {
  it('does NOT set potentialConfusion for a same-registry round major bump (cryptography 41.x -> 50.0.0)', () => {
    // Same registry origin on both sides — no source/registry change at all.
    const result = checkRegistry(
      change({
        old_version: '41.0.7',
        new_version: '50.0.0',
        old_registry_url: PYPI_ORIGIN,
        new_registry_url: PYPI_ORIGIN,
      }),
    );

    expect(result).toBeDefined();
    expect(result?.registryChanged).toBe(false);
    expect(result?.versionShapeSuspicious).toBe(true);
    // Reported for visibility, but must not stand alone as a confusion verdict.
    expect(result?.confusionReasons.length).toBeGreaterThan(0);
    expect(result?.potentialConfusion).toBe(false);
  });

  it('still flags suspiciously high (>=100) versions as version-shape suspicious, not standalone confusion', () => {
    const result = checkRegistry(
      change({
        new_version: '100.0.0',
        old_registry_url: NPM_ORIGIN,
        new_registry_url: NPM_ORIGIN,
      }),
    );

    expect(result?.versionShapeSuspicious).toBe(true);
    expect(result?.potentialConfusion).toBe(false);
  });

  it('leaves ordinary versions untouched', () => {
    const result = checkRegistry(
      change({
        old_version: '1.2.3',
        new_version: '1.3.0',
        old_registry_url: NPM_ORIGIN,
        new_registry_url: NPM_ORIGIN,
      }),
    );

    expect(result).toBeUndefined();
  });
});

describe('checkRegistry — registry/provenance anomalies stand on their own', () => {
  it('flags a private -> public registry move as potentialConfusion regardless of version shape', () => {
    const result = checkRegistry(
      change({
        old_version: '1.2.3',
        new_version: '1.2.4',
        old_registry_url: PRIVATE_ORIGIN,
        new_registry_url: NPM_ORIGIN,
      }),
    );

    expect(result?.registryChanged).toBe(true);
    expect(result?.potentialConfusion).toBe(true);
  });
});

describe('reconcileConfusionSignal', () => {
  it('promotes a version-shape signal to potentialConfusion when the registry also changed', () => {
    const registryCheck = checkRegistry(
      change({
        old_version: '9.0.0',
        new_version: '50.0.0',
        old_registry_url: PRIVATE_ORIGIN,
        new_registry_url: NPM_ORIGIN,
      }),
    );
    expect(registryCheck?.versionShapeSuspicious).toBe(true);
    // Already true because of the registry move itself; reconciliation is a no-op here.
    expect(registryCheck?.potentialConfusion).toBe(true);

    const reconciled = reconcileConfusionSignal(registryCheck, undefined);
    expect(reconciled?.potentialConfusion).toBe(true);
  });

  it('promotes a version-shape signal to potentialConfusion when the source repo release tag is missing', () => {
    const registryCheck = checkRegistry(
      change({
        old_version: '41.0.7',
        new_version: '50.0.0',
        old_registry_url: PYPI_ORIGIN,
        new_registry_url: PYPI_ORIGIN,
      }),
    );
    expect(registryCheck?.potentialConfusion).toBe(false);

    const repoCheck: RepoCheck = {
      repoUrl: 'https://github.com/pyca/cryptography',
      oldRelease: { found: true, tag: '41.0.7' },
      newRelease: { found: false },
      releaseDropped: true,
    };

    const reconciled = reconcileConfusionSignal(registryCheck, repoCheck);
    expect(reconciled?.potentialConfusion).toBe(true);
  });

  it('leaves the signal uncorroborated when the matching tag exists and the registry did not change', () => {
    const registryCheck = checkRegistry(
      change({
        old_version: '41.0.7',
        new_version: '50.0.0',
        old_registry_url: PYPI_ORIGIN,
        new_registry_url: PYPI_ORIGIN,
      }),
    );

    const repoCheck: RepoCheck = {
      repoUrl: 'https://github.com/pyca/cryptography',
      oldRelease: { found: true, tag: '41.0.7' },
      newRelease: { found: true, tag: '50.0.0' },
      releaseDropped: false,
    };

    const reconciled = reconcileConfusionSignal(registryCheck, repoCheck);
    expect(reconciled?.potentialConfusion).toBe(false);
    expect(reconciled?.versionShapeSuspicious).toBe(true);
  });

  it('is a no-op when there is no registryCheck', () => {
    expect(reconcileConfusionSignal(undefined, undefined)).toBeUndefined();
  });
});

describe('packageMaxSeverity — round version number severity', () => {
  it('does not escalate to critical for an uncorroborated round version bump', () => {
    const analysis = pkg({
      registryCheck: {
        registryChanged: false,
        potentialConfusion: false,
        versionShapeSuspicious: true,
        confusionReasons: ['round high version (50.0.0) with no minor/patch'],
      },
    });

    expect(packageMaxSeverity(analysis)).toBe('low');
  });

  it('escalates to critical once corroborated by a dropped release tag', () => {
    const analysis = pkg({
      registryCheck: {
        registryChanged: false,
        potentialConfusion: true,
        versionShapeSuspicious: true,
        confusionReasons: ['round high version (50.0.0) with no minor/patch'],
      },
      repoCheck: {
        repoUrl: 'https://github.com/pyca/cryptography',
        newRelease: { found: false },
        releaseDropped: true,
      },
    });

    expect(packageMaxSeverity(analysis)).toBe('critical');
  });

  it('still treats a private -> public registry move as critical on its own', () => {
    const analysis = pkg({
      registryCheck: {
        registryChanged: true,
        potentialConfusion: true,
        versionShapeSuspicious: false,
        confusionReasons: ['registry moved from private to public'],
      },
    });

    expect(packageMaxSeverity(analysis)).toBe('critical');
  });
});
