import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { PackageChange } from 'lockdelta';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { PhpAnalyzer } from '../../../src/ecosystems/php/index.js';

/**
 * Integration tests — these make real HTTP requests to Packagist and GitHub.
 * They verify the full analysis pipeline from registry metadata fetch through
 * artifact download, ZIP extraction, and pattern scanning.
 */

const analyzer = new PhpAnalyzer();

let tmpDir: string;

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'lockscan-php-test-'));
});

afterEach(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

const OPTIONS = {
  platforms: [{ os: 'linux' as const, arch: 'x86_64' as const }],
  get tmpDir() {
    return tmpDir;
  },
};

describe('PhpAnalyzer — added', () => {
  it('analyzes a newly added package (psr/log 3.0.0)', async () => {
    const change = {
      name: 'psr/log',
      change_type: 'added',
      old_version: null,
      new_version: '3.0.0',
      is_direct: true,
      is_dev: false,
    } as PackageChange;

    const result = await analyzer.analyzeChange(change, OPTIONS);

    expect(result.name).toBe('psr/log');
    expect(result.changeType).toBe('added');
    expect(result.ecosystem).toBe('php');
    expect(result.newVersion).toBe('3.0.0');
    expect(result.oldVersion).toBeNull();
    // Verify the full pipeline ran: findings structure is populated even if count > 0
    // (psr/log's TestLogger uses call_user_func for matcher callbacks — intentional, not malicious)
    expect(result.securityFindings).toBeDefined();
    expect(result.securityFindings?.old).toHaveLength(0);
    expect(result.securityFindings?.platformDivergence).toBe(false);
    expect(result.registryInfo?.summary).toBeTruthy();
    expect(result.registryInfo?.license).toBeTruthy();
  }, 30_000);
});

describe('PhpAnalyzer — updated', () => {
  it('analyzes an updated package and computes a delta (psr/log 2.0.0 → 3.0.0)', async () => {
    const change = {
      name: 'psr/log',
      change_type: 'updated',
      old_version: '2.0.0',
      new_version: '3.0.0',
      is_direct: true,
      is_dev: false,
    } as PackageChange;

    const result = await analyzer.analyzeChange(change, OPTIONS);

    expect(result.changeType).toBe('updated');
    expect(result.oldVersion).toBe('2.0.0');
    expect(result.newVersion).toBe('3.0.0');
    expect(result.codeDelta).toBeDefined();
    expect(result.metadataDelta).toBeDefined();
    expect(result.verification?.oldArtifacts).toHaveLength(1);
    expect(result.verification?.newArtifacts).toHaveLength(1);
  }, 60_000);
});

describe('PhpAnalyzer — removed', () => {
  it('handles a removed package without network I/O', async () => {
    const change = {
      name: 'psr/log',
      change_type: 'removed',
      old_version: '3.0.0',
      new_version: null,
      is_direct: true,
      is_dev: false,
    } as PackageChange;

    const result = await analyzer.analyzeChange(change, OPTIONS);

    expect(result.changeType).toBe('removed');
    expect(result.oldVersion).toBe('3.0.0');
    expect(result.newVersion).toBeNull();
    // removed packages are not downloaded — no security findings
    expect(result.securityFindings).toBeUndefined();
  });
});

describe('PhpAnalyzer — registry check', () => {
  it('flags a package moving from private Satis to Packagist', async () => {
    const change = {
      name: 'psr/log',
      change_type: 'updated',
      old_version: '2.0.0',
      new_version: '3.0.0',
      is_direct: true,
      is_dev: false,
      old_registry_url: 'https://satis.internal.example.com/dist/psr-log-2.0.0.zip',
      new_registry_url: 'https://api.github.com/repos/php-fig/log/zipball/3.0.0',
    } as PackageChange;

    const result = await analyzer.analyzeChange(change, OPTIONS);

    expect(result.registryCheck).toBeDefined();
    expect(result.registryCheck?.registryChanged).toBe(true);
    expect(result.registryCheck?.confusionReasons.length).toBeGreaterThan(0);
  }, 60_000);
});
