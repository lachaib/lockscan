import { join } from 'node:path';
import type { PackageChange } from 'lockdelta';
import type { PackageAnalysis, SecurityFinding } from '../../types.js';
import {
  extractTarball,
  extractZip,
  extractZipBinaries,
  type FileMap,
} from '../../utils/extract.js';
import type { AnalysisOptions, EcosystemAnalyzer } from '../base.js';
import { diffFiles } from '../shared/diff.js';
import { annotateHooks, detectPythonWheelHooks } from '../shared/install-hooks.js';
import { checkRegistry } from '../shared/registry-check.js';
import { checkRepoRelease } from '../shared/repo-check.js';
import { findingsDelta, scanPatterns } from '../shared/scan.js';
import { type BinaryScan, binaryFindingsDelta, scanBinary } from './binary-scan.js';
import { DANGEROUS_PATTERNS, PY_EXTENSIONS } from './patterns.js';
import {
  computeMetadataDelta,
  downloadAndVerify,
  extractRegistryInfo,
  extractRepoUrl,
  fetchPyPI,
  type PyPIArtifact,
  selectArtifacts,
} from './pypi.js';

interface WheelScan {
  artifact: PyPIArtifact;
  files: FileMap;
  findings: SecurityFinding[];
  binaryScans: Map<string, BinaryScan>;
}

async function scanArtifacts(
  artifacts: PyPIArtifact[],
  tmpDir: string,
  tag: string,
): Promise<WheelScan[]> {
  return Promise.all(
    artifacts.map(async (artifact) => {
      const data = await downloadAndVerify(artifact);
      let files: FileMap;
      let binaryScans: Map<string, BinaryScan>;
      if (artifact.isSdist) {
        files = await extractTarball(
          data,
          join(tmpDir, `${tag}_${artifact.sha256.slice(0, 8)}`),
          PY_EXTENSIONS,
        );
        binaryScans = new Map();
      } else {
        files = extractZip(data, PY_EXTENSIONS);
        const binaries = extractZipBinaries(data);
        binaryScans = new Map(
          [...binaries.entries()].map(([name, buf]) => [name, scanBinary(name, buf)]),
        );
      }
      return { artifact, files, findings: scanPatterns(files, DANGEROUS_PATTERNS), binaryScans };
    }),
  );
}

function mergeBinaryScans(scans: WheelScan[]): Map<string, BinaryScan> {
  const merged = new Map<string, BinaryScan>();
  for (const { binaryScans } of scans) {
    for (const [filename, scan] of binaryScans) {
      if (!merged.has(filename)) merged.set(filename, scan);
    }
  }
  return merged;
}

/** True when different wheels for the same version carry different security findings. */
function hasPlatformDivergence(scans: WheelScan[]): boolean {
  if (scans.length <= 1) return false;
  const labelSets = scans.map((s) => new Set(s.findings.map((f) => `${f.file}\0${f.label}`)));
  for (let i = 0; i < labelSets.length; i++) {
    for (let j = i + 1; j < labelSets.length; j++) {
      for (const item of labelSets[i]) if (!labelSets[j].has(item)) return true;
      for (const item of labelSets[j]) if (!labelSets[i].has(item)) return true;
    }
  }
  return false;
}

function unionFindings(scans: WheelScan[]): SecurityFinding[] {
  const seen = new Set<string>();
  const result: SecurityFinding[] = [];
  for (const { findings } of scans) {
    for (const f of findings) {
      const key = `${f.file}\0${f.line}\0${f.label}`;
      if (!seen.has(key)) {
        seen.add(key);
        result.push(f);
      }
    }
  }
  return result;
}

/** Build system files whose modification is a signal for XZ-style build-time injection. */
const BUILD_SYSTEM_BASENAMES = new Set([
  'setup.py',
  'setup.cfg',
  'pyproject.toml',
  'CMakeLists.txt',
  'configure.ac',
  'configure.in',
  'Makefile.am',
  'Makefile.in',
]);

function basename(path: string): string {
  return path.split(/[/\\]/).pop() ?? path;
}

function checkBuildSystemFiles(oldFiles: FileMap, newFiles: FileMap): boolean {
  for (const [path, content] of newFiles) {
    if (!BUILD_SYSTEM_BASENAMES.has(basename(path))) continue;
    const oldContent = oldFiles.get(path);
    if (oldContent === undefined || oldContent !== content) return true;
  }
  for (const path of oldFiles.keys()) {
    if (BUILD_SYSTEM_BASENAMES.has(basename(path)) && !newFiles.has(path)) return true;
  }
  return false;
}

function deriveFindings(scans: WheelScan[]) {
  return {
    findings: unionFindings(scans),
    platformDivergence: hasPlatformDivergence(scans),
    binaries: mergeBinaryScans(scans),
    hooks: detectPythonWheelHooks(scans[0]?.files ?? new Map()),
  };
}

export class PythonAnalyzer implements EcosystemAnalyzer {
  readonly ecosystem = 'python';

  async analyzeChange(change: PackageChange, options: AnalysisOptions): Promise<PackageAnalysis> {
    const { name, change_type, old_version, new_version, is_direct, is_dev } = change;
    const { platforms, tmpDir } = options;
    const base = {
      name,
      changeType: change_type,
      isDirect: is_direct,
      isDev: is_dev,
      ecosystem: this.ecosystem,
    } as const;

    const registryCheck = checkRegistry(change);

    if (change_type === 'removed') {
      return {
        ...base,
        oldVersion: old_version,
        newVersion: null,
        ...(registryCheck && { registryCheck }),
      };
    }

    if (change_type === 'added') {
      const newMeta = await fetchPyPI(name, new_version!);
      const newArtifacts = selectArtifacts(newMeta, platforms);

      if (newArtifacts.length === 0) {
        return {
          ...base,
          oldVersion: null,
          newVersion: new_version,
          error: 'no downloadable artifact found on PyPI for the given platform(s)',
          ...(registryCheck && { registryCheck }),
        };
      }

      const repoUrl = extractRepoUrl(newMeta);

      // artifact scanning and repo check are independent network I/O
      const [newScans, repoCheck] = await Promise.all([
        scanArtifacts(newArtifacts, tmpDir, `${name}_${new_version}_new`),
        checkRepoRelease({ repoUrl, packageName: name, oldVersion: null, newVersion: new_version }),
      ]);

      const { findings, platformDivergence, binaries, hooks } = deriveFindings(newScans);
      const binaryDelta = binaryFindingsDelta(new Map(), binaries);

      return {
        ...base,
        oldVersion: null,
        newVersion: new_version,
        verification: { platforms, oldArtifacts: [], newArtifacts },
        registryInfo: extractRegistryInfo(newMeta),
        securityFindings: { old: [], new: findings, delta: findings, platformDivergence },
        ...(binaryDelta.length > 0 && { binaryFindings: { delta: binaryDelta } }),
        ...(hooks.length > 0 && { installHooks: hooks.map((h) => ({ ...h, isNew: true })) }),
        ...(repoCheck && { repoCheck }),
        ...(registryCheck && { registryCheck }),
      };
    }

    // updated — fetch both registry metas in parallel, then scan both artifact sets
    // and run the repo check all concurrently
    const [newMeta, oldMeta] = await Promise.all([
      fetchPyPI(name, new_version!),
      fetchPyPI(name, old_version!),
    ]);

    const newArtifacts = selectArtifacts(newMeta, platforms);
    const oldArtifacts = selectArtifacts(oldMeta, platforms);
    const repoUrl = extractRepoUrl(newMeta);

    if (newArtifacts.length === 0) {
      return {
        ...base,
        oldVersion: old_version,
        newVersion: new_version,
        error: 'no downloadable artifact found on PyPI for the given platform(s)',
        ...(registryCheck && { registryCheck }),
      };
    }

    if (oldArtifacts.length === 0) {
      const [newScans, repoCheck] = await Promise.all([
        scanArtifacts(newArtifacts, tmpDir, `${name}_${new_version}_new`),
        checkRepoRelease({
          repoUrl,
          packageName: name,
          oldVersion: old_version,
          newVersion: new_version,
        }),
      ]);

      const { findings, platformDivergence, binaries, hooks } = deriveFindings(newScans);
      const binaryDelta = binaryFindingsDelta(new Map(), binaries);

      return {
        ...base,
        oldVersion: old_version,
        newVersion: new_version,
        verification: { platforms, oldArtifacts: [], newArtifacts },
        securityFindings: { old: [], new: findings, delta: findings, platformDivergence },
        ...(binaryDelta.length > 0 && { binaryFindings: { delta: binaryDelta } }),
        ...(hooks.length > 0 && { installHooks: hooks.map((h) => ({ ...h, isNew: true })) }),
        ...(repoCheck && { repoCheck }),
        ...(registryCheck && { registryCheck }),
        error: `old version ${old_version} has no artifact for the given platform(s) — diff skipped`,
      };
    }

    // both versions have artifacts — scan old, scan new, and check repo all at once
    const [newScans, oldScans, repoCheck] = await Promise.all([
      scanArtifacts(newArtifacts, tmpDir, `${name}_${new_version}_new`),
      scanArtifacts(oldArtifacts, tmpDir, `${name}_${old_version}_old`),
      checkRepoRelease({
        repoUrl,
        packageName: name,
        oldVersion: old_version,
        newVersion: new_version,
      }),
    ]);

    const newDerived = deriveFindings(newScans);
    const oldDerived = deriveFindings(oldScans);
    const binaryDelta = binaryFindingsDelta(oldDerived.binaries, newDerived.binaries);
    const annotated = annotateHooks(oldDerived.hooks, newDerived.hooks);

    const buildSystemChanged = checkBuildSystemFiles(oldScans[0].files, newScans[0].files);
    const newBinaryWheels =
      oldArtifacts.every((a) => a.isSdist) && newArtifacts.some((a) => !a.isSdist);
    const baseDelta = computeMetadataDelta(oldMeta, newMeta);
    const metadataDelta = {
      ...baseDelta,
      ...(buildSystemChanged && { buildSystemChanged }),
      ...(newBinaryWheels && { newBinaryWheels }),
    };

    return {
      ...base,
      oldVersion: old_version,
      newVersion: new_version,
      verification: { platforms, oldArtifacts, newArtifacts },
      metadataDelta,
      codeDelta: diffFiles(oldScans[0].files, newScans[0].files),
      securityFindings: {
        old: oldDerived.findings,
        new: newDerived.findings,
        delta: findingsDelta(oldDerived.findings, newDerived.findings),
        platformDivergence: newDerived.platformDivergence,
      },
      ...(binaryDelta.length > 0 && { binaryFindings: { delta: binaryDelta } }),
      ...(annotated.length > 0 && { installHooks: annotated }),
      ...(repoCheck && { repoCheck }),
      ...(registryCheck && { registryCheck }),
    };
  }
}
