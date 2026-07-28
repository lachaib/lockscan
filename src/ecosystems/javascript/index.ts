import { join } from 'node:path';
import type { PackageChange } from 'lockdelta';
import type { PackageAnalysis } from '../../types.js';
import type { FileMap } from '../../utils/extract.js';
import { extractTarball, extractTarballBinaries } from '../../utils/extract.js';
import type { AnalysisOptions, EcosystemAnalyzer } from '../base.js';
import { type BinaryScan, binaryFindingsDelta, scanBinary } from '../shared/binary-scan.js';
import { diffFiles } from '../shared/diff.js';
import { findingsDelta, scanPatterns } from '../shared/scan.js';

/** Native add-on build scripts; being added or modified means the package now compiles C/C++. */
const NATIVE_BUILD_FILES = new Set(['binding.gyp', 'binding.gyp.json']);

function checkNpmNativeBuild(oldFiles: FileMap, newFiles: FileMap): boolean {
  for (const name of NATIVE_BUILD_FILES) {
    const wasAbsent = !oldFiles.has(name);
    const nowPresent = newFiles.has(name);
    if (wasAbsent && nowPresent) return true;
    if (!wasAbsent && nowPresent && oldFiles.get(name) !== newFiles.get(name)) return true;
  }
  return false;
}

import { annotateHooks, detectNpmHooks } from '../shared/install-hooks.js';
import { checkRegistry } from '../shared/registry-check.js';
import { checkRepoRelease } from '../shared/repo-check.js';
import {
  computeMetadataDelta,
  downloadNpmTarball,
  extractRegistryInfo,
  extractRepoUrl,
  fetchNpmVersion,
  getArtifactInfo,
} from './npm.js';
import { DANGEROUS_PATTERNS, JS_EXTENSIONS } from './patterns.js';

interface NpmArtifactScan {
  files: FileMap;
  binaryScans: Map<string, BinaryScan>;
}

async function scanNpmArtifact(data: Buffer, destDir: string): Promise<NpmArtifactScan> {
  const files = await extractTarball(data, destDir, JS_EXTENSIONS);
  const binaries = await extractTarballBinaries(destDir);
  const binaryScans = new Map(
    [...binaries.entries()].map(([name, buf]) => [name, scanBinary(name, buf)]),
  );
  return { files, binaryScans };
}

export class JavaScriptAnalyzer implements EcosystemAnalyzer {
  readonly ecosystem = 'javascript';

  async analyzeChange(change: PackageChange, options: AnalysisOptions): Promise<PackageAnalysis> {
    const { name, change_type, old_version, new_version, is_direct, is_dev } = change;
    const base = {
      name,
      changeType: change_type,
      isDirect: is_direct,
      isDev: is_dev,
      ecosystem: this.ecosystem,
    } as const;
    const safeName = name.replace(/\//g, '__');

    const registryCheck = checkRegistry(change);

    if (change_type === 'removed') {
      return {
        ...base,
        oldVersion: old_version,
        newVersion: null,
        ...(registryCheck && { registryCheck }),
      };
    }

    const download = (version: string, slot: string) => (url: string) =>
      downloadNpmTarball(url).then((data) =>
        scanNpmArtifact(data, join(options.tmpDir, `${safeName}_${version}_${slot}`)),
      );

    if (change_type === 'added') {
      const newMeta = await fetchNpmVersion(name, new_version!);
      const newArtifact = getArtifactInfo(newMeta);
      const repoUrl = extractRepoUrl(newMeta);

      // tarball download+extract, registry info, and repo check are all independent network I/O
      const [newScan, registryInfo, repoCheck] = await Promise.all([
        download(new_version!, 'new')(newArtifact.url),
        extractRegistryInfo(newMeta),
        checkRepoRelease({ repoUrl, packageName: name, oldVersion: null, newVersion: new_version }),
      ]);

      const newFindings = scanPatterns(newScan.files, DANGEROUS_PATTERNS);
      const newHooks = detectNpmHooks(newScan.files);
      const binaryDelta = binaryFindingsDelta(new Map(), newScan.binaryScans);

      return {
        ...base,
        oldVersion: null,
        newVersion: new_version,
        verification: {
          platforms: options.platforms,
          oldArtifacts: [],
          newArtifacts: [newArtifact],
        },
        registryInfo,
        securityFindings: {
          old: [],
          new: newFindings,
          delta: newFindings,
          platformDivergence: false,
        },
        ...(binaryDelta.length > 0 && { binaryFindings: { delta: binaryDelta } }),
        ...(newHooks.length > 0 && { installHooks: newHooks.map((h) => ({ ...h, isNew: true })) }),
        ...(repoCheck && { repoCheck }),
        ...(registryCheck && { registryCheck }),
      };
    }

    // updated — fetch both registry metas, then download+extract both tarballs and repo check concurrently
    const [newMeta, oldMeta] = await Promise.all([
      fetchNpmVersion(name, new_version!),
      fetchNpmVersion(name, old_version!),
    ]);

    const newArtifact = getArtifactInfo(newMeta);
    const oldArtifact = getArtifactInfo(oldMeta);
    const repoUrl = extractRepoUrl(newMeta);

    const [newScan, oldScan, repoCheck] = await Promise.all([
      download(new_version!, 'new')(newArtifact.url),
      download(old_version!, 'old')(oldArtifact.url),
      checkRepoRelease({
        repoUrl,
        packageName: name,
        oldVersion: old_version,
        newVersion: new_version,
      }),
    ]);

    const newFindings = scanPatterns(newScan.files, DANGEROUS_PATTERNS);
    const oldFindings = scanPatterns(oldScan.files, DANGEROUS_PATTERNS);
    const annotated = annotateHooks(detectNpmHooks(oldScan.files), detectNpmHooks(newScan.files));
    const binaryDelta = binaryFindingsDelta(oldScan.binaryScans, newScan.binaryScans);

    const buildSystemChanged = checkNpmNativeBuild(oldScan.files, newScan.files);
    const baseDelta = computeMetadataDelta(oldMeta, newMeta);
    const metadataDelta = { ...baseDelta, ...(buildSystemChanged && { buildSystemChanged }) };

    return {
      ...base,
      oldVersion: old_version,
      newVersion: new_version,
      verification: {
        platforms: options.platforms,
        oldArtifacts: [oldArtifact],
        newArtifacts: [newArtifact],
      },
      metadataDelta,
      codeDelta: diffFiles(oldScan.files, newScan.files),
      securityFindings: {
        old: oldFindings,
        new: newFindings,
        delta: findingsDelta(oldFindings, newFindings),
        platformDivergence: false,
      },
      ...(binaryDelta.length > 0 && { binaryFindings: { delta: binaryDelta } }),
      ...(annotated.length > 0 && { installHooks: annotated }),
      ...(repoCheck && { repoCheck }),
      ...(registryCheck && { registryCheck }),
    };
  }
}
