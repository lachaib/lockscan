import type { PackageChange } from 'lockdelta';
import type { PackageAnalysis } from '../../types.js';
import type { FileMap } from '../../utils/extract.js';
import { extractZip } from '../../utils/extract.js';
import type { AnalysisOptions, EcosystemAnalyzer } from '../base.js';
import { diffFiles } from '../shared/diff.js';
import { annotateHooks, detectComposerHooks } from '../shared/install-hooks.js';
import { checkRegistry } from '../shared/registry-check.js';
import { checkRepoRelease } from '../shared/repo-check.js';
import { findingsDelta, scanPatterns } from '../shared/scan.js';
import {
  computeMetadataDelta,
  downloadArtifact,
  extractRegistryInfo,
  extractRepoUrl,
  fetchPackagistWithVersions,
  getArtifactInfo,
} from './packagist.js';
import { DANGEROUS_PATTERNS, PHP_EXTENSIONS } from './patterns.js';

/**
 * GitHub zipball archives include a top-level directory named `vendor-package-sha/`.
 * Strip it so that paths are comparable across old and new versions.
 */
function stripTopLevel(files: FileMap): FileMap {
  const result: FileMap = new Map();
  for (const [path, content] of files) {
    const slash = path.indexOf('/');
    const stripped = slash >= 0 ? path.slice(slash + 1) : path;
    if (stripped) result.set(stripped, content);
  }
  return result;
}

async function fetchAndExtract(name: string, version: string): Promise<FileMap> {
  const { meta } = await fetchPackagistWithVersions(name, version);
  const artifact = getArtifactInfo(meta);
  if (!artifact) throw new Error(`No downloadable artifact for ${name}@${version} on Packagist`);
  const data = await downloadArtifact(artifact.url);
  return stripTopLevel(extractZip(data, PHP_EXTENSIONS));
}

export class PhpAnalyzer implements EcosystemAnalyzer {
  readonly ecosystem = 'php';

  async analyzeChange(change: PackageChange, options: AnalysisOptions): Promise<PackageAnalysis> {
    const { name, change_type, old_version, new_version, is_direct, is_dev } = change;
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
      const { meta: newMeta, allVersions } = await fetchPackagistWithVersions(name, new_version!);
      const artifact = getArtifactInfo(newMeta);
      const repoUrl = extractRepoUrl(newMeta);

      if (!artifact) {
        return {
          ...base,
          oldVersion: null,
          newVersion: new_version,
          error: 'no downloadable artifact found on Packagist',
          ...(registryCheck && { registryCheck }),
        };
      }

      const [newFiles, repoCheck] = await Promise.all([
        downloadArtifact(artifact.url).then((data) =>
          stripTopLevel(extractZip(data, PHP_EXTENSIONS)),
        ),
        checkRepoRelease({ repoUrl, packageName: name, oldVersion: null, newVersion: new_version }),
      ]);

      const newFindings = scanPatterns(newFiles, DANGEROUS_PATTERNS);
      const newHooks = detectComposerHooks(newFiles);

      return {
        ...base,
        oldVersion: null,
        newVersion: new_version,
        verification: {
          platforms: options.platforms,
          oldArtifacts: [],
          newArtifacts: [artifact],
        },
        registryInfo: extractRegistryInfo(newMeta, allVersions),
        securityFindings: {
          old: [],
          new: newFindings,
          delta: newFindings,
          platformDivergence: false,
        },
        ...(newHooks.length > 0 && { installHooks: newHooks.map((h) => ({ ...h, isNew: true })) }),
        ...(repoCheck && { repoCheck }),
        ...(registryCheck && { registryCheck }),
      };
    }

    // updated — fetch both versions' metadata, then download+extract and repo check in parallel
    const [newFetched, oldFetched] = await Promise.all([
      fetchPackagistWithVersions(name, new_version!),
      fetchPackagistWithVersions(name, old_version!),
    ]);

    const newArtifact = getArtifactInfo(newFetched.meta);
    const oldArtifact = getArtifactInfo(oldFetched.meta);
    const repoUrl = extractRepoUrl(newFetched.meta);

    if (!newArtifact) {
      return {
        ...base,
        oldVersion: old_version,
        newVersion: new_version,
        error: 'no downloadable artifact found on Packagist for new version',
        ...(registryCheck && { registryCheck }),
      };
    }

    const downloads: Array<Promise<FileMap>> = [
      downloadArtifact(newArtifact.url).then((data) =>
        stripTopLevel(extractZip(data, PHP_EXTENSIONS)),
      ),
    ];

    if (oldArtifact) {
      downloads.push(
        downloadArtifact(oldArtifact.url).then((data) =>
          stripTopLevel(extractZip(data, PHP_EXTENSIONS)),
        ),
      );
    }

    const [newFiles, maybeOldFiles, repoCheck] = await Promise.all([
      downloads[0],
      downloads[1] ?? Promise.resolve(new Map<string, string>()),
      checkRepoRelease({
        repoUrl,
        packageName: name,
        oldVersion: old_version,
        newVersion: new_version,
      }),
    ]);

    const oldFiles = maybeOldFiles;
    const newFindings = scanPatterns(newFiles, DANGEROUS_PATTERNS);
    const oldFindings = scanPatterns(oldFiles, DANGEROUS_PATTERNS);
    const annotated = annotateHooks(detectComposerHooks(oldFiles), detectComposerHooks(newFiles));
    const metadataDelta = computeMetadataDelta(oldFetched.meta, newFetched.meta);

    return {
      ...base,
      oldVersion: old_version,
      newVersion: new_version,
      verification: {
        platforms: options.platforms,
        oldArtifacts: oldArtifact ? [oldArtifact] : [],
        newArtifacts: [newArtifact],
      },
      registryInfo: extractRegistryInfo(newFetched.meta, newFetched.allVersions),
      metadataDelta,
      codeDelta: diffFiles(oldFiles, newFiles),
      securityFindings: {
        old: oldFindings,
        new: newFindings,
        delta: findingsDelta(oldFindings, newFindings),
        platformDivergence: false,
      },
      ...(annotated.length > 0 && { installHooks: annotated }),
      ...(repoCheck && { repoCheck }),
      ...(registryCheck && { registryCheck }),
    };
  }
}
