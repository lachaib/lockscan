import { join } from 'node:path';
import type { PackageChange } from 'lockdelta';
import type { PackageAnalysis } from '../../types.js';
import { extractTarball } from '../../utils/extract.js';
import type { AnalysisOptions, EcosystemAnalyzer } from '../base.js';
import {
  computeMetadataDelta,
  downloadNpmTarball,
  extractRegistryInfo,
  extractRepoUrl,
  fetchNpmVersion,
  getArtifactInfo,
} from '../javascript/npm.js';
import { diffFiles } from '../shared/diff.js';
import { annotateHooks, detectNpmHooks } from '../shared/install-hooks.js';
import { checkRegistry } from '../shared/registry-check.js';
import { checkRepoRelease } from '../shared/repo-check.js';
import { findingsDelta, scanPatterns } from '../shared/scan.js';
import {
  computeJsrMetadataDelta,
  extractJsrRegistryInfo,
  fetchJsrVersion,
  resolveJsrRepoUrl,
} from './jsr.js';
import { DANGEROUS_PATTERNS, JSR_EXTENSIONS, NPM_EXTENSIONS } from './patterns.js';

export class DenoAnalyzer implements EcosystemAnalyzer {
  readonly ecosystem = 'deno';

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

    if (name.startsWith('jsr:')) {
      return this.analyzeJsr(
        base,
        name.slice(4),
        change_type,
        old_version,
        new_version,
        options,
        registryCheck,
      );
    }
    return this.analyzeNpm(
      base,
      name,
      change_type,
      old_version,
      new_version,
      options,
      registryCheck,
    );
  }

  // ─── npm: packages ───────────────────────────────────────────────────────────
  // Treated identically to the JS ecosystem: same npm registry, same tarball
  // format, same install hook model. We extend the pattern set with Deno-native
  // APIs so packages that bridge Node.js and Deno are fully covered.

  private async analyzeNpm(
    base: {
      name: string;
      changeType: PackageChange['change_type'];
      isDirect: boolean;
      isDev: boolean;
      ecosystem: 'deno';
    },
    name: string,
    changeType: PackageChange['change_type'],
    oldVersion: string | null | undefined,
    newVersion: string | null | undefined,
    options: AnalysisOptions,
    registryCheck: ReturnType<typeof checkRegistry>,
  ): Promise<PackageAnalysis> {
    const safeName = name.replace(/\//g, '__');

    const download = (version: string, slot: string) => (url: string) =>
      downloadNpmTarball(url).then((data) =>
        extractTarball(
          data,
          join(options.tmpDir, `deno_npm_${safeName}_${version}_${slot}`),
          NPM_EXTENSIONS,
        ),
      );

    if (changeType === 'removed') {
      return {
        ...base,
        oldVersion: oldVersion ?? null,
        newVersion: null,
        ...(registryCheck && { registryCheck }),
      };
    }

    if (changeType === 'added') {
      const newMeta = await fetchNpmVersion(name, newVersion!);
      const newArtifact = getArtifactInfo(newMeta);
      const repoUrl = extractRepoUrl(newMeta);

      const [newFiles, registryInfo, repoCheck] = await Promise.all([
        download(newVersion!, 'new')(newArtifact.url),
        extractRegistryInfo(newMeta),
        checkRepoRelease({ repoUrl, packageName: name, oldVersion: null, newVersion }),
      ]);

      const newFindings = scanPatterns(newFiles, DANGEROUS_PATTERNS);
      const newHooks = detectNpmHooks(newFiles);

      return {
        ...base,
        oldVersion: null,
        newVersion: newVersion!,
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
        ...(newHooks.length > 0 && { installHooks: newHooks.map((h) => ({ ...h, isNew: true })) }),
        ...(repoCheck && { repoCheck }),
        ...(registryCheck && { registryCheck }),
      };
    }

    // updated
    const [newMeta, oldMeta] = await Promise.all([
      fetchNpmVersion(name, newVersion!),
      fetchNpmVersion(name, oldVersion!),
    ]);
    const newArtifact = getArtifactInfo(newMeta);
    const oldArtifact = getArtifactInfo(oldMeta);
    const repoUrl = extractRepoUrl(newMeta);

    const [newFiles, oldFiles, repoCheck] = await Promise.all([
      download(newVersion!, 'new')(newArtifact.url),
      download(oldVersion!, 'old')(oldArtifact.url),
      checkRepoRelease({ repoUrl, packageName: name, oldVersion, newVersion }),
    ]);

    const newFindings = scanPatterns(newFiles, DANGEROUS_PATTERNS);
    const oldFindings = scanPatterns(oldFiles, DANGEROUS_PATTERNS);
    const annotated = annotateHooks(detectNpmHooks(oldFiles), detectNpmHooks(newFiles));
    const metadataDelta = computeMetadataDelta(oldMeta, newMeta);

    return {
      ...base,
      oldVersion: oldVersion!,
      newVersion: newVersion!,
      verification: {
        platforms: options.platforms,
        oldArtifacts: [oldArtifact],
        newArtifacts: [newArtifact],
      },
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

  // ─── jsr: packages ───────────────────────────────────────────────────────────
  // JSR packages are pure TypeScript source distributed via an npm compatibility
  // layer at npm.jsr.io. They cannot have install scripts (forbidden by JSR) and
  // do not ship native binaries, so those checks are omitted.

  private async analyzeJsr(
    base: {
      name: string;
      changeType: PackageChange['change_type'];
      isDirect: boolean;
      isDev: boolean;
      ecosystem: 'deno';
    },
    jsrName: string,
    changeType: PackageChange['change_type'],
    oldVersion: string | null | undefined,
    newVersion: string | null | undefined,
    options: AnalysisOptions,
    registryCheck: ReturnType<typeof checkRegistry>,
  ): Promise<PackageAnalysis> {
    const safeName = jsrName.replace(/[/:@]/g, '_');

    const download = (version: string, slot: string) => async () => {
      const meta = await fetchJsrVersion(jsrName, version);
      const artifact = getArtifactInfo(meta);
      const data = await downloadNpmTarball(artifact.url);
      return {
        files: await extractTarball(
          data,
          join(options.tmpDir, `deno_jsr_${safeName}_${version}_${slot}`),
          JSR_EXTENSIONS,
        ),
        meta,
        artifact,
      };
    };

    if (changeType === 'removed') {
      return {
        ...base,
        oldVersion: oldVersion ?? null,
        newVersion: null,
        ...(registryCheck && { registryCheck }),
      };
    }

    if (changeType === 'added') {
      const {
        files: newFiles,
        meta: newMeta,
        artifact: newArtifact,
      } = await download(newVersion!, 'new')();
      const [repoUrl, registryInfo] = await Promise.all([
        resolveJsrRepoUrl(jsrName, newMeta),
        extractJsrRegistryInfo(jsrName, newMeta),
      ]);

      const [repoCheck] = await Promise.all([
        checkRepoRelease({ repoUrl, packageName: jsrName, oldVersion: null, newVersion }),
      ]);

      const newFindings = scanPatterns(newFiles, DANGEROUS_PATTERNS);

      return {
        ...base,
        oldVersion: null,
        newVersion: newVersion!,
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
        ...(repoCheck && { repoCheck }),
        ...(registryCheck && { registryCheck }),
      };
    }

    // updated — download both versions concurrently
    const [newResult, oldResult] = await Promise.all([
      download(newVersion!, 'new')(),
      download(oldVersion!, 'old')(),
    ]);
    const { files: newFiles, meta: newMeta, artifact: newArtifact } = newResult;
    const { files: oldFiles, meta: oldMeta, artifact: oldArtifact } = oldResult;

    const repoUrl = await resolveJsrRepoUrl(jsrName, newMeta);
    const repoCheck = await checkRepoRelease({
      repoUrl,
      packageName: jsrName,
      oldVersion,
      newVersion,
    });

    const newFindings = scanPatterns(newFiles, DANGEROUS_PATTERNS);
    const oldFindings = scanPatterns(oldFiles, DANGEROUS_PATTERNS);
    const jsrDelta = computeJsrMetadataDelta(oldMeta, newMeta);

    return {
      ...base,
      oldVersion: oldVersion!,
      newVersion: newVersion!,
      verification: {
        platforms: options.platforms,
        oldArtifacts: [oldArtifact],
        newArtifacts: [newArtifact],
      },
      metadataDelta: {
        authorChanged: false,
        depsAdded: [],
        depsRemoved: [],
        ...jsrDelta,
      },
      codeDelta: diffFiles(oldFiles, newFiles),
      securityFindings: {
        old: oldFindings,
        new: newFindings,
        delta: findingsDelta(oldFindings, newFindings),
        platformDivergence: false,
      },
      ...(repoCheck && { repoCheck }),
      ...(registryCheck && { registryCheck }),
    };
  }
}
