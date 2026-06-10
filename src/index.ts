import type { DiffReport } from 'lockdelta';
import { analyze as runAnalyze } from './core/analyzer.js';
import type { Platform } from './platforms.js';
import type { SecurityReport } from './types.js';

export type { EcosystemAnalyzer } from './ecosystems/index.js';
export { registerAnalyzer } from './ecosystems/index.js';
export type { Platform } from './platforms.js';
export type {
  LockfileAnalysis,
  PackageAnalysis,
  SecurityFinding,
  SecurityReport,
} from './types.js';

export interface AnalyzeOptions {
  /**
   * Platforms to analyze wheels against. Each entry is an OS + arch + optional Python version.
   *
   * Defaults to the current host platform. If no `python` is set on any platform, lockscan
   * will try to detect the version from `pyproject.toml` or `.python-version` in the working directory.
   *
   * @example [{ os: 'linux', arch: 'arm64', python: '3.12' }, { os: 'macos', arch: 'arm64' }]
   */
  platforms?: Platform[];
  /** Limit analysis to these change types. Defaults to all: added, updated, removed. */
  onlyTypes?: string[];
}

export async function analyze(
  report: DiffReport,
  options: AnalyzeOptions = {},
): Promise<SecurityReport> {
  return runAnalyze(report, options);
}
