import type { PackageChange } from 'lockdelta';
import type { Platform } from '../platforms.js';
import type { PackageAnalysis } from '../types.js';

export interface AnalysisOptions {
  platforms: Platform[];
  tmpDir: string;
  /** Also write archives that are normally scanned in memory (wheels) under tmpDir. */
  keepArtifacts?: boolean;
}

export interface EcosystemAnalyzer {
  readonly ecosystem: string;
  analyzeChange(change: PackageChange, options: AnalysisOptions): Promise<PackageAnalysis>;
}
