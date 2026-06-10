import type { PackageChange } from 'lockdelta';
import type { Platform } from '../platforms.js';
import type { PackageAnalysis } from '../types.js';

export interface AnalysisOptions {
  platforms: Platform[];
  tmpDir: string;
}

export interface EcosystemAnalyzer {
  readonly ecosystem: string;
  analyzeChange(change: PackageChange, options: AnalysisOptions): Promise<PackageAnalysis>;
}
