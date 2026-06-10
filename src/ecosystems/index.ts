import type { EcosystemAnalyzer } from './base.js';
import { DenoAnalyzer } from './deno/index.js';
import { JavaScriptAnalyzer } from './javascript/index.js';
import { PythonAnalyzer } from './python/index.js';

const registry = new Map<string, EcosystemAnalyzer>([
  ['python', new PythonAnalyzer()],
  ['javascript', new JavaScriptAnalyzer()],
  ['deno', new DenoAnalyzer()],
]);

export function getAnalyzer(ecosystem: string): EcosystemAnalyzer | undefined {
  return registry.get(ecosystem);
}

export function registerAnalyzer(analyzer: EcosystemAnalyzer): void {
  registry.set(analyzer.ecosystem, analyzer);
}

export type { EcosystemAnalyzer } from './base.js';
