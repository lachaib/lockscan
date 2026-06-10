import type { SecurityFinding } from '../../types.js';
import type { FileMap } from '../../utils/extract.js';

export interface Pattern {
  regex: RegExp;
  label: string;
}

export function scanPatterns(files: FileMap, patterns: Pattern[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const [filename, content] of files) {
    for (const { regex, label } of patterns) {
      const g = new RegExp(regex.source, `gm${regex.flags.replace(/[gm]/g, '')}`);
      let match: RegExpExecArray | null;
      while ((match = g.exec(content)) !== null) {
        const lineNum = content.slice(0, match.index).split('\n').length;
        findings.push({ file: filename, line: lineNum, label });
        // avoid infinite loop on zero-length matches
        if (match.index === g.lastIndex) g.lastIndex++;
      }
    }
  }

  return findings;
}

export function findingsDelta(
  oldFindings: SecurityFinding[],
  newFindings: SecurityFinding[],
): SecurityFinding[] {
  const oldSet = new Set(oldFindings.map((f) => `${f.file}\0${f.label}`));
  return newFindings.filter((f) => !oldSet.has(`${f.file}\0${f.label}`));
}
