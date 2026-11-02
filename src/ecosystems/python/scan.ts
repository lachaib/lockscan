import type { SecurityFinding } from '../../types.js';
import type { FileMap } from '../../utils/extract.js';
import { scanPatterns } from '../shared/scan.js';
import { maskPython } from './mask.js';
import { DANGEROUS_PATTERNS, STRING_SCOPED_LABELS } from './patterns.js';

const CODE_PATTERNS = DANGEROUS_PATTERNS.filter((p) => !STRING_SCOPED_LABELS.has(p.label));
const STRING_PATTERNS = DANGEROUS_PATTERNS.filter((p) => STRING_SCOPED_LABELS.has(p.label));

/** Pattern-scans Python sources, ignoring comments, docstrings and (for code patterns) string contents. */
export function scanPythonPatterns(files: FileMap): SecurityFinding[] {
  const code: FileMap = new Map();
  const text: FileMap = new Map();
  for (const [name, content] of files) {
    const masked = maskPython(content);
    code.set(name, masked.code);
    text.set(name, masked.text);
  }
  return [...scanPatterns(code, CODE_PATTERNS), ...scanPatterns(text, STRING_PATTERNS)];
}
