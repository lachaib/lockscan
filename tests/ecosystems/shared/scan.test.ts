import { describe, expect, it } from 'vitest';
import { DANGEROUS_PATTERNS as JS_PATTERNS } from '../../../src/ecosystems/javascript/patterns.js';
import { DANGEROUS_PATTERNS as PY_PATTERNS } from '../../../src/ecosystems/python/patterns.js';
import { findingsDelta, scanPatterns } from '../../../src/ecosystems/shared/scan.js';
import type { FileMap } from '../../../src/utils/extract.js';

function files(entries: Record<string, string>): FileMap {
  return new Map(Object.entries(entries));
}

describe('scanPatterns — python', () => {
  it('detects eval', () => {
    const findings = scanPatterns(files({ 'setup.py': 'eval(user_input)' }), PY_PATTERNS);
    expect(findings.some((f) => f.label === 'exec:eval')).toBe(true);
  });

  it('detects subprocess', () => {
    const findings = scanPatterns(files({ 'runner.py': 'subprocess.run(["ls"])' }), PY_PATTERNS);
    expect(findings.some((f) => f.label === 'shell:subprocess')).toBe(true);
  });

  it('returns empty for clean files', () => {
    const findings = scanPatterns(
      files({ 'clean.py': 'def hello():\n    return 42\n' }),
      PY_PATTERNS,
    );
    expect(findings).toHaveLength(0);
  });
});

describe('scanPatterns — javascript', () => {
  it('detects eval', () => {
    const findings = scanPatterns(files({ 'index.js': 'eval(code)' }), JS_PATTERNS);
    expect(findings.some((f) => f.label === 'exec:eval')).toBe(true);
  });

  it('detects child_process require', () => {
    const findings = scanPatterns(
      files({ 'run.js': "require('child_process').exec(cmd)" }),
      JS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'shell:require-child_process')).toBe(true);
  });
});

describe('findingsDelta', () => {
  it('returns findings new in new but absent in old', () => {
    const old = [{ file: 'a.py', line: 1, label: 'exec:eval' }];
    const newF = [
      { file: 'a.py', line: 1, label: 'exec:eval' },
      { file: 'b.py', line: 5, label: 'shell:subprocess' },
    ];
    const delta = findingsDelta(old, newF);
    expect(delta).toHaveLength(1);
    expect(delta[0].label).toBe('shell:subprocess');
  });

  it('returns empty when nothing new', () => {
    const f = [{ file: 'a.py', line: 1, label: 'exec:eval' }];
    expect(findingsDelta(f, f)).toHaveLength(0);
  });
});
