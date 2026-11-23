import { describe, expect, it } from 'vitest';
import { DANGEROUS_PATTERNS as DENO } from '../../../src/ecosystems/deno/patterns.js';
import { DANGEROUS_PATTERNS as JS } from '../../../src/ecosystems/javascript/patterns.js';
import { DANGEROUS_PATTERNS as PHP } from '../../../src/ecosystems/php/patterns.js';
import { scanPythonPatterns } from '../../../src/ecosystems/python/scan.js';
import { scanPatterns } from '../../../src/ecosystems/shared/scan.js';
import { patternSeverity } from '../../../src/github/severity.js';

const scan = (src: string, patterns: typeof JS): string[] =>
  scanPatterns(new Map([['a', src]]), patterns).map((f) => f.label);
const py = (src: string): string[] =>
  scanPythonPatterns(new Map([['a.py', src]])).map((f) => f.label);

const CASES: Array<[string, (src: string) => string[]]> = [
  ['js', (s) => scan(s, JS)],
  ['deno', (s) => scan(s, DENO)],
  ['php', (s) => scan(`<?php ${s}`, PHP)],
  ['python', py],
];

describe.each(CASES)('git credential literals — %s', (_name, labels) => {
  it('flags extraheader and .git-credentials as cred:git-credentials', () => {
    expect(labels(`x = "http.https://github.com/.extraheader"`)).toContain('cred:git-credentials');
    expect(labels(`x = "http.extraHeader"`)).toContain('cred:git-credentials');
    expect(labels(`x = "/home/runner/.git-credentials"`)).toContain('cred:git-credentials');
  });

  it('flags .git/ path fragments as fs:git-dir only', () => {
    for (const src of [`x = ".git/config"`, `x = "../.git/hooks/pre-commit"`, `x = ".git"`]) {
      const found = labels(src);
      expect(found).toContain('fs:git-dir');
      expect(found).not.toContain('cred:git-credentials');
    }
  });

  it('does not match git-adjacent names', () => {
    for (const src of [
      `x = ".gitignore"`,
      `x = ".github/workflows"`,
      `x = ".gitattributes"`,
      `x = ".gitconfig"`,
      `x = "https://example.com/repo.git/info"`,
      `x = "extraheaders"`,
    ]) {
      const found = labels(src);
      expect(found).not.toContain('fs:git-dir');
      expect(found).not.toContain('cred:git-credentials');
    }
  });
});

describe('git credential literals — path joining', () => {
  it('flags a .git segment passed to path.join', () => {
    expect(scan("path.join(dir, '.git', 'config')", JS)).toContain('fs:git-dir');
    expect(py('os.path.join(repo, ".git", "config")')).toContain('fs:git-dir');
  });

  it('known limitation: constructed or encoded paths are not detected', () => {
    expect(scan("['.g', 'it'].join('') + '/config'", JS)).not.toContain('fs:git-dir');
    expect(scan("Buffer.from('LmdpdC9jb25maWc=', 'base64')", JS)).not.toContain('fs:git-dir');
    expect(py('open("." + "git" + "/config")')).not.toContain('fs:git-dir');
  });
});

describe('severity', () => {
  it('is critical for credentials and moderate for the .git directory', () => {
    expect(patternSeverity('cred:git-credentials')).toBe('critical');
    expect(patternSeverity('fs:git-dir')).toBe('moderate');
  });
});
