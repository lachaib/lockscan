import { describe, expect, it } from 'vitest';
import { DANGEROUS_PATTERNS as DENO } from '../../../src/ecosystems/deno/patterns.js';
import { DANGEROUS_PATTERNS as JS } from '../../../src/ecosystems/javascript/patterns.js';
import { DANGEROUS_PATTERNS as PHP } from '../../../src/ecosystems/php/patterns.js';
import { scanPythonPatterns } from '../../../src/ecosystems/python/scan.js';
import { CI_ENV_NAMES } from '../../../src/ecosystems/shared/ci-env.js';
import { scanPatterns } from '../../../src/ecosystems/shared/scan.js';

const labels = (file: string, src: string, patterns: typeof JS): string[] =>
  scanPatterns(new Map([[file, src]]), patterns).map((f) => f.label);
const pyLabels = (src: string): string[] =>
  scanPythonPatterns(new Map([['a.py', src]])).map((f) => f.label);

describe('cred:ci-token — variable list', () => {
  it('covers the Actions runtime/OIDC variables and GH_TOKEN', () => {
    for (const name of [
      'GH_TOKEN',
      'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
      'ACTIONS_ID_TOKEN_REQUEST_URL',
      'ACTIONS_RUNTIME_TOKEN',
    ]) {
      expect(CI_ENV_NAMES).toContain(name);
    }
  });

  it.each(CI_ENV_NAMES)('%s is flagged in every ecosystem', (name) => {
    expect(labels('a.js', `process.env.${name}`, JS)).toContain('cred:ci-token');
    expect(labels('a.ts', `Deno.env.get('${name}')`, DENO)).toContain('cred:ci-token');
    expect(pyLabels(`os.getenv("${name}")`)).toContain('cred:ci-token');
    expect(labels('a.php', `<?php getenv('${name}');`, PHP)).toContain('cred:ci-token');
  });

  it('does not match look-alike names', () => {
    expect(labels('a.js', 'process.env.GH_TOKENIZER', JS)).not.toContain('cred:ci-token');
    expect(labels('a.js', 'process.env.MY_GH_TOKEN', JS)).not.toContain('cred:ci-token');
    expect(pyLabels('os.environ["GH_TOKEN_DOC"]')).not.toContain('cred:ci-token');
  });
});

describe('cred:ci-token — access forms', () => {
  it('JS: optional chaining', () => {
    expect(labels('a.js', 'process.env?.GH_TOKEN', JS)).toContain('cred:ci-token');
  });

  it('JS: bracket access with each quote style', () => {
    for (const q of ["'", '"', '`']) {
      expect(labels('a.js', `process.env[${q}GH_TOKEN${q}]`, JS)).toContain('cred:ci-token');
    }
  });

  it('JS: destructuring, with rename and default', () => {
    expect(
      labels('a.js', 'const { ACTIONS_ID_TOKEN_REQUEST_TOKEN: t } = process.env;', JS),
    ).toContain('cred:ci-token');
    expect(labels('a.js', 'const { A, GH_TOKEN = "x", B } = process.env;', JS)).toContain(
      'cred:ci-token',
    );
    expect(labels('a.js', 'const {\n  PATH,\n  NPM_TOKEN,\n} = process.env;', JS)).toContain(
      'cred:ci-token',
    );
  });

  it('JS: plain process.env.PATH stays informational only', () => {
    expect(labels('a.js', 'process.env.PATH', JS)).toEqual(['info:process.env']);
  });

  it('Python: os.environ subscript, .get and os.getenv', () => {
    expect(pyLabels('os.environ["GITHUB_TOKEN"]')).toContain('cred:ci-token');
    expect(pyLabels("os.environ.get('GITHUB_TOKEN')")).toContain('cred:ci-token');
    expect(pyLabels('os.getenv("GITHUB_TOKEN")')).toContain('cred:ci-token');
  });

  it('Python: a name in a comment is not a hit', () => {
    expect(pyLabels('# os.getenv("GH_TOKEN")')).toEqual([]);
  });

  it('PHP: $_ENV and $_SERVER subscripts', () => {
    expect(labels('a.php', `<?php $_ENV['GH_TOKEN'];`, PHP)).toContain('cred:ci-token');
    expect(labels('a.php', `<?php $_SERVER["GH_TOKEN"];`, PHP)).toContain('cred:ci-token');
  });
});

describe('cred:generic-secret', () => {
  it('flags other secret-looking names without duplicating cred:ci-token', () => {
    expect(labels('a.js', 'process.env.MY_SERVICE_TOKEN', JS)).toContain('cred:generic-secret');
    expect(labels('a.js', 'process.env.GH_TOKEN', JS)).not.toContain('cred:generic-secret');
    expect(labels('a.js', 'process.env.GH_TOKEN', JS)).toContain('cred:ci-token');
    expect(pyLabels('os.environ["DB_PASSWORD"]')).toContain('cred:generic-secret');
    expect(labels('a.php', `<?php getenv('STRIPE_SECRET');`, PHP)).toContain('cred:generic-secret');
    expect(labels('a.ts', `Deno.env.get('MY_TOKEN')`, DENO)).toContain('cred:generic-secret');
  });

  it('ignores names without a secret suffix', () => {
    expect(labels('a.js', 'process.env.NODE_ENV', JS)).not.toContain('cred:generic-secret');
    expect(labels('a.js', 'process.env.TOKENIZER', JS)).not.toContain('cred:generic-secret');
  });
});
