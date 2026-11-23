import { describe, expect, it } from 'vitest';
import { DANGEROUS_PATTERNS as DENO } from '../../src/ecosystems/deno/patterns.js';
import { DANGEROUS_PATTERNS as JS } from '../../src/ecosystems/javascript/patterns.js';
import { DANGEROUS_PATTERNS as PHP } from '../../src/ecosystems/php/patterns.js';
import { scanPythonPatterns } from '../../src/ecosystems/python/scan.js';
import { scanPatterns } from '../../src/ecosystems/shared/scan.js';
import { COMPOUND_EXFIL, shouldFail, withSeverity } from '../../src/github/severity.js';
import type { PackageAnalysis, SecurityFinding } from '../../src/types.js';

const f = (label: string, file = 'a.js'): SecurityFinding => ({ file, line: 1, label });

const pkg = (oldF: SecurityFinding[], newF: SecurityFinding[]): PackageAnalysis => {
  const seen = new Set(oldF.map((x) => `${x.file}\0${x.label}`));
  return withSeverity({
    name: 'pkg',
    changeType: 'updated',
    oldVersion: '1.0.0',
    newVersion: '1.0.1',
    isDirect: true,
    isDev: false,
    ecosystem: 'npm',
    securityFindings: {
      old: oldF,
      new: newF,
      delta: newF.filter((x) => !seen.has(`${x.file}\0${x.label}`)),
      platformDivergence: false,
    },
  });
};

const sev = (p: PackageAnalysis, label: string) =>
  p.securityFindings?.delta.find((x) => x.label === label)?.severity;

describe('compound escalation', () => {
  it('env enumeration + network, both new -> high on the participating findings', () => {
    const p = pkg([], [f('env:enumerate'), f('net:fetch'), f('fs:writeFileSync')]);
    expect(p.maxSeverity).toBe('high');
    expect(sev(p, 'env:enumerate')).toBe('high');
    expect(sev(p, 'net:fetch')).toBe('high');
    expect(sev(p, 'fs:writeFileSync')).toBe('low');
    expect(p.securityFindings?.delta.find((x) => x.label === 'net:fetch')?.escalation).toBe(
      COMPOUND_EXFIL,
    );
    expect(shouldFail('high', p.maxSeverity ?? null)).toBe(true);
    expect(shouldFail('critical', p.maxSeverity ?? null)).toBe(false);
  });

  it('strong obfuscation + network -> high; dynamic require counts as strong', () => {
    expect(pkg([], [f('obfusc:fromCharCode'), f('net:http')]).maxSeverity).toBe('high');
    expect(pkg([], [f('exec:dynamic-require'), f('net:http')]).maxSeverity).toBe('high');
  });

  it('base64 or hex escapes alone with network stay low', () => {
    expect(pkg([], [f('obfusc:base64'), f('net:fetch')]).maxSeverity).toBe('low');
    expect(pkg([], [f('obfusc:hex-escape'), f('net:fetch')]).maxSeverity).toBe('low');
  });

  it('enumeration + network + obfuscation -> critical', () => {
    expect(pkg([], [f('env:enumerate'), f('net:fetch'), f('obfusc:base64')]).maxSeverity).toBe(
      'critical',
    );
    expect(pkg([], [f('env:enumerate'), f('net:http'), f('obfusc:fromCharCode')]).maxSeverity).toBe(
      'critical',
    );
  });

  it('a generic secret read next to a network call is not escalated', () => {
    const p = pkg([], [f('cred:generic-secret'), f('net:fetch')]);
    expect(p.maxSeverity).toBe('moderate');
    expect(sev(p, 'net:fetch')).toBe('low');
  });

  it('enumeration alone, network alone: unchanged', () => {
    expect(pkg([], [f('env:enumerate')]).maxSeverity).toBe('low');
    expect(pkg([], [f('net:fetch')]).maxSeverity).toBe('low');
  });

  it('does not combine when one signal was already present in the old version', () => {
    const old = [f('net:fetch', 'old.js')];
    const p = pkg(old, [...old, f('env:enumerate', 'b.js')]);
    expect(p.maxSeverity).toBe('low');
  });

  it('ignores a lateral network change (no growth in network findings)', () => {
    const p = pkg(
      [f('net:fetch', 'old.js')],
      [f('net:http', 'new.js'), f('env:enumerate', 'new.js')],
    );
    expect(p.maxSeverity).toBe('low');
  });

  it('keeps a higher own severity and does not tag it as escalated', () => {
    const p = pkg([], [f('cred:ci-token'), f('net:fetch')]);
    expect(p.maxSeverity).toBe('critical');
    expect(p.securityFindings?.delta.find((x) => x.label === 'cred:ci-token')?.escalation).toBe(
      undefined,
    );
    expect(sev(p, 'net:fetch')).toBe('high');
  });
});

describe('env:enumerate patterns', () => {
  const js = (src: string) => scanPatterns(new Map([['a.js', src]]), JS).map((x) => x.label);
  const py = (src: string) => scanPythonPatterns(new Map([['a.py', src]])).map((x) => x.label);
  const php = (src: string) =>
    scanPatterns(new Map([['a.php', `<?php ${src}`]]), PHP).map((x) => x.label);
  const deno = (src: string) => scanPatterns(new Map([['a.ts', src]]), DENO).map((x) => x.label);

  it.each([
    'JSON.stringify(process.env)',
    'JSON.stringify(process.env, null, 2)',
    'Object.keys(process.env)',
    'Object.entries(process.env)',
    'Object.assign({}, process.env)',
    'const e = { ...process.env, A: 1 };',
    'for (const k in process.env) {}',
  ])('JS flags %s', (src) => {
    expect(js(src)).toContain('env:enumerate');
  });

  it.each([
    'process.env.PATH',
    "process.env['PATH']",
    "if ('X' in process.env) {}",
    'const x = { ...process.env.FOO };',
  ])('JS ignores %s', (src) => {
    expect(js(src)).not.toContain('env:enumerate');
  });

  it('Deno', () => {
    expect(deno('Deno.env.toObject()')).toContain('env:enumerate');
    expect(deno('Deno.env.get("HOME")')).not.toContain('env:enumerate');
  });

  it.each([
    'dict(os.environ)',
    'json.dumps(os.environ)',
    'os.environ.items()',
    'for k, v in os.environ.items(): pass',
    'for k in os.environ: pass',
    'requests.post(u, data={**os.environ})',
  ])('Python flags %s', (src) => {
    expect(py(src)).toContain('env:enumerate');
  });

  it.each(['os.environ["HOME"]', 'os.environ.get("HOME")', 'if "X" in os.environ: pass'])(
    'Python ignores %s',
    (src) => {
      expect(py(src)).not.toContain('env:enumerate');
    },
  );

  it('Python ignores enumeration in comments and strings', () => {
    expect(py('# dict(os.environ)')).not.toContain('env:enumerate');
    expect(py('x = "dict(os.environ)"')).not.toContain('env:enumerate');
  });

  it.each([
    'getenv();',
    'json_encode($_ENV);',
    'print_r($_SERVER);',
    'foreach ($_ENV as $k => $v) {}',
  ])('PHP flags %s', (src) => {
    expect(php(src)).toContain('env:enumerate');
  });

  it.each(["getenv('HOME');", "$_SERVER['HTTP_HOST'];", "isset($_ENV['X']);"])(
    'PHP ignores %s',
    (src) => {
      expect(php(src)).not.toContain('env:enumerate');
    },
  );
});

describe('pattern scan cost on adversarial input', () => {
  it('stays fast on repeated unterminated constructs', () => {
    const inputs = [
      'Object.keys('.repeat(20000),
      'Object.assign({}, '.repeat(20000),
      'for ('.repeat(20000),
      '{ A, '.repeat(20000),
    ];
    const start = performance.now();
    for (const text of inputs) scanPatterns(new Map([['a.js', text]]), JS);
    scanPythonPatterns(new Map([['a.py', 'for '.repeat(20000)]]));
    expect(performance.now() - start).toBeLessThan(2000);
  });
});
