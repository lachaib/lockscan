import { describe, expect, it } from 'vitest';
import { patternSeverity, withSeverity } from '../../src/github/severity.js';
import type { PackageAnalysis } from '../../src/types.js';

const base: PackageAnalysis = {
  name: 'pkg',
  changeType: 'updated',
  oldVersion: '1.0.0',
  newVersion: '1.0.1',
  isDirect: true,
  isDev: false,
  ecosystem: 'python',
};

describe('withSeverity', () => {
  it('annotates binary findings with rule, symbol and severity, and sets maxSeverity', () => {
    const pkg = withSeverity({
      ...base,
      binaryFindings: {
        delta: [
          { file: 'a.so', label: 'binary:base64', detail: 'x' },
          { file: 'a.so', label: 'native:socket', detail: 'new symbol (count: 1)' },
        ],
      },
    });

    expect(pkg.binaryFindings?.delta).toEqual([
      { file: 'a.so', label: 'binary:base64', detail: 'x', rule: 'binary:base64', severity: 'low' },
      {
        file: 'a.so',
        label: 'native:socket',
        detail: 'new symbol (count: 1)',
        rule: 'binary:native-symbol',
        symbol: 'socket',
        severity: 'high',
      },
    ]);
    expect(pkg.maxSeverity).toBe('high');
  });

  it('applies the family downgrade to pattern findings and reports the max', () => {
    const f = { file: 'a.js', line: 1, label: 'exec:eval' };
    const pkg = withSeverity({
      ...base,
      securityFindings: {
        old: [f, f, f, f, f],
        new: [f, f, f, f, f, f],
        delta: [f],
        platformDivergence: false,
      },
    });

    expect(pkg.securityFindings?.delta[0]).toMatchObject({ rule: 'exec:eval', severity: 'low' });
    expect(pkg.maxSeverity).toBe('low');
  });

  it('sets a null maxSeverity for a clean package and leaves errored ones alone', () => {
    expect(withSeverity(base).maxSeverity).toBeNull();
    const errored = { ...base, error: 'boom' };
    expect(withSeverity(errored)).toBe(errored);
  });
});

describe('report severity summary', () => {
  it('is zeroed with a null max for a clean report', async () => {
    const { analyze } = await import('../../src/core/analyzer.js');
    const report = await analyze({ base_ref: 'a', head_ref: 'b', lockfiles: [] } as never, {
      platforms: [{ os: 'linux', arch: 'x86_64' }],
      quiet: true,
    });
    expect(report.summary.maxSeverity).toBeNull();
    expect(report.summary.bySeverity).toEqual({ critical: 0, high: 0, moderate: 0, low: 0 });
    expect(report.summary.findingsBySeverity).toEqual({
      critical: 0,
      high: 0,
      moderate: 0,
      low: 0,
    });
  });
});

describe('patternSeverity — credential labels', () => {
  it('ci-token is critical and generic-secret is moderate', () => {
    expect(patternSeverity('cred:ci-token')).toBe('critical');
    expect(patternSeverity('cred:generic-secret')).toBe('moderate');
  });
});

describe('network severity', () => {
  it('keeps HTTP-level labels low and raises sockets and DNS to moderate', () => {
    for (const l of ['net:http', 'net:http-client', 'net:fetch', 'net:axios', 'net:http-lib']) {
      expect(patternSeverity(l)).toBe('low');
    }
    for (const l of ['net:raw-socket', 'net:dns', 'net:Deno.connect', 'net:fsockopen']) {
      expect(patternSeverity(l)).toBe('moderate');
    }
  });

  it('keeps a lone socket finding moderate', () => {
    const f = { file: 'a.js', line: 1, label: 'net:raw-socket' };
    const p = withSeverity({
      ...base,
      securityFindings: { old: [], new: [f], delta: [f], platformDivergence: false },
    });
    expect(p.securityFindings?.delta[0].severity).toBe('moderate');
  });
});
