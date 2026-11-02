import { describe, expect, it } from 'vitest';
import { binaryFindingsDelta, scanBinary } from '../../../src/ecosystems/shared/binary-scan.js';
import { buildElf, buildMachO } from './binary-fixtures.js';

describe('scanBinary — native symbol detection (issue #4)', () => {
  it('does not flag a defined symbol whose mangled name merely contains a dangerous substring', () => {
    const buf = buildElf([
      { name: '_CPyDef_graph_utils___strongly_connected_components', undefined: false },
      { name: '_CPyDef_fscache___FileSystemCache', undefined: false },
      { name: '_CPyModule_socket', undefined: false },
    ]);
    const scan = scanBinary('mypyc.so', buf);
    expect(scan.symbolCounts).toEqual({});
  });

  it('flags an actually imported dangerous libc symbol', () => {
    const buf = buildElf([{ name: 'connect', undefined: true }]);
    const scan = scanBinary('evil.so', buf);
    expect(scan.symbolCounts).toEqual({ connect: 1 });
  });

  it('flags an imported dangerous symbol in a Mach-O binary too', () => {
    const buf = buildMachO([
      { name: 'strongly_connected_components', undefined: false },
      { name: 'system', undefined: true },
    ]);
    const scan = scanBinary('evil.dylib', buf);
    expect(scan.symbolCounts).toEqual({ system: 1 });
  });

  it('ignores non-dangerous imported symbols', () => {
    const buf = buildElf([{ name: 'malloc', undefined: true }]);
    const scan = scanBinary('benign.so', buf);
    expect(scan.symbolCounts).toEqual({});
  });
});

describe('binaryFindingsDelta — native symbol findings', () => {
  it('reports a new native: finding only for a newly imported dangerous symbol', () => {
    const oldBuf = buildElf([{ name: 'malloc', undefined: true }]);
    const newBuf = buildElf([
      { name: 'malloc', undefined: true },
      { name: 'connect', undefined: true },
    ]);
    const oldScans = new Map([['ext.so', scanBinary('ext.so', oldBuf)]]);
    const newScans = new Map([['ext.so', scanBinary('ext.so', newBuf)]]);

    const findings = binaryFindingsDelta(oldScans, newScans);
    expect(findings).toEqual([
      { file: 'ext.so', label: 'native:connect', detail: 'new symbol (count: 1)' },
    ]);
  });

  it('does not report a finding when a mangled defined symbol collides with a dangerous name across versions', () => {
    const oldBuf = buildElf([
      { name: '_CPyDef_graph_utils___strongly_connected_components', undefined: false },
    ]);
    const newBuf = buildElf([
      { name: '_CPyDef_graph_utils___strongly_connected_components', undefined: false },
      { name: '_CPyDef_fscache___FileSystemCache', undefined: false },
    ]);
    const oldScans = new Map([['ext.so', scanBinary('ext.so', oldBuf)]]);
    const newScans = new Map([['ext.so', scanBinary('ext.so', newBuf)]]);

    expect(binaryFindingsDelta(oldScans, newScans)).toEqual([]);
  });
});

describe('scanBinary — base64 precision (issue #24)', () => {
  const withString = (text: string) => Buffer.from(`\0\0\0${text}\0\0\0`, 'latin1');
  const labels = (text: string) =>
    scanBinary('x.so', withString(text)).suspiciousStrings.map((s) => s.label);

  it('ignores repetitive compiled data tables that only look like base64', () => {
    expect(
      labels('RASARARARARASARARASASASATASARATARAUARARARARARARASARARARARARARARARAUAUASAUASAR'),
    ).toEqual([]);
  });

  it('ignores pure-hex runs such as key ids and digests', () => {
    expect(labels('3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b')).toEqual([]);
    expect(labels(`${'0123456789abcdef'.repeat(4)}`)).toEqual([]);
  });

  it('still flags a real base64 payload', () => {
    const payload = Buffer.from(Array.from({ length: 96 }, (_, i) => (i * 37 + 11) % 256)).toString(
      'base64',
    );
    expect(labels(payload)).toEqual(['binary:base64']);
  });
});

describe('binaryFindingsDelta — hash-prefixed filenames (issue #24)', () => {
  const scan = (filename: string, text: string) =>
    scanBinary(filename, Buffer.from(`\0\0${text}\0\0`));

  it('pairs a binary whose build-hash prefix changed instead of treating it as new', () => {
    const url = 'http://example.com/docs/page';
    const oldScans = new Map([
      ['aaaaaaaaaaaaaaaaaaaa__mypyc.so', scan('aaaaaaaaaaaaaaaaaaaa__mypyc.so', url)],
    ]);
    const newScans = new Map([
      ['bbbbbbbbbbbbbbbbbbbb__mypyc.so', scan('bbbbbbbbbbbbbbbbbbbb__mypyc.so', url)],
    ]);
    expect(binaryFindingsDelta(oldScans, newScans)).toEqual([]);
  });

  it('keeps reporting a genuinely new string in the paired binary', () => {
    const oldScans = new Map([
      ['aaaaaaaaaaaaaaaaaaaa__m.so', scan('aaaaaaaaaaaaaaaaaaaa__m.so', 'nothing here')],
    ]);
    const newScans = new Map([
      ['bbbbbbbbbbbbbbbbbbbb__m.so', scan('bbbbbbbbbbbbbbbbbbbb__m.so', 'wss://evil.example/ws')],
    ]);
    expect(binaryFindingsDelta(oldScans, newScans).map((f) => f.label)).toEqual([
      'binary:url-other-scheme',
    ]);
  });
});
