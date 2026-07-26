import { describe, expect, it } from 'vitest';
import { binaryFindingsDelta, scanBinary } from '../../../src/ecosystems/python/binary-scan.js';
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
