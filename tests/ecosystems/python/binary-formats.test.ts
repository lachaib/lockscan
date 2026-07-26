import { describe, expect, it } from 'vitest';
import { extractImportedSymbols } from '../../../src/ecosystems/python/binary-formats.js';
import { buildElf, buildMachO, buildPe } from './binary-fixtures.js';

describe('extractImportedSymbols — ELF', () => {
  it('extracts undefined (imported) symbols by exact name', () => {
    const buf = buildElf([{ name: 'connect', undefined: true }]);
    expect(extractImportedSymbols(buf)).toEqual(['connect']);
  });

  it('excludes defined symbols even when their mangled name contains a dangerous substring', () => {
    const buf = buildElf([
      { name: '_CPyDef_graph_utils___strongly_connected_components', undefined: false },
      { name: 'connect', undefined: true },
    ]);
    expect(extractImportedSymbols(buf)).toEqual(['connect']);
  });

  it('returns [] for non-ELF/Mach-O/PE data', () => {
    expect(extractImportedSymbols(Buffer.from('not a binary'))).toEqual([]);
  });

  it('returns [] for truncated/malformed ELF header', () => {
    const buf = Buffer.from('\x7fELF');
    expect(extractImportedSymbols(buf)).toEqual([]);
  });
});

describe('extractImportedSymbols — Mach-O', () => {
  it('extracts undefined (imported) symbols, stripping the leading underscore', () => {
    const buf = buildMachO([{ name: 'connect', undefined: true }]);
    expect(extractImportedSymbols(buf)).toEqual(['connect']);
  });

  it('excludes defined symbols even when their mangled name contains a dangerous substring', () => {
    const buf = buildMachO([
      { name: 'CPyDef_graph_utils___strongly_connected_components', undefined: false },
      { name: 'connect', undefined: true },
    ]);
    expect(extractImportedSymbols(buf)).toEqual(['connect']);
  });

  it('supports a fat/universal binary by unioning imports across slices', () => {
    const sliceA = buildMachO([{ name: 'connect', undefined: true }]);
    const sliceB = buildMachO([{ name: 'system', undefined: true }]);

    const fatHeader = Buffer.alloc(8);
    fatHeader.writeUInt32BE(0xcafebabe, 0); // FAT_MAGIC
    fatHeader.writeUInt32BE(2, 4); // nfat_arch

    const archEntrySize = 20;
    const archOffsetA = 8 + archEntrySize * 2;
    const archOffsetB = archOffsetA + sliceA.length;

    const archs = Buffer.alloc(archEntrySize * 2);
    archs.writeUInt32BE(archOffsetA, 8);
    archs.writeUInt32BE(sliceA.length, 12);
    archs.writeUInt32BE(archOffsetB, 20 + 8);
    archs.writeUInt32BE(sliceB.length, 20 + 12);

    const buf = Buffer.concat([fatHeader, archs, sliceA, sliceB]);
    expect(extractImportedSymbols(buf).sort()).toEqual(['connect', 'system']);
  });
});

describe('extractImportedSymbols — PE', () => {
  it('returns [] for a truncated MZ header (no crash)', () => {
    const buf = Buffer.from([0x4d, 0x5a, 0, 0]);
    expect(extractImportedSymbols(buf)).toEqual([]);
  });

  it('extracts a named import from the import address table', () => {
    const buf = buildPe('WS2_32.dll', 'connect');
    expect(extractImportedSymbols(buf)).toEqual(['connect']);
  });
});
