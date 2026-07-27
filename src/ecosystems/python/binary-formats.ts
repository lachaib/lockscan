/**
 * Extract the *imported* (undefined) symbol names a compiled extension declares —
 * i.e. the actual external calls it can make at runtime — as opposed to every symbol
 * defined inside the binary. Compiler-mangled internal names (mypyc, Cython, C++) live
 * in the defined-symbol space and must never be treated as capability signals.
 *
 * Supports ELF (Linux .so), Mach-O incl. fat/universal (macOS .so/.dylib), and PE
 * (Windows .pyd/.dll). Returns [] for unrecognized or malformed input rather than
 * falling back to a whole-file string scan, since that reintroduces the false-positive
 * class this module exists to avoid.
 */
export function extractImportedSymbols(data: Buffer): string[] {
  try {
    if (data.length < 4) return [];
    const magic = data.readUInt32LE(0);
    if (magic === ELF_MAGIC) return parseElfImports(data);
    if (magic === MH_MAGIC || magic === MH_MAGIC_64) return parseThinMachO(data, 0, data.length);
    // Fat/universal Mach-O headers are always stored big-endian on disk, regardless of host.
    const fatMagic = data.readUInt32BE(0);
    if (fatMagic === FAT_MAGIC || fatMagic === FAT_MAGIC_64) {
      return parseFatMachO(data, fatMagic === FAT_MAGIC_64);
    }
    if (data[0] === 0x4d && data[1] === 0x5a) return parsePeImports(data);
    return [];
  } catch {
    return [];
  }
}

function readCString(data: Buffer, offset: number): string {
  if (offset < 0 || offset >= data.length) return '';
  let end = offset;
  while (end < data.length && data[end] !== 0) end++;
  return data.subarray(offset, end).toString('ascii');
}

// ---------------------------------------------------------------------------
// ELF
// ---------------------------------------------------------------------------

const ELF_MAGIC = 0x464c457f; // 0x7f 'E' 'L' 'F' read little-endian
const SHT_DYNSYM = 11;

interface ElfSection {
  type: number;
  offset: number;
  size: number;
  link: number;
  entsize: number;
}

function parseElfImports(data: Buffer): string[] {
  if (data.length < 20) return [];
  const eiClass = data[4]; // 1 = 32-bit, 2 = 64-bit
  const eiData = data[5]; // 1 = little-endian, 2 = big-endian
  if (eiData !== 1) return []; // big-endian ELF is not produced by any current wheel toolchain
  const is64 = eiClass === 2;

  let eShoff: number;
  let eShentsize: number;
  let eShnum: number;
  if (is64) {
    if (data.length < 0x40) return [];
    eShoff = Number(data.readBigUInt64LE(0x28));
    eShentsize = data.readUInt16LE(0x3a);
    eShnum = data.readUInt16LE(0x3c);
  } else {
    if (data.length < 0x34) return [];
    eShoff = data.readUInt32LE(0x20);
    eShentsize = data.readUInt16LE(0x2e);
    eShnum = data.readUInt16LE(0x30);
  }
  if (eShentsize === 0) return [];

  const sections: ElfSection[] = [];
  for (let i = 0; i < eShnum; i++) {
    const base = eShoff + i * eShentsize;
    if (base + eShentsize > data.length) break;
    sections.push(
      is64
        ? {
            type: data.readUInt32LE(base + 4),
            offset: Number(data.readBigUInt64LE(base + 24)),
            size: Number(data.readBigUInt64LE(base + 32)),
            link: data.readUInt32LE(base + 40),
            entsize: Number(data.readBigUInt64LE(base + 56)),
          }
        : {
            type: data.readUInt32LE(base + 4),
            offset: data.readUInt32LE(base + 16),
            size: data.readUInt32LE(base + 20),
            link: data.readUInt32LE(base + 24),
            entsize: data.readUInt32LE(base + 36),
          },
    );
  }

  const dynsym = sections.find((s) => s.type === SHT_DYNSYM);
  const dynstr = dynsym ? sections[dynsym.link] : undefined;
  if (!dynsym || !dynstr) return [];

  const entsize = dynsym.entsize || (is64 ? 24 : 16);
  const count = Math.floor(dynsym.size / entsize);

  const names: string[] = [];
  for (let i = 0; i < count; i++) {
    const symBase = dynsym.offset + i * entsize;
    if (symBase + entsize > data.length) break;
    const stName = data.readUInt32LE(symBase);
    const stShndx = is64 ? data.readUInt16LE(symBase + 6) : data.readUInt16LE(symBase + 14);
    if (stName === 0 || stShndx !== 0) continue; // SHN_UNDEF (0) === imported, not locally defined
    const name = readCString(data, dynstr.offset + stName);
    if (name) names.push(name);
  }
  return names;
}

// ---------------------------------------------------------------------------
// Mach-O
// ---------------------------------------------------------------------------

const MH_MAGIC = 0xfeedface;
const MH_MAGIC_64 = 0xfeedfacf;
const FAT_MAGIC = 0xcafebabe;
const FAT_MAGIC_64 = 0xcafebabf;
const LC_SYMTAB = 0x2;
const LC_DYSYMTAB = 0xb;
const N_TYPE_MASK = 0x0e;
const N_UNDF = 0x00;

function parseFatMachO(data: Buffer, is64Arch: boolean): string[] {
  if (data.length < 8) return [];
  const nfatArch = data.readUInt32BE(4);
  const archEntrySize = is64Arch ? 32 : 20;
  const names: string[] = [];
  for (let i = 0; i < nfatArch; i++) {
    const base = 8 + i * archEntrySize;
    if (base + archEntrySize > data.length) break;
    const offset = is64Arch ? Number(data.readBigUInt64BE(base + 8)) : data.readUInt32BE(base + 8);
    const size = is64Arch ? Number(data.readBigUInt64BE(base + 16)) : data.readUInt32BE(base + 12);
    if (size <= 0 || offset + size > data.length) continue;
    names.push(...parseThinMachO(data, offset, offset + size));
  }
  return names;
}

function parseThinMachO(data: Buffer, start: number, end: number): string[] {
  if (start + 4 > end) return [];
  const magic = data.readUInt32LE(start);
  if (magic !== MH_MAGIC && magic !== MH_MAGIC_64) return [];
  const is64 = magic === MH_MAGIC_64;

  const headerSize = is64 ? 32 : 28;
  if (start + headerSize > end) return [];
  const ncmds = data.readUInt32LE(start + 16);

  let symtabOffset = -1;
  let nsyms = 0;
  let stroff = -1;
  let iundefsym = -1;
  let nundefsym = -1;

  let cmdPtr = start + headerSize;
  for (let i = 0; i < ncmds; i++) {
    if (cmdPtr + 8 > end) break;
    const cmd = data.readUInt32LE(cmdPtr);
    const cmdsize = data.readUInt32LE(cmdPtr + 4);
    if (cmdsize < 8 || cmdPtr + cmdsize > end) break;

    if (cmd === LC_SYMTAB && cmdsize >= 24) {
      symtabOffset = start + data.readUInt32LE(cmdPtr + 8);
      nsyms = data.readUInt32LE(cmdPtr + 12);
      stroff = start + data.readUInt32LE(cmdPtr + 16);
    } else if (cmd === LC_DYSYMTAB && cmdsize >= 32) {
      iundefsym = data.readUInt32LE(cmdPtr + 24);
      nundefsym = data.readUInt32LE(cmdPtr + 28);
    }
    cmdPtr += cmdsize;
  }
  if (symtabOffset < 0 || stroff < 0) return [];

  const nlistSize = is64 ? 16 : 12;
  const hasDysymtab = iundefsym >= 0 && nundefsym >= 0;
  const rangeStart = hasDysymtab ? iundefsym : 0;
  const rangeCount = hasDysymtab ? nundefsym : nsyms;

  const names: string[] = [];
  for (let i = 0; i < rangeCount; i++) {
    const idx = rangeStart + i;
    if (idx >= nsyms) break;
    const symBase = symtabOffset + idx * nlistSize;
    if (symBase + nlistSize > end) break;
    const nStrx = data.readUInt32LE(symBase);
    const nType = data[symBase + 4];
    if (!hasDysymtab && (nType & N_TYPE_MASK) !== N_UNDF) continue;
    if (nStrx === 0) continue;
    const name = readCString(data, stroff + nStrx);
    if (!name) continue;
    // Mach-O C symbols carry a leading underscore by convention (e.g. "_connect").
    names.push(name.startsWith('_') ? name.slice(1) : name);
  }
  return names;
}

// ---------------------------------------------------------------------------
// PE (Windows .pyd / .dll)
// ---------------------------------------------------------------------------

function parsePeImports(data: Buffer): string[] {
  if (data.length < 0x40) return [];
  const peOffset = data.readUInt32LE(0x3c);
  if (peOffset + 24 > data.length) return [];
  if (data.readUInt32LE(peOffset) !== 0x00004550) return []; // 'PE\0\0'

  const numberOfSections = data.readUInt16LE(peOffset + 6);
  const sizeOfOptionalHeader = data.readUInt16LE(peOffset + 20);
  const optHeaderOffset = peOffset + 24;
  if (sizeOfOptionalHeader === 0 || optHeaderOffset + sizeOfOptionalHeader > data.length) return [];

  const magic = data.readUInt16LE(optHeaderOffset);
  const isPe32Plus = magic === 0x20b; // PE32+ (64-bit)
  // Data directory index 1 is the Import Table (index 0 is Export Table).
  const importDirEntryOffset = optHeaderOffset + (isPe32Plus ? 112 : 96) + 8;
  if (importDirEntryOffset + 8 > data.length) return [];

  const importDirRva = data.readUInt32LE(importDirEntryOffset);
  const importDirSize = data.readUInt32LE(importDirEntryOffset + 4);
  if (importDirRva === 0 || importDirSize === 0) return [];

  const sectionTableOffset = optHeaderOffset + sizeOfOptionalHeader;
  const sections: { va: number; rawOffset: number; size: number }[] = [];
  for (let i = 0; i < numberOfSections; i++) {
    const base = sectionTableOffset + i * 40;
    if (base + 40 > data.length) break;
    sections.push({
      va: data.readUInt32LE(base + 12),
      size: data.readUInt32LE(base + 16),
      rawOffset: data.readUInt32LE(base + 20),
    });
  }

  const rvaToOffset = (rva: number): number => {
    for (const s of sections) {
      if (rva >= s.va && rva < s.va + s.size) return s.rawOffset + (rva - s.va);
    }
    return -1;
  };

  const names: string[] = [];
  const seen = new Set<number>(); // guard against malformed/circular descriptor tables
  let descOffset = rvaToOffset(importDirRva);
  const IMAGE_IMPORT_DESCRIPTOR_SIZE = 20;
  let iterations = 0;
  while (
    descOffset >= 0 &&
    descOffset + IMAGE_IMPORT_DESCRIPTOR_SIZE <= data.length &&
    iterations < 1000
  ) {
    iterations++;
    const originalFirstThunk = data.readUInt32LE(descOffset);
    const nameRva = data.readUInt32LE(descOffset + 12);
    const firstThunk = data.readUInt32LE(descOffset + 16);
    if (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0) break;

    const thunkRva = originalFirstThunk !== 0 ? originalFirstThunk : firstThunk;
    let thunkOffset = rvaToOffset(thunkRva);
    const entrySize = isPe32Plus ? 8 : 4;
    const ordinalFlag = isPe32Plus ? 0x8000000000000000n : 0x80000000;

    while (thunkOffset >= 0 && thunkOffset + entrySize <= data.length) {
      const entry = isPe32Plus
        ? data.readBigUInt64LE(thunkOffset)
        : BigInt(data.readUInt32LE(thunkOffset));
      if (entry === 0n) break;
      const isOrdinal = (entry & (ordinalFlag as bigint)) !== 0n;
      if (!isOrdinal) {
        const hintNameRva = Number(entry & 0x7fffffffn);
        const hintNameOffset = rvaToOffset(hintNameRva);
        if (hintNameOffset >= 0 && !seen.has(hintNameOffset)) {
          seen.add(hintNameOffset);
          const name = readCString(data, hintNameOffset + 2); // skip 2-byte Hint field
          if (name) names.push(name);
        }
      }
      thunkOffset += entrySize;
    }

    descOffset += IMAGE_IMPORT_DESCRIPTOR_SIZE;
  }
  return names;
}
