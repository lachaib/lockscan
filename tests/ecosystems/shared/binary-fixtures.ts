/** Synthetic minimal-but-valid binary builders used to test symbol-table parsing without shipping multi-MB real-world fixtures. */

/** Build a minimal ELF64 (little-endian) buffer with a .dynsym/.dynstr pair. */
export function buildElf(symbols: { name: string; undefined: boolean }[]): Buffer {
  // string table: leading NUL (offset 0 is conventionally the empty string) then each name
  const names = ['', ...symbols.map((s) => s.name)];
  const dynstr = Buffer.from(`${names.join('\0')}\0`, 'ascii');
  const nameOffsets: number[] = [];
  {
    let offset = 0;
    for (const n of names) {
      nameOffsets.push(offset);
      offset += n.length + 1;
    }
  }

  const symEntrySize = 24;
  // symtab entry 0 is the mandatory null symbol
  const dynsym = Buffer.alloc(symEntrySize * (symbols.length + 1));
  symbols.forEach((s, i) => {
    const base = symEntrySize * (i + 1);
    dynsym.writeUInt32LE(nameOffsets[i + 1], base); // st_name
    dynsym.writeUInt8(0, base + 4); // st_info
    dynsym.writeUInt8(0, base + 5); // st_other
    dynsym.writeUInt16LE(s.undefined ? 0 : 1, base + 6); // st_shndx: 0 = SHN_UNDEF
    dynsym.writeBigUInt64LE(0n, base + 8); // st_value
    dynsym.writeBigUInt64LE(0n, base + 16); // st_size
  });

  const header = Buffer.alloc(64);
  header.write('\x7fELF', 0, 'ascii');
  header.writeUInt8(2, 4); // EI_CLASS = 64-bit
  header.writeUInt8(1, 5); // EI_DATA = little-endian

  const dynstrOffset = header.length;
  const dynsymOffset = dynstrOffset + dynstr.length;
  const shoff = dynsymOffset + dynsym.length;

  header.writeBigUInt64LE(BigInt(shoff), 0x28); // e_shoff
  header.writeUInt16LE(64, 0x3a); // e_shentsize
  header.writeUInt16LE(3, 0x3c); // e_shnum (null, dynstr, dynsym)

  const shdrs = Buffer.alloc(64 * 3);
  // section 0: SHT_NULL, all zero — left as-is

  // section 1: .dynstr (SHT_STRTAB = 3)
  shdrs.writeUInt32LE(3, 64 + 4); // sh_type
  shdrs.writeBigUInt64LE(BigInt(dynstrOffset), 64 + 24); // sh_offset
  shdrs.writeBigUInt64LE(BigInt(dynstr.length), 64 + 32); // sh_size

  // section 2: .dynsym (SHT_DYNSYM = 11), sh_link -> section 1
  shdrs.writeUInt32LE(11, 128 + 4); // sh_type
  shdrs.writeBigUInt64LE(BigInt(dynsymOffset), 128 + 24); // sh_offset
  shdrs.writeBigUInt64LE(BigInt(dynsym.length), 128 + 32); // sh_size
  shdrs.writeUInt32LE(1, 128 + 40); // sh_link
  shdrs.writeBigUInt64LE(24n, 128 + 56); // sh_entsize

  return Buffer.concat([header, dynstr, dynsym, shdrs]);
}

/** Build a minimal thin Mach-O 64-bit buffer with LC_SYMTAB + LC_DYSYMTAB. */
export function buildMachO(symbols: { name: string; undefined: boolean }[]): Buffer {
  // Mach-O convention: C symbol names are prefixed with a leading underscore.
  const names = ['', ...symbols.map((s) => `_${s.name}`)];
  const strtab = Buffer.from(`${names.join('\0')}\0`, 'ascii');
  const nameOffsets: number[] = [];
  {
    let offset = 0;
    for (const n of names) {
      nameOffsets.push(offset);
      offset += n.length + 1;
    }
  }

  // Defined symbols first, then undefined — matches how dysymtab partitions the symtab.
  const ordered = [...symbols.entries()].sort(
    ([, a], [, b]) => Number(a.undefined) - Number(b.undefined),
  );

  const nlistSize = 16;
  const symtab = Buffer.alloc(nlistSize * ordered.length);
  ordered.forEach(([origIndex], i) => {
    const base = nlistSize * i;
    symtab.writeUInt32LE(nameOffsets[origIndex + 1], base); // n_strx
    symtab.writeUInt8(symbols[origIndex].undefined ? 0x01 : 0x0f, base + 4); // n_type
    symtab.writeUInt8(0, base + 5); // n_sect
    symtab.writeUInt16LE(0, base + 6); // n_desc
    symtab.writeBigUInt64LE(0n, base + 8); // n_value
  });

  const nundefsym = symbols.filter((s) => s.undefined).length;
  const iundefsym = symbols.length - nundefsym;

  const headerSize = 32;
  const symtabCmdSize = 24;
  const dysymtabCmdSize = 80;
  const symoff = headerSize + symtabCmdSize + dysymtabCmdSize;
  const stroff = symoff + symtab.length;

  const header = Buffer.alloc(headerSize);
  header.writeUInt32LE(0xfeedfacf, 0); // MH_MAGIC_64
  header.writeUInt32LE(2, 16); // ncmds
  header.writeUInt32LE(symtabCmdSize + dysymtabCmdSize, 20); // sizeofcmds

  const symtabCmd = Buffer.alloc(symtabCmdSize);
  symtabCmd.writeUInt32LE(0x2, 0); // LC_SYMTAB
  symtabCmd.writeUInt32LE(symtabCmdSize, 4);
  symtabCmd.writeUInt32LE(symoff, 8);
  symtabCmd.writeUInt32LE(ordered.length, 12); // nsyms
  symtabCmd.writeUInt32LE(stroff, 16);
  symtabCmd.writeUInt32LE(strtab.length, 20);

  const dysymtabCmd = Buffer.alloc(dysymtabCmdSize);
  dysymtabCmd.writeUInt32LE(0xb, 0); // LC_DYSYMTAB
  dysymtabCmd.writeUInt32LE(dysymtabCmdSize, 4);
  dysymtabCmd.writeUInt32LE(iundefsym, 24);
  dysymtabCmd.writeUInt32LE(nundefsym, 28);

  return Buffer.concat([header, symtabCmd, dysymtabCmd, symtab, strtab]);
}

/** Build a minimal PE32+ buffer importing a single named function from one DLL. */
export function buildPe(dllName: string, importName: string): Buffer {
  const SECTION_VA = 0x1000;
  const dosHeader = Buffer.alloc(64);
  dosHeader.write('MZ', 0, 'ascii');
  dosHeader.writeUInt32LE(64, 0x3c); // e_lfanew -> PE header right after

  const optHeaderSize = 240; // IMAGE_OPTIONAL_HEADER64
  const coffHeader = Buffer.alloc(24); // "PE\0\0" (4) + COFF header (20)
  coffHeader.writeUInt32LE(0x00004550, 0); // "PE\0\0"
  coffHeader.writeUInt16LE(1, 4 + 2); // NumberOfSections
  coffHeader.writeUInt16LE(optHeaderSize, 4 + 16); // SizeOfOptionalHeader

  const optHeader = Buffer.alloc(optHeaderSize);
  optHeader.writeUInt16LE(0x20b, 0); // Magic: PE32+

  const sectionHeader = Buffer.alloc(40);
  sectionHeader.write('.idata', 0, 'ascii');
  sectionHeader.writeUInt32LE(SECTION_VA, 12); // VirtualAddress

  // --- import data blob, laid out at file offset FILE_DATA_OFFSET / RVA SECTION_VA ---
  const descriptorSize = 20;
  const thunkSize = 8; // PE32+
  const ilt = Buffer.alloc(thunkSize * 2); // one entry + zero terminator
  const hintName = Buffer.concat([Buffer.alloc(2), Buffer.from(`${importName}\0`, 'ascii')]);
  const dllNameBuf = Buffer.from(`${dllName}\0`, 'ascii');

  const iltOffset = descriptorSize * 2; // after descriptor table (1 entry + zero terminator)
  const hintNameOffset = iltOffset + ilt.length;
  const dllNameOffset = hintNameOffset + hintName.length;

  ilt.writeBigUInt64LE(BigInt(SECTION_VA + hintNameOffset), 0);

  const descriptors = Buffer.alloc(descriptorSize * 2);
  descriptors.writeUInt32LE(SECTION_VA + iltOffset, 0); // OriginalFirstThunk
  descriptors.writeUInt32LE(SECTION_VA + dllNameOffset, 12); // Name
  descriptors.writeUInt32LE(SECTION_VA + iltOffset, 16); // FirstThunk

  const blob = Buffer.concat([descriptors, ilt, hintName, dllNameBuf]);

  const fileDataOffset =
    dosHeader.length + coffHeader.length + optHeader.length + sectionHeader.length;
  sectionHeader.writeUInt32LE(blob.length, 16); // SizeOfRawData
  sectionHeader.writeUInt32LE(fileDataOffset, 20); // PointerToRawData

  // Import Table is data directory index 1 (index 0 is Export Table), 112 bytes into a
  // PE32+ optional header, 8 bytes per entry.
  optHeader.writeUInt32LE(SECTION_VA, 112 + 8);
  optHeader.writeUInt32LE(descriptors.length, 112 + 12);

  return Buffer.concat([dosHeader, coffHeader, optHeader, sectionHeader, blob]);
}
