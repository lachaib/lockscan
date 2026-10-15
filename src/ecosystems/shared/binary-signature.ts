import { X509Certificate } from 'node:crypto';

/** An embedded code signature found in a native binary (Mach-O Developer ID / PE Authenticode). */
export interface CodeSignature {
  format: 'macho' | 'pe';
  /** Stable signer identity: Apple Team ID, or the Authenticode leaf certificate's organization. */
  identity?: string;
}

/**
 * Extract the embedded code signature of a Mach-O (thin or fat) or PE binary.
 * Returns undefined for unsigned, ad-hoc signed, ELF, unrecognized or malformed input.
 * The signature is parsed, not cryptographically verified.
 */
export function extractCodeSignature(data: Buffer): CodeSignature | undefined {
  try {
    if (data.length < 4) return undefined;
    const magic = data.readUInt32LE(0);
    if (magic === MH_MAGIC || magic === MH_MAGIC_64) return machoSignature(data, 0, data.length);
    const fatMagic = data.readUInt32BE(0);
    if (fatMagic === FAT_MAGIC || fatMagic === FAT_MAGIC_64) {
      return fatMachoSignature(data, fatMagic === FAT_MAGIC_64);
    }
    if (data[0] === 0x4d && data[1] === 0x5a) return peSignature(data);
    return undefined;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Mach-O
// ---------------------------------------------------------------------------

const MH_MAGIC = 0xfeedface;
const MH_MAGIC_64 = 0xfeedfacf;
const FAT_MAGIC = 0xcafebabe;
const FAT_MAGIC_64 = 0xcafebabf;
const LC_CODE_SIGNATURE = 0x1d;
const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
const CSSLOT_CODEDIRECTORY = 0;
const CSSLOT_CMS_SIGNATURE = 0x10000;
const CS_SUPPORTSTEAMID = 0x20200;

function fatMachoSignature(data: Buffer, is64Arch: boolean): CodeSignature | undefined {
  const nfatArch = data.readUInt32BE(4);
  const entrySize = is64Arch ? 32 : 20;
  let first: CodeSignature | undefined;
  for (let i = 0; i < nfatArch; i++) {
    const base = 8 + i * entrySize;
    if (base + entrySize > data.length) return undefined;
    const offset = is64Arch ? Number(data.readBigUInt64BE(base + 8)) : data.readUInt32BE(base + 8);
    const size = is64Arch ? Number(data.readBigUInt64BE(base + 16)) : data.readUInt32BE(base + 12);
    if (size <= 0 || offset + size > data.length) return undefined;
    // Every slice must be signed: stripping a single architecture's signature is a downgrade.
    const sig = machoSignature(data, offset, offset + size);
    if (!sig) return undefined;
    first ??= sig;
  }
  return first;
}

function machoSignature(data: Buffer, start: number, end: number): CodeSignature | undefined {
  if (start + 4 > end) return undefined;
  const magic = data.readUInt32LE(start);
  if (magic !== MH_MAGIC && magic !== MH_MAGIC_64) return undefined;
  const headerSize = magic === MH_MAGIC_64 ? 32 : 28;
  if (start + headerSize > end) return undefined;
  const ncmds = data.readUInt32LE(start + 16);

  let cmdPtr = start + headerSize;
  for (let i = 0; i < ncmds; i++) {
    if (cmdPtr + 8 > end) return undefined;
    const cmd = data.readUInt32LE(cmdPtr);
    const cmdsize = data.readUInt32LE(cmdPtr + 4);
    if (cmdsize < 8 || cmdPtr + cmdsize > end) return undefined;
    if (cmd === LC_CODE_SIGNATURE && cmdsize >= 16) {
      const dataoff = start + data.readUInt32LE(cmdPtr + 8);
      const datasize = data.readUInt32LE(cmdPtr + 12);
      if (dataoff + datasize > end) return undefined;
      return parseEmbeddedSignature(data.subarray(dataoff, dataoff + datasize));
    }
    cmdPtr += cmdsize;
  }
  return undefined;
}

/** Parse a code-signing SuperBlob (all fields big-endian); only CMS-signed blobs count as signed. */
function parseEmbeddedSignature(blob: Buffer): CodeSignature | undefined {
  if (blob.length < 12 || blob.readUInt32BE(0) !== CSMAGIC_EMBEDDED_SIGNATURE) return undefined;
  const count = blob.readUInt32BE(8);

  let hasCms = false;
  let identity: string | undefined;
  for (let i = 0; i < count; i++) {
    const entry = 12 + i * 8;
    if (entry + 8 > blob.length) break;
    const type = blob.readUInt32BE(entry);
    const offset = blob.readUInt32BE(entry + 4);
    if (offset + 8 > blob.length) continue;
    if (type === CSSLOT_CMS_SIGNATURE) {
      // An ad-hoc signature carries an empty (8-byte) CMS wrapper.
      hasCms = blob.readUInt32BE(offset + 4) > 8;
    } else if (type === CSSLOT_CODEDIRECTORY) {
      identity = codeDirectoryIdentity(blob, offset);
    }
  }
  return hasCms ? { format: 'macho', identity } : undefined;
}

function codeDirectoryIdentity(blob: Buffer, dir: number): string | undefined {
  if (dir + 52 > blob.length || blob.readUInt32BE(dir) !== CSMAGIC_CODEDIRECTORY) return undefined;
  const version = blob.readUInt32BE(dir + 8);
  if (version >= CS_SUPPORTSTEAMID) {
    const teamOffset = blob.readUInt32BE(dir + 48);
    if (teamOffset !== 0) {
      const team = cString(blob, dir + teamOffset);
      if (team) return `Team ID ${team}`;
    }
  }
  const identifier = cString(blob, dir + blob.readUInt32BE(dir + 20));
  return identifier ? `identifier ${identifier}` : undefined;
}

function cString(data: Buffer, offset: number): string {
  if (offset < 0 || offset >= data.length) return '';
  let end = offset;
  while (end < data.length && data[end] !== 0) end++;
  return data.subarray(offset, end).toString('utf8');
}

// ---------------------------------------------------------------------------
// PE (Authenticode)
// ---------------------------------------------------------------------------

const WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002;
const CERTIFICATE_TABLE_INDEX = 4;

function peSignature(data: Buffer): CodeSignature | undefined {
  if (data.length < 0x40) return undefined;
  const peOffset = data.readUInt32LE(0x3c);
  if (peOffset + 24 > data.length || data.readUInt32LE(peOffset) !== 0x00004550) return undefined;

  const sizeOfOptionalHeader = data.readUInt16LE(peOffset + 20);
  const optHeader = peOffset + 24;
  const isPe32Plus = data.readUInt16LE(optHeader) === 0x20b;
  const dirEntry = optHeader + (isPe32Plus ? 112 : 96) + CERTIFICATE_TABLE_INDEX * 8;
  if (dirEntry + 8 > optHeader + sizeOfOptionalHeader || dirEntry + 8 > data.length) {
    return undefined;
  }

  // Unlike other data directories, the certificate table address is a raw file offset.
  const tableOffset = data.readUInt32LE(dirEntry);
  const tableSize = data.readUInt32LE(dirEntry + 4);
  if (tableOffset === 0 || tableSize < 8 || tableOffset + 8 > data.length) return undefined;

  const certLength = data.readUInt32LE(tableOffset);
  const certType = data.readUInt16LE(tableOffset + 6);
  if (certType !== WIN_CERT_TYPE_PKCS_SIGNED_DATA || certLength <= 8) return undefined;

  const pkcs7 = data.subarray(tableOffset + 8, Math.min(tableOffset + certLength, data.length));
  return { format: 'pe', identity: pkcs7SignerIdentity(pkcs7) };
}

interface Tlv {
  tag: number;
  /** Offset of the tag byte. */
  start: number;
  /** Offset of the first content byte. */
  body: number;
  /** Offset one past the last content byte. */
  end: number;
}

function readTlv(buf: Buffer, pos: number): Tlv | undefined {
  if (pos + 2 > buf.length) return undefined;
  const tag = buf[pos];
  const first = buf[pos + 1];
  let length = first;
  let body = pos + 2;
  if (first & 0x80) {
    const n = first & 0x7f;
    if (n === 0 || n > 4 || pos + 2 + n > buf.length) return undefined; // indefinite or oversized
    length = 0;
    for (let i = 0; i < n; i++) length = length * 256 + buf[pos + 2 + i];
    body = pos + 2 + n;
  }
  if (body + length > buf.length) return undefined;
  return { tag, start: pos, body, end: body + length };
}

function children(buf: Buffer, parent: Tlv): Tlv[] {
  const result: Tlv[] = [];
  let pos = parent.body;
  while (pos < parent.end) {
    const tlv = readTlv(buf, pos);
    if (!tlv) break;
    result.push(tlv);
    pos = tlv.end;
  }
  return result;
}

const normalizeSerial = (hex: string): string => hex.toUpperCase().replace(/^0+/, '');

/** Resolve the signer certificate of a PKCS#7 SignedData blob and return its organization (or CN). */
function pkcs7SignerIdentity(pkcs7: Buffer): string | undefined {
  try {
    const contentInfo = readTlv(pkcs7, 0);
    const explicit = contentInfo && children(pkcs7, contentInfo)[1]; // [0] EXPLICIT content
    const signedDataSeq = explicit && children(pkcs7, explicit)[0];
    if (!signedDataSeq) return undefined;

    // SignedData: version, digestAlgorithms, contentInfo, [0] certificates, [1] crls?, signerInfos
    const parts = children(pkcs7, signedDataSeq);
    const certsField = parts.find((p) => p.tag === 0xa0);
    const signerInfos = parts[parts.length - 1];
    if (!certsField || signerInfos?.tag !== 0x31) return undefined;

    const certs = children(pkcs7, certsField)
      .filter((c) => c.tag === 0x30)
      .map((c) => new X509Certificate(pkcs7.subarray(c.start, c.end)));

    // SignerInfo: version, issuerAndSerialNumber { issuer, serialNumber }, ...
    const signerInfo = children(pkcs7, signerInfos)[0];
    const issuerAndSerial = signerInfo && children(pkcs7, signerInfo)[1];
    const serialTlv = issuerAndSerial && children(pkcs7, issuerAndSerial)[1];
    const serial =
      serialTlv && normalizeSerial(pkcs7.subarray(serialTlv.body, serialTlv.end).toString('hex'));

    const leaf = certs.find((c) => normalizeSerial(c.serialNumber) === serial);
    return leaf ? subjectIdentity(leaf.subject) : undefined;
  } catch {
    return undefined;
  }
}

function subjectIdentity(subject: string): string | undefined {
  const field = (key: string) =>
    subject
      .split('\n')
      .find((line) => line.startsWith(`${key}=`))
      ?.slice(key.length + 1)
      .replace(/\\,/g, ',');
  return field('O') ?? field('CN');
}
