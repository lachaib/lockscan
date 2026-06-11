/** Dangerous libc / OS symbols — a pure math or data library importing these is suspicious. */
const DANGEROUS_NATIVE_SYMBOLS = [
  // Network
  'socket',
  'connect',
  'bind',
  'recv',
  'recvfrom',
  'send',
  'sendto',
  'sendmsg',
  'getaddrinfo',
  'gethostbyname',
  'getnameinfo',
  'getpeername',
  // Process execution
  'system',
  'popen',
  'execve',
  'execl',
  'execle',
  'execlp',
  'execvp',
  'execvpe',
  'fork',
  'posix_spawn',
  'posix_spawnp',
  'CreateProcessA',
  'CreateProcessW',
  // Dynamic loading
  'dlopen',
  'dlsym',
  'LoadLibraryA',
  'LoadLibraryW',
  'GetProcAddress',
  // Privilege
  'setuid',
  'setgid',
  'seteuid',
  'setegid',
  // Memory protection
  'mprotect',
  'VirtualProtect',
  // File manipulation
  'chmod',
  'chown',
] as const;

const SYMBOL_SET = new Set<string>(DANGEROUS_NATIVE_SYMBOLS);

const SUSPICIOUS_STRING_PATTERNS: RegExp[] = [
  // biome-ignore lint/suspicious/noControlCharactersInRegex: intentional null-byte exclusion
  /https?:\/\/[^\s"'<>\x00]{10,}/,
  /\b(?:\d{1,3}\.){3}\d{1,3}\b/,
  /\/etc\/(?:passwd|shadow|hosts|crontab|sudoers)/,
  // biome-ignore lint/suspicious/noControlCharactersInRegex: intentional null-byte exclusion
  /\/tmp\/[^\s\x00]{3,}/,
  /[A-Za-z0-9+/]{48,}={0,2}/,
];

const HIGH_ENTROPY_THRESHOLD = 7.2;
const SYMBOL_COUNT_RATIO_THRESHOLD = 5;
const SYMBOL_COUNT_ABS_THRESHOLD = 5;

export interface BinaryScan {
  filename: string;
  /** How many times each dangerous symbol name appears in the binary's string data. */
  symbolCounts: Record<string, number>;
  /** Suspicious strings extracted from the binary (URLs, IPs, base64 blobs, etc.). */
  suspiciousStrings: string[];
  /** Shannon entropy of the binary — high values suggest packed/encrypted sections. */
  entropy: number;
}

export interface BinaryFinding {
  file: string;
  label: string;
  detail: string;
}

/** Extract runs of printable ASCII characters (≥ minLen) from a binary buffer. */
export function extractStrings(data: Buffer, minLen = 6): string[] {
  const result: string[] = [];
  let start = -1;
  for (let i = 0; i < data.length; i++) {
    const b = data[i];
    if (b >= 0x20 && b < 0x7f) {
      if (start === -1) start = i;
    } else {
      if (start !== -1 && i - start >= minLen) {
        result.push(data.subarray(start, i).toString('ascii'));
      }
      start = -1;
    }
  }
  if (start !== -1 && data.length - start >= minLen) {
    result.push(data.subarray(start).toString('ascii'));
  }
  return result;
}

export function shannonEntropy(data: Buffer): number {
  if (data.length === 0) return 0;
  const freq = new Uint32Array(256);
  for (let i = 0; i < data.length; i++) freq[data[i]]++;
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      const p = freq[i] / data.length;
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

export function scanBinary(filename: string, data: Buffer): BinaryScan {
  const strings = extractStrings(data);

  // Symbol name appears in .dynstr/.strtab as a null-terminated token — exact match captures it.
  const symbolCounts: Record<string, number> = {};
  for (const s of strings) {
    if (SYMBOL_SET.has(s)) {
      symbolCounts[s] = (symbolCounts[s] ?? 0) + 1;
    }
  }

  const seen = new Set<string>();
  const suspiciousStrings: string[] = [];
  for (const s of strings) {
    if (!seen.has(s) && SUSPICIOUS_STRING_PATTERNS.some((p) => p.test(s))) {
      seen.add(s);
      suspiciousStrings.push(s);
      if (suspiciousStrings.length >= 50) break;
    }
  }

  return { filename, symbolCounts, suspiciousStrings, entropy: shannonEntropy(data) };
}

/**
 * Compute what changed between old and new binary scans.
 * For added packages pass an empty Map for oldScans — all findings are then reported.
 */
export function binaryFindingsDelta(
  oldScans: Map<string, BinaryScan>,
  newScans: Map<string, BinaryScan>,
): BinaryFinding[] {
  const findings: BinaryFinding[] = [];

  for (const [filename, newScan] of newScans) {
    const oldScan = oldScans.get(filename);

    // Entropy spike (packed/encrypted section introduced or grown)
    if (newScan.entropy >= HIGH_ENTROPY_THRESHOLD) {
      const oldEntropy = oldScan?.entropy;
      if (oldEntropy === undefined || newScan.entropy > oldEntropy + 0.3) {
        findings.push({
          file: filename,
          label: 'binary:high-entropy',
          detail:
            oldEntropy !== undefined
              ? `entropy ${oldEntropy.toFixed(2)} → ${newScan.entropy.toFixed(2)}`
              : `entropy ${newScan.entropy.toFixed(2)} (new file)`,
        });
      }
    }

    // Symbol count changes — catches both newly imported symbols and significant count spikes
    const oldCounts = oldScan?.symbolCounts ?? {};
    for (const [sym, newCount] of Object.entries(newScan.symbolCounts)) {
      const oldCount = oldCounts[sym] ?? 0;
      if (newCount <= oldCount) continue;
      const isNew = oldCount === 0;
      const absIncrease = newCount - oldCount;
      const ratioExceeded = oldCount > 0 && newCount / oldCount >= SYMBOL_COUNT_RATIO_THRESHOLD;
      if (isNew || absIncrease >= SYMBOL_COUNT_ABS_THRESHOLD || ratioExceeded) {
        findings.push({
          file: filename,
          label: `native:${sym}`,
          detail: isNew ? `new symbol (count: ${newCount})` : `count: ${oldCount} → ${newCount}`,
        });
      }
    }

    // New suspicious strings not present in old version
    const oldStrSet = new Set(oldScan?.suspiciousStrings ?? []);
    for (const s of newScan.suspiciousStrings) {
      if (!oldStrSet.has(s)) {
        findings.push({
          file: filename,
          label: 'binary:new-string',
          detail: s.length > 100 ? `${s.slice(0, 100)}…` : s,
        });
      }
    }
  }

  return findings;
}
