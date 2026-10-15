import { describe, expect, it } from 'vitest';
import { binaryFindingsDelta, scanBinary } from '../../../src/ecosystems/shared/binary-scan.js';
import { extractCodeSignature } from '../../../src/ecosystems/shared/binary-signature.js';
import {
  buildElf,
  buildFatMachO,
  buildSignedMachO,
  buildSignedPe,
  PKCS7_ACME,
  PKCS7_EVIL,
} from './binary-fixtures.js';

describe('extractCodeSignature — Mach-O', () => {
  it('returns the Team ID of a CMS-signed (Developer ID) binary', () => {
    const buf = buildSignedMachO({ identifier: 'ruff', teamId: 'ABCDE12345', cms: true });
    expect(extractCodeSignature(buf)).toEqual({ format: 'macho', identity: 'Team ID ABCDE12345' });
  });

  it('falls back to the signing identifier when there is no Team ID', () => {
    const buf = buildSignedMachO({ identifier: 'com.example.tool', cms: true });
    expect(extractCodeSignature(buf)?.identity).toBe('identifier com.example.tool');
  });

  it('treats an ad-hoc signature (empty CMS slot) as unsigned', () => {
    const buf = buildSignedMachO({ identifier: 'ruff', cms: false });
    expect(extractCodeSignature(buf)).toBeUndefined();
  });

  it('requires every slice of a universal binary to be signed', () => {
    const signed = buildSignedMachO({ identifier: 'ruff', teamId: 'ABCDE12345', cms: true });
    const adhoc = buildSignedMachO({ identifier: 'ruff', cms: false });
    expect(extractCodeSignature(buildFatMachO([signed, signed]))?.identity).toBe(
      'Team ID ABCDE12345',
    );
    expect(extractCodeSignature(buildFatMachO([signed, adhoc]))).toBeUndefined();
  });
});

describe('extractCodeSignature — PE Authenticode', () => {
  it('returns the organization of the signer certificate', () => {
    expect(extractCodeSignature(buildSignedPe(PKCS7_ACME))).toEqual({
      format: 'pe',
      identity: 'Acme Software Inc.',
    });
  });

  it('returns undefined for an unsigned PE', () => {
    expect(extractCodeSignature(buildSignedPe())).toBeUndefined();
  });

  it('keeps the binary signed but without identity when the PKCS#7 blob is garbage', () => {
    const sig = extractCodeSignature(buildSignedPe(Buffer.from('not der at all')));
    expect(sig).toEqual({ format: 'pe', identity: undefined });
  });
});

describe('extractCodeSignature — robustness', () => {
  it('returns undefined for ELF and truncated input', () => {
    expect(extractCodeSignature(buildElf([{ name: 'malloc', undefined: true }]))).toBeUndefined();
    expect(extractCodeSignature(Buffer.from([0xcf, 0xfa]))).toBeUndefined();
    const truncated = buildSignedMachO({ identifier: 'x', teamId: 'T', cms: true }).subarray(0, 60);
    expect(extractCodeSignature(truncated)).toBeUndefined();
  });
});

describe('binaryFindingsDelta — signature regressions', () => {
  const scan = (buf: Buffer) => new Map([['bin/tool', scanBinary('bin/tool', buf)]]);
  const signedMac = (teamId: string) => buildSignedMachO({ identifier: 'tool', teamId, cms: true });

  it('flags a signature that disappeared', () => {
    const findings = binaryFindingsDelta(
      scan(signedMac('ABCDE12345')),
      scan(buildSignedMachO({ identifier: 'tool', cms: false })),
    );
    expect(findings).toEqual([
      {
        file: 'bin/tool',
        label: 'binary:signature-dropped',
        detail: 'Team ID ABCDE12345 → unsigned',
      },
    ]);
  });

  it('flags a changed Mach-O signer', () => {
    const findings = binaryFindingsDelta(
      scan(signedMac('ABCDE12345')),
      scan(signedMac('ZZZZZ99999')),
    );
    expect(findings.map((f) => f.label)).toEqual(['binary:signer-changed']);
    expect(findings[0].detail).toBe('Team ID ABCDE12345 → Team ID ZZZZZ99999');
  });

  it('flags a changed Authenticode signer', () => {
    const findings = binaryFindingsDelta(
      scan(buildSignedPe(PKCS7_ACME)),
      scan(buildSignedPe(PKCS7_EVIL)),
    );
    expect(findings).toEqual([
      {
        file: 'bin/tool',
        label: 'binary:signer-changed',
        detail: 'Acme Software Inc. → Evil Corp',
      },
    ]);
  });

  it('stays silent when the same signer re-signs, or when nothing was signed before', () => {
    expect(
      binaryFindingsDelta(scan(signedMac('ABCDE12345')), scan(signedMac('ABCDE12345'))),
    ).toEqual([]);
    expect(binaryFindingsDelta(scan(buildSignedPe()), scan(buildSignedPe(PKCS7_ACME)))).toEqual([]);
    expect(binaryFindingsDelta(new Map(), scan(buildSignedPe(PKCS7_ACME)))).toEqual([]);
  });

  it('does not compare signer identities across signing schemes', () => {
    const findings = binaryFindingsDelta(
      scan(signedMac('ABCDE12345')),
      scan(buildSignedPe(PKCS7_ACME)),
    );
    expect(findings).toEqual([]);
  });
});
