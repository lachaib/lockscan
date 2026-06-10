import { createHash } from 'node:crypto';

export function sha256hex(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

export function verifySha256(data: Buffer, expected: string): void {
  const actual = sha256hex(data);
  if (actual !== expected) {
    throw new Error(`SHA256 mismatch\n  expected: ${expected}\n  actual:   ${actual}`);
  }
}
