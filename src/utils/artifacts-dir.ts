import { mkdir, mkdtemp } from 'node:fs/promises';
import { join, resolve } from 'node:path';

/** Creates a unique lockscan-owned subdirectory under `dir`, so only what lockscan created is ever deleted. */
export async function prepareArtifactsDir(dir: string, base: string): Promise<string> {
  const parent = resolve(base, dir);
  await mkdir(parent, { recursive: true });
  return mkdtemp(join(parent, 'lockscan-'));
}
