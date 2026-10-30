import { rm } from 'node:fs/promises';
import * as core from '@actions/core';

(async () => {
  const dir = core.getState('artifacts-dir');
  if (!dir) return;
  try {
    await rm(dir, { recursive: true, force: true });
  } catch (err) {
    core.warning(`lockscan: could not remove ${dir}: ${err instanceof Error ? err.message : err}`);
  }
})();
