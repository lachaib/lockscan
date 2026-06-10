import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: { index: 'src/index.ts' },
    format: ['esm'],
    target: 'node20',
    dts: true,
    clean: true,
    sourcemap: true,
  },
  {
    entry: { cli: 'src/cli.ts' },
    format: ['esm'],
    target: 'node20',
    dts: false,
    banner: { js: '#!/usr/bin/env node' },
    sourcemap: true,
  },
  {
    entry: { action: 'src/action.ts' },
    format: ['cjs'],
    target: 'node24',
    dts: false,
    sourcemap: true,
    // Bundle all npm packages into the single CJS file — the Actions runner
    // does not install node_modules from the repo.
    noExternal: [/.*/],
  },
]);
