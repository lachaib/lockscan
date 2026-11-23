import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as tar from 'tar';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { JSR_EXTENSIONS } from '../../../src/ecosystems/deno/patterns.js';
import { DANGEROUS_PATTERNS, JS_EXTENSIONS } from '../../../src/ecosystems/javascript/patterns.js';
import { scanPatterns } from '../../../src/ecosystems/shared/scan.js';
import { extractTarball } from '../../../src/utils/extract.js';

const labels = (src: string): string[] =>
  scanPatterns(new Map([['a.js', src]]), DANGEROUS_PATTERNS).map((f) => f.label);

describe('shell:require-child_process — module syntaxes', () => {
  it.each([
    "const cp = require('child_process');",
    "const cp = require('node:child_process');",
    "import { execSync } from 'node:child_process';",
    'import * as cp from "child_process";',
    "import 'child_process';",
    "const cp = await import('node:child_process');",
  ])('flags %s', (src) => {
    expect(labels(src)).toContain('shell:require-child_process');
  });

  it('does not flag look-alike module names', () => {
    expect(labels("import x from 'my-child_process-wrapper';")).not.toContain(
      'shell:require-child_process',
    );
    expect(labels("import x from './child_process_utils';")).not.toContain(
      'shell:require-child_process',
    );
  });
});

describe('JS_EXTENSIONS', () => {
  it('includes TypeScript and JSX sources', () => {
    for (const ext of ['.js', '.mjs', '.cjs', '.jsx', '.ts', '.mts', '.cts', '.tsx']) {
      expect(JS_EXTENSIONS.has(ext)).toBe(true);
      expect(JSR_EXTENSIONS.has(ext)).toBe(true);
    }
  });
});

describe('extractTarball — TypeScript sources', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'lockscan-ts-test-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('collects .ts sources and ignores declaration files', async () => {
    const pkg = join(dir, 'src-tree', 'package');
    await mkdir(join(pkg, 'src'), { recursive: true });
    await writeFile(join(pkg, 'src', 'run.ts'), "import { execSync } from 'node:child_process';");
    await writeFile(join(pkg, 'src', 'run.mts'), 'export {};');
    await writeFile(join(pkg, 'src', 'types.d.ts'), "import 'child_process';");
    await writeFile(join(pkg, 'src', 'types.d.mts'), 'export {};');
    const archive = join(dir, 'pkg.tgz');
    await tar.c({ gzip: true, cwd: join(dir, 'src-tree'), file: archive }, ['package']);

    const files = await extractTarball(await readFile(archive), join(dir, 'out'), JS_EXTENSIONS);

    expect([...files.keys()].sort()).toEqual(['src/run.mts', 'src/run.ts']);
    expect(
      scanPatterns(files, DANGEROUS_PATTERNS).some(
        (f) => f.label === 'shell:require-child_process',
      ),
    ).toBe(true);
  });
});

describe('network patterns — JS', () => {
  it.each([
    ["const https = require('https');", 'net:http'],
    ["const https = require('node:https');", 'net:http'],
    ["import https from 'node:https';", 'net:http'],
    ["import { request } from 'http2';", 'net:http'],
    ["const h = await import('node:http');", 'net:http'],
    ["import { request } from 'undici';", 'net:http-client'],
    ["const f = require('node-fetch');", 'net:http-client'],
    ['const x = new XMLHttpRequest();', 'net:http-client'],
    ["const ws = new WebSocket('wss://x.example');", 'net:http-client'],
    ["import net from 'node:net';", 'net:raw-socket'],
    ["const tls = require('tls');", 'net:raw-socket'],
    ["import dgram from 'dgram';", 'net:raw-socket'],
    ["import dns from 'node:dns/promises';", 'net:dns'],
    ["const dns = require('dns');", 'net:dns'],
  ])('%s -> %s', (src, label) => {
    expect(labels(src)).toContain(label);
  });

  it('does not match look-alikes', () => {
    expect(labels("import x from './http-utils';")).not.toContain('net:http');
    expect(labels("import x from 'my-net';")).not.toContain('net:raw-socket');
    expect(labels('prefetch(url)')).not.toContain('net:fetch');
    expect(labels("import x from 'dnsmasq';")).not.toContain('net:dns');
  });
});
