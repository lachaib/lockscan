import { readFileSync } from 'node:fs';
import { Command } from 'commander';
import type { DiffReport } from 'lockdelta';
import { formatReport } from './core/report.js';
import { analyze } from './index.js';
import type { Platform } from './platforms.js';
import { parsePlatform, parsePlatforms } from './platforms.js';

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
}

const program = new Command();

program
  .name('lockscan')
  .description(
    'Security analysis of lockfile changes across ecosystems — consumes lockdelta output',
  )
  .option('--input <file>', 'lockdelta JSON output file (default: stdin)')
  .option(
    '--platform <spec>',
    'platform to analyze: os/arch[/python], e.g. linux/arm64/3.12 (repeatable; overrides LOCKSCAN_PLATFORMS)',
    (val: string, prev: Platform[]) => [...prev, parsePlatform(val)],
    [] as Platform[],
  )
  .option(
    '--only <types>',
    'comma-separated change types to analyze: added,updated,removed (default: all)',
  )
  .option('--format <fmt>', 'output format: text|json (default: text)', 'text')
  .action(async (opts: { input?: string; platform: Platform[]; only?: string; format: string }) => {
    const raw = opts.input ? readFileSync(opts.input, 'utf8') : await readStdin();

    let input: DiffReport;
    try {
      input = JSON.parse(raw) as DiffReport;
    } catch (err) {
      process.stderr.write(`ERROR: invalid JSON input — ${err}\n`);
      process.exit(1);
    }

    // Platform resolution order: --platform flags > LOCKSCAN_PLATFORMS env var > auto-detect
    let platforms: Platform[] | undefined;
    if (opts.platform.length > 0) {
      platforms = opts.platform;
    } else if (process.env.LOCKSCAN_PLATFORMS) {
      try {
        platforms = parsePlatforms(process.env.LOCKSCAN_PLATFORMS);
      } catch (err) {
        process.stderr.write(`ERROR: LOCKSCAN_PLATFORMS — ${err}\n`);
        process.exit(1);
      }
    }
    // if still undefined, analyzer.ts falls back to host + pyproject.toml detection

    const report = await analyze(input, {
      platforms,
      onlyTypes: opts.only ? opts.only.split(',') : undefined,
    });

    if (opts.format === 'json') {
      process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    } else {
      process.stdout.write(formatReport(report) + '\n');
    }
  });

program.parseAsync(process.argv).catch((err: unknown) => {
  process.stderr.write(`ERROR: ${err}\n`);
  process.exit(1);
});
