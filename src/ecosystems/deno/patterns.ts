import { DANGEROUS_PATTERNS as JS_PATTERNS } from '../javascript/patterns.js';
import type { Pattern } from '../shared/scan.js';

// Deno native APIs not covered by the JS pattern set
const DENO_PATTERNS: Pattern[] = [
  // Subprocess execution
  { regex: /\bnew\s+Deno\.Command\s*\(/, label: 'exec:Deno.Command' },
  { regex: /\bDeno\.run\s*\(/, label: 'exec:Deno.run' },
  // File system writes / deletes
  { regex: /\bDeno\.writeFile\s*\(/, label: 'fs:Deno.writeFile' },
  { regex: /\bDeno\.writeTextFile\s*\(/, label: 'fs:Deno.writeTextFile' },
  { regex: /\bDeno\.remove\s*\(/, label: 'fs:Deno.remove' },
  // Environment access
  { regex: /\bDeno\.env\.(?:get|toObject|has)\s*\(/, label: 'info:Deno.env' },
  // CI token targeting via Deno.env
  {
    regex:
      /Deno\.env\.get\s*\(\s*['"](?:GITHUB_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|CI_JOB_TOKEN|CIRCLE_TOKEN|VERCEL_TOKEN|CODECOV_TOKEN|FIREBASE_TOKEN|HEROKU_API_KEY)['"]/,
    label: 'cred:ci-token',
  },
  // Raw TCP/TLS connections — typical C2 exfiltration channel
  { regex: /\bDeno\.connect\s*\(/, label: 'net:Deno.connect' },
  { regex: /\bDeno\.connectTls\s*\(/, label: 'net:Deno.connectTls' },
  // Dynamic import with a computed URL or env-controlled string.
  // Uniquely dangerous in Deno: URLs are first-class module identifiers,
  // so import(Deno.env.get('X')) loads arbitrary remote code.
  {
    regex: /\bimport\s*\(\s*(?:Deno\.env\.|[a-zA-Z_$][\w$]*\s*\+|`[^`]*\${)/,
    label: 'exec:dynamic-import',
  },
];

// Combined pattern set used for all Deno packages (npm: and jsr:).
// The Node.js-specific patterns (require, execSync, …) are harmless on JSR source —
// they simply won't match — so one unified set keeps the logic simple.
export const DANGEROUS_PATTERNS: Pattern[] = [...JS_PATTERNS, ...DENO_PATTERNS];

// npm: packages ship compiled JS, same extensions as the JS ecosystem.
export const NPM_EXTENSIONS = new Set(['.js', '.mjs', '.cjs']);

// jsr: packages are TypeScript source; also include .js/.mjs for generated output.
export const JSR_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.mjs', '.jsx']);
