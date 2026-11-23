import { CI_NAME, GENERIC_SECRET_NAME } from '../shared/ci-env.js';
import type { Pattern } from '../shared/scan.js';

// `process.env.NAME`, `process.env['NAME']` and `const { NAME } = process.env`.
const envAccess = (name: string): RegExp =>
  new RegExp(
    `process\\.env(?:\\.${name}(?![\\w$])|\\[\\s*['"\`]${name}['"\`]\\s*\\])|\\{[^}]*?(?<![\\w$])${name}(?![\\w$])[^}]*\\}\\s*=\\s*process\\.env\\b`,
  );

// Start of a module reference: require('x'), import('x'), `import x from 'x'`, `import 'x'`; an optional `node:` prefix follows.
const MODULE_REF = `(?:\\brequire\\s*\\(\\s*|\\bimport\\s*\\(\\s*|\\bfrom\\s+|\\bimport\\s+)['"](?:node:)?`;

export const DANGEROUS_PATTERNS: Pattern[] = [
  // Code execution
  { regex: /\beval\s*\(/, label: 'exec:eval' },
  { regex: /new\s+Function\s*\(/, label: 'exec:Function' },
  { regex: /\bvm\.(runIn|createContext|Script\b)/, label: 'exec:vm' },
  // Shell execution
  { regex: new RegExp(`${MODULE_REF}child_process['"]`), label: 'shell:require-child_process' },
  { regex: /\bexecSync\s*\(/, label: 'shell:execSync' },
  { regex: /\bspawnSync\s*\(/, label: 'shell:spawnSync' },
  { regex: /\bexecFileSync\s*\(/, label: 'shell:execFileSync' },
  // Dynamic require with computed module name (require(variable), require(env.X))
  {
    regex: /require\s*\(\s*(?:process\.env\b|global\b|[a-zA-Z_$][\w$]*\s*\+)/,
    label: 'exec:dynamic-require',
  },
  // Deserialization
  { regex: /\byaml\.load\s*\(/, label: 'deser:yaml.load' },
  { regex: /\bdeserialize\s*\(/, label: 'deser:generic' },
  // Obfuscation — encode-then-eval compounds (flatmap-stream / ua-parser-js pattern)
  { regex: /eval\s*\(\s*(?:Buffer\.from|atob)\s*\(/, label: 'obfusc:eval-decode' },
  { regex: /Buffer\.from\s*\([^,)]+,\s*['"]base64['"]/, label: 'obfusc:base64' },
  { regex: /String\.fromCharCode\s*\(/, label: 'obfusc:fromCharCode' },
  { regex: /\\x[0-9a-fA-F]{2}/, label: 'obfusc:hex-escape' },
  { regex: /\batob\s*\(/, label: 'obfusc:atob' },
  // Network
  { regex: new RegExp(`${MODULE_REF}(?:https?|http2)['"]`), label: 'net:http' },
  {
    regex: new RegExp(
      `${MODULE_REF}(?:undici|node-fetch|superagent|needle)['"]|\\bnew\\s+(?:XMLHttpRequest|WebSocket)\\s*\\(`,
    ),
    label: 'net:http-client',
  },
  { regex: new RegExp(`${MODULE_REF}(?:net|tls|dgram)['"]`), label: 'net:raw-socket' },
  { regex: new RegExp(`${MODULE_REF}dns(?:/promises)?['"]`), label: 'net:dns' },
  { regex: /\bfetch\s*\(/, label: 'net:fetch' },
  { regex: /\baxios\b/, label: 'net:axios' },
  { regex: /\bgot\s*\(/, label: 'net:got' },
  // Filesystem writes/deletes
  { regex: /\bwriteFileSync\s*\(/, label: 'fs:writeFileSync' },
  { regex: /\bappendFileSync\s*\(/, label: 'fs:appendFileSync' },
  { regex: /\brmSync\s*\(/, label: 'fs:rmSync' },
  { regex: /\bunlinkSync\s*\(/, label: 'fs:unlinkSync' },
  { regex: /\bfs\.promises\.(writeFile|rm|unlink|mkdir)\b/, label: 'fs:async-write' },
  // Process / environment
  { regex: /\bprocess\.env\b/, label: 'info:process.env' },
  // Targeted CI credential access
  { regex: envAccess(CI_NAME), label: 'cred:ci-token' },
  { regex: envAccess(GENERIC_SECRET_NAME), label: 'cred:generic-secret' },
  // Git credentials persisted by CI checkouts (http.<url>.extraheader, .git-credentials); literals only
  { regex: /\bextraheader\b|\.git-credentials\b/i, label: 'cred:git-credentials' },
  { regex: /(?<![\w.-])\.git[\\/]|['"`]\.git['"`]/, label: 'fs:git-dir' },
  // Prototype pollution (Object.prototype tampering)
  { regex: /__proto__\s*[:[{]/, label: 'inject:proto-pollution' },
  { regex: /Object\.defineProperty\s*\(\s*Object\.prototype/, label: 'inject:proto-pollution' },
];

export const JS_EXTENSIONS = new Set([
  '.js',
  '.mjs',
  '.cjs',
  '.jsx',
  '.ts',
  '.mts',
  '.cts',
  '.tsx',
]);
