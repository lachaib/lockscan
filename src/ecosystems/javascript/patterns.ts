import type { Pattern } from '../shared/scan.js';

export const DANGEROUS_PATTERNS: Pattern[] = [
  // Code execution
  { regex: /\beval\s*\(/, label: 'exec:eval' },
  { regex: /new\s+Function\s*\(/, label: 'exec:Function' },
  { regex: /\bvm\.(runIn|createContext|Script\b)/, label: 'exec:vm' },
  // Shell execution
  { regex: /require\s*\(\s*['"]child_process['"]/, label: 'shell:require-child_process' },
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
  { regex: /require\s*\(\s*['"]https?['"]/, label: 'net:http' },
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
  // Targeted CI credential access (event-stream / ctx / dbus-next pattern)
  {
    regex:
      /process\.env\.(GITHUB_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|CI_JOB_TOKEN|CIRCLE_TOKEN|VERCEL_TOKEN|CODECOV_TOKEN|FIREBASE_TOKEN|HEROKU_API_KEY)/,
    label: 'cred:ci-token',
  },
  // Prototype pollution (Object.prototype tampering)
  { regex: /__proto__\s*[:[{]/, label: 'inject:proto-pollution' },
  { regex: /Object\.defineProperty\s*\(\s*Object\.prototype/, label: 'inject:proto-pollution' },
];

export const JS_EXTENSIONS = new Set(['.js', '.mjs', '.cjs']);
