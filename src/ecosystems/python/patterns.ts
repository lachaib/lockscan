import { CI_NAME, GENERIC_SECRET_NAME } from '../shared/ci-env.js';
import type { Pattern } from '../shared/scan.js';

// `os.environ["NAME"]`, `os.environ.get("NAME")` and `os.getenv("NAME")`.
const envAccess = (name: string): RegExp =>
  new RegExp(`os\\.(?:environ(?:\\.get)?|getenv)\\s*[(\\[]\\s*['"]${name}['"]`);

export const DANGEROUS_PATTERNS: Pattern[] = [
  // Builtins only: `re.compile(...)` or `model.eval()` are attribute calls, `builtins.eval(...)` is not.
  { regex: /(?<![.\w])(?:_{0,2}builtins_{0,2}\.)?eval\s*\(/, label: 'exec:eval' },
  { regex: /(?<![.\w])(?:_{0,2}builtins_{0,2}\.)?exec\s*\(/, label: 'exec:exec' },
  { regex: /(?<![.\w])(?:_{0,2}builtins_{0,2}\.)?compile\s*\(/, label: 'exec:compile' },
  { regex: /\b__import__\s*\(/, label: 'exec:__import__' },
  { regex: /\bimportlib\.import_module\b/, label: 'exec:importlib' },
  // Dynamic module loading from a file path (used to execute a dropped payload)
  { regex: /\bimportlib\.util\.spec_from_file_location\s*\(/, label: 'exec:dynamic-load-path' },
  { regex: /\bos\.system\s*\(/, label: 'shell:os.system' },
  { regex: /\bos\.popen\s*\(/, label: 'shell:os.popen' },
  { regex: /\bsubprocess\.(run|Popen|call|check_output)\b/, label: 'shell:subprocess' },
  { regex: /\bpickle\.loads\s*\(/, label: 'deser:pickle' },
  { regex: /\bmarshal\.loads\s*\(/, label: 'deser:marshal' },
  { regex: /\byaml\.load\s*\(/, label: 'deser:yaml.load' },
  { regex: /\bbase64\.b64decode\s*\(/, label: 'obfusc:base64' },
  { regex: /\bbytes\.fromhex\s*\(/, label: 'obfusc:fromhex' },
  { regex: /\\x[0-9a-fA-F]{2}/, label: 'obfusc:hex-escape' },
  {
    regex:
      /\b(?:import|from)\s+(?:requests|httpx|aiohttp|ftplib|smtplib|urllib3|urllib\.request|http\.client|websockets?)\b|\bfrom\s+urllib\s+import\s+request\b|(?<![.\w])(?:requests|httpx|aiohttp|ftplib|smtplib|urllib3|urllib\.request|http\.client)\.\w/,
    label: 'net:http-lib',
  },
  {
    regex:
      /\bsocket\.(socket|connect|create_connection)\b|\basyncio\.(?:open_connection|start_server)\b/,
    label: 'net:raw-socket',
  },
  {
    regex: /\bsocket\.(?:gethostbyname(?:_ex)?|getaddrinfo)\b|\bdns\.resolver\b/,
    label: 'net:dns',
  },
  { regex: /\bopen\s*\([^)]*["']w/, label: 'fs:file-write' },
  { regex: /\bos\.(remove|unlink)\s*\(/, label: 'fs:file-delete' },
  { regex: /\bshutil\.rmtree\s*\(/, label: 'fs:dir-delete' },
  // Native library loading via ctypes / cffi (can bypass Python-level analysis entirely)
  { regex: /\bctypes\.CDLL\s*\(|ctypes\.cdll\.LoadLibrary\s*\(/, label: 'native:ctypes-load' },
  { regex: /\bcffi\.FFI\s*\(\)|ffi\.dlopen\s*\(/, label: 'native:cffi-load' },
  // Targeted CI / secret credential access
  { regex: envAccess(CI_NAME), label: 'cred:ci-token' },
  { regex: envAccess(GENERIC_SECRET_NAME), label: 'cred:generic-secret' },
];

/** Labels whose evidence is a string literal; they run on a view that keeps short strings. */
export const STRING_SCOPED_LABELS = new Set([
  'obfusc:hex-escape',
  'fs:file-write',
  'cred:ci-token',
  'cred:generic-secret',
]);

export const PY_EXTENSIONS = new Set(['.py']);
