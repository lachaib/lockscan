import type { Pattern } from '../shared/scan.js';

export const DANGEROUS_PATTERNS: Pattern[] = [
  { regex: /\beval\s*\(/, label: 'exec:eval' },
  { regex: /\bexec\s*\(/, label: 'exec:exec' },
  { regex: /\bcompile\s*\(/, label: 'exec:compile' },
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
  { regex: /\b(requests|httpx|aiohttp|ftplib|smtplib)\b/, label: 'net:http-lib' },
  { regex: /\bsocket\.(socket|connect|create_connection)\b/, label: 'net:raw-socket' },
  { regex: /\bopen\s*\([^)]*["']w/, label: 'fs:file-write' },
  { regex: /\bos\.(remove|unlink)\s*\(/, label: 'fs:file-delete' },
  { regex: /\bshutil\.rmtree\s*\(/, label: 'fs:dir-delete' },
  // Native library loading via ctypes / cffi (can bypass Python-level analysis entirely)
  { regex: /\bctypes\.CDLL\s*\(|ctypes\.cdll\.LoadLibrary\s*\(/, label: 'native:ctypes-load' },
  { regex: /\bcffi\.FFI\s*\(\)|ffi\.dlopen\s*\(/, label: 'native:cffi-load' },
  // Targeted CI / secret credential access (similar to event-stream pattern but in Python)
  {
    regex:
      /os\.environ(?:\.get)?\s*\(?\s*['"](?:GITHUB_TOKEN|NPM_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|CI_JOB_TOKEN|CIRCLE_TOKEN|PYPI_TOKEN|TWINE_PASSWORD|CODECOV_TOKEN)/,
    label: 'cred:ci-token',
  },
];

export const PY_EXTENSIONS = new Set(['.py']);
