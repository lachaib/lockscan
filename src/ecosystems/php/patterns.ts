import { CI_NAME, GENERIC_SECRET_NAME } from '../shared/ci-env.js';
import type { Pattern } from '../shared/scan.js';

// `getenv('NAME')`, `$_ENV['NAME']` and `$_SERVER['NAME']`.
const envAccess = (name: string): RegExp =>
  new RegExp(`(?:getenv\\s*\\(|\\$_(?:ENV|SERVER)\\s*\\[)\\s*['"]${name}['"]`);

export const DANGEROUS_PATTERNS: Pattern[] = [
  // Code execution
  { regex: /\beval\s*\(/, label: 'exec:eval' },
  { regex: /\bcreate_function\s*\(/, label: 'exec:create_function' },
  { regex: /\bcall_user_func\s*\(/, label: 'exec:call_user_func' },
  { regex: /\bcall_user_func_array\s*\(/, label: 'exec:call_user_func_array' },
  { regex: /\bpreg_replace\s*\(\s*['"][^'"]*e['"]/, label: 'exec:preg_replace-e-modifier' },
  // Shell execution
  { regex: /\bexec\s*\(/, label: 'shell:exec' },
  { regex: /\bshell_exec\s*\(/, label: 'shell:shell_exec' },
  { regex: /\bsystem\s*\(/, label: 'shell:system' },
  { regex: /\bpassthru\s*\(/, label: 'shell:passthru' },
  { regex: /\bpopen\s*\(/, label: 'shell:popen' },
  { regex: /\bproc_open\s*\(/, label: 'shell:proc_open' },
  { regex: /\bpcntl_exec\s*\(/, label: 'shell:pcntl_exec' },
  // Backtick shell operator
  { regex: /`[^`]+`/, label: 'shell:backtick' },
  // Deserialization — unserialize() with untrusted data is a classic PHP RCE vector
  { regex: /\bunserialize\s*\(/, label: 'deser:unserialize' },
  { regex: /\byaml_parse\s*\(/, label: 'deser:yaml_parse' },
  // Obfuscation
  { regex: /\bbase64_decode\s*\(/, label: 'obfusc:base64_decode' },
  { regex: /\bstr_rot13\s*\(/, label: 'obfusc:str_rot13' },
  { regex: /\bgzinflate\s*\(/, label: 'obfusc:gzinflate' },
  { regex: /\bgzuncompress\s*\(/, label: 'obfusc:gzuncompress' },
  { regex: /\bhex2bin\s*\(/, label: 'obfusc:hex2bin' },
  { regex: /\\x[0-9a-fA-F]{2}/, label: 'obfusc:hex-escape' },
  // eval-then-decode compounds (commonly used to hide payloads)
  {
    regex: /eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|hex2bin)\s*\(/,
    label: 'obfusc:eval-decode',
  },
  // Network I/O
  { regex: /\bfsockopen\s*\(/, label: 'net:fsockopen' },
  { regex: /\bstream_socket_client\s*\(/, label: 'net:stream_socket_client' },
  { regex: /\bcurl_(?:exec|multi_exec|init)\s*\(/, label: 'net:curl_exec' },
  { regex: /\b(?:dns_get_record|gethostbyname|checkdnsrr)\s*\(/, label: 'net:dns' },
  // file_get_contents is dual-use; flag when called with a URL-like argument
  { regex: /\b(?:file_get_contents|fopen)\s*\(\s*['"]https?:/, label: 'net:file_get_contents-url' },
  // Filesystem writes / deletes
  { regex: /\bfile_put_contents\s*\(/, label: 'fs:file_put_contents' },
  { regex: /\bfwrite\s*\(/, label: 'fs:fwrite' },
  { regex: /\bunlink\s*\(/, label: 'fs:unlink' },
  { regex: /\brmdir\s*\(/, label: 'fs:rmdir' },
  // Environment / process info access
  { regex: /\bgetenv\s*\(/, label: 'info:getenv' },
  { regex: /\$_ENV\b/, label: 'info:$_ENV' },
  { regex: /\$_SERVER\b/, label: 'info:$_SERVER' },
  // Targeted CI credential access
  { regex: envAccess(CI_NAME), label: 'cred:ci-token' },
  { regex: envAccess(GENERIC_SECRET_NAME), label: 'cred:generic-secret' },
];

export const PHP_EXTENSIONS = new Set(['.php', '.phtml', '.php5', '.php7', '.phps']);
