import { describe, expect, it } from 'vitest';
import { DANGEROUS_PATTERNS } from '../../../src/ecosystems/php/patterns.js';
import { detectComposerHooks } from '../../../src/ecosystems/shared/install-hooks.js';
import { scanPatterns } from '../../../src/ecosystems/shared/scan.js';
import type { FileMap } from '../../../src/utils/extract.js';

function files(entries: Record<string, string>): FileMap {
  return new Map(Object.entries(entries));
}

describe('scanPatterns — php: code execution', () => {
  it('detects eval', () => {
    const findings = scanPatterns(
      files({ 'src/Loader.php': '<?php eval($userInput);' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'exec:eval')).toBe(true);
  });

  it('detects create_function', () => {
    const findings = scanPatterns(
      files({ 'src/Func.php': '<?php $fn = create_function("$a", "return $a;");' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'exec:create_function')).toBe(true);
  });

  it('detects call_user_func', () => {
    const findings = scanPatterns(
      files({ 'src/Dispatch.php': '<?php call_user_func($handler, $args);' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'exec:call_user_func')).toBe(true);
  });

  it('detects call_user_func_array', () => {
    const findings = scanPatterns(
      files({ 'src/Dispatch.php': '<?php call_user_func_array($fn, $args);' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'exec:call_user_func_array')).toBe(true);
  });
});

describe('scanPatterns — php: shell execution', () => {
  it('detects exec', () => {
    const findings = scanPatterns(
      files({ 'src/Runner.php': '<?php exec("ls -la");' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'shell:exec')).toBe(true);
  });

  it('detects shell_exec', () => {
    const findings = scanPatterns(
      files({ 'src/Runner.php': '<?php $out = shell_exec("id");' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'shell:shell_exec')).toBe(true);
  });

  it('detects system', () => {
    const findings = scanPatterns(
      files({ 'src/Runner.php': '<?php system("whoami");' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'shell:system')).toBe(true);
  });

  it('detects passthru', () => {
    const findings = scanPatterns(
      files({ 'src/Runner.php': '<?php passthru($cmd);' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'shell:passthru')).toBe(true);
  });

  it('detects proc_open', () => {
    const findings = scanPatterns(
      files({ 'src/Proc.php': '<?php $p = proc_open($cmd, $descriptors, $pipes);' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'shell:proc_open')).toBe(true);
  });

  it('detects backtick operator', () => {
    const findings = scanPatterns(
      files({ 'src/Runner.php': '<?php $result = `ls -la`;' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'shell:backtick')).toBe(true);
  });
});

describe('scanPatterns — php: deserialization', () => {
  it('detects unserialize', () => {
    const findings = scanPatterns(
      files({ 'src/Cache.php': '<?php $obj = unserialize($data);' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'deser:unserialize')).toBe(true);
  });
});

describe('scanPatterns — php: obfuscation', () => {
  it('detects base64_decode', () => {
    const findings = scanPatterns(
      files({ 'src/Payload.php': '<?php $code = base64_decode($input);' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'obfusc:base64_decode')).toBe(true);
  });

  it('detects eval+base64_decode compound', () => {
    const findings = scanPatterns(
      files({ 'src/Loader.php': '<?php eval(base64_decode("dGVzdA=="));' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'obfusc:eval-decode')).toBe(true);
  });

  it('detects gzinflate', () => {
    const findings = scanPatterns(
      files({ 'src/Packed.php': '<?php eval(gzinflate($data));' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'obfusc:gzinflate')).toBe(true);
  });

  it('detects str_rot13', () => {
    const findings = scanPatterns(
      files({ 'src/Obfusc.php': '<?php echo str_rot13($str);' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'obfusc:str_rot13')).toBe(true);
  });
});

describe('scanPatterns — php: network I/O', () => {
  it('detects fsockopen', () => {
    const findings = scanPatterns(
      files({ 'src/Http.php': '<?php $sock = fsockopen("example.com", 80);' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'net:fsockopen')).toBe(true);
  });

  it('detects curl_exec', () => {
    const findings = scanPatterns(
      files({ 'src/Client.php': '<?php $result = curl_exec($ch);' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'net:curl_exec')).toBe(true);
  });

  it('detects file_get_contents with URL', () => {
    const findings = scanPatterns(
      files({ 'src/Fetch.php': '<?php $data = file_get_contents("https://example.com/data");' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'net:file_get_contents-url')).toBe(true);
  });

  it('does not flag file_get_contents on local paths', () => {
    const findings = scanPatterns(
      files({ 'src/Reader.php': '<?php $data = file_get_contents("/tmp/file.txt");' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'net:file_get_contents-url')).toBe(false);
  });
});

describe('scanPatterns — php: environment access', () => {
  it('detects getenv', () => {
    const findings = scanPatterns(
      files({ 'src/Config.php': '<?php $key = getenv("API_KEY");' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'info:getenv')).toBe(true);
  });

  it('detects CI credential access', () => {
    const findings = scanPatterns(
      files({ 'src/Exfil.php': '<?php $token = getenv("GITHUB_TOKEN");' }),
      DANGEROUS_PATTERNS,
    );
    expect(findings.some((f) => f.label === 'cred:ci-token')).toBe(true);
  });
});

describe('scanPatterns — php: clean code produces no findings', () => {
  it('returns empty for a clean class', () => {
    const findings = scanPatterns(
      files({
        'src/Service.php': `<?php
namespace Acme\\Service;

class UserService
{
    public function __construct(private readonly string $name) {}

    public function greet(): string
    {
        return "Hello, {$this->name}!";
    }
}
`,
      }),
      DANGEROUS_PATTERNS,
    );
    expect(findings).toHaveLength(0);
  });
});

describe('detectComposerHooks', () => {
  it('detects post-install-cmd script', () => {
    const f = files({
      'composer.json': JSON.stringify({
        name: 'vendor/pkg',
        scripts: {
          'post-install-cmd': 'php artisan migrate',
          test: 'phpunit',
        },
      }),
    });
    const hooks = detectComposerHooks(f);
    expect(hooks).toHaveLength(1);
    expect(hooks[0].name).toBe('post-install-cmd');
    expect(hooks[0].command).toBe('php artisan migrate');
    expect(hooks[0].type).toBe('composer-script');
  });

  it('joins array commands with &&', () => {
    const f = files({
      'composer.json': JSON.stringify({
        scripts: {
          'post-install-cmd': ['php artisan cache:clear', 'php artisan config:cache'],
        },
      }),
    });
    const hooks = detectComposerHooks(f);
    expect(hooks[0].command).toBe('php artisan cache:clear && php artisan config:cache');
  });

  it('ignores non-lifecycle scripts', () => {
    const f = files({
      'composer.json': JSON.stringify({
        scripts: { test: 'phpunit', lint: 'phpcs' },
      }),
    });
    expect(detectComposerHooks(f)).toHaveLength(0);
  });

  it('detects multiple lifecycle hooks', () => {
    const f = files({
      'composer.json': JSON.stringify({
        scripts: {
          'pre-install-cmd': 'echo before',
          'post-install-cmd': 'echo after',
          'post-autoload-dump': 'php generate.php',
        },
      }),
    });
    const hooks = detectComposerHooks(f);
    expect(hooks).toHaveLength(3);
  });

  it('returns empty when no composer.json', () => {
    expect(detectComposerHooks(new Map())).toHaveLength(0);
  });

  it('returns empty when scripts section is absent', () => {
    const f = files({ 'composer.json': JSON.stringify({ name: 'vendor/pkg' }) });
    expect(detectComposerHooks(f)).toHaveLength(0);
  });
});
