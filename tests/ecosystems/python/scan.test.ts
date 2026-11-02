import { describe, expect, it } from 'vitest';
import { maskPython } from '../../../src/ecosystems/python/mask.js';
import { scanPythonPatterns } from '../../../src/ecosystems/python/scan.js';

const labels = (src: string) => scanPythonPatterns(new Map([['m.py', src]])).map((f) => f.label);

describe('maskPython', () => {
  it('keeps offsets and line breaks', () => {
    const src = '# c\nx = "a\\"b"  # t\ny = """d\ne"""\n';
    const { code, text } = maskPython(src);
    expect(code).toHaveLength(src.length);
    expect(text).toHaveLength(src.length);
    expect(code.split('\n')).toHaveLength(src.split('\n').length);
  });

  it('does not treat a # inside a string as a comment', () => {
    expect(maskPython('x = "# not a comment"; eval(y)').code).toContain('eval(y)');
  });

  it('keeps f-string bodies because they hold expressions', () => {
    expect(maskPython('f"{exec(p)}"').code).toContain('exec(p)');
  });
});

describe('scanPythonPatterns — false positives from issue #22', () => {
  it.each([
    ['re.compile', '_SEGMENT_RE = re.compile(r"^(?P<name>[A-Za-z0-9_]+)$")'],
    ['method compile', 'return _JSONPATH.compile(path)'],
    ['string literal', 'REQUESTS_METRIC: Literal["requests"] = "requests"'],
    ['comment', '# Keep this module independent of the optional httpx and aiohttp packages'],
    ['docstring', 'def f():\n    """two CodeType.replace() clones, or two exec()\'d copies"""\n'],
    ['torch eval', 'model.eval()'],
  ])('ignores %s', (_name, src) => {
    expect(labels(src)).toEqual([]);
  });
});

describe('scanPythonPatterns — real hits are kept', () => {
  it.each([
    ['exec:eval', 'eval(payload)'],
    ['exec:exec', 'exec(code, ns)'],
    ['exec:compile', 'c = compile(src, "<s>", "exec")'],
    ['exec:eval', 'builtins.eval(x)'],
    ['exec:exec', 'f"{exec(payload)}"'],
    ['net:http-lib', 'import requests'],
    ['net:http-lib', 'from aiohttp import ClientSession'],
    ['net:http-lib', 'requests.post(url, data=d)'],
    ['shell:os.system', 'os.system("id")'],
    ['obfusc:hex-escape', 'p = "\\x41\\x42"'],
    ['fs:file-write', 'open(path, "w")'],
    ['cred:ci-token', 'os.environ.get("GITHUB_TOKEN")'],
  ])('%s in `%s`', (label, src) => {
    expect(labels(src)).toContain(label);
  });

  it('reports the right line after masked docstrings', () => {
    const [finding] = scanPythonPatterns(
      new Map([['m.py', '"""doc\nwith eval( inside\n"""\neval(x)\n']]),
    );
    expect(finding).toMatchObject({ label: 'exec:eval', line: 4 });
  });
});
