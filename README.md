# lockscan

Security analysis of lockfile changes across ecosystems — consumes [lockdelta](https://github.com/nicolo-ribaudo/lockdelta) output and produces a structured threat report.

## Overview

When a dependency update lands in a pull request, most CI pipelines verify only that the build succeeds. `lockscan` runs a deeper pass: it downloads the new (and old) package artifacts, scans them across multiple detection dimensions, and flags anything that matches known supply-chain attack patterns.

```
lockdelta diff base.lock head.lock | lockscan
```

---

## Intelligence — what attacks this tool is designed to detect

The sections below map each detection dimension to the real-world attacks it would have caught, and explain how the detection works technically.

---

### 1. Static source pattern scanning

**What it detects:** Dangerous API calls introduced or increased by a version update.

Every source file inside the downloaded artifact is scanned with a catalogue of regular-expression patterns. The tool reports the full old/new hit count and a delta of patterns that are *new* in the updated version.

#### JavaScript / npm patterns

| Label | Pattern | Why it matters |
|---|---|---|
| `exec:eval` | `eval(` | Arbitrary code execution from a string |
| `exec:Function` | `new Function(` | Same as eval, slightly more obfuscated |
| `exec:vm` | `vm.runIn*`, `vm.Script` | Node sandboxed eval escape |
| `shell:require-child_process` | `require('child_process')` | Importing the shell execution module |
| `shell:execSync` / `spawnSync` / `execFileSync` | — | Direct shell execution |
| `exec:dynamic-require` | `require(process.env…)` or `require(var +…)` | Module loaded from a computed name — attacker can swap it at runtime |
| `deser:yaml.load` | `yaml.load(` | Unsafe YAML deserialization (use `yaml.safeLoad`) |
| `deser:generic` | `deserialize(` | Generic unsafe deserialization |
| `obfusc:eval-decode` | `eval(Buffer.from(…))` / `eval(atob(…))` | Decode-then-eval compound — the canonical obfuscation pattern used in **flatmap-stream (2018)** and **ua-parser-js (2021)** |
| `obfusc:base64` | `Buffer.from(…, 'base64')` | Encoded payload |
| `obfusc:fromCharCode` | `String.fromCharCode(` | Character-code obfuscation, used in many npm attacks |
| `obfusc:hex-escape` | `\xNN` sequences | Hex-encoded strings to bypass simple scanners |
| `obfusc:atob` | `atob(` | Base64 decode in browser-targeting code |
| `net:http` / `net:fetch` / `net:axios` / `net:got` | — | Outbound network I/O — expected in a network library, suspicious in a math/utility package |
| `fs:writeFileSync` / `fs:async-write` / `fs:rmSync` / `fs:unlinkSync` | — | Filesystem writes and deletes |
| `info:process.env` | `process.env` | Environment variable access |
| `cred:ci-token` | `process.env.GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `NPM_TOKEN`, `CI_JOB_TOKEN`, `CIRCLE_TOKEN`, `VERCEL_TOKEN`, `CODECOV_TOKEN`, `FIREBASE_TOKEN`, `HEROKU_API_KEY`, `NODE_AUTH_TOKEN` | Targeted CI credential exfiltration — exact pattern used in **event-stream (2018)**, **ctx (2022)**, **dbus-next (2022)** |
| `inject:proto-pollution` | `__proto__` assignment or `Object.defineProperty(Object.prototype…)` | Prototype pollution enabling property injection across the entire runtime |

#### Python patterns

| Label | Pattern | Why it matters |
|---|---|---|
| `exec:eval` / `exec:exec` / `exec:compile` | — | String-to-code execution |
| `exec:__import__` / `exec:importlib` | `__import__(`, `importlib.import_module(` | Dynamic import from string — can load modules the static scanner would miss |
| `exec:dynamic-load-path` | `importlib.util.spec_from_file_location(` | Loads a Python module from a filesystem path — used to execute a payload dropped to `/tmp` |
| `shell:os.system` / `shell:os.popen` | — | Shell execution via the OS module |
| `shell:subprocess` | `subprocess.run`, `Popen`, `call`, `check_output` | Full subprocess spawn |
| `deser:pickle` / `deser:marshal` | `pickle.loads(`, `marshal.loads(` | Arbitrary code execution hidden in a serialized object |
| `deser:yaml.load` | `yaml.load(` without `Loader=SafeLoader` | Unsafe YAML deserialization |
| `obfusc:base64` / `obfusc:fromhex` / `obfusc:hex-escape` | — | Encoded payload techniques |
| `net:http-lib` | `requests`, `httpx`, `aiohttp`, `ftplib`, `smtplib` | Network I/O libraries |
| `net:raw-socket` | `socket.socket(`, `socket.connect(`, `create_connection(` | Raw TCP/UDP connections — unusual outside of networking packages |
| `fs:file-write` / `fs:file-delete` / `fs:dir-delete` | `open(…,'w')`, `os.remove(`, `shutil.rmtree(` | Filesystem modification and deletion |
| `native:ctypes-load` | `ctypes.CDLL(`, `ctypes.cdll.LoadLibrary(` | Loads a shared library dynamically — bypasses Python-level analysis entirely |
| `native:cffi-load` | `cffi.FFI()`, `ffi.dlopen(` | Same via the C Foreign Function Interface |
| `cred:ci-token` | `os.environ[…'GITHUB_TOKEN']`, `AWS_ACCESS_KEY_ID`, `PYPI_TOKEN`, `TWINE_PASSWORD`, `CODECOV_TOKEN` | Targeted CI credential exfiltration in Python |

---

### 2. Binary wheel scanning

**What it detects:** Malicious code hidden inside compiled extensions (`.so`, `.pyd`, `.dylib`, `.dll`) that static Python source scanning cannot reach.

**Why it matters:** PyO3 (Rust) and C/C++ extensions are opaque to source scanners. An attacker distributing a compiled backdoor is invisible to any tool that only reads `.py` files. This is the threat vector behind the **3CX supply-chain attack (2023)**, where a legitimate Windows installer was trojaned with a compiled DLL payload.

**How it works:** For each binary file extracted from a wheel:

- **String extraction:** Runs of printable ASCII characters (≥ 6 chars) are extracted from the raw binary, mimicking `strings(1)`. These reveal URLs, IP addresses, file paths, and other artefacts that compiled code cannot hide.
- **Dangerous native symbols:** The extracted strings are matched against a list of libc / Windows API symbols (socket, connect, execve, system, popen, dlopen, CreateProcessA, setuid, mprotect, …). A library that legitimately uses these will already have them in the old version; a *new* or *spiking* symbol count is the signal.
- **Shannon entropy:** A high-entropy region (threshold 7.2 bits/byte) indicates packed or encrypted data — the classic signature of a payload that decrypts itself at runtime.
- **Suspicious embedded strings:** URLs, IP addresses, `/etc/passwd`-style paths, `/tmp/…` paths, and long base64-like blobs are flagged.

**Delta analysis:** The tool compares old and new binary scans so that a library that legitimately imports `socket` does not generate noise — only *changes* between versions are reported.

---

### 3. Platform divergence detection

**What it detects:** Different compiled wheels for the same package version carrying different security findings across platforms.

**Why it matters:** An attacker can publish a benign `linux_x86_64` wheel alongside a malicious `win_amd64` wheel for the same version. Most scanners only test against one platform. `lockscan` tests all platforms in the configured matrix and raises a `PLATFORM DIVERGENCE` warning if the finding sets differ.

---

### 4. Post-install hooks

**What it detects:** Code that runs automatically at install time — before the user's application imports anything.

#### npm lifecycle scripts

npm executes `preinstall`, `install`, `postinstall`, `prepare`, and `prepublish` scripts defined in `package.json` automatically during `npm install`. This is the most common supply-chain vector in npm: it requires zero import by the victim.

**Attacks caught:** Virtually every major npm supply-chain incident has used postinstall scripts: **event-stream (2018)**, **eslint-scope (2018)**, **ua-parser-js (2021)**, **node-ipc (2022)**, **colors.js (2022)**.

The tool diffs hooks between the old and new version and flags any hook that is *new* or whose command *changed*.

#### Python .pth files

`.pth` files placed in a site-packages directory are processed by Python's `site` module at interpreter startup. Any line that begins with `import` is executed as Python code — before the user's script runs, before any virtualenv activation, and before any audit hook can fire.

#### Python data scripts

Wheel files may contain executables in `*.data/scripts/` that are installed into the Python `bin/` directory (alongside `pip`, `python`, etc.) and become available system-wide. A malicious script installed here runs whenever the user uses their Python environment.

---

### 5. Repository release matching

**What it detects:** A package version that has no corresponding tagged release in its source repository — or more importantly, a version where the *previous* version had a release tag but the *current* one does not.

**Why it matters:** Legitimate maintainers tag releases. A version published to the registry without a corresponding source tag means the distributed artifact was *not built from the tagged source*. It may have been built from a modified working tree, a CI pipeline tampered with after the tag, or submitted directly without any source-to-artifact traceability.

The `releaseDropped` flag specifically targets the case where an attacker takes over an existing package: the old maintainer tagged releases diligently, but the new actor published directly to the registry to avoid leaving a public paper trail.

**Supported:** GitHub (requires `GITHUB_TOKEN` for rate limits). GitLab support is a planned addition.

---

### 6. Known vulnerability database (OSV)

**What it detects:** Package versions with already-known CVEs or security advisories at the time of the update.

The tool queries [osv.dev](https://osv.dev) — the same database used by `pip audit` and `uv audit` — using a two-step approach: one batch call to get affected advisory IDs, then parallel fetches for full advisory details. Results include severity (CRITICAL / HIGH / MODERATE / LOW), CVE aliases, and a link to the advisory.

**Why it matters:** An updated dependency might already be known-compromised before your scan runs. This catches the case where someone pins to a version flagged in OSV.

---

### 7. Registry change and dependency confusion

**What it detects:** Packages that switched registry source, or whose version number matches the hallmarks of a dependency confusion attack.

**Dependency confusion** (discovered by Alex Birsan, 2021): if a private package `acme-utils` exists only in your internal registry, an attacker can publish `acme-utils` to the public npm / PyPI registry with a very high version number. Package managers that check the public registry first will resolve to the attacker's version.

Detection heuristics:
- **Major version ≥ 100:** The classic confusion signal — no real package reaches v100+ without warning.
- **Round high version (e.g. 99.0.0):** Attacker sets an implausibly round version to win the resolver.
- **Private → public registry switch:** The resolved registry URL changed from an internal host to npmjs.org / pypi.org.
- **New package added directly from public registry with suspiciously high version.**


---

### 8. npm publisher change

**What it detects:** A package version published by a different npm account than all previous versions.

**Why it matters:** This is the literal mechanism of the **event-stream (2018)** attack. The original maintainer (dominictarr) transferred the package to a contributor (right9ctrl) who had no prior publishing history for the package. The npm registry records `_npmUser` per version, making this detectable.

The tool compares `_npmUser.name` between the old and new version metadata and flags any change.

---

### 9. Version freshness (sniper-pattern)

**What it detects:** Package versions published within the last 24 hours.

**Why it matters:** Supply-chain attackers often publish a malicious version just before a scheduled deployment window — the "sniper" pattern. The malicious version may be pulled within hours once discovered, but damage is done to any pipeline that ran during that window. A freshness flag does not mean the package is malicious, but it warrants a manual review before merging.

The tool surfaces `versionAgeDays` (days since that specific version was published) and raises a `FRESH PUBLISH` summary warning for any package with `versionAgeDays < 1`.

---

### 10. License change detection

**What it detects:** A package that changed its declared license between the old and new version.

**Why it matters:** A license change from a permissive license (MIT, Apache 2.0) to a proprietary, copyleft, or "source-available" license can affect your legal compliance posture. It may also be a signal of an ownership change — a new maintainer relicensing to monetize an existing install base (as happened with several HashiCorp and Elastic products).

---

### 11. Build system file changes (XZ-style injection)

**What it detects:** Modifications to build configuration files — the files that control how source code is compiled into a package.

**Why it matters:** The **XZ Utils backdoor (CVE-2024-3094, March 2024)** is the most sophisticated supply-chain attack on record. The attacker (Jia Tan, an identity that turned out to be fictitious) spent two years contributing legitimate patches before injecting a backdoor through modifications to `configure.ac` and `Makefile.am`. The payload was compiled into `liblzma` during the build, was absent from the source tree, and bypassed review because it arrived as seemingly routine build-system fixes.

Monitored files:
- **Python / general:** `setup.py`, `setup.cfg`, `pyproject.toml`, `CMakeLists.txt`, `configure.ac`, `configure.in`, `Makefile.am`, `Makefile.in`
- **npm native add-ons:** `binding.gyp`, `binding.gyp.json` — the build descriptor for native C/C++ Node.js modules. A package that previously shipped pure JavaScript adding a `binding.gyp` now compiles native code on install.

Any of these files being added, removed, or modified between the old and new version triggers a `BUILD SYSTEM FILES CHANGED` warning.

---

### 12. New binary wheels (sdist → wheel transition)

**What it detects:** A Python package that previously shipped only a source distribution (`.tar.gz`) now includes compiled binary wheels (`.whl`).

**Why it matters:** Source distributions are fully readable Python source. Binary wheels contain compiled code that cannot be statically analyzed without reverse-engineering tools. The transition from sdist-only to wheel-distribution is a meaningful security boundary change: the same code audit that worked for the old version is now insufficient for the new one. Several PyPI malware campaigns have used this pattern — publishing a benign sdist to establish a reputation, then adding a malicious wheel in a later version.

---

## Artifact verification

For every downloaded artifact, `lockscan` verifies the cryptographic hash against the value published by the registry:

- **PyPI:** SHA-256 from the JSON API — the same hash that `pip` verifies
- **npm:** SHA-1 (`shasum`) from the version metadata, with `integrity` (SHA-512) available

A hash mismatch is a hard error — the artifact is rejected and the analysis is aborted for that package.

---

## Platform-aware wheel selection

For Python packages, `lockscan` needs to pick the right wheel for each target platform. The selection algorithm implements the PEP 425 compatibility tag matching:

1. **Python tag:** Exact CPython version match (e.g. `cp312`) scores highest; `py3` / `py2.py3` (pure Python) scores lower; wrong CPython version or PyPy is incompatible.
2. **Platform tag:** Matches `linux_x86_64` / `manylinux`, `macosx_*_arm64` / `universal2`, `win_amd64` / `win_arm64`.

Each target platform in the configured matrix gets the best-scoring wheel. Unique artifacts (by SHA-256) are deduplicated, preserving which platforms they serve. If no wheel matches, the sdist is used as a fallback (with binary scanning skipped).

---

## Configuration

### CLI

```bash
lockscan [options] < diff.json
lockdelta diff base.lock head.lock | lockscan [options]
```

| Option | Description |
|---|---|
| `--platform <spec>` | Target platform(s). Format: `os/arch[/pyver]` (e.g. `linux/x86_64/3.12`, `macos/arm64`). Repeatable. Defaults to current host. |
| `--only <types>` | Restrict to `added`, `updated`, or `removed`. Comma-separated. |
| `--format json\|text` | Output format. Default: `text`. |

### Environment variables

| Variable | Effect |
|---|---|
| `GITHUB_TOKEN` | GitHub personal access token for the repo release check. Without it, the GitHub API rate limit applies (60 requests/hour per IP). |

### Platform auto-detection

If no `--platform` is specified, `lockscan` detects the current OS and architecture. For the Python version, it reads (in order):

1. `.python-version` in the working directory
2. `[tool.python]` or `[tool.rye]` tables in `pyproject.toml`

---

## GitHub Action

`lockscan` ships as a GitHub Action (`lachaib/lockscan`). It consumes the JSON diff produced by [lockdelta](https://github.com/nicolo-ribaudo/lockdelta) and surfaces findings as step annotations, a step summary, PR comments, and/or a SARIF report.

### Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `lockdelta-output` | yes | — | The lockdelta JSON diff. Accepts a raw JSON string (e.g. `${{ steps.lockdelta.outputs.diff }}`) or a file path written by lockdelta's `json-to-file` option. |
| `github-token` | no | `${{ github.token }}` | GitHub token for the repo release check and PR comment posting. |
| `platform` | no | host platform | Target platform(s). Format: `os/arch[/pyver]` (e.g. `linux/x86_64/3.12`, `macos/arm64`). Comma- or newline-separated. |
| `only` | no | all | Restrict analysis to specific change types. Comma-separated: `added`, `updated`, `removed`. |
| `markdown` | no | `false` | Generate a markdown summary and expose it as the `summary` output. |
| `markdown-to-file` | no | — | Write the markdown summary to this file path. |
| `sarif-to-file` | no | — | Write a SARIF 2.1.0 report to this file path. Use with `actions/upload-sarif` to surface findings in the Security / Code Scanning tab. |
| `annotate` | no | `true` | Emit workflow annotations on the dependency manifest file for each finding. Set to `false` to disable. |
| `post-comment` | no | `false` | Post or update a PR comment with the markdown summary. `true` always posts/updates. `if-findings` posts when findings exist and updates to a "resolved" message when clean. `false` never posts. |
| `fail-on` | no | `never` | Fail the step when findings at or above this severity are detected: `critical`, `high`, `any`, or `never`. |
| `write-summary` | no | `true` | Write the markdown summary to the GitHub step summary (`$GITHUB_STEP_SUMMARY`). Set to `false` to disable. |

### Outputs

| Output | Description |
|---|---|
| `report` | Full security report as a JSON string. |
| `summary` | Markdown summary of findings. Set when `markdown: true` or `post-comment` is enabled. |
| `sarif` | SARIF 2.1.0 report as a JSON string. Only set when `sarif-to-file` is specified. |
| `has-findings` | `true` if any security findings were identified, `false` otherwise. |
| `has-critical` | `true` if any CRITICAL severity findings were identified. |
| `has-high` | `true` if any HIGH or CRITICAL severity findings were identified. |

### Examples

#### Basic — annotations and step summary

```yaml
on: [pull_request]

jobs:
  lockscan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
    steps:
      - name: Diff dependencies
        id: lockdelta
        uses: lachaib/lockdelta@v0.1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - uses: lachaib/lockscan@v0.1.0
        with:
          lockdelta-output: ${{ steps.lockdelta.outputs.diff }}
```

#### Fail on high-severity findings

```yaml
      - uses: lachaib/lockscan@v0.1.0
        with:
          lockdelta-output: ${{ steps.lockdelta.outputs.diff }}
          fail-on: high
```

#### SARIF upload to GitHub Code Scanning

```yaml
      - uses: lachaib/lockscan@v0.1.0
        id: lockscan
        with:
          lockdelta-output: ${{ steps.lockdelta.outputs.diff }}
          sarif-to-file: lockscan.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: lockscan.sarif
```

#### PR comment with automatic resolution message

```yaml
    permissions:
      contents: read
      pull-requests: write
    ...

      - uses: lachaib/lockscan@v0.1.0
        with:
          lockdelta-output: ${{ steps.lockdelta.outputs.diff }}
          post-comment: if-findings
          fail-on: any
```

#### Multi-platform Python project

```yaml
      - uses: lachaib/lockscan@v0.1.0
        with:
          lockdelta-output: ${{ steps.lockdelta.outputs.diff }}
          platform: |
            linux/x86_64/3.12
            macos/arm64/3.12
            linux/arm64/3.12
```

---

## Output format

```
=== LOCKSCAN SECURITY REPORT ===
Generated:   2025-06-09T14:32:01.000Z
Base ref:    main
Head ref:    feature/upgrade-deps
Analyzed:    12 package(s) — 0 error(s)
New hits:    3 new security pattern hit(s)
⚠ BINARY ANOMALIES: 1 package(s) have suspicious changes in compiled extensions
⚠ KNOWN VULNERABILITIES: 2 known CVE/advisory across changed packages (OSV)
⚠ PUBLISHER CHANGE: 1 package(s) published by a different npm account than before

══════════════════════════════════════════════════════════════
[1/12] some-package  UPDATED  1.2.3 → 1.2.4  (direct)
══════════════════════════════════════════════════════════════

VERIFICATION
  platforms: linux x86_64 (Python 3.12)
  old: some_package-1.2.3-cp312-cp312-manylinux_2_17_x86_64.whl [linux x86_64 (Python 3.12)]
    sha256: abc123…  STATUS:VERIFIED
  new: some_package-1.2.4-cp312-cp312-manylinux_2_17_x86_64.whl [linux x86_64 (Python 3.12)]
    sha256: def456…  STATUS:VERIFIED

METADATA DELTA
  ⚠ PUBLISHER CHANGED (different npm account)
  author:       unchanged
  homepage:     unchanged
  license:      unchanged
  deps_added:   none
  deps_removed: none

BINARY SCAN
  delta: 2 anomaly(ies)
  by type:
    native:socket: 1
    binary:high-entropy: 1
  detail:
    libfoo.so — native:socket: new symbol (count: 1)
    libfoo.so — binary:high-entropy: entropy 6.91 → 7.34

SECURITY SCAN
  old_hits: 2 hit(s)
  new_hits: 2 hit(s)
  delta: +1 new hit(s) not in old version
```

---

## Programmatic API

```typescript
import { analyze } from 'lockscan';
import type { DiffReport } from 'lockdelta';

const report = await analyze(diffReport, {
  platforms: [{ os: 'linux', arch: 'x86_64', python: '3.12' }],
  onlyTypes: ['added', 'updated'],
});

for (const lf of report.lockfiles) {
  for (const pkg of lf.packages) {
    if (pkg.binaryFindings?.delta.length) {
      console.warn(`Binary anomaly in ${pkg.name}@${pkg.newVersion}`);
    }
  }
}
```

---

## Attack reference

The table below summarises real supply-chain incidents and which detection(s) in `lockscan` would have flagged them.

| Incident | Year | Vector | lockscan detection |
|---|---|---|---|
| event-stream | 2018 | Maintainer transfer + postinstall payload targeting Bitcoin wallets | Post-install hooks, publisher change, `cred:ci-token` patterns, `obfusc:eval-decode` |
| eslint-scope | 2018 | Compromised npm account published malicious version | Publisher change, post-install hooks |
| flatmap-stream | 2018 | Malicious transitive dep with AES-encrypted payload | `obfusc:eval-decode`, binary entropy (if compiled), post-install hooks |
| ua-parser-js | 2021 | Account hijack, crypto miner + trojan | Publisher change, post-install hooks, `obfusc:eval-decode` |
| PyTorch nightly | 2022 | Dependency confusion: `torchtriton` on PyPI shadowed private package | Registry/confusion check (high version heuristic) |
| ctx / dbus-next | 2022 | Malicious PyPI packages exfiltrating env vars | `cred:ci-token`, `net:http-lib` patterns |
| node-ipc (protestware) | 2022 | Maintainer added destructive code targeting Russian/Belarusian IPs | Pattern scan (`fs:dir-delete`), build system check |
| colors.js / faker.js | 2022 | Maintainer sabotage (infinite loop) | Pattern scan, version freshness |
| 3CX | 2023 | Trojanised Windows installer via compromised upstream | Binary scan (symbol/entropy), platform divergence |
| XZ Utils | 2024 | Build system injection via `configure.ac` over 2 years | Build system files changed, binary scan (symbol changes), release dropped |
| Polyfill.io | 2024 | CDN domain acquired, serving malware to sites that depended on it | Registry change, repo check |

---

## Limitations and roadmap

- **Typosquatting / homoglyph detection:** Comparing added package names against a popularity-ranked list (npm top-5000, PyPI top-5000) with Levenshtein distance ≤ 2 is not yet implemented. This would catch campaigns like `crossenv` (targeting `cross-env`) and hundreds of similar attacks.
- **Transitive dependency analysis:** `lockscan` analyses direct changes reported by `lockdelta`. If a trusted package adds a malicious new dependency, the *dependency itself* is flagged if it appears in the lockfile diff, but the relationship is not visualised.
- **GitLab / Bitbucket release checks:** Only GitHub is supported for repo release matching.
