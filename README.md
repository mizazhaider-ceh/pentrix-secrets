# pentrix-secrets

![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Dependencies: zero](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey.svg)

A fast, zero-dependency secret scanner. Point it at a file or a directory and it flags exposed API keys, tokens and private keys, one finding per line as `file:line:rule`. Standard library only, so it runs anywhere Python 3 exists, including CI runners.

## Contents

- [Features](#features)
- [Screenshots](#screenshots)
- [Detection rules](#detection-rules)
- [Install](#install)
- [Usage](#usage)
  - [Scan a directory](#scan-a-directory)
  - [JSON output](#json-output)
  - [Exclude paths and scan top level only](#exclude-paths-and-scan-top-level-only)
  - [Use in CI](#use-in-ci)
- [When it finds something](#when-it-finds-something)
- [False positives](#false-positives)
- [Ethical use](#ethical-use)
- [License](#license)

## Features

- 9 detection rules covering AWS, GitHub, GitLab, Slack, Google, Stripe, generic API key assignments and private key blocks
- Recursive directory scanning (on by default for directories)
- `--redact` masks matched secrets in output for safe logs and CI
- `--json` for machine-readable output
- `--exclude` patterns to skip `.git`, `node_modules`, `__pycache__`, `.venv` (skipped by default) or anything you name
- Binary files are detected and skipped gracefully
- CI-friendly exit codes: `1` when findings exist, `0` when clean, `2` on bad input

## Screenshots

Findings on the shipped test fixtures, with secrets redacted:

![Scan with redacted findings](docs/images/scan-redacted.png)

Machine-readable JSON output:

![JSON output mode](docs/images/scan-json.png)

Built-in help:

![Help output](docs/images/help.png)

## Detection rules

| Rule | What it matches |
|---|---|
| AWS Access Key ID | `AKIA` followed by 16 uppercase alphanumerics |
| AWS Secret Key Assignment | `aws_secret_access_key = "..."` style assignments |
| GitHub Token | `ghp_...`, `gho_...`, `github_pat_...` |
| GitLab Token | `glpat-...` |
| Slack Token | `xoxb-...`, `xoxa-...`, `xoxp-...` |
| Generic API Key Assignment | `api_key = "..."`, `api-key: "..."`, `secret = "..."` and similar |
| Private Key Block | `-----BEGIN ... PRIVATE KEY-----` headers |
| Google API Key | `AIza...` (39 chars) |
| Stripe Secret Key | `sk_live_...`, `rk_live_...`, `sk_test_...` |

## Install

```bash
git clone https://github.com/mizazhaider-ceh/pentrix-secrets.git
cd pentrix-secrets
python3 secrets.py --help
```

No dependencies. No virtualenv. Python 3 is the only requirement.

## Usage

### Scan a directory

Recursive by default. The repo ships planted fake secrets under `tests/fixtures/`, so you can try it safely:

```bash
$ python3 secrets.py tests/fixtures/ --redact
tests/fixtures/aws.env:1:AWS Access Key ID: AKIA...MPLE (redacted)
tests/fixtures/github.py:1:GitHub Token: ghp_...1234 (redacted)
tests/fixtures/key.pem:1:Private Key Block: ----...---- (redacted)
```

(All fixture values are planted fakes, shown here with `--redact` masking.)

### JSON output

```bash
$ python3 secrets.py tests/fixtures/github.py --redact --json
[
  {
    "file": "tests/fixtures/github.py",
    "line": 1,
    "rule": "GitHub Token",
    "snippet": "ghp_...1234 (redacted)"
  }
]
```

### Exclude paths and scan top level only

```bash
$ python3 secrets.py . --exclude .git node_modules vendor --no-recursive --redact
```

### Use in CI

Fail the build when a secret is found:

```bash
$ python3 secrets.py . --redact || echo "secrets found, failing build"
```

Exit codes: `0` = clean, `1` = findings, `2` = bad path or unreadable input.

## When it finds something

1. **Rotate the secret immediately.** Assume anything the scanner saw is compromised.
2. Revoke the old value in the provider's dashboard (AWS IAM, GitHub settings, etc.).
3. Check whether it was ever committed: `git log -p -S 'the-secret'` and scrub history if needed (or rotate and move on for throwaway repos).
4. Move the secret to an environment variable or a secrets manager. Never hardcode it again.

## False positives

Regexes trade precision for coverage, so expect noise:

- Example keys from docs and tutorials (like `AKIAIOSFODNN7EXAMPLE`) will match. That is by design: better a flagged example than a missed real key.
- Long random strings assigned to `api_key` or `secret` variables match the generic rule even when they are not real credentials.
- `--exclude` is your friend: point it at vendored code, fixtures and test data you know are safe.

If a rule keeps firing on something harmless, exclude the path rather than ignoring the whole report.

## Ethical use

Only scan code you own or have explicit permission to test: your own projects, your employer's repos, or systems covered by a bug bounty scope or written authorization. Never point this tool at someone else's systems, leaked data, or code you are not authorized to review. The `tests/fixtures/` directory contains planted fake secrets for safe demos; do not use real credentials anywhere near this tool's examples.

## License

MIT. See [LICENSE](LICENSE).
