# pentrix-secrets

![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

A fast, zero-dependency secret scanner. Point it at a file or a directory and it flags exposed API keys, tokens and private keys, one finding per line as `file:line:rule`. Standard library only, so it runs anywhere Python 3 exists, including CI runners.

## Features

- 9 detection rules covering AWS, GitHub, GitLab, Slack, Google, Stripe, generic API key assignments and private key blocks
- Recursive directory scanning (on by default for directories)
- `--redact` masks matched secrets in output for safe logs and CI
- `--json` for machine-readable output
- `--exclude` patterns to skip `.git`, `node_modules`, `__pycache__`, `.venv` (skipped by default) or anything you name
- Binary files are detected and skipped gracefully
- CI-friendly exit codes: `1` when findings exist, `0` when clean, `2` on bad input

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

Scan a directory (recursive by default):

```bash
$ python3 secrets.py ./src
./src/config/settings.py:12:GitHub Token: ghp_FAKE1234567890abcdef1234
./src/deploy/aws.env:3:AWS Access Key ID: AKIAIOSFODNN7EXAMPLE
```

(All example keys here are obviously fake.)

Scan a single file, redact secrets, output JSON:

```bash
$ python3 secrets.py .env --redact --json
[
  {
    "file": ".env",
    "line": 5,
    "rule": "Stripe Secret Key",
    "snippet": "sk_l...7890 (redacted)"
  }
]
```

Skip extra paths and scan top level only:

```bash
$ python3 secrets.py . --exclude .git node_modules vendor --no-recursive --redact
```

Use in CI (fails the build when a secret is found):

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

## License

MIT. See [LICENSE](LICENSE).
