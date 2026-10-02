#!/usr/bin/env python3
"""pentrix-secrets: scan files and directories for exposed secrets.

Scans text files line by line against a set of detection rules (API keys,
tokens, private key blocks) and reports matches as file:line:rule. Designed
to run fast with no dependencies: Python 3 standard library only.

Usage:
    python3 secrets.py PATH [--recursive] [--no-recursive]
                          [--exclude PATTERN ...] [--redact] [--json]

Exit codes:
    0  no findings (clean)
    1  one or more secrets found
    2  usage / input error (bad path, unreadable input)
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Detection rules: (name, compiled regex)
#
# Patterns are deliberately conservative. All example keys used in the docs
# and tests are obviously fake.
# ---------------------------------------------------------------------------
RULES = [
    (
        "AWS Access Key ID",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "AWS Secret Key Assignment",
        re.compile(
            r"(?i)\baws[_-]?secret[_-]?access[_-]?key\b\s*[:=]\s*"
            r"['\"]?([A-Za-z0-9/+=]{30,})['\"]?"
        ),
    ),
    (
        "GitHub Token",
        re.compile(
            r"\b(ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|"
            r"github_pat_[A-Za-z0-9_]{20,})\b"
        ),
    ),
    (
        "GitLab Token",
        re.compile(r"\bglpat-[A-Za-z0-9_\-]{16,}\b"),
    ),
    (
        "Slack Token",
        re.compile(r"\bxox[bap]-[A-Za-z0-9-]{10,}\b"),
    ),
    (
        "Generic API Key Assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|apikey|api[_-]?secret|secret)\b\s*[:=]\s*"
            r"['\"][^'\"]{4,}['\"]"
        ),
    ),
    (
        "Private Key Block",
        re.compile(r"-----BEGIN (?:[A-Z ]*)PRIVATE KEY-----"),
    ),
    (
        "Google API Key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ),
    (
        "Stripe Secret Key",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b"),
    ),
]

DEFAULT_EXCLUDES = [".git", "node_modules", "__pycache__", ".venv"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def is_binary(path: Path) -> bool:
    """Return True if the file looks binary (NUL byte in the first 8 KB)."""
    try:
        with open(path, "rb") as fh:
            return b"\x00" in fh.read(8192)
    except OSError:
        return True


def redact_match(rule_name: str, match_text: str) -> str:
    """Mask the sensitive part of a match, keeping a hint of its shape.

    The rule name and the first/last 4 characters are kept so the finding is
    still identifiable in logs without leaking the full secret.
    """
    text = match_text.strip()
    if len(text) <= 12:
        return "***REDACTED***"
    return f"{text[:4]}...{text[-4:]} (redacted)"


def iter_target_files(target: Path, recursive: bool, excludes: list):
    """Yield text files under target, honouring recursion and exclusions."""
    if target.is_file():
        if not is_binary(target):
            yield target
        return

    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if not any(e in d for e in excludes)]
        for name in files:
            path = Path(root) / name
            if any(e in str(path) for e in excludes):
                continue
            if not is_binary(path):
                yield path
        if not recursive:
            break


def scan_file(path: Path, rules: list, redact: bool) -> list:
    """Scan one file line by line. Returns a list of finding dicts."""
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="strict") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeDecodeError):
        return findings

    for lineno, line in enumerate(lines, start=1):
        for rule_name, pattern in rules:
            for match in pattern.finditer(line):
                snippet = match.group(0).strip()
                findings.append(
                    {
                        "file": str(path),
                        "line": lineno,
                        "rule": rule_name,
                        "snippet": redact_match(rule_name, snippet) if redact else snippet,
                    }
                )
    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secrets.py",
        description=(
            "Scan a file or directory for exposed secrets (API keys, tokens, "
            "private keys). Reports findings as file:line:rule. Exits 1 when "
            "anything is found, so it works in CI pipelines. Zero "
            "dependencies: Python 3 standard library only."
        ),
        epilog=(
            "examples:\n"
            "  python3 secrets.py ./src\n"
            "  python3 secrets.py config.env --redact --json\n"
            "  python3 secrets.py . --exclude .git node_modules --redact\n"
            "\n"
            "When a finding is real: rotate the secret immediately, revoke "
            "the old value, and check whether it was ever committed to git "
            "history."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "path",
        help="file or directory to scan",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        dest="recursive",
        action="store_true",
        default=None,
        help="scan directories recursively (default: on for directories)",
    )
    parser.add_argument(
        "--no-recursive",
        dest="recursive",
        action="store_false",
        help="scan only the top level of a directory",
    )
    parser.add_argument(
        "--redact",
        action="store_true",
        help="mask matched secrets in the output (keeps first/last 4 chars)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit findings as a JSON array instead of text",
    )
    parser.add_argument(
        "--exclude",
        nargs="*",
        default=[],
        metavar="PATTERN",
        help="skip paths containing these patterns (default skips: %s)"
        % ", ".join(DEFAULT_EXCLUDES),
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    target = Path(args.path)
    if not target.exists():
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    recursive = args.recursive
    if recursive is None:
        recursive = target.is_dir()

    excludes = list(DEFAULT_EXCLUDES) + list(args.exclude)

    findings = []
    for path in iter_target_files(target, recursive, excludes):
        findings.extend(scan_file(path, RULES, redact=args.redact))

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        for f in findings:
            print(f"{f['file']}:{f['line']}:{f['rule']}: {f['snippet']}")

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
