#!/usr/bin/env python3
"""Lint .spl query files for structural issues and accidental hardcoded secrets."""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

SECRET_PATTERNS = [
    (re.compile(r"SPLUNK_TOKEN\s*=\s*\S+"), "hardcoded SPLUNK_TOKEN value"),
    (re.compile(r"SPLUNK_HOST\s*=\s*\S+"), "hardcoded SPLUNK_HOST value"),
    (re.compile(r"password\s*=\s*\S+", re.IGNORECASE), "hardcoded password"),
    (re.compile(r"Authorization:\s*(Bearer|Splunk)\s+\S+", re.IGNORECASE), "hardcoded Authorization header"),
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "embedded JWT-looking token"),
]


def check_balance(text, open_ch, close_ch, label, errors):
    depth = 0
    for ch in text:
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth < 0:
                errors.append(f"unbalanced {label}: unmatched '{close_ch}'")
                return
    if depth != 0:
        errors.append(f"unbalanced {label}: {depth} unclosed '{open_ch}'")


def check_quotes(text, errors):
    # Ignore escaped quotes (\") when counting.
    unescaped = re.sub(r'\\"', "", text)
    if unescaped.count('"') % 2 != 0:
        errors.append("unbalanced double quotes")


def lint_file(path):
    errors = []
    text = path.read_text(encoding="utf-8", errors="replace")
    stripped = text.strip()

    if not stripped:
        errors.append("file is empty")
        return errors

    check_balance(stripped, "(", ")", "parentheses", errors)
    check_balance(stripped, "[", "]", "brackets", errors)
    check_quotes(stripped, errors)

    if stripped.endswith("|"):
        errors.append("query ends with a dangling '|' (incomplete pipeline)")

    for pattern, message in SECRET_PATTERNS:
        if pattern.search(stripped):
            errors.append(message)

    return errors


def main():
    spl_files = sorted(REPO_ROOT.rglob("*.spl"))

    if not spl_files:
        print("No .spl files found — nothing to lint.")
        return 0

    had_errors = False
    for path in spl_files:
        rel = path.relative_to(REPO_ROOT)
        errors = lint_file(path)
        if errors:
            had_errors = True
            print(f"FAIL {rel}")
            for err in errors:
                print(f"  - {err}")
        else:
            print(f"OK   {rel}")

    if had_errors:
        print("\nlint_spl.py: one or more .spl files failed linting.")
        return 1

    print(f"\nlint_spl.py: {len(spl_files)} file(s) passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
