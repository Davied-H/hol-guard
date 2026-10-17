"""Fail when tracked files or commit messages contain a runner-supplied private token.

The denylist is never committed: it comes from ``GUARD_PRIVATE_TOKEN_DENYLIST`` in the
runner environment (newline- or comma-separated, case-insensitive). When it is unset or
empty the check is skipped. Matches are reported by location and denylist entry number
only, so the log never repeats a private token.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path

ENV_NAMES = ("GUARD_PRIVATE_TOKEN_DENYLIST", "GUARD_PRIVATE_TOKEN_DENYLIST_SECRET")
MAX_FILE_BYTES = 4 * 1024 * 1024


def load_denylist(environ: Mapping[str, str] | None = None) -> list[str]:
    """Tokens from the first non-empty variable; short tokens are ignored to avoid noise."""
    environ = os.environ if environ is None else environ
    for name in ENV_NAMES:
        raw = environ.get(name, "")
        tokens = [token.strip().lower() for token in raw.replace(",", "\n").splitlines()]
        tokens = [token for token in tokens if len(token) >= 3]
        if tokens:
            return sorted(set(tokens))
    return []


def _matches(text: str, tokens: list[str]) -> list[int]:
    lowered = text.lower()
    return [index for index, token in enumerate(tokens, start=1) if token in lowered]


def scan_text(label: str, text: str, tokens: list[str]) -> list[str]:
    """Findings for one text blob, naming the line and entry, never the token."""
    findings = []
    for number, line in enumerate(text.splitlines(), start=1):
        for entry in _matches(line, tokens):
            findings.append(f"{label}:{number}: matches private denylist entry #{entry}")
    return findings


def tracked_files(root: Path) -> list[str]:
    """Every path git tracks under ``root``."""
    output = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True, timeout=120
    ).stdout.decode("utf-8", "surrogateescape")
    return [name for name in output.split("\0") if name]


def commit_messages(root: Path, revision_range: str) -> Iterable[tuple[str, str]]:
    """Short SHA and full message for each commit in the range."""
    output = subprocess.run(
        ["git", "log", "--format=%H%x00%B%x01", revision_range],
        cwd=root,
        check=True,
        capture_output=True,
        timeout=120,
    ).stdout.decode("utf-8", "replace")
    for record in output.split("\x01"):
        sha, _, body = record.strip("\n").partition("\0")
        if sha:
            yield sha[:12], body


def scan(root: Path, tokens: list[str], revision_range: str | None) -> list[str]:
    """Findings across tracked paths, tracked text files and, optionally, commit messages."""
    findings: list[str] = []
    for index, name in enumerate(tracked_files(root), start=1):
        # A path can itself carry the token; then it is named by position, not spelled out.
        label = f"tracked file #{index}" if _matches(name, tokens) else name
        if label != name:
            findings.append(f"{label}: path matches a private denylist entry")
        path = root / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
            continue
        data = path.read_bytes()
        if b"\0" in data[:8192]:
            continue
        findings.extend(scan_text(label, data.decode("utf-8", "replace"), tokens))
    if revision_range:
        for sha, body in commit_messages(root, revision_range):
            findings.extend(scan_text(f"commit {sha} message", body, tokens))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--range", dest="revision_range", help="Also scan commit messages in this git range")
    args = parser.parse_args(argv)
    tokens = load_denylist()
    if not tokens:
        print("private-token check skipped: GUARD_PRIVATE_TOKEN_DENYLIST is not set")
        return 0
    findings = scan(args.root.resolve(), tokens, args.revision_range)
    for finding in findings:
        print(finding)
    if findings:
        print(f"private-token check failed: {len(findings)} finding(s)", file=sys.stderr)
        return 1
    print(f"private-token check passed against {len(tokens)} denylist entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
