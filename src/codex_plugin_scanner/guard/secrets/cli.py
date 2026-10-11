"""CLI for free local HOL Guard leaked-secret detection."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import Any

from ..native_secrets import (
    NativeSecretsError,
    SecretsRefusedError,
    native_secrets_hook,
    native_secrets_rules,
    native_secrets_scan,
)

DEFAULT_MAX_FILES = 5_000
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 128 * 1024 * 1024
DEFAULT_MAX_FINDINGS = 500
DEFAULT_MAX_COMMITS = 500


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def build_parser(*, program_name: str = "hol-guard-secrets") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=program_name,
        description="Find leaked credentials locally. Raw secret values are never printed or sent to Guard Cloud.",
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        metavar="{scan,rules,install-hook,uninstall-hook}",
    )
    scan = subparsers.add_parser("scan", help="Scan the working tree, staged index, or bounded Git history")
    scan.add_argument("target", nargs="?", default=".")
    scope = scan.add_mutually_exclusive_group()
    scope.add_argument("--staged", action="store_true", help="Scan only content currently staged for commit")
    scope.add_argument("--history", action="store_true", help="Scan the working tree plus bounded Git history")
    scan.add_argument("--max-commits", type=_positive_int, default=DEFAULT_MAX_COMMITS)
    scan.add_argument("--max-files", type=_positive_int, default=DEFAULT_MAX_FILES)
    scan.add_argument("--max-file-bytes", type=_positive_int, default=DEFAULT_MAX_FILE_BYTES)
    scan.add_argument("--max-total-bytes", type=_positive_int, default=DEFAULT_MAX_TOTAL_BYTES)
    scan.add_argument("--max-findings", type=_positive_int, default=DEFAULT_MAX_FINDINGS)
    scan.add_argument("--fail-on-findings", action="store_true")
    scan.add_argument("--format", choices=("text", "json"), default="text")
    scan.add_argument("--json", action="store_true", help="Compatibility alias for --format json")

    rules = subparsers.add_parser("rules", help="List built-in detector families")
    rules.add_argument("--json", action="store_true")

    install_hook = subparsers.add_parser(
        "install-hook",
        help="Install a staged-secret pre-commit scan without overwriting an existing hook",
    )
    install_hook.add_argument("target", nargs="?", default=".")
    install_hook.add_argument("--json", action="store_true")

    uninstall_hook = subparsers.add_parser(
        "uninstall-hook",
        help="Remove the Guard-managed hook and restore any preserved user hook",
    )
    uninstall_hook.add_argument("target", nargs="?", default=".")
    uninstall_hook.add_argument("--json", action="store_true")
    return parser


def _write_scan(public: dict[str, Any], *, json_output: bool) -> None:
    if json_output:
        print(json.dumps(public, sort_keys=True))
        return
    findings = public["findings"]
    print(
        f"HOL Guard Secrets: {len(findings)} finding(s), "
        f"{public['files_scanned']} file version(s), "
        f"{public['commits_scanned']} Git commit(s)."
    )
    for finding in findings:
        commit = f" @{finding['commit'][:12]}" if finding["commit"] else ""
        print(
            f"- {finding['severity'].upper()} {finding['family']} at "
            f"{finding['path']}:{finding['line']}{commit} [{finding['confidence']} confidence]"
        )
    if public["truncated"]:
        print(
            "Scan coverage is partial. Increase the configured bounds or resolve the "
            "reported Git error before treating it as clean."
        )
    for error in public["errors"]:
        print(f"Warning: {error}", file=sys.stderr)
    print("Raw secret values are intentionally omitted.")


def _run_scan(args: argparse.Namespace) -> int:
    bounds = {
        "include_history": bool(args.history),
        "max_commits": args.max_commits,
        "max_files": args.max_files,
        "max_file_bytes": args.max_file_bytes,
        "max_total_bytes": args.max_total_bytes,
        "max_findings": args.max_findings,
    }
    try:
        public = native_secrets_scan(args.target, staged=bool(args.staged), bounds=bounds)
    except (SecretsRefusedError, NativeSecretsError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    _write_scan(public, json_output=bool(args.json) or args.format == "json")
    if public["truncated"] or public["errors"]:
        return 2
    return 3 if args.fail_on_findings and public["findings"] else 0


def _run_rules(args: argparse.Namespace) -> int:
    try:
        json_text, plain_text = native_secrets_rules()
    except NativeSecretsError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    sys.stdout.write(json_text if args.json else plain_text)
    return 0


def _run_hook(args: argparse.Namespace, *, install: bool) -> int:
    try:
        payload = native_secrets_hook(args.target, install=install)
    except (SecretsRefusedError, NativeSecretsError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        action = "installed" if install else "uninstalled"
        print(f"HOL Guard Secrets pre-commit hook {action}: {payload['status']} ({payload['hook']})")
        if payload["chained_existing"]:
            print("Existing pre-commit behavior is preserved and chained before the staged secret scan.")
    return 0


def main(
    argv: Sequence[str] | None = None,
    *,
    program_name: str = "hol-guard-secrets",
) -> int:
    args = build_parser(program_name=program_name).parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "rules":
        return _run_rules(args)
    if args.command == "install-hook":
        return _run_hook(args, install=True)
    if args.command == "uninstall-hook":
        return _run_hook(args, install=False)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
