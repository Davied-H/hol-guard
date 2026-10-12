"""Harness launcher rendering is native; ``run-shim`` argument parsing stays here.

The launcher bytes, the durable-CLI choice and the Windows script are covered by the
``guard-command`` harness unit tests and the ``shim_admin`` parity vectors.
"""

from __future__ import annotations

import argparse

from codex_plugin_scanner.guard.cli.commands_parser import add_guard_root_parser


def test_run_shim_keeps_windows_forwarded_arguments_verbatim() -> None:
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)
    args = parser.parse_args(
        [
            "run-shim",
            "--guard-home",
            "guard home",
            "--workspace",
            "project root",
            "omp",
            "--",
            "--help",
            "prompt with spaces",
        ]
    )

    assert args.guard_command == "run-shim"
    assert args.harness == "omp"
    assert args.guard_home == "guard home"
    assert args.workspace == "project root"
    assert args.passthrough_args == ["--help", "prompt with spaces"]
