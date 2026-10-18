"""Registry for the false-positive regression cases: staging, environment, checks and output proof.

A case id listed here gets its project files, PATH stubs and extra environment at run time, and
its pass additionally requires every declared output and filesystem proof. The catalog rows only
carry the prompt and the exact commands.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .fp_file_cases import FILE_CASES
from .fp_package_cases import PACKAGE_CASES
from .fp_spec import FpCase, output_matches, stage_case

FP_CASES: dict[str, FpCase] = {**PACKAGE_CASES, **FILE_CASES}
# Cases whose commands call a stubbed program, so the fixture's stub directory leads PATH.
FP_STUB_CASES = frozenset(case_id for case_id, case in FP_CASES.items() if case.stubs)


def stage_fp_cases(workspace: Path, home: Path, bin_dir: Path, scenario_id: str) -> None:
    """Add one case's files and stubs; every other scenario keeps the shared fixture."""
    case = FP_CASES.get(scenario_id)
    if case is not None:
        stage_case(case, workspace, home, bin_dir)


def fp_environment(scenario_id: str) -> dict[str, str]:
    case = FP_CASES.get(scenario_id)
    return dict(case.environment) if case is not None else {}


def fp_case_checks(workspace: Path, home: Path, scenario_id: str) -> dict[str, bool]:
    case = FP_CASES.get(scenario_id)
    if case is None:
        return {}
    results: dict[str, bool] = {}
    for name, check in case.checks.items():
        try:
            results[name] = bool(check(workspace, home))
        except OSError:
            results[name] = False
    return results


def fp_required_checks(scenario_id: str) -> set[str]:
    case = FP_CASES.get(scenario_id)
    return set(case.checks) if case is not None else set()


def fp_outputs_match(scenario_id: str, texts: list[str | None]) -> bool:
    """Every command printed what its case expects; a silent command is proven on disk instead."""
    case = FP_CASES[scenario_id]
    return len(texts) == len(case.outputs) and all(
        output_matches(expected, text) for expected, text in zip(case.outputs, texts, strict=True)
    )


def expected_failure(scenario_id: str, call: dict[str, Any]) -> bool:
    """A call whose command is listed as failing by design; Guard denials are still judged separately."""
    case = FP_CASES.get(scenario_id)
    args = call.get("args")
    command = args.get("command", args.get("cmd")) if isinstance(args, dict) else None
    return case is not None and isinstance(command, str) and command in case.expected_failures
