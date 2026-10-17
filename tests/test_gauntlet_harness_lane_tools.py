"""Each harness lane reaches every case its own tools can drive.

A false positive the Gauntlet never provokes is one nobody sees. The shell
spelling of a read and the harness's own read tool are different requests to
Guard, so a lane that only ever runs shell commands cannot report on the calls
Claude Code or Cursor actually make.
"""

from __future__ import annotations

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.harness_suite import lane_catalog

# Oh My Pi's own tools. No other lane has anything to map them onto.
OMP_ONLY = {"glob", "grep", "eval", "task", "wait", "todo", "learn"}


def _native_tools_cases() -> tuple:
    return tuple(s for s in load_catalog() if s.oracle == "native-tools")


@pytest.mark.parametrize("harness", ["claude-code", "cursor"])
def test_structured_read_cases_run_on_lanes_with_a_read_tool(harness: str) -> None:
    selected = {s.id for s in lane_catalog(harness)}
    reads = [s for s in _native_tools_cases() if set(s.required_tools) <= {"bash", "read", "write", "edit"}]
    assert reads, "no structured-tool cases in the catalog"
    missing = sorted(s.id for s in reads if s.id not in selected)
    assert not missing, f"{harness} can drive these tools but the lane skips the cases: {missing}"


def test_codex_keeps_the_shell_only_selection() -> None:
    selected = {s.id for s in lane_catalog("codex")}
    structured = [s for s in _native_tools_cases() if set(s.required_tools) - {"bash"} and s.id in selected]
    assert not structured, "Codex has no structured read, write or edit tool"


@pytest.mark.parametrize("harness", ["claude-code", "codex", "cursor"])
def test_no_lane_claims_an_oh_my_pi_only_tool(harness: str) -> None:
    selected = {s.id for s in lane_catalog(harness)}
    claimed = sorted(s.id for s in _native_tools_cases() if s.id in selected and set(s.required_tools) & OMP_ONLY)
    assert not claimed, f"{harness} has no tool for: {claimed}"


@pytest.mark.parametrize("harness", ["claude-code", "codex", "cursor"])
def test_memory_note_cases_stay_on_oh_my_pi(harness: str) -> None:
    selected = {s.id for s in lane_catalog(harness)}
    notes = sorted(s.id for s in load_catalog() if s.oracle == "blocked-memory-note" and s.id in selected)
    assert not notes, f"{harness} has no memory-note tool: {notes}"
