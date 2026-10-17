"""What a qualification run covers, said out loud.

A release is decided from `qualification.json`, and that file used to carry a
bare `qualified: true` for a run that drove Oh My Pi on the core profile and
nothing else. Eleven other lanes — the harness CLIs a person actually types
into, the full developer tasks — were never named, so a green record read as
coverage it did not have. These tests hold the lane matrix to the runner's own
options and keep the record honest about which single lane it drove.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from ci.gauntlet.lane_coverage import (
    HARNESSES,
    PROFILES,
    QUALIFYING_LANE,
    lane_coverage,
    lane_profiles,
    lanes,
)

_RUNNER = Path(__file__).resolve().parents[1] / "ci" / "gauntlet" / "__main__.py"


def _cli_choices(option: str) -> tuple[str, ...]:
    """The literal choices the runner's own parser accepts for one option."""
    tree = ast.parse(_RUNNER.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        first = node.args[0]
        if not isinstance(first, ast.Constant) or first.value != option:
            continue
        for keyword in node.keywords:
            if keyword.arg == "choices":
                return tuple(ast.literal_eval(keyword.value))
    raise AssertionError(f"runner declares no choices for {option}")


def test_the_matrix_tracks_the_runner_s_own_options() -> None:
    """A new harness or profile has to reach the coverage record with it."""
    assert set(HARNESSES) == set(_cli_choices("--harness"))
    assert set(PROFILES) == set(_cli_choices("--profile"))


def test_only_oh_my_pi_on_core_qualifies_a_merge() -> None:
    assert QUALIFYING_LANE == ("omp", "core")
    qualifying = [lane for lane in lanes() if lane_coverage(*lane)["is_qualifying_lane"]]
    assert qualifying == [QUALIFYING_LANE]


def test_the_profiles_each_harness_owns() -> None:
    """The runner refuses the two crossings; the matrix must not offer them."""
    assert "approval-retry" not in lane_profiles("omp")
    assert "contained-bun-vitest" in lane_profiles("omp")
    for harness in ("claude-code", "codex", "cursor"):
        assert "approval-retry" in lane_profiles(harness)
        assert "contained-bun-vitest" not in lane_profiles(harness)


def test_a_qualification_run_names_every_lane_it_left_alone() -> None:
    coverage = lane_coverage()
    driven = (coverage["driven"]["harness"], coverage["driven"]["profile"])
    left = {(lane["harness"], lane["profile"]) for lane in coverage["not_driven"]}
    assert driven == QUALIFYING_LANE
    assert left == set(lanes()) - {driven}
    assert len(left) == len(lanes()) - 1
    assert ("claude-code", "full-tasks") in left


def test_an_unknown_lane_is_refused() -> None:
    for harness, profile in (("omp", "approval-retry"), ("codex", "contained-bun-vitest"), ("zcode", "core")):
        with pytest.raises(ValueError):
            lane_coverage(harness, profile)
