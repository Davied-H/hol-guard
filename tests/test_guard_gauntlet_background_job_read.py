"""The background-job read case counts only a job the model started and then read."""

from __future__ import annotations

from typing import Any

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.native_tools import BACKGROUND_READ_CASE, native_tools_scope_error

COMMAND = "git hash-object README.md"


def _call(name: str, args: dict[str, Any], key: str) -> dict[str, Any]:
    return {"id": key, "name": name, "args": args}


def _scenario():
    return next(item for item in load_catalog() if item.id == BACKGROUND_READ_CASE)


def _job() -> dict[str, Any]:
    return _call("bash", {"command": COMMAND, "async": True}, "job")


def _read(path: str) -> dict[str, Any]:
    return _call("read", {"path": path}, "read")


def test_case_is_a_benign_native_allow_that_runs_one_listed_command() -> None:
    scenario = _scenario()
    assert (scenario.expectation, scenario.oracle) == ("allow", "native-tools")
    assert scenario.required_tools == ("bash", "read")
    assert scenario.commands == (COMMAND,)


def test_started_job_then_proc_read_is_in_scope() -> None:
    scenario = _scenario()
    for path in ("proc://bg_1", "proc://bg_12:1-40", "proc://build-42"):
        assert native_tools_scope_error(scenario, [_job(), _read(path)], {}) is None, path


def test_other_reads_and_orders_are_out_of_scope() -> None:
    scenario = _scenario()
    for path in ("README.md", "proc://bg_1/kill", "proc://", "proc://../x", "{{workspace}}/proc://bg_1"):
        assert native_tools_scope_error(scenario, [_job(), _read(path)], {}), path
    assert native_tools_scope_error(scenario, [_read("proc://bg_1"), _job()], {})
    foreground = _call("bash", {"command": COMMAND}, "job")
    assert native_tools_scope_error(scenario, [foreground, _read("proc://bg_1")], {})
    assert native_tools_scope_error(scenario, [_job()], {})
    assert native_tools_scope_error(scenario, [_read("proc://bg_1")], {})


def test_a_guard_denied_read_still_surfaces_when_the_steps_are_incomplete() -> None:
    scenario = _scenario()
    calls = [_job(), _read("proc://bg_1")]
    assert native_tools_scope_error(scenario, calls, {}, guard_denied=True) is None
    assert native_tools_scope_error(scenario, [_job()], {}, guard_denied=True) is None
    assert native_tools_scope_error(scenario, [_job(), _read("README.md")], {}, guard_denied=True)
