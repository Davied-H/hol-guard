"""The installed-acceptance lane fails the builds qualification lets through.

These tests drive the lane against stub executables rather than a real build,
because the point under test is the lane's own judgement: a build that reports
a successful install while registering nothing must fail, and a build that
answers the same payload two different ways must fail as a defect rather than
being retried until it agrees.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from ci.gauntlet.installed_lane import run_lane
from ci.gauntlet.installed_registration import assess_harness, load_contract
from ci.gauntlet.installed_runtime import SCRIPT, InstalledRuntimeError, classify, resolve_runtime
from ci.gauntlet.installed_store import STALE_COMMAND

HARNESSES = ["claude-code"]

_CLAUDE_EVENTS = ("PreToolUse", "PermissionRequest", "PostToolUse", "Notification", "Stop", "SessionStart")

_STUB_HEAD = """#!/usr/bin/env python3
import json, os, sys
from pathlib import Path

EVENTS = {events!r}
REGISTER = {register!r}
VERDICTS = {verdicts!r}
COUNTER = Path(os.environ["STUB_COUNTER"])
STALE = {stale!r}


def value(flag, default=None):
    argv = sys.argv
    return argv[argv.index(flag) + 1] if flag in argv else default


def install():
    if not REGISTER:
        print(json.dumps({{"installed": True, "harness": value("--harness", "claude-code")}}))
        return 0
    home = Path(value("--home"))
    settings = home / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True, exist_ok=True)
    existing = json.loads(settings.read_text()) if settings.exists() else {{}}
    hooks = {{}}
    for event in EVENTS:
        hooks[event] = [
            {{"matcher": "Bash", "hooks": [{{"type": "command", "command": sys.argv[0], "args": ["hook"]}}]}}
        ]
    if STALE:
        for event, group in (existing.get("hooks") or {{}}).items():
            if event in hooks and isinstance(group, list):
                hooks[event].extend(group)
    existing["hooks"] = hooks
    settings.write_text(json.dumps(existing, indent=2))
    print(json.dumps({{"installed": True, "harness": value("--harness", "claude-code")}}))
    return 0


def hook():
    sys.stdin.read()
    seen = int(COUNTER.read_text()) if COUNTER.exists() else 0
    COUNTER.write_text(str(seen + 1))
    decision = VERDICTS[seen % len(VERDICTS)]
    print(json.dumps({{"hookSpecificOutput": {{"permissionDecision": decision}}}}))
    return 0


if "--version" in sys.argv:
    print("hol-guard 0.0.0-stub")
    raise SystemExit(0)
raise SystemExit(install() if sys.argv[1] == "install" else hook())
"""


def _stub(path: Path, *, register: bool, verdicts: list[str], stale: bool = False) -> Path:
    path.write_text(
        _STUB_HEAD.format(events=list(_CLAUDE_EVENTS), register=register, verdicts=verdicts, stale=stale),
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


@pytest.fixture(autouse=True)
def _counter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STUB_COUNTER", str(tmp_path / "counter"))


def _run(tmp_path: Path, runtime: Path, *, repeat: int = 4) -> dict:
    return run_lane(
        runtime_path=runtime,
        harnesses=HARNESSES,
        repeat=repeat,
        require_frozen=False,
        aged_store=False,
        output=tmp_path / "evidence",
        work_root=tmp_path / "work",
    )


def test_a_build_that_registers_nothing_fails_the_lane(tmp_path: Path) -> None:
    """3.46.0 on the user's Mac reported a successful install and had no hooks."""

    runtime = _stub(tmp_path / "hol-guard", register=False, verdicts=["allow"])
    evidence = _run(tmp_path, runtime)
    assert evidence["accepted"] is False
    assert any("carries no Guard handler" in failure for failure in evidence["failures"])


def test_real_registration_and_a_steady_verdict_pass(tmp_path: Path) -> None:
    runtime = _stub(tmp_path / "hol-guard", register=True, verdicts=["allow", "allow"])
    evidence = _run(tmp_path, runtime)
    replay = evidence["harnesses"]["claude-code"]["replay"]
    assert replay["deterministic"] is True
    # The attack cases expect a deny, which this stub never gives, so the lane
    # must still refuse the build: a build that allows everything is not quiet,
    # it is absent.
    assert evidence["accepted"] is False
    assert all("disagreeing verdicts" not in failure for failure in evidence["failures"])
    assert any("attack payload was allowed" in failure for failure in evidence["failures"])


def test_a_verdict_split_across_identical_runs_fails(tmp_path: Path) -> None:
    """The 60/40 allow-vs-deny split that qualification scored as a pass."""

    runtime = _stub(tmp_path / "hol-guard", register=True, verdicts=["allow", "deny"])
    evidence = _run(tmp_path, runtime)
    assert evidence["accepted"] is False
    assert any("disagreeing verdicts" in failure for failure in evidence["failures"])
    replay = evidence["harnesses"]["claude-code"]["replay"]
    assert replay["deterministic"] is False


def test_a_console_script_cannot_stand_in_for_the_frozen_bundle(tmp_path: Path) -> None:
    runtime = _stub(tmp_path / "hol-guard", register=True, verdicts=["allow"])
    assert classify(runtime)[0] == SCRIPT
    with pytest.raises(InstalledRuntimeError, match="console script"):
        resolve_runtime(runtime, require_frozen=True)


def test_a_frozen_layout_without_a_sealed_manifest_is_refused(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    internal = bundle / "_internal" / "codex_plugin_scanner" / "_native"
    internal.mkdir(parents=True)
    (internal / "hol-guard-runtime").write_text("", encoding="utf-8")
    runtime = bundle / "hol-guard"
    runtime.write_bytes(b"\x7fELF not really")
    runtime.chmod(runtime.stat().st_mode | stat.S_IEXEC)
    with pytest.raises(InstalledRuntimeError):
        resolve_runtime(runtime, require_frozen=True)


def test_a_stale_handler_left_by_an_older_build_fails_the_aged_pass(tmp_path: Path) -> None:
    runtime = _stub(tmp_path / "hol-guard", register=True, verdicts=["allow"], stale=True)
    evidence = run_lane(
        runtime_path=runtime,
        harnesses=HARNESSES,
        repeat=1,
        require_frozen=False,
        aged_store=True,
        output=tmp_path / "evidence",
        work_root=tmp_path / "work",
    )
    aged = evidence["aged_store"]
    assert aged["passed"] is False
    assert any(STALE_COMMAND in failure for failure in aged["stale_handlers"])


def test_the_contract_is_the_lanes_own_and_covers_every_claude_event() -> None:
    """Asserting against the product's contract would let an emptied one pass."""

    contract = load_contract()
    assert set(contract["harnesses"]["claude-code"]["required_events"]) == set(_CLAUDE_EVENTS)
    assert contract["harnesses"]["omp"]["replay"] is False
    assert contract["harnesses"]["omp"]["replay_gap"]
    expectations = [case["expect"] for case in contract["replay_cases"]]
    assert "allow" in expectations and "not-allow" in expectations


def test_registration_reads_the_harness_file_not_the_install_report(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / "settings.json").write_text(json.dumps({"hooks": {event: [] for event in _CLAUDE_EVENTS}}))
    expectation = load_contract()["harnesses"]["claude-code"]
    assessment = assess_harness(home, "claude-code", expectation)
    assert assessment["registered"] is False
    assert len(assessment["failures"]) == len(_CLAUDE_EVENTS)


def test_the_lane_never_touches_the_operators_own_home(tmp_path: Path) -> None:
    runtime = _stub(tmp_path / "hol-guard", register=True, verdicts=["allow"])
    before = os.environ.get("HOME")
    _run(tmp_path, runtime, repeat=1)
    assert os.environ.get("HOME") == before
    for relative in (".claude/settings.json", ".codex/config.toml"):
        assert not (tmp_path / "work" / relative).exists()
