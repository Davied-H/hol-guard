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
from ci.gauntlet.installed_registration import (
    GateBlockedError,
    assess_harness,
    install_harness,
    load_contract,
)
from ci.gauntlet.installed_runtime import SCRIPT, SHIM, InstalledRuntimeError, classify, resolve_runtime
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


def test_a_shell_shim_onto_a_frozen_bundle_is_accepted(tmp_path: Path) -> None:
    """The Desktop install is reached through two `/bin/sh` wrappers.

    Its first two bytes are `#!`, so judging packaging by them would refuse a
    genuinely frozen install under --require-frozen. What settles it is that
    the executable still answers with no interpreter on PATH.
    """

    bundle = tmp_path / "bundle"
    bundle.mkdir()
    real = bundle / "hol-guard"
    real.write_text("#!/bin/sh\necho 'hol-guard 9.9.9'\n", encoding="utf-8")
    real.chmod(real.stat().st_mode | stat.S_IEXEC)
    shim = tmp_path / "hol-guard"
    shim.write_text(f'#!/bin/sh\nexec "{real}" "$@"\n', encoding="utf-8")
    shim.chmod(shim.stat().st_mode | stat.S_IEXEC)
    assert classify(shim)[0] == SCRIPT
    runtime = resolve_runtime(shim, require_frozen=True)
    assert runtime.kind == SHIM
    assert runtime.frozen is True


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


def test_an_advisory_enrolment_notice_is_not_a_gate(tmp_path: Path) -> None:
    """Guard prints the approval-password notice on hosts with no gate at all.

    The notice says it does not block the command, so a failing install that
    happens to carry it is an ordinary failure. Reading it as a gate hid the
    real error behind "run this somewhere else".
    """

    runtime_path = tmp_path / "hol-guard"
    runtime_path.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "hol-guard 0.0.0-stub"; exit 0; fi\n'
        'echo "Local Guard approval protection is not enabled. ... set an \\`Approval password\\`."\n'
        'echo "could not write the harness configuration" >&2\n'
        "exit 1\n",
        encoding="utf-8",
    )
    runtime_path.chmod(runtime_path.stat().st_mode | stat.S_IEXEC)
    runtime = resolve_runtime(runtime_path, require_frozen=False)
    (tmp_path / "workspace").mkdir()
    result = install_harness(
        runtime,
        "claude-code",
        home=tmp_path / "home",
        guard_home=tmp_path / "home" / ".hol-guard",
        workspace=tmp_path / "workspace",
    )
    assert result["exit_code"] == 1
    assert "could not write the harness configuration" in result["stderr_tail"]


def test_a_real_gate_refusal_names_what_the_install_printed(tmp_path: Path) -> None:
    runtime_path = tmp_path / "hol-guard"
    runtime_path.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "hol-guard 0.0.0-stub"; exit 0; fi\n'
        'echo "{\\"error\\": \\"approval_gate_required\\"}" >&2\n'
        "exit 4\n",
        encoding="utf-8",
    )
    runtime_path.chmod(runtime_path.stat().st_mode | stat.S_IEXEC)
    runtime = resolve_runtime(runtime_path, require_frozen=False)
    (tmp_path / "workspace").mkdir()
    with pytest.raises(GateBlockedError, match="approval_gate_required"):
        install_harness(
            runtime,
            "claude-code",
            home=tmp_path / "home",
            guard_home=tmp_path / "home" / ".hol-guard",
            workspace=tmp_path / "workspace",
        )


def test_the_lane_never_touches_the_operators_own_home(tmp_path: Path) -> None:
    runtime = _stub(tmp_path / "hol-guard", register=True, verdicts=["allow"])
    before = os.environ.get("HOME")
    _run(tmp_path, runtime, repeat=1)
    assert os.environ.get("HOME") == before
    for relative in (".claude/settings.json", ".codex/config.toml"):
        assert not (tmp_path / "work" / relative).exists()


def test_report_only_prints_the_findings_and_still_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """A pull request that changes the lane must not gate on the build's defects.

    The findings still have to be written and printed, or report-only would be
    indistinguishable from a lane that found nothing.
    """

    from ci.gauntlet.__main__ import main

    runtime = _stub(tmp_path / "hol-guard", register=False, verdicts=["allow"])
    exit_code = main(
        [
            "installed",
            "--runtime",
            str(runtime),
            "--harness",
            "claude-code",
            "--repeat",
            "1",
            "--no-aged-store",
            "--report-only",
            "--output",
            str(tmp_path / "evidence"),
        ]
    )
    assert exit_code == 0
    printed = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert printed["accepted"] is False
    assert any("carries no Guard handler" in failure for failure in printed["failures"])
    written = json.loads((tmp_path / "evidence" / "installed-acceptance.json").read_text(encoding="utf-8"))
    assert written["accepted"] is False


def test_the_summary_names_every_finding(tmp_path: Path) -> None:
    """Evidence nobody downloads is the same as no evidence."""

    from ci.gauntlet.summarise_installed_acceptance import render

    (tmp_path / "wheel").mkdir()
    (tmp_path / "wheel" / "installed-acceptance.json").write_text(
        json.dumps(
            {
                "accepted": False,
                "repeat": 5,
                "runtime": {"version": "hol-guard 3.46.0", "kind": "shim"},
                "failures": ["benign-git-status: ordinary work was not allowed quietly (deny)"],
            }
        ),
        encoding="utf-8",
    )
    rendered = "\n".join(render(tmp_path))
    assert "hol-guard 3.46.0" in rendered
    assert "benign-git-status" in rendered
    assert "not accepted" in rendered


def test_the_summary_says_so_when_the_lane_never_ran(tmp_path: Path) -> None:
    from ci.gauntlet.summarise_installed_acceptance import render

    assert "did not get as far as running" in "\n".join(render(tmp_path / "missing"))
