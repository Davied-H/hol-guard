"""Prove that `hol-guard install <harness>` really registers Guard's hooks.

The qualification lane calls ``apply_managed_install`` as a library and accepts
its own ``active: true`` as the answer. That is the structural blind spot this
module closes: here the lane runs the shipped ``install`` command as a
subprocess and then reads the harness's own configuration file, against
``installed_contract.json`` rather than against a product contract, so a build
that registers nothing fails even if it reports success.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import tomllib

from .installed_runtime import InstalledRuntime, isolated_environment, json_payload, run_guard

CONTRACT_PATH = Path(__file__).with_name("installed_contract.json")

#: Marks a hook handler as Guard's. The command may be the frozen executable,
#: the native bridge or the Python bridge, so the lane matches on the family
#: name rather than one spelling.
GUARD_COMMAND_MARKERS = ("hol-guard", "hol_guard", "guard-command", "codex_plugin_scanner")

#: The gate refuses non-interactively rather than letting the lane through.
#:
#: These are the gate's own error codes, not its prose. Guard prints an
#: advisory enrolment notice mentioning the approval password on hosts that
#: have no gate at all, and that notice says in so many words that it does not
#: block the command, so matching on wording turned every unrelated install
#: failure into "this host has a gate".
GATE_REASONS = ("approval_gate_required", "approval_gate_totp_required", "lifecycle_gate")


class GateBlockedError(RuntimeError):
    """Raised when the host's canonical approval gate owns the install path.

    ``lifecycle_authority_home`` redirects protection mutations to the OS
    account's canonical Guard home whenever that home has an enabled gate, and
    that home is resolved from ``pwd``, not from ``HOME``. There is deliberately
    no environment seam, so the lane refuses to run on such a host instead of
    reaching for one. CI runners have no enrolled gate and are unaffected.
    """


def load_contract() -> dict[str, Any]:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def install_harness(
    runtime: InstalledRuntime,
    harness: str,
    *,
    home: Path,
    guard_home: Path,
    workspace: Path,
    timeout: float = 600.0,
) -> dict[str, Any]:
    """Run the shipped install command for ``harness`` into a lane-owned home."""

    environment = isolated_environment(home=home, guard_home=guard_home)
    completed = run_guard(
        runtime,
        [
            "install",
            harness,
            "--home",
            str(home),
            "--guard-home",
            str(guard_home),
            "--workspace",
            str(workspace),
            "--json",
        ],
        environment=environment,
        timeout=timeout,
        cwd=workspace,
    )
    combined = f"{completed.stdout}\n{completed.stderr}"
    if completed.returncode != 0 and any(reason in combined for reason in GATE_REASONS):
        raise GateBlockedError(
            "the host's canonical approval gate owns `install`, so this lane cannot run here; "
            "run it on a machine with no enrolled gate (CI runners have none). "
            f"`install {harness}` exited {completed.returncode}: {combined.strip()[-400:]}"
        )
    return {
        "harness": harness,
        "exit_code": completed.returncode,
        "payload": json_payload(completed),
        "stderr_tail": (completed.stderr or "").strip()[-600:],
    }


def _is_guard_command(value: object) -> bool:
    return isinstance(value, str) and any(marker in value for marker in GUARD_COMMAND_MARKERS)


def _handler_is_guard(handler: object) -> bool:
    """Whether one hook handler runs Guard.

    A Claude handler is ``{"type": "command", "command": …, "args": [...]}``;
    the command may be the executable itself or a bridge whose Guard identity
    shows up in its arguments instead.
    """

    if _is_guard_command(handler):
        return True
    if not isinstance(handler, dict):
        return False
    if _is_guard_command(handler.get("command")):
        return True
    arguments = handler.get("args")
    return isinstance(arguments, list) and any(_is_guard_command(argument) for argument in arguments)


def guard_handlers(group: object) -> list[dict[str, Any]]:
    """Every Guard handler inside one hook event group."""

    found: list[dict[str, Any]] = []
    entries = group if isinstance(group, list) else [group]
    for entry in entries:
        handlers = entry.get("hooks") if isinstance(entry, dict) else None
        candidates = handlers if isinstance(handlers, list) else [entry]
        for handler in candidates:
            if _handler_is_guard(handler) and isinstance(handler, dict):
                found.append(handler)
    return found


def read_config(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".toml":
        try:
            return tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def assess_claude(home: Path, expectation: dict[str, Any]) -> dict[str, Any]:
    """Every required Claude hook event must carry at least one Guard handler."""

    config_path = home / expectation["config"]
    config = read_config(config_path)
    hooks = config.get(expectation["hooks_key"]) if isinstance(config, dict) else None
    hooks = hooks if isinstance(hooks, dict) else {}
    events: dict[str, int] = {}
    failures: list[str] = []
    for event in expectation["required_events"]:
        handlers = guard_handlers(hooks.get(event))
        events[event] = len(handlers)
        if not handlers:
            failures.append(f"{config_path}: hook event {event} carries no Guard handler")
    return {
        "config": str(config_path),
        "config_present": config is not None,
        "events": events,
        "failures": failures,
    }


def assess_codex(home: Path, expectation: dict[str, Any]) -> dict[str, Any]:
    """Guard's Codex hooks live in ``config.toml`` now, with ``hooks.json`` as history.

    Recent builds migrate ``~/.codex/hooks.json`` into ``~/.codex/config.toml``,
    so a missing ``hooks.json`` is not by itself a defect. The lane requires
    Guard entries in either file and records which one carried them.
    """

    candidates = [home / expectation["config"]]
    alternate = expectation.get("alternate_config")
    if alternate:
        candidates.append(home / alternate)
    carriers: dict[str, int] = {}
    for path in candidates:
        config = read_config(path)
        hooks = config.get(expectation["hooks_key"]) if isinstance(config, dict) else None
        if not isinstance(hooks, dict):
            continue
        count = sum(len(guard_handlers(group)) for group in hooks.values())
        if count:
            carriers[str(path)] = count
    minimum = int(expectation.get("minimum_guard_entries", 1))
    total = sum(carriers.values())
    failures: list[str] = []
    if total < minimum:
        spelled = " or ".join(str(path) for path in candidates)
        failures.append(f"{spelled}: {total} Guard hook entries, expected at least {minimum}")
    return {
        "config": [str(path) for path in candidates],
        "carriers": carriers,
        "entries": total,
        "failures": failures,
    }


def assess_files(home: Path, expectation: dict[str, Any]) -> dict[str, Any]:
    """Harnesses whose registration is a set of installed files."""

    present: dict[str, bool] = {}
    failures: list[str] = []
    for relative in expectation["required_files"]:
        path = home / relative
        present[relative] = path.exists()
        if not path.exists():
            failures.append(f"{path}: Guard did not install this file")
    return {"files": present, "failures": failures, "replay_gap": expectation.get("replay_gap")}


def assess_harness(home: Path, harness: str, expectation: dict[str, Any]) -> dict[str, Any]:
    if "required_events" in expectation:
        assessment = assess_claude(home, expectation)
    elif "required_files" in expectation:
        assessment = assess_files(home, expectation)
    else:
        assessment = assess_codex(home, expectation)
    assessment["harness"] = harness
    assessment["registered"] = not assessment["failures"]
    return assessment


__all__ = [
    "CONTRACT_PATH",
    "GateBlockedError",
    "assess_claude",
    "assess_codex",
    "assess_files",
    "assess_harness",
    "guard_handlers",
    "install_harness",
    "load_contract",
    "read_config",
]
