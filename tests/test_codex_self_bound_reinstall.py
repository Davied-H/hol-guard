"""A reinstall replaces the handlers this same installation wrote before."""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.codex_config import dump_toml, read_toml_payload
from codex_plugin_scanner.guard.codex_hook_compatibility import NATIVE_CODEX_HOOK_COMMAND
from codex_plugin_scanner.guard.codex_hook_self_binding import (
    codex_hook_guard_home,
    self_bound_hook_bindings,
)


def _install(home: Path, guard_home: Path) -> None:
    CodexHarnessAdapter().install(HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard_home))


def _config_path(home: Path) -> Path:
    return home / ".codex" / "config.toml"


def _handlers(home: Path) -> list[dict[str, object]]:
    payload = read_toml_payload(_config_path(home))
    hooks = payload.get("hooks")
    found: list[dict[str, object]] = []
    for groups in hooks.values() if isinstance(hooks, dict) else []:
        for group in groups if isinstance(groups, list) else []:
            if isinstance(group, dict):
                found.extend(handler for handler in group.get("hooks", []) if isinstance(handler, dict))
    return found


def _rewrite_commands(home: Path, rewrite) -> None:
    payload = read_toml_payload(_config_path(home))
    for groups in payload["hooks"].values():
        for group in groups if isinstance(groups, list) else []:
            for handler in group.get("hooks", []) if isinstance(group, dict) else []:
                command = handler.get("command")
                if isinstance(command, str):
                    handler["command"] = rewrite(command)
    _config_path(home).write_text(dump_toml(payload), encoding="utf-8")


def test_reinstall_replaces_a_stale_generation_of_this_install(tmp_path):
    home = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    _install(home, guard_home)
    before = len(_handlers(home))
    assert before

    # An upgrade, a moved virtualenv or a reinstalled package changes the
    # launcher, so the signed manifest stops matching what is registered.
    _rewrite_commands(home, lambda command: command.replace(sys.executable, "/usr/bin/python3", 1))

    _install(home, guard_home)

    commands = [handler["command"] for handler in _handlers(home)]
    assert not [command for command in commands if command.startswith("/usr/bin/python3")]
    assert len(commands) == before


def test_reinstall_refuses_a_guard_handler_bound_to_another_guard_home(tmp_path):
    home = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    _install(home, guard_home)
    other = str(tmp_path / "other-guard-home")
    _rewrite_commands(home, lambda command: command.replace(str(guard_home), other))
    before = read_toml_payload(_config_path(home))

    with pytest.raises(RuntimeError, match="codex_hook_owner_conflict"):
        _install(home, guard_home)

    assert read_toml_payload(_config_path(home)) == before


def test_reinstall_keeps_a_foreign_handler_sharing_a_group_with_a_stale_one(tmp_path):
    home = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    _install(home, guard_home)
    foreign = {"type": "command", "command": "/usr/bin/true audit"}
    payload = read_toml_payload(_config_path(home))
    group = payload["hooks"]["PreToolUse"][0]
    group["hooks"] = [
        {**handler, "command": handler["command"].replace(sys.executable, "/usr/bin/python3", 1)}
        for handler in group["hooks"]
    ]
    group["hooks"].append(foreign)
    _config_path(home).write_text(dump_toml(payload), encoding="utf-8")

    _install(home, guard_home)

    commands = [handler["command"] for handler in _handlers(home)]
    assert foreign["command"] in commands
    assert not [command for command in commands if command.startswith("/usr/bin/python3")]


def _cli_command(*arguments: str) -> str:
    """The isolated CLI fallback spelling the installer writes."""

    bootstrap = "import sys;sys.path.insert(0, '/opt/guard');from codex_plugin_scanner.cli import main"
    return shlex.join(("/usr/bin/python3", "-I", "-c", bootstrap, "guard", "hook", "--harness", "codex", *arguments))


def _bridge_command(payload: dict[str, object], *extra: str) -> str:
    """The bridge launcher spelling the installer writes."""

    return shlex.join(
        ("/opt/guard/python", "-I", "/opt/guard/codex_daemon_hook_bridge.py", json.dumps(payload), *extra)
    )


_BRIDGE_PAYLOAD: dict[str, object] = {
    "state_path": "/srv/guard/daemon-state.json",
    "query": "guard-home=/srv/guard&home=/home/dev",
    "fallback_command": ["python", "-m", "codex_plugin_scanner.cli", "--guard-home", "/srv/guard"],
}


def test_guard_home_option_identifies_the_installation():
    command = _cli_command("--home", "/home/dev", "--guard-home", "/srv/guard", "--workspace", "/w")
    assert codex_hook_guard_home(command) == Path("/srv/guard")


def test_native_bridge_payload_identifies_the_installation():
    assert codex_hook_guard_home(_bridge_command(_BRIDGE_PAYLOAD)) == Path("/srv/guard")


def test_the_native_bridge_wrapper_identifies_the_installation():
    wrapped = shlex.join(("/opt/guard/hol-guard-runtime", NATIVE_CODEX_HOOK_COMMAND))
    assert codex_hook_guard_home(f"{wrapped} {_bridge_command(_BRIDGE_PAYLOAD)}") == Path("/srv/guard")


@pytest.mark.parametrize(
    "command",
    (
        _cli_command(),
        "/usr/local/bin/hol-guard-codex-hook.sh",
        # A bridge payload whose fields disagree names no one installation.
        _bridge_command({**_BRIDGE_PAYLOAD, "state_path": "/srv/other/daemon-state.json"}),
    ),
)
def test_a_command_naming_no_single_guard_home_identifies_nothing(command):
    assert codex_hook_guard_home(command) is None


@pytest.mark.parametrize(
    "command",
    (
        # An argument the installer never writes, on either launcher spelling.
        _cli_command("--guard-home", "/srv/guard") + " --tampered",
        _bridge_command(_BRIDGE_PAYLOAD, "--tampered"),
        # A wrapper of someone else's around a launcher of ours.
        "/usr/bin/env " + _cli_command("--guard-home", "/srv/guard"),
        # An option the installer only writes once.
        _cli_command("--guard-home", "/srv/guard", "--guard-home", "/srv/guard"),
    ),
)
def test_a_tampered_command_is_not_this_installations_own(command):
    assert codex_hook_guard_home(command) is None


def test_self_bound_bindings_name_the_group_by_matcher_alone():
    handler = {"type": "command", "command": _cli_command("--guard-home", "/srv/guard")}
    hooks = {"PreToolUse": [{"matcher": "Bash", "hooks": [handler, {"type": "command", "command": "other"}]}]}
    bindings = self_bound_hook_bindings(hooks, guard_home=Path("/srv/guard"))
    assert bindings == [{"event": "PreToolUse", "group": {"matcher": "Bash"}, "handler": handler}]
