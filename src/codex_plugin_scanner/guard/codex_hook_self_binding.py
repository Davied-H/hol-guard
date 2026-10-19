"""Recognize a Guard Codex handler this installation registered itself.

A managed handler carries the installation it serves inside its own command:
the native bridge launches with a JSON payload naming the Guard home it talks
to, and the plain CLI form passes that home as an option. Guard rewrites its
registration whenever the launcher changes - a new interpreter, a moved
package, a reinstall after an upgrade - so the signed manifest that proved the
previous entry stops matching while the entry keeps naming this Guard home.

Those entries are this installation's own earlier generations. Replacing them
is what a reinstall is for. A Guard-looking handler that names a different
Guard home, or names none at all, still belongs to an owner this install
cannot speak for, so it keeps its refusal.

Naming this home is not enough on its own. Only the launcher spellings Guard
itself writes are claimed, token for token: the bridge launcher, the native
bridge wrapper around it, and the isolated CLI fallback with the options the
installer emits. Anything else - an extra argument, a reordered launcher, a
wrapper of someone else's - is a command this install never wrote, so it stays
unowned and keeps its conflict even when the Guard home inside it is ours.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from urllib.parse import parse_qsl

from .codex_hook_bridge_runtime import decode_bridge_config_argument
from .codex_hook_command_line import hook_command_tokens, hook_token_name
from .codex_hook_compatibility import NATIVE_CODEX_HOOK_COMMAND
from .codex_hook_events import MANAGED_CODEX_HOOK_EVENTS

_GUARD_HOME_OPTION = "--guard-home"
_GUARD_HOME_QUERY_KEY = "guard-home"
_DAEMON_STATE_NAME = "daemon-state.json"
_BRIDGE_SCRIPT_NAME = "codex_daemon_hook_bridge.py"
_ISOLATED_FLAG = "-I"
_INLINE_PROGRAM_FLAG = "-c"
_BRIDGE_LAUNCH_TOKENS = 4
_NATIVE_LAUNCH_TOKENS = 6
_CLI_BOOTSTRAP_MARKER = "codex_plugin_scanner.cli"
_CLI_GUARD_ARGS_HEAD = ("guard", "hook", "--harness", "codex")
_CLI_VALUE_OPTIONS = ("--home", _GUARD_HOME_OPTION, "--workspace")


def _resolved(value: str) -> Path | None:
    text = value.strip()
    if not text:
        return None
    try:
        return Path(text).resolve(strict=False)
    except (OSError, ValueError):
        return None


def _option_guard_home(tokens: Sequence[str]) -> set[Path]:
    homes: set[Path] = set()
    for index, token in enumerate(tokens):
        if token == _GUARD_HOME_OPTION and index + 1 < len(tokens):
            candidate = _resolved(tokens[index + 1])
        elif token.startswith(f"{_GUARD_HOME_OPTION}="):
            candidate = _resolved(token.split("=", 1)[1])
        else:
            continue
        if candidate is not None:
            homes.add(candidate)
    return homes


def _payload_guard_home(payload: Mapping[str, object]) -> set[Path]:
    """Every Guard home the native bridge payload names, from each field that names one."""

    homes: set[Path] = set()
    query = payload.get("query")
    if isinstance(query, str):
        for key, value in parse_qsl(query, keep_blank_values=False):
            if key == _GUARD_HOME_QUERY_KEY and (candidate := _resolved(value)) is not None:
                homes.add(candidate)
    state_path = payload.get("state_path")
    if (
        isinstance(state_path, str)
        and (candidate := _resolved(state_path)) is not None
        and candidate.name == _DAEMON_STATE_NAME
    ):
        homes.add(candidate.parent)
    for key in ("fallback_command", "start_command"):
        command = payload.get(key)
        if isinstance(command, list):
            homes |= _option_guard_home([item for item in command if isinstance(item, str)])
    return homes


def _bridge_launch_tokens(tokens: Sequence[str]) -> list[str] | None:
    """The interpreter argv of a bridge launcher, once its native wrapper is stripped."""

    if len(tokens) == _NATIVE_LAUNCH_TOKENS and tokens[1] == NATIVE_CODEX_HOOK_COMMAND:
        return list(tokens[2:])
    if len(tokens) == _BRIDGE_LAUNCH_TOKENS:
        return list(tokens)
    return None


def _bridge_payload(tokens: Sequence[str], *, windows: bool | None) -> Mapping[str, object] | None:
    """The configuration a bridge launcher Guard wrote carries, or ``None``.

    The launcher is one interpreter, the isolation flag, the bridge script and
    exactly one config operand. A command carrying anything else is not a
    launcher this installer emitted.
    """

    launch = _bridge_launch_tokens(tokens)
    if launch is None or launch[1] != _ISOLATED_FLAG:
        return None
    if hook_token_name(launch[2], windows=windows) != _BRIDGE_SCRIPT_NAME:
        return None
    try:
        decoded = json.loads(decode_bridge_config_argument(launch[3]))
    except (TypeError, ValueError):
        return None
    return decoded if isinstance(decoded, Mapping) else None


def _cli_guard_arguments(tokens: Sequence[str]) -> list[str] | None:
    """The ``guard hook`` arguments of the isolated CLI fallback Guard writes.

    Every trailing token must be one of the options the installer emits, given
    once and with a value, so an argument Guard would never write disqualifies
    the whole command.
    """

    if len(tokens) < len(_CLI_GUARD_ARGS_HEAD) + 4:
        return None
    if tokens[1] != _ISOLATED_FLAG or tokens[2] != _INLINE_PROGRAM_FLAG:
        return None
    if _CLI_BOOTSTRAP_MARKER not in tokens[3]:
        return None
    arguments = list(tokens[4:])
    if tuple(arguments[: len(_CLI_GUARD_ARGS_HEAD)]) != _CLI_GUARD_ARGS_HEAD:
        return None
    options = arguments[len(_CLI_GUARD_ARGS_HEAD) :]
    seen: set[str] = set()
    index = 0
    while index < len(options):
        option = options[index]
        if option not in _CLI_VALUE_OPTIONS or option in seen or index + 1 >= len(options):
            return None
        seen.add(option)
        index += 2
    return arguments


def codex_hook_guard_home(command: str, *, windows: bool | None = None) -> Path | None:
    """The single Guard home a launcher Guard wrote is bound to, when it names one.

    Returns ``None`` for a command that is not one of Guard's own launcher
    spellings, and for one that names no Guard home or names more than one,
    because none of those identify an installation that may replace it.
    """

    tokens = hook_command_tokens(command, windows=windows)
    if not tokens:
        return None
    payload = _bridge_payload(tokens, windows=windows)
    if payload is not None:
        homes = _payload_guard_home(payload)
    else:
        arguments = _cli_guard_arguments(tokens)
        if arguments is None:
            return None
        homes = _option_guard_home(arguments)
    if len(homes) != 1:
        return None
    return next(iter(homes))


def codex_hook_binds_guard_home(command: str, guard_home: Path, *, windows: bool | None = None) -> bool:
    """Whether this command is bound to ``guard_home`` and to nothing else."""

    bound = codex_hook_guard_home(command, windows=windows)
    if bound is None:
        return False
    try:
        return bound == guard_home.resolve(strict=False)
    except (OSError, ValueError):
        return False


def self_bound_hook_bindings(
    hooks: Mapping[str, object],
    *,
    guard_home: Path,
    windows: bool | None = None,
) -> list[dict[str, object]]:
    """Exact bindings for the handlers an earlier generation of this install left behind."""

    bindings: list[dict[str, object]] = []
    for event_name in MANAGED_CODEX_HOOK_EVENTS:
        groups = hooks.get(event_name)
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, Mapping):
                continue
            handlers = group.get("hooks")
            if not isinstance(handlers, list):
                # The group is the handler, so removing the handler removes
                # the group, and the exact group is what identifies it.
                if _binds(group, guard_home, windows=windows):
                    bindings.append({"event": event_name, "group": dict(group), "handler": dict(group)})
                continue
            for handler in handlers:
                if not isinstance(handler, Mapping) or not _binds(handler, guard_home, windows=windows):
                    continue
                # The group is named by its matcher alone: a group that also
                # holds a handler this install cannot speak for must lose only
                # the handler it owns, never the whole group.
                bindings.append(
                    {
                        "event": event_name,
                        "group": {"matcher": group.get("matcher")},
                        "handler": dict(handler),
                    }
                )
    return bindings


def _binds(entry: Mapping[str, object], guard_home: Path, *, windows: bool | None) -> bool:
    command = entry.get("command")
    return isinstance(command, str) and codex_hook_binds_guard_home(command, guard_home, windows=windows)


__all__ = [
    "codex_hook_binds_guard_home",
    "codex_hook_guard_home",
    "self_bound_hook_bindings",
]
