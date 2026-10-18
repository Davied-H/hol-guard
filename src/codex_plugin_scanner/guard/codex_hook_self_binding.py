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
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from urllib.parse import parse_qsl

from .codex_hook_command_line import hook_command_tokens, hook_token_name
from .codex_hook_compatibility import NATIVE_CODEX_HOOK_COMMAND
from .codex_hook_events import MANAGED_CODEX_HOOK_EVENTS

_GUARD_HOME_OPTION = "--guard-home"
_GUARD_HOME_QUERY_KEY = "guard-home"
_DAEMON_STATE_NAME = "daemon-state.json"


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


def _bridge_payloads(tokens: Sequence[str], *, windows: bool | None) -> list[Mapping[str, object]]:
    """The JSON configuration operands a native bridge launcher was given."""

    payloads: list[Mapping[str, object]] = []
    rest = list(tokens[2:]) if len(tokens) > 2 and tokens[1] == NATIVE_CODEX_HOOK_COMMAND else list(tokens)
    bridge = next(
        (
            index
            for index, token in enumerate(rest)
            if hook_token_name(token, windows=windows) == "codex_daemon_hook_bridge.py"
        ),
        None,
    )
    if bridge is None:
        return payloads
    for operand in rest[bridge + 1 :]:
        try:
            decoded = json.loads(operand)
        except (TypeError, ValueError):
            continue
        if isinstance(decoded, Mapping):
            payloads.append(decoded)
    return payloads


def codex_hook_guard_home(command: str, *, windows: bool | None = None) -> Path | None:
    """The single Guard home a Codex hook command is bound to, when it names one.

    Returns ``None`` when the command names no Guard home, or names more than
    one, because neither state identifies an installation that may replace it.
    """

    tokens = hook_command_tokens(command, windows=windows)
    if not tokens:
        return None
    homes = _option_guard_home(tokens)
    for payload in _bridge_payloads(tokens, windows=windows):
        homes |= _payload_guard_home(payload)
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
