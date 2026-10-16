"""Give the lane a Guard home with history instead of a fresh one.

Every qualification case installs into a home created moments earlier, so the
migration paths a real machine goes through are never on the tested route.
Some defects only appear once a home has been written by an older build: a
``~/.codex/hooks.json`` that has to be folded into ``config.toml``, or a Claude
handler from a previous install that has to be pruned rather than joined. This
module manufactures that history and then checks what the install left behind.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .installed_registration import guard_handlers
from .installed_replay import handler_argv

#: A path an older build could plausibly have registered and that no longer
#: exists. If the install joins rather than prunes, this stays behind and the
#: harness ends up calling a command that is not there.
STALE_COMMAND = "/opt/hol-guard-previous/bin/hol-guard"


def age_home(home: Path) -> dict[str, Any]:
    """Write the artifacts a previous Guard version would have left behind."""

    applied: list[str] = []
    claude = home / ".claude" / "settings.json"
    if claude.exists():
        settings = json.loads(claude.read_text(encoding="utf-8"))
        hooks = settings.setdefault("hooks", {})
        for event, group in list(hooks.items()):
            if not isinstance(group, list) or not group:
                continue
            group.append(
                {
                    "matcher": "Bash",
                    "hooks": [
                        {"type": "command", "command": STALE_COMMAND, "args": ["hook", "--harness", "claude-code"]}
                    ],
                }
            )
            applied.append(f"claude:{event}")
        claude.write_text(json.dumps(settings, indent=2), encoding="utf-8")

    legacy_hooks = home / ".codex" / "hooks.json"
    legacy_hooks.parent.mkdir(parents=True, exist_ok=True)
    legacy_hooks.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [
                                {"type": "command", "command": STALE_COMMAND, "args": ["hook", "--harness", "codex"]}
                            ]
                        }
                    ]
                }
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    applied.append("codex:legacy-hooks-json")
    return {"applied": applied, "stale_command": STALE_COMMAND}


def stale_handlers(home: Path, relative_paths: list[str]) -> list[str]:
    """Handlers left pointing at a command that is not on this machine."""

    found: list[str] = []
    for relative in relative_paths:
        path = home / relative
        if not path.exists() or path.suffix != ".json":
            continue
        try:
            config = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        hooks = config.get("hooks") if isinstance(config, dict) else None
        if not isinstance(hooks, dict):
            continue
        for event, group in hooks.items():
            for handler in guard_handlers(group):
                argv = handler_argv(handler)
                if argv and not Path(argv[0]).exists():
                    found.append(f"{path}:{event}: handler still points at {argv[0]}")
    return found


def assess_aged(home: Path, relative_paths: list[str], registration: list[dict[str, Any]]) -> dict[str, Any]:
    """Judge the second install over an aged home."""

    stale = stale_handlers(home, relative_paths)
    failures = list(stale)
    for assessment in registration:
        failures.extend(assessment["failures"])
    return {
        "stale_handlers": stale,
        "failures": failures,
        "registration": registration,
        "passed": not failures,
    }


__all__ = ["STALE_COMMAND", "age_home", "assess_aged", "stale_handlers"]
