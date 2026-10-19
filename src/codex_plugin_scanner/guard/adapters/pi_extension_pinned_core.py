"""Detect a generated Pi-family extension pinned to a replaceable Desktop core.

Desktop installs each core release under ``versions/<release>/`` and moves its
``current`` pointer on every update. An extension that bakes one of those
launcher paths keeps running the superseded CLI against the current resident,
so its hook and contained-run calls fail until the extension is regenerated.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import cast

from ..stable_guard_cli import desktop_core_shim_for_executable, frozen_cli_path_is_runnable

_MAX_EXTENSION_BYTES = 2_000_000
_BAKED_COMMAND = re.compile(
    r"^const (?:GUARD_CLI_WRAPPER_COMMAND|GUARD_DAEMON_RECOVERY_COMMAND) = (\"(?:[^\"\\\n]|\\.)*\");$",
    re.MULTILINE,
)


def pinned_versioned_core(extension_path: Path) -> str | None:
    """Return the versioned Core launcher an extension bakes, when a stable one exists.

    Only a launcher that has a runnable ``current-hol-guard`` beside its
    ``versions`` directory counts: regenerating the extension then bakes that
    launcher, so the finding is one repair can clear.
    """

    try:
        if not extension_path.is_file() or extension_path.stat().st_size > _MAX_EXTENSION_BYTES:
            return None
        source = extension_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    for match in _BAKED_COMMAND.finditer(source):
        try:
            command = cast(object, json.loads(match.group(1)))
        except json.JSONDecodeError:
            continue
        if not isinstance(command, str) or not command:
            continue
        shim = desktop_core_shim_for_executable(Path(command))
        if shim is not None and frozen_cli_path_is_runnable(shim):
            return command
    return None


def with_pinned_core_warning(
    diagnostics: dict[str, object], *, extension_path: Path, display_name: str
) -> dict[str, object]:
    """Mark a managed extension broken when it is pinned to a versioned Desktop core."""

    pinned = pinned_versioned_core(extension_path)
    if pinned is None:
        return diagnostics
    warnings = diagnostics.get("warnings")
    updated: list[object] = [*cast(list[object], warnings)] if isinstance(warnings, list) else []
    updated.append(
        f"The managed {display_name} extension runs a pinned Desktop core ({pinned}) that Desktop replaces on update, "
        + "so its Guard calls can run against a newer Guard. Run `hol-guard repair` to regenerate it."
    )
    status = diagnostics.get("setup_status")
    return {
        **diagnostics,
        "setup_status": "broken" if status == "active" else status,
        "warnings": updated,
    }


__all__ = ["pinned_versioned_core", "with_pinned_core_warning"]
