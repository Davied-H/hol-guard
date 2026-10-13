"""Which hook launcher a measured install runs, for the warm-path benchmark."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


def handler_route(handler: list[str] | str) -> str:
    """Which launcher the installed handler starts, without recording its paths."""

    if isinstance(handler, str):
        return "shell"
    if len(handler) > 1 and handler[1] == "claude-hook-bridge":
        return "native-bridge"
    if len(handler) > 1 and handler[1] == "-c":
        return "python-bridge"
    return "other"


_NATIVE_STATUS_CODE = """
import json
try:
    from codex_plugin_scanner.guard.native_runtime import native_runtime_status
    status = native_runtime_status()
    capabilities = getattr(status, "capabilities", None)
    print(json.dumps({
        "available": status.available,
        "compatible": status.compatible,
        "reason": status.reason,
        "features": sorted(getattr(capabilities, "features", None) or []),
    }))
except Exception as error:
    print(json.dumps({"error": f"{type(error).__name__}: {error}"[:300]}))
"""


def native_status(cli: Path, env: dict[str, str], cwd: Path) -> dict[str, object]:
    """The target install's own view of its native runtime, as the installer sees it."""

    result = subprocess.run(
        [str(cli.parent / "python"), "-c", _NATIVE_STATUS_CODE],
        env=env,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        return {"error": f"exit {result.returncode}: {result.stderr[-300:]}"}
