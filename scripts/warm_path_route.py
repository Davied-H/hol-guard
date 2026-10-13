"""Which hook launcher a measured install runs, for the warm-path benchmark."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
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


def traced_programs(handler: list[str] | str, payload: str, env: dict[str, str], cwd: Path) -> dict[str, object]:
    """Programs one hook call executes, by basename, when strace is available."""

    strace = shutil.which("strace")
    if strace is None or isinstance(handler, str):
        return {"error": "strace unavailable"}
    with tempfile.NamedTemporaryFile(prefix="wpl-trace-", suffix=".txt") as trace:
        subprocess.run(
            [strace, "-f", "-qq", "-e", "trace=execve", "-o", trace.name, *handler],
            input=payload,
            env=env,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        lines = Path(trace.name).read_text(encoding="utf-8", errors="replace").splitlines()
    programs: dict[str, int] = {}
    for line in lines:
        if "execve(" not in line or "= -1" in line:
            continue
        name = Path(line.split('execve("', 1)[-1].split('"', 1)[0]).name
        programs[name] = programs.get(name, 0) + 1
    return {"programs": programs}
