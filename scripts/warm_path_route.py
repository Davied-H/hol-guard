"""Which hook launcher a measured install runs, for the warm-path benchmark."""

from __future__ import annotations

import json
import re
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


_PATH_SYSCALLS = frozenset(
    {
        "execve",
        "open",
        "openat",
        "newfstatat",
        "statx",
        "stat",
        "lstat",
        "readlink",
        "readlinkat",
        "access",
        "faccessat2",
        "connect",
    }
)
_TRACE_LINE = re.compile(r"^(?P<pid>\d+)\s+(?P<time>\d+\.\d+)\s+(?P<call>[a-z_0-9]+)\((?P<args>.*)$")


def _trace_event(match: re.Match[str]) -> str:
    """A syscall without buffer contents: its name, plus the path for path calls."""

    call = match["call"]
    if call in _PATH_SYSCALLS:
        quoted = re.search(r'"([^"]*)"', match["args"])
        if quoted is not None:
            return f"{call} {quoted.group(1)}"
    return call


def traced_programs(handler: list[str] | str, payload: str, env: dict[str, str], cwd: Path) -> dict[str, object]:
    """Programs one hook call executes and the largest CPU gaps between its syscalls."""

    strace = shutil.which("strace")
    if strace is None or isinstance(handler, str):
        return {"error": "strace unavailable"}
    with tempfile.NamedTemporaryFile(prefix="wpl-trace-", suffix=".txt") as trace:
        subprocess.run(
            [strace, "-f", "-qq", "-ttt", "-s", "256", "-o", trace.name, *handler],
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
    previous: dict[str, tuple[float, str]] = {}
    gaps: list[tuple[float, str, str, str]] = []
    calls: dict[str, int] = {}
    for line in lines:
        match = _TRACE_LINE.match(line)
        if match is None:
            continue
        call = match["call"]
        calls[call] = calls.get(call, 0) + 1
        if call == "execve" and "= -1" not in line:
            name = Path(line.split('execve("', 1)[-1].split('"', 1)[0]).name
            programs[name] = programs.get(name, 0) + 1
        event, moment = _trace_event(match), float(match["time"])
        if match["pid"] in previous:
            before_time, before_event = previous[match["pid"]]
            gaps.append((moment - before_time, match["pid"], before_event, event))
        previous[match["pid"]] = (moment, event)
    gaps.sort(reverse=True)
    return {
        "programs": programs,
        "syscalls": sum(calls.values()),
        "top_syscalls": dict(sorted(calls.items(), key=lambda item: -item[1])[:12]),
        "largest_gaps": [
            {"ms": round(gap * 1000, 2), "pid": pid, "after": before, "before": after}
            for gap, pid, before, after in gaps[:8]
        ],
    }
