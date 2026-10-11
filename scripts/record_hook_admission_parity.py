"""Record parity vectors from the Python hook admission helpers.

The vectors pin the behaviour of the pure helpers the daemon runs before a
runtime hook reaches the native edge (lane selection, scheduler client key,
payload size, remaining-budget hints, deadline math, workspace and workdir
normalisation).  A native handler that replaces them must reproduce every vector.
Run without arguments to rewrite the fixture; the test module compares it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "hook_admission_parity" / "vectors.v1.json"

PAYLOADS: list[dict[str, object]] = [
    {},
    {"hook_event_name": "PreToolUse", "session_id": "s1", "tool_name": "Bash"},
    {"hook_event_name": "pre_tool_use", "conversation_id": "c9"},
    {"hook_event_name": "PermissionRequest", "thread_id": "t3"},
    {"hook_event_name": "UserPromptSubmit", "session_id": "s1", "prompt": "hi"},
    {"hook_event_name": "user-prompt-submitted"},
    {"hook_event_name": "PostToolUse", "session_id": "s2", "tool_response": {"ok": True}},
    {"event": "SessionStart"},
    {"hook_event_name": "PreToolUse", "session_id": "", "conversation_id": "c1", "thread_id": "t1"},
    {"hook_event_name": "PreToolUse", "session_id": 7, "thread_id": "t2"},
    {"hook_event_name": "PostToolUse", "tool_input": {"text": "café ☃ \U0001f600"}},
]
WORKSPACES: list[str | None] = [None, "", "/work/space", "/work/spaceé"]
HINT_PAYLOADS: list[dict[str, object]] = [
    {},
    {"guard_remaining_seconds": 2.5},
    {"guard_remaining_seconds": 7},
    {"guard_remaining_ms": 1500},
    {"guard_remaining_seconds": True, "guard_remaining_ms": 900},
    {"guard_remaining_seconds": "3"},
    {"guard_remaining_seconds": float("inf"), "guard_remaining_ms": 2000},
    {"guard_remaining_seconds": float("nan")},
    {"guard_remaining_ms": 0},
    {"guard_remaining_seconds": -1},
    {"guard_remaining_seconds": 3, "guard_remaining_ms": 9000},
]
WORKSPACE_STRINGS: list[object] = [
    None,
    7,
    "",
    "   ",
    "None",
    "null",
    "NULL",
    "/work/space",
    "/work/space/",
    "/work/./space/../space",
    "/work/None",
    "/None",
    " /work/space ",
    "/work//space",
]
WORKDIR_PAYLOADS: list[dict[str, object]] = [
    {},
    {"tool_name": "Bash", "tool_input": {"workdir": "/w"}},
    {"tool_name": "exec_command"},
    {"tool_name": "exec_command", "tool_input": {}},
    {"tool_name": "exec_command", "tool_input": []},
    {"tool_name": "Exec_Command", "tool_input": {"workdir": "/w/x"}},
    {"tool_name": " exec_command ", "tool_input": {"workdir": "/w/./x/"}},
    {"tool_name": "exec_command", "tool_input": {"workdir": 5}},
    {"tool_name": "exec_command", "tool_input": {"workdir": ""}},
    {"tool_name": "exec_command", "tool_input": {"workdir": "none"}},
    {"tool_name": "exec_command", "tool_input": {"workdir": " NULL "}},
]
DEADLINE_CASES: list[dict[str, object]] = [
    {"hint": hint, "hint_missing": missing, "prompt": prompt, "admission": admission, "transport": transport}
    for hint in (3.0, 0.05, 1.0, 12.0, 4.0)
    for missing in (True, False)
    for prompt, admission in ((False, 3.0), (True, 10.0))
    for transport in (1.0, 4.0, 11.0)
]


def _vectors() -> dict[str, object]:
    from codex_plugin_scanner.guard.daemon import server
    from codex_plugin_scanner.guard.daemon.hook_request_parsing import runtime_hook_event_name
    from codex_plugin_scanner.guard.daemon.runtime_hook_deadline import RuntimeHookDeadline

    handler = server._GuardDaemonHandler
    lane = [
        {
            "payload": payload,
            "event_name": runtime_hook_event_name(payload),
            "lane": handler._runtime_hook_lane(payload),
        }
        for payload in PAYLOADS
    ]
    client_key = [
        {"payload": payload, "workspace": workspace, "key": handler._runtime_hook_client_key(payload, workspace)}
        for payload in PAYLOADS
        for workspace in WORKSPACES
    ]
    payload_size = [{"payload": payload, "bytes": handler._runtime_hook_payload_size(payload)} for payload in PAYLOADS]
    hints = []
    for payload in HINT_PAYLOADS:
        working = dict(payload)
        hints.append(
            {
                "payload": {key: _jsonable(value) for key, value in payload.items()},
                "remaining_seconds": server._runtime_hook_remaining_hint(working),
                "remaining_payload_keys": sorted(working),
            }
        )
    workspaces = [
        {"value": value, "normalized": handler._normalized_hook_workspace_string(value)} for value in WORKSPACE_STRINGS
    ]
    workdirs = []
    for payload in WORKDIR_PAYLOADS:
        provided, workdir = handler._runtime_hook_exec_command_workdir(payload)
        workdirs.append({"payload": payload, "provided": provided, "workdir": workdir})
    deadlines = []
    base = 100.0
    for case in DEADLINE_CASES:
        transport_deadline = base + float(case["transport"])  # type: ignore[arg-type]
        admission = float(case["admission"])  # type: ignore[arg-type]
        if case["prompt"]:
            prompt_now = transport_deadline - admission
            hinted = RuntimeHookDeadline.from_remaining_hint(
                admission if case["hint_missing"] else case["hint"],
                monotonic=lambda now=prompt_now: now,
                maximum_budget_seconds=10.0,
            )
        else:
            hinted = RuntimeHookDeadline.from_remaining_hint(case["hint"], monotonic=lambda now=base: now)
        deadlines.append({**case, "expires_offset": round(min(hinted.expires_at, transport_deadline) - base, 6)})
    return {
        "schema": "hook-admission-parity.v1",
        "lane": lane,
        "client_key": client_key,
        "payload_size": payload_size,
        "remaining_hint": hints,
        "workspace_string": workspaces,
        "exec_command_workdir": workdirs,
        "deadline": deadlines,
    }


def _jsonable(value: object) -> object:
    if isinstance(value, float) and value != value:
        return "nan"
    if isinstance(value, float) and value in (float("inf"), float("-inf")):
        return "inf" if value > 0 else "-inf"
    return value


def _normalise(value: object) -> object:
    if isinstance(value, float):
        return _jsonable(value)
    if isinstance(value, dict):
        return {key: _normalise(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalise(item) for item in value]
    return value


def build() -> dict[str, object]:
    sys.path.insert(0, str(ROOT / "src"))
    return _normalise(_vectors())  # type: ignore[return-value]


def main() -> int:
    FIXTURE.write_text(json.dumps(build(), indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
