"""Compatibility launcher for Codex hook commands written before the native bridge.

The daemon hook review itself lives in the runtime
(``rust/crates/guard-runtime/src/codex_hook_bridge.rs``). Guard installs that
runtime's ``codex-hook-bridge`` command ahead of this bridge whenever the
runtime is present, so what is left here is the hook command of a session
written before the runtime shipped, and the frozen Desktop entry point that
still calls ``main`` in process: both run the same native command with the
same config argument.

There is no Python evaluator behind it. Every hook review needs the native
runtime, so an install without one has nothing left to ask and the hook
fails closed.

A frozen macOS Desktop keeps one lane of its own. A transition probe there
must be answered by the signed bundle executable, not by a runtime copy
published beside the Guard home, so this module still builds that strict
signed-proxy command and runs it. Python decides nothing on that lane either;
it only chooses which signed binary reviews the hook.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from urllib.parse import parse_qs

if __package__:
    from ..approval_wait_limits import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS
    from ..codex_hook_bridge_runtime import BridgeConfig
    from ..codex_hook_bridge_runtime import bounded_hook_input as _hook_input
    from ..codex_hook_bridge_runtime import bridge_config_from_argv as _parse_bridge_config
    from ..codex_hook_compatibility import NATIVE_CODEX_HOOK_COMMAND, NATIVE_CODEX_HOOK_FEATURE
    from ..codex_hook_launch_runtime import (
        desktop_hook_proxy_context,
        isolated_hook_environment,
        run_isolated_hook_process,
    )
    from ..daemon.hook_availability_policy import hook_event_is_permission_request
    from ..daemon.hook_request_parsing import runtime_hook_event_name
    from ..hook_execution_environment import stamp_hook_input_text
    from ..live_process_identity import (
        CODEX_BROWSER_WAIT_PROCESS_KEY,
        CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
        current_process_identity,
    )
    from .native_hook_bridge import native_hook_bridge_executable
else:  # pragma: no cover - exercised by subprocess integration tests
    _package_root = str(Path(__file__).resolve().parents[3])
    if _package_root not in sys.path:
        sys.path.insert(0, _package_root)
    from codex_plugin_scanner.guard.adapters.native_hook_bridge import native_hook_bridge_executable
    from codex_plugin_scanner.guard.approval_wait_limits import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS
    from codex_plugin_scanner.guard.codex_hook_bridge_runtime import (
        BridgeConfig,
    )
    from codex_plugin_scanner.guard.codex_hook_bridge_runtime import (
        bounded_hook_input as _hook_input,
    )
    from codex_plugin_scanner.guard.codex_hook_bridge_runtime import (
        bridge_config_from_argv as _parse_bridge_config,
    )
    from codex_plugin_scanner.guard.codex_hook_compatibility import (
        NATIVE_CODEX_HOOK_COMMAND,
        NATIVE_CODEX_HOOK_FEATURE,
    )
    from codex_plugin_scanner.guard.codex_hook_launch_runtime import (
        desktop_hook_proxy_context,
        isolated_hook_environment,
        run_isolated_hook_process,
    )
    from codex_plugin_scanner.guard.daemon.hook_availability_policy import (
        hook_event_is_permission_request,
    )
    from codex_plugin_scanner.guard.daemon.hook_request_parsing import runtime_hook_event_name
    from codex_plugin_scanner.guard.hook_execution_environment import stamp_hook_input_text
    from codex_plugin_scanner.guard.live_process_identity import (
        CODEX_BROWSER_WAIT_PROCESS_KEY,
        CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY,
        current_process_identity,
    )

_HOOK_TIMEOUT_GRACE_SECONDS = 2
_MAX_HOOK_INPUT_BYTES = 1_000_000
_TRANSITION_PROBE_OUTPUT_LIMIT = 64 * 1024
_NATIVE_RUNTIME_UNAVAILABLE = (
    "HOL Guard could not complete native review (the native runtime is unavailable) and denied this action."
)


def main(
    *,
    state_path: str | Path,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    query: str,
    hook_timeouts: Mapping[str, int],
    manifest_path: str | Path | None = None,
    config_json: str | None = None,
) -> int:
    """Run this hook call in the native bridge, or deny when there is no runtime."""

    state = Path(state_path)
    if _desktop_probe_lane():
        return _desktop_main(
            state=state,
            query=query,
            hook_timeouts=hook_timeouts,
            fallback_command=fallback_command,
            start_command=start_command,
            manifest_path=manifest_path,
            config_json=config_json,
        )
    native = _native_bridge_executable(state.parent)
    if native is None:
        return _deny_without_a_runtime()
    sys.stdout.flush()
    # The child inherits this hook call's stdio, so it reads the hook body and
    # writes the response itself. ``exec`` would save the fork, but this entry
    # point is also called in process, where replacing the caller is wrong.
    return subprocess.run(
        _native_argv(
            native,
            state_path=state_path,
            fallback_command=fallback_command,
            start_command=start_command,
            query=query,
            hook_timeouts=hook_timeouts,
            manifest_path=manifest_path,
            config_json=config_json,
        ),
        check=False,
    ).returncode


def _desktop_main(
    *,
    state: Path,
    query: str,
    hook_timeouts: Mapping[str, int],
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    manifest_path: str | Path | None,
    config_json: str | None,
) -> int:
    """Review this hook inside the signed bundle, or hand the body to the runtime.

    The probe lane is the one case where Python has to read the hook body
    before it knows where the review belongs, so a body read here is passed on
    rather than inherited.
    """

    hook_input = _bound_hook_input(hook_timeouts)
    if hook_input is None:
        sys.stdout.write(json.dumps(_fail_closed("PreToolUse"), separators=(",", ":")))
        return 0
    event_name, data, timeout_seconds, input_ready_at = hook_input
    try:
        probe_command = _desktop_transition_probe_command(
            data=data,
            state_path=state,
            query=query,
            hook_timeouts=hook_timeouts,
        )
    except (OSError, RuntimeError, ValueError):
        sys.stdout.write(json.dumps(_fail_closed(event_name), separators=(",", ":")))
        return 1
    if probe_command is None:
        native = _native_bridge_executable(state.parent)
        if native is None:
            sys.stdout.write(json.dumps(_fail_closed(event_name), separators=(",", ":")))
            return 0
        sys.stdout.flush()
        return subprocess.run(
            _native_argv(
                native,
                state_path=state,
                fallback_command=fallback_command,
                start_command=start_command,
                query=query,
                hook_timeouts=hook_timeouts,
                manifest_path=manifest_path,
                config_json=config_json,
            ),
            input=data.encode("utf-8", "surrogateescape"),
            check=False,
        ).returncode
    try:
        probe_result = run_isolated_hook_process(
            probe_command,
            input_text=data,
            cwd=Path.home(),
            environment=isolated_hook_environment(),
            output_limit=_TRANSITION_PROBE_OUTPUT_LIMIT,
            deadline_monotonic=input_ready_at + timeout_seconds,
        )
    except OSError:
        sys.stdout.write(json.dumps(_fail_closed(event_name), separators=(",", ":")))
        return 1
    if (
        probe_result.returncode != 0
        or probe_result.timed_out
        or probe_result.containment_failed
        or probe_result.output_limit_exceeded
    ):
        sys.stdout.write(json.dumps(_fail_closed(event_name), separators=(",", ":")))
        return 1
    sys.stdout.write(probe_result.stdout)
    sys.stderr.write(probe_result.stderr)
    return 0


def _desktop_probe_lane(environment: Mapping[str, str] | None = None) -> bool:
    """Whether this call is the frozen macOS Desktop lane that owns the probe."""

    source = os.environ if environment is None else environment
    return bool(getattr(sys, "frozen", False)) and sys.platform == "darwin" and source.get("HOL_GUARD_DESKTOP") == "1"


def _native_argv(
    native: Path,
    *,
    state_path: str | Path,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    query: str,
    hook_timeouts: Mapping[str, int],
    manifest_path: str | Path | None,
    config_json: str | None,
) -> tuple[str, ...]:
    return (
        str(native),
        _native_bridge_command(),
        config_json
        if config_json is not None
        else _native_bridge_config(
            state_path=state_path,
            fallback_command=fallback_command,
            start_command=start_command,
            query=query,
            hook_timeouts=hook_timeouts,
            manifest_path=manifest_path,
        ),
    )


def _native_bridge_executable(guard_home: Path) -> Path | None:
    return native_hook_bridge_executable(NATIVE_CODEX_HOOK_FEATURE, guard_home=guard_home)


def _native_bridge_command() -> str:
    return NATIVE_CODEX_HOOK_COMMAND


def _native_bridge_config(
    *,
    state_path: str | Path,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    query: str,
    hook_timeouts: Mapping[str, int],
    manifest_path: str | Path | None,
) -> str:
    """The config the installed native command carries, rebuilt from this call.

    The runtime reads the same fields ``bridge_config_from_argv`` does, and
    refuses anything Python would refuse, so a call that arrives without its
    original argument is rebuilt here rather than repaired.
    """

    config = {
        "state_path": str(state_path),
        "manifest_path": str(manifest_path or ""),
        "fallback_command": [str(item) for item in fallback_command],
        "start_command": [str(item) for item in start_command],
        "query": query,
        "hook_timeouts": {str(event): int(timeout) for event, timeout in hook_timeouts.items()},
    }
    return json.dumps(config, ensure_ascii=False, separators=(",", ":"))


def _desktop_transition_probe_command(
    *,
    data: str,
    state_path: str | Path,
    query: str,
    hook_timeouts: Mapping[str, int],
    environment: Mapping[str, str] | None = None,
) -> tuple[str, ...] | None:
    """Build the strict signed-proxy path for an authenticated Desktop probe."""

    source = os.environ if environment is None else environment
    if not _desktop_probe_lane(source):
        return None

    payload = _json_object(data)
    if payload is None or payload.get("hook_event_name") != "PreToolUse":
        return None
    from codex_plugin_scanner.guard.runtime_transition_hook_probe import (
        PROBE_FIELD,
        transition_hook_probe,
    )

    if PROBE_FIELD not in payload or transition_hook_probe(payload) is None:
        return None

    guard_home = Path(state_path)
    if guard_home.name == "daemon-state.json":
        guard_home = guard_home.parent
    if not guard_home.is_absolute():
        raise RuntimeError("Desktop transition probe has no absolute Guard home")

    proxy = desktop_hook_proxy_context(source).get("HOL_GUARD_DESKTOP_HOOK_PROXY")
    timeout_seconds = hook_timeouts.get("PreToolUse")
    if proxy is None or type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise RuntimeError("Desktop transition probe has no signed proxy or valid deadline")

    query_values = parse_qs(query, keep_blank_values=True)
    home_values = query_values.get("home", [])
    home = Path(home_values[0]) if len(home_values) == 1 else None
    workspace_value = payload.get("cwd")
    workspace = Path(workspace_value) if isinstance(workspace_value, str) else None
    if (
        home is None
        or not home.is_absolute()
        or workspace is None
        or not workspace.is_absolute()
        or "\x00" in str(home)
        or "\x00" in str(workspace)
    ):
        raise RuntimeError("Desktop transition probe has an invalid home or workspace")

    from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import bounded_cli_hook_command

    command = bounded_cli_hook_command(
        # The bundle executable is both the signed proxy and the fallback
        # target. Requiring the proxy makes fallback exit before Core runs.
        python_executable=proxy,
        package_root=Path(__file__).resolve().parents[3],
        guard_home=guard_home,
        cli_args=[
            "guard",
            "hook",
            "--guard-home",
            str(guard_home.resolve(strict=False)),
            "--harness",
            "codex",
            "--home",
            str(home.resolve(strict=False)),
            "--workspace",
            str(workspace.resolve(strict=False)),
        ],
        harness="codex",
        timeout_seconds=float(timeout_seconds),
        require_desktop_proxy=True,
    )
    if len(command) != 10 or command[4] != proxy or command[8] != proxy or command[9] != "1":
        raise RuntimeError("Desktop transition probe did not resolve to its strict signed proxy")
    return command


def _bound_hook_input(hook_timeouts: Mapping[str, int]) -> tuple[str, str, float, float] | None:
    """The probe lane's hook body, stamped the way the runtime stamps its own."""

    raw_data = _hook_input(_MAX_HOOK_INPUT_BYTES)
    if raw_data is None:
        return None
    input_ready_at = time.monotonic()
    event_name = _event_name(raw_data)
    timeout_seconds = _request_timeout(event_name, hook_timeouts)
    data = (
        _with_browser_wait_process(raw_data, wait_timeout_seconds=max(1.0, timeout_seconds - 1.0))
        if event_name == "PreToolUse"
        else raw_data
    )
    # Native Git-helper checks need the environment Codex will run the command
    # in; without it every Git read is treated as unverifiable.
    return event_name, stamp_hook_input_text(data), timeout_seconds, input_ready_at


def _with_browser_wait_process(data: str, *, wait_timeout_seconds: float) -> str:
    payload = _json_object(data)
    if payload is None:
        return data
    process_identity = current_process_identity()
    if process_identity is None:
        payload.pop(CODEX_BROWSER_WAIT_PROCESS_KEY, None)
        payload.pop(CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY, None)
    else:
        payload[CODEX_BROWSER_WAIT_PROCESS_KEY] = process_identity
        payload[CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY] = min(
            MAX_APPROVAL_WAIT_TIMEOUT_SECONDS,
            max(1, int(wait_timeout_seconds)),
        )
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def _request_timeout(event_name: str, hook_timeouts: Mapping[str, int]) -> float:
    timeout = hook_timeouts.get(event_name, min(hook_timeouts.values(), default=10))
    return float(max(1, timeout - _HOOK_TIMEOUT_GRACE_SECONDS))


def _deny_without_a_runtime() -> int:
    data = _hook_input(_MAX_HOOK_INPUT_BYTES)
    event_name = "PreToolUse" if data is None else _event_name(data)
    sys.stdout.write(json.dumps(_fail_closed(event_name), separators=(",", ":")))
    return 0


def _json_object(text: str) -> dict[str, object] | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _event_name(data: str) -> str:
    payload = _json_object(data)
    if payload is None:
        return "PreToolUse"
    return runtime_hook_event_name(payload)


def _fail_closed(event_name: str, reason: str = _NATIVE_RUNTIME_UNAVAILABLE) -> dict[str, object]:
    if hook_event_is_permission_request(event_name):
        return {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "deny",
                    "message": reason,
                },
            }
        }
    if event_name == "PreToolUse":
        return {
            "hookSpecificOutput": {
                "hookEventName": event_name,
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
    return {
        "continue": True,
        "systemMessage": reason,
    }


def _bridge_config_from_argv(argv: Sequence[str]) -> BridgeConfig:
    return _parse_bridge_config(argv, timeout_grace_seconds=_HOOK_TIMEOUT_GRACE_SECONDS)


if __name__ == "__main__":
    _config = _bridge_config_from_argv(sys.argv)
    raise SystemExit(
        main(
            state_path=_config["state_path"],
            manifest_path=_config["manifest_path"],
            fallback_command=_config["fallback_command"],
            start_command=_config["start_command"],
            query=_config["query"],
            hook_timeouts=_config["hook_timeouts"],
            config_json=_config["config_json"],
        )
    )
