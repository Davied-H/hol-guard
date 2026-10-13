"""Record the Oh My Pi steps the daemon takes on the hooks the resident answers.

Three groups, each recorded from the daemon code itself:

* ``source_ref_external_allowed``: the flag ``_review_native_edge_with_snapshot``
  passes the edge for a route harness spelling, captured at its edge call.
* ``structured_mediation``: whether ``_apply_structured_mediation`` reads the
  managed structured-output config for a harness and event, captured at that
  read. The resident cannot read it, so such a hook defers.
* ``lifecycle``: the constant ``availability_harness_response`` returns for an
  ``pi`` or ``omp`` event the edge does not review.

Run from the repository root:

    .venv/bin/python rust/crates/guard-runtime/testdata/hook_direct_pi/record_pi_vectors.py
"""

from __future__ import annotations

import json
import tempfile
from contextlib import suppress
from pathlib import Path

from codex_plugin_scanner.guard.daemon.hook_availability_policy import availability_harness_response
from codex_plugin_scanner.guard.daemon.hook_worker_native import HookWorkerNativeMixin

OUT = Path(__file__).with_name("pi_vectors.json")
HOME = Path("/home/guard")
UNAVAILABLE_REASON_CODE = "native_hook_event_unavailable"
SPELLINGS = [
    "pi",
    "omp",
    "PI",
    " Omp ",
    "\tpi\n",
    "\x1cpi\x1f",
    "\u3000omp\u00a0",
    "o_m_p",
    "oh-my-pi",
    "oh_my_pi",
    "pi-agent",
    "pi_coding_agent",
    "pi-coding-agent",
    "pix",
    "p i",
    "",
    "codex",
    "claude-code",
    "cursor",
    "copilot",
    "kimi",
    "devin",
    "zcode",
    "openclaw",
    "hermes",
    "cline",
    "opencode",
    "grok",
]
EVENTS = ["PreToolUse", "PostToolUse", "UserPromptSubmit"]
LIFECYCLE_EVENTS = [
    "SessionStart",
    "SessionEnd",
    "session_start",
    "Stop",
    "SubagentStop",
    "Notification",
    "TaskStart",
    "SessionShutdown",
    "agent_end",
    "turn_end",
]


class _ReachedError(Exception):
    pass


class _EdgeHost:
    """Stops `_review_native_edge_with_snapshot` at its edge call."""

    def __init__(self) -> None:
        self.captured: dict[str, object] = {}

    def _review_raw_hook_native(self, **kwargs: object) -> None:
        self.captured = kwargs
        raise _ReachedError


class _MediationHost:
    """Stops `_apply_structured_mediation` at its config read."""

    def _structured_output_resolution(self, **_kwargs: object) -> None:
        raise _ReachedError


def _source_ref_external_allowed(spelling: str, guard_home: Path) -> bool:
    host = _EdgeHost()
    with suppress(_ReachedError):
        HookWorkerNativeMixin._review_native_edge_with_snapshot(  # pyright: ignore[reportPrivateUsage]
            host,  # type: ignore[arg-type]
            payload={"tool_name": "Bash", "tool_input": {"command": "pwd"}},
            harness=spelling,
            event_name="PreToolUse",
            default_harness=spelling,
            home_dir=HOME,
            guard_home=guard_home,
            workspace=None,
            deadline=None,
            policy_snapshot={"generation": 1},
            recording_only=False,
        )
    allowed = host.captured["source_ref_external_allowed"]
    assert isinstance(allowed, bool)
    return allowed


def _structured_mediation(spelling: str, event: str, guard_home: Path) -> bool:
    try:
        HookWorkerNativeMixin._apply_structured_mediation(  # pyright: ignore[reportPrivateUsage]
            _MediationHost(),  # type: ignore[arg-type]
            {},
            payload={},
            native_harness=spelling,
            native_event=event,
            accepted_receipt=None,
            guard_home=guard_home,
            workspace=None,
            deadline=None,
            recording_only=False,
        )
    except _ReachedError:
        return True
    return False


def main() -> None:
    with tempfile.TemporaryDirectory() as root:
        guard_home = Path(root)
        source_ref = [
            {"harness": spelling, "allowed": _source_ref_external_allowed(spelling, guard_home)}
            for spelling in SPELLINGS
        ]
        mediation = [
            {"harness": spelling, "event": event, "mediated": _structured_mediation(spelling, event, guard_home)}
            for spelling in SPELLINGS
            for event in EVENTS
        ]
    lifecycle = [
        {
            "harness": harness,
            "event": event,
            "response": availability_harness_response(
                {},
                harness=harness,
                event_name=event,
                reason_code=UNAVAILABLE_REASON_CODE,
                reason="HOL Guard could not complete the native hook decision safely.",
            ),
        }
        for harness in ("pi", "omp")
        for event in LIFECYCLE_EVENTS
    ]
    vectors = {
        "source_ref_external_allowed": source_ref,
        "structured_mediation": mediation,
        "lifecycle": lifecycle,
    }
    OUT.write_text(json.dumps(vectors, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
