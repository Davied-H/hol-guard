"""Count what ordinary work makes the harness show or ask, and nothing else.

Guard is meant to behave like a silent antivirus: ordinary agent work flows with
zero interruptions and only real attack vectors stop. A harness is interrupted
whenever it receives any of:

* a decision other than allow (deny, ask or an approval/review requirement);
* rendered warning, notice or permission-reason text, even on an allow;
* an approval row created in Guard's store.

A ``warn`` is an allow plus visible text, so it is an interruption exactly when
text is rendered. A warn that renders nothing is quiet. This module only
classifies; the judges decide which cases are held to zero.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .catalog import Scenario

# Response keys whose non-empty string is shown to the harness or its user on any decision.
TEXT_KEYS = ("systemMessage", "message", "stopReason", "additionalContext", "permissionDecisionReason")
# The Pi/Oh My Pi shape carries its text in ``reason``; Guard only renders it for a warning or notice.
WARNING_ACTIONS = frozenset({"warn"})
LOUD_NOTICES = frozenset({"warning", "excerpt"})
REVIEW_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})
# Protection cases and the Watch case expect Guard to speak; only ordinary work is held to zero.
EXEMPT_ORACLES = frozenset({"watch-command", "mixed-read-batch"})
KNOWN_GAPS = Path(__file__).with_name("known_gaps.json")


def _flatten(response: dict[str, Any]) -> dict[str, Any]:
    specific = response.get("hookSpecificOutput")
    merged = dict(response)
    if isinstance(specific, dict):
        for key, value in specific.items():
            merged.setdefault(key, value)
    return merged


def _decision(flat: dict[str, Any]) -> str:
    if flat.get("continue") is False or flat.get("decision") == "block":
        return "deny"
    permission = flat.get("permissionDecision") or flat.get("permission") or flat.get("decision")
    decision = flat.get("decision")
    if isinstance(decision, dict):
        permission = permission if isinstance(permission, str) else decision.get("behavior")
    return {"deny": "deny", "ask": "ask", "block": "deny"}.get(str(permission or "").lower(), "allow")


def rendered_fields(response: Any) -> list[str]:
    """Name each response field that carries text the harness would render.

    Mirrors ``rendered_fields`` in ``observer.ts``; names, never text, are evidence.
    """
    if not isinstance(response, dict):
        return []
    flat = _flatten(response)
    fields = [key for key in TEXT_KEYS if isinstance(flat.get(key), str) and flat[key].strip()]
    notice = flat.get("notice")
    loud = isinstance(notice, str) and notice in LOUD_NOTICES
    if loud:
        fields.append("notice")
    reason = flat.get("reason")
    if isinstance(reason, str) and reason.strip() and (loud or flat.get("policy_action") in WARNING_ACTIONS):
        fields.append("reason")
    return fields


def _event(kind: str, row: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "kind": kind,
        "harness": row.get("harness"),
        "tool": row.get("tool"),
        "event": row.get("event"),
        "reason_code": row.get("reason_code"),
        **extra,
    }


def observation_interruptions(row: dict[str, Any], harness: str | None = None) -> list[dict[str, Any]]:
    """Interruptions one hook answer caused. Accepts observer rows and daemon tap rows."""
    if row.get("observer_error") or row.get("transport_error"):
        return []
    response = row.get("response") if isinstance(row.get("response"), dict) else None
    receipt = row.get("receipt") if isinstance(row.get("receipt"), dict) else {}
    payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
    if response is not None:
        flat = _flatten(response)
        decision = _decision(flat)
        action = response.get("policy_action") or receipt.get("policy_action")
        reason_code = response.get("reason_code") or receipt.get("reason_code")
        fields = rendered_fields(response)
        tool = payload.get("tool_name")
        event = receipt.get("event_name") or payload.get("hook_event_name")
    else:
        decision = str(row.get("decision") or "allow")
        action = row.get("policy_action")
        reason_code = row.get("reason_code")
        fields = row.get("rendered_fields")
        tool, event = row.get("tool"), row.get("event")
        if not isinstance(fields, list):
            # Without the observer's rendered-text proof a quiet answer cannot be claimed.
            fields = ["unproven"]
    base = {"harness": harness or row.get("route_harness") or receipt.get("harness"), "tool": tool, "event": event}
    base["reason_code"] = reason_code
    found = []
    if decision != "allow" or action in REVIEW_ACTIONS:
        found.append(_event("decision", base, decision=decision if decision != "allow" else str(action)))
    if fields:
        found.append(_event("rendered", base, fields=sorted(fields)))
    return found


def case_interruptions(
    scenario: Scenario,
    observations: list[dict[str, Any]],
    approvals: list[dict[str, Any]],
    approval_delta: int,
    harness: str = "omp",
) -> dict[str, Any]:
    """The compact interruption record stored on a case's assessment."""
    events: list[dict[str, Any]] = []
    decisions = quiet = 0
    for row in observations:
        if row.get("observer_error") or row.get("transport_error"):
            continue
        decisions += 1
        found = observation_interruptions(row, harness)
        quiet += not found
        events.extend(found)
    rows = [row for row in approvals if isinstance(row, dict)]
    approval_events = [
        _event("approval", {"harness": harness, "tool": row.get("tool_name"), "reason_code": row.get("reason_code")})
        for row in rows
    ]
    if isinstance(approval_delta, int) and approval_delta > len(rows):
        approval_events.extend(_event("approval", {"harness": harness}) for _ in range(approval_delta - len(rows)))
    events.extend(approval_events)
    return {
        "benign": scenario.expectation == "allow" and scenario.oracle not in EXEMPT_ORACLES,
        "decisions": decisions,
        "quiet_decisions": quiet,
        "approval_rows": len(approval_events),
        "events": events,
    }


def describe(events: list[dict[str, Any]]) -> str:
    """One short human sentence naming the first interruption."""
    first = events[0]
    where = first.get("tool") or "a tool call"
    code = first.get("reason_code") or "no reason code"
    if first["kind"] == "rendered":
        return f"Guard rendered warning text ({','.join(first['fields'])}) on {where} ({code})"
    if first["kind"] == "approval":
        return f"ordinary work created an approval row for {where} ({code})"
    return f"Guard stopped or reviewed {where} ({code})"


def summarize_interruptions(cases: list[dict[str, Any]], harness: str | None = None) -> dict[str, Any]:
    """Aggregate per-case records into run totals by harness, reason code and tool."""
    benign = [c for c in cases if isinstance(c.get("interruptions"), dict) and c["interruptions"].get("benign")]
    events = [e for c in benign for e in c["interruptions"].get("events", [])]
    decisions = sum(c["interruptions"].get("decisions", 0) for c in benign)
    quiet = sum(c["interruptions"].get("quiet_decisions", 0) for c in benign)
    approvals = sum(c["interruptions"].get("approval_rows", 0) for c in benign)
    interrupted_cases = sum(bool(c["interruptions"].get("events")) for c in benign)

    def count(key: str) -> dict[str, int]:
        return dict(sorted(Counter(str(e.get(key) or harness or "unknown") for e in events).items()))

    return {
        "benign_cases": len(benign),
        "benign_decisions": decisions,
        "benign_interruptions": len(events),
        "benign_interrupted_cases": interrupted_cases,
        "by_kind": count("kind"),
        "by_harness": count("harness"),
        "by_reason_code": count("reason_code"),
        "by_tool": count("tool"),
        # Share of ordinary hook answers that raised nothing; 1.0 means a silent run.
        "quiet_allow_rate": round(quiet / (decisions + approvals), 4) if decisions + approvals else None,
        "quiet_case_rate": round(1 - interrupted_cases / len(benign), 4) if benign else None,
    }


def load_known_gaps(path: Path = KNOWN_GAPS) -> dict[str, str]:
    """Cases expected to fail on the current product, with why. Reported, never hidden."""
    data = json.loads(path.read_text(encoding="utf-8"))
    gaps = data.get("known_gaps") if isinstance(data, dict) else None
    if not isinstance(gaps, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in gaps.items()):
        raise ValueError("known gaps must map scenario ids to reasons")
    return gaps


def known_gap_report(cases: list[dict[str, Any]], gaps: dict[str, str]) -> list[dict[str, Any]]:
    """Each known-gap case that ran: still failing (expected) or passing (stale, remove it)."""
    return [
        {"id": c["id"], "outcome": c.get("outcome"), "stale": c.get("outcome") == "pass", "reason": gaps[c["id"]]}
        for c in cases
        if c.get("id") in gaps
    ]


def report_sections(cases: list[dict[str, Any]], harness: str | None = None) -> dict[str, Any]:
    """The summary.json blocks every run publishes: interruption metrics and known-gap status."""
    return {
        "interruptions": summarize_interruptions(cases, harness),
        "known_gaps": known_gap_report(cases, load_known_gaps()) if KNOWN_GAPS.is_file() else [],
    }
