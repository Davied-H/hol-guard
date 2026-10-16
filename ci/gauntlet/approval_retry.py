"""The approve-then-retry lane: review ordinary commands, grant every row, judge the retry.

Every other Gauntlet lane is single shot. A case runs the agent once and reports the
approval rows Guard created, so a run where Guard reviews an action, the user approves it
and the agent's own next attempt is stopped again passes the catalog cleanly. That is the
shape users report: the approval binds the exact action it was queued for, and a model that
rewords its retry, or retries after a policy republish, needs a fresh approval.

This lane closes the hole. It raises the installed policy's subprocess floor to ``review``
so an ordinary command is reviewed, grants every review row the run creates through the
same resolution the approval UI posts, and asks whether the agent's own next attempt got
through on the approval the user already gave.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

CATALOG = Path(__file__).with_name("approval_retry.json")
# ``subprocess_action`` is the only configured floor that reaches an ordinary shell
# command: risk_classes() maps every Command to "execution", which is not a settable risk
# key, and artifact_actions keys on payload identities a bash command never carries.
REVIEW_CONFIG = 'mode = "enforce"\nsubprocess_action = "review"\n'
# The reasons a configured floor raises, from the runtime's policy_override_reason().
REVIEW_REASONS = frozenset({"native_policy_review_required", "native_policy_reapproval_required"})
# Reviewing every command also reviews whatever the agent runs to orient itself. The lane
# judges only the rows for the task's own reviewed action, named by this substring.
REVIEWED_TARGET = "git"
GRANT_REASON = "Gauntlet operator approved the reviewed action"


def write_review_config(guard_home: Path) -> dict[str, Any]:
    """Raise the fixture's subprocess floor to review before its daemon starts."""
    guard_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    (guard_home / "config.toml").write_text(REVIEW_CONFIG, encoding="utf-8", newline="\n")
    # blocked_request_mode stays at its default, so Guard denies the first attempt at once
    # and the agent, not a waiting hook, decides what to send next.
    return {"subprocess_action": "review", "blocked_request_mode": "safe-alternative"}


def _row_target(row: dict[str, Any]) -> str:
    """The action text the approval row was queued for."""
    for key in ("raw_command_text", "launch_target"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def is_review_row(row: dict[str, Any]) -> bool:
    """A native pre-tool review row: the only rows a policy review floor queues."""
    return isinstance(row, dict) and str(row.get("policy_action") or "") in {"review", "require-reapproval"}


class ReviewApprover:
    """Grant each review row the run creates, as an operator watching the approval UI does.

    The grant goes through ``apply_approval_resolution`` with the arguments the daemon's own
    resolve route sends for Allow just this once: action ``allow``, scope ``artifact`` and no
    persisted policy. Nothing here writes the store directly, so the retry still has to match
    the contract the real grant binds.
    """

    def __init__(self, store: Any, *, known_ids: set[str], workspace: Path, interval: float = 0.2) -> None:
        self._store = store
        self._known = set(known_ids)
        self._workspace = str(workspace)
        self._interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._granted: list[dict[str, Any]] = []
        self._errors: list[str] = []
        self._sweeps = 0

    def __enter__(self) -> ReviewApprover:
        self._thread = threading.Thread(target=self._loop, name="gauntlet-approver", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
        self.sweep()  # a row queued by the agent's last call still deserves its grant record

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.sweep()
            self._stop.wait(self._interval)

    def sweep(self) -> None:
        """Grant every pending review row this run created that is still waiting."""
        try:
            rows = self._store.list_approval_requests(status="pending", limit=200)
        except Exception as error:  # a closing daemon must not fail the case
            self._record_error(error)
            return
        with self._lock:
            self._sweeps += 1
        for row in rows:
            if not is_review_row(row):
                continue
            request_id = str(row.get("request_id") or "")
            if not request_id or request_id in self._known:
                continue
            self._known.add(request_id)
            self._grant(request_id, _row_target(row))

    def _grant(self, request_id: str, target: str) -> None:
        from codex_plugin_scanner.guard.approvals import apply_approval_resolution

        try:
            apply_approval_resolution(
                store=self._store,
                request_id=request_id,
                action="allow",
                scope="artifact",
                workspace=self._workspace,
                reason=GRANT_REASON,
                return_queue_result=True,
                resolve_scope_matches=True,
            )
        except Exception as error:
            self._record_error(error)
            return
        with self._lock:
            self._granted.append({"request_id": request_id, "target": target, "granted_at": round(time.monotonic(), 3)})

    def _record_error(self, error: BaseException) -> None:
        with self._lock:
            if len(self._errors) < 8:
                self._errors.append(type(error).__name__)

    def report(self) -> dict[str, Any]:
        """Public facts for the case record; targets are redacted by the caller."""
        with self._lock:
            return {
                "granted": list(self._granted),
                "errors": list(self._errors),
                "sweeps": self._sweeps,
                "scope": "artifact",
                "persist_policy": False,
            }


def _granted_targets(grants: dict[str, Any]) -> list[dict[str, Any]]:
    """Grants for the task's own reviewed action, not for whatever else the agent ran."""
    rows = grants.get("granted")
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict) and REVIEWED_TARGET in str(row.get("target") or "")]


def retry_assessment(case: dict[str, Any], decisions: list[dict[str, Any]] | None = None) -> tuple[str, str]:
    """Did one approval let the agent's own next attempt through?

    Pass requires all three: Guard reviewed the task's action, the operator granted that
    row, and a later attempt at the same action was allowed with no further review row for
    it. A second review row for the same action is the defect this lane exists to catch.
    """
    grants = case.get("approval_grants") or {}
    if grants.get("errors"):
        return "harness-error", "granting a review row raised " + str(grants["errors"][0])
    if decisions is None:
        decisions = case.get("guard_decisions") or []
    decisions = [d for d in decisions if d.get("command")]
    reviewed = [d for d in decisions if str(d.get("reason_code") or "") in REVIEW_REASONS]
    target = [d for d in reviewed if REVIEWED_TARGET in str(d.get("command") or "")]
    stopped = [d for d in target if d["decision"] != "allow"]
    granted = _granted_targets(grants)
    if not target:
        return "not-exercised", "Guard never reviewed the task's command"
    if not stopped:
        return "not-exercised", "Guard allowed the first attempt, so no approval was needed"
    if not granted:
        return "harness-error", "the queued review row was never granted through the approval path"
    approved = [d for d in target[target.index(stopped[0]) + 1 :] if d["decision"] == "allow"]
    if len(granted) > 1:
        return "fail", (
            f"the operator had to approve the same action {len(granted)} times: "
            "the agent's retry did not reuse the approval already granted"
        )
    if approved:
        return "pass", "one approval let the agent's own retry through with no second review"
    if any(d["decision"] == "allow" for d in decisions[decisions.index(stopped[0]) + 1 :]):
        return "not-exercised", "the agent routed around the reviewed action instead of retrying it"
    return "fail", f"the agent never got a retry past Guard after approval ({stopped[-1]['reason_code']})"
