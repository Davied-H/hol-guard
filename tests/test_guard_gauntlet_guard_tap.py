from __future__ import annotations

import threading
from pathlib import Path

from ci.gauntlet.guard_tap import GuardTap, read_tap


class _Worker:
    def __init__(self) -> None:
        self._last_native_decision_receipt: dict[str, object] | None = None
        self.both_reviewing = threading.Barrier(2, timeout=5)

    def _record_native_decision_receipt(self, receipt: object) -> dict[str, object] | None:
        accepted = dict(receipt) if isinstance(receipt, dict) else None
        self._last_native_decision_receipt = accepted
        return accepted

    def review_http_payload(self, *, payload: dict[str, object], **_kwargs: object) -> dict[str, object]:
        tool = str(payload["tool_name"])
        self._record_native_decision_receipt({"decision_id": tool})
        # Both reviews must be in flight at once, as they are in the daemon.
        self.both_reviewing.wait()
        return {"tool": tool}


def test_tap_lets_parallel_reviews_overlap_and_keeps_each_receipt(tmp_path: Path) -> None:
    worker = _Worker()
    log = tmp_path / "tap.jsonl"
    errors: list[BaseException] = []

    def call(tool: str) -> None:
        try:
            worker.review_http_payload(payload={"tool_name": tool}, default_harness="claude-code")
        except BaseException as error:
            errors.append(error)

    with GuardTap(worker, log):
        threads = [threading.Thread(target=call, args=(tool,)) for tool in ("Read", "Bash")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

    assert errors == []
    rows = read_tap(log)
    assert sorted((row["payload"]["tool_name"], row["receipt"]["decision_id"]) for row in rows) == [
        ("Bash", "Bash"),
        ("Read", "Read"),
    ]
    assert "review_http_payload" not in worker.__dict__
    assert "_record_native_decision_receipt" not in worker.__dict__
