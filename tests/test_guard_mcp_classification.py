"""The MCP classification bridge carries declarations; it never describes them.

Describing a tool is the native runtime's job, and the semantics of that
description are covered by its own tests. What matters here is that Python
hands the declaration over unchanged, keeps the answers in request order and
produces nothing at all when the resident cannot answer.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_mcp_classification
from codex_plugin_scanner.guard.native_mcp_classification import (
    _MAX_ITEMS,
    _MAX_REQUEST_BYTES,
    McpClassificationUnavailableError,
)
from codex_plugin_scanner.guard.runtime.mcp_classification import (
    classify_mcp_action,
    classify_mcp_actions,
)


def _install_transport(
    monkeypatch: pytest.MonkeyPatch,
    *,
    available: bool = True,
) -> list[list[dict[str, object]]]:
    """Record the batches that reach the resident and answer each by name."""

    sent: list[list[dict[str, object]]] = []

    def resident_request(**kwargs: object) -> dict[str, object]:
        request = kwargs["request"]
        assert isinstance(request, dict)
        items = request["items"]
        assert isinstance(items, list)
        sent.append([dict(item) for item in items if isinstance(item, dict)])
        return {"status": "ok"}

    def payload(
        response: dict[str, object] | None,
        request: dict[str, object],
        guard_home: Path,
    ) -> dict[str, object]:
        del response, guard_home
        items = request["items"]
        assert isinstance(items, list)
        return {"classifications": [{"described": item["name"]} for item in items]}

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_mcp_classification.ensure_resident_prerequisite",
        lambda guard_home: available,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_mcp_classification._resident_request",
        resident_request,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_mcp_classification._payload",
        payload,
    )
    return sent


def test_a_declaration_travels_to_the_resident_exactly_as_declared(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sent = _install_transport(monkeypatch)
    schema = {"properties": {"query": {"type": "string", "default": "SECRET"}}}
    described = classify_mcp_action(
        "SLACK_SEARCH_MESSAGES",
        schema,
        guard_home=tmp_path,
        provider="composio",
        annotations={"readOnlyHint": True},
        full_schema=False,
    )

    assert described == {"described": "SLACK_SEARCH_MESSAGES"}
    assert sent == [
        [
            {
                "name": "SLACK_SEARCH_MESSAGES",
                "schema": schema,
                "provider": "composio",
                "annotations": {"readOnlyHint": True},
                "full_schema": False,
            }
        ]
    ]


def test_a_batch_comes_back_in_the_order_it_was_asked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install_transport(monkeypatch)
    names = [f"tool_{index}" for index in range(12)]
    described = classify_mcp_actions(
        [{"name": name, "schema": {"type": "object"}} for name in names],
        guard_home=tmp_path,
    )

    assert [entry["described"] for entry in described] == names


def test_nothing_is_asked_for_an_empty_batch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _install_transport(monkeypatch, available=False)

    assert classify_mcp_actions([], guard_home=tmp_path) == []
    assert sent == []


def test_a_batch_is_split_under_the_count_cap_and_stays_in_order(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sent = _install_transport(monkeypatch)
    names = [f"tool_{index}" for index in range(_MAX_ITEMS + 5)]
    described = classify_mcp_actions([{"name": name, "schema": None} for name in names], guard_home=tmp_path)

    assert len(sent) == 2
    assert [len(batch) for batch in sent] == [_MAX_ITEMS, 5]
    assert [entry["described"] for entry in described] == names


def test_a_batch_is_split_under_the_byte_cap(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _install_transport(monkeypatch)
    filler = "f" * (_MAX_REQUEST_BYTES // 4)
    definitions = [{"name": f"tool_{index}", "schema": {"properties": {filler: {}}}} for index in range(6)]
    described = classify_mcp_actions(definitions, guard_home=tmp_path)

    assert len(sent) > 1
    assert all(len(batch) >= 1 for batch in sent)
    assert [entry["described"] for entry in described] == [str(item["name"]) for item in definitions]


def test_a_declaration_too_large_to_send_is_refused_not_guessed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sent = _install_transport(monkeypatch)
    oversized = {"name": "huge", "schema": {"properties": {"f" * (_MAX_REQUEST_BYTES + 1): {}}}}

    with pytest.raises(McpClassificationUnavailableError):
        classify_mcp_actions([oversized], guard_home=tmp_path)
    assert sent == []


def test_an_unavailable_resident_yields_no_classification(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _install_transport(monkeypatch, available=False)

    with pytest.raises(McpClassificationUnavailableError):
        classify_mcp_action("anything", {"type": "object"}, guard_home=tmp_path)
    assert sent == []


def test_a_reply_that_does_not_answer_every_item_is_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install_transport(monkeypatch)
    monkeypatch.setattr(
        native_mcp_classification,
        "_payload",
        lambda response, request, guard_home: {"classifications": [{"described": "only-one"}]},
    )

    with pytest.raises(McpClassificationUnavailableError):
        classify_mcp_actions(
            [{"name": "a", "schema": None}, {"name": "b", "schema": None}],
            guard_home=tmp_path,
        )


def test_a_transport_failure_never_becomes_a_local_description(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install_transport(monkeypatch)

    def failing_request(**kwargs: object) -> dict[str, object]:
        raise OSError("resident gone")

    monkeypatch.setattr(native_mcp_classification, "_resident_request", failing_request)

    with pytest.raises(McpClassificationUnavailableError):
        classify_mcp_action("anything", {"type": "object"}, guard_home=tmp_path)
