"""The sensitive-request client presents resident answers and never invents one."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_sensitive_request as client
from codex_plugin_scanner.guard.native_request_context import NativeRequestContextFailure
from codex_plugin_scanner.guard.runtime import secret_file_requests


def _reply(query: str, result: object) -> dict[str, object]:
    return {"kind": "sensitive_request", "query": query, "result": result}


def _answer(monkeypatch: pytest.MonkeyPatch, reply: object, seen: list[dict[str, Any]] | None = None) -> None:
    def fake_call(action: dict[str, Any], **_kwargs: object) -> object:
        if seen is not None:
            seen.append(action)
        return reply

    monkeypatch.setattr(client, "_call", fake_call)
    monkeypatch.setattr(client, "_control_snapshot", lambda: None)


@pytest.mark.parametrize(
    "reply",
    [
        NativeRequestContextFailure("native_request_context_unavailable"),
        {},
        {"kind": "other", "query": "tool_action", "result": {"match": None}},
        {"kind": "sensitive_request", "query": "file_read", "result": {"match": None}},
        {"kind": "sensitive_request", "query": "tool_action", "result": {"match": None}, "extra": 1},
        _reply("tool_action", {"match": {"tool_name": "Bash"}}),
        _reply("tool_action", "unreviewed"),
    ],
)
def test_refused_or_malformed_reply_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, reply: Any) -> None:
    _answer(monkeypatch, reply)
    with pytest.raises(client.NativeSensitiveRequestError):
        secret_file_requests.extract_sensitive_tool_action_request(
            "Bash", {"command": "cat ~/.ssh/id_rsa"}, cwd=tmp_path, home_dir=tmp_path
        )


def test_classifier_error_keeps_the_legacy_value_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _answer(monkeypatch, _reply("tool_action", {"error": "native command evaluation does not match"}))
    with pytest.raises(ValueError, match="does not match"):
        secret_file_requests.extract_sensitive_tool_action_request("Bash", {"command": "ls"}, cwd=tmp_path)


def test_file_read_match_is_rebuilt_from_the_reply(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: list[dict[str, Any]] = []
    path_match = {
        "family": "ssh_private_key",
        "path": str(tmp_path / ".ssh/id_rsa"),
        "reason": "synthetic",
        "requested_path": "~/.ssh/id_rsa",
        "sensitivity": "critical",
    }
    _answer(
        monkeypatch,
        _reply("file_read", {"tool_name": "Read", "normalized_tool_name": "read", "path_match": path_match}),
        seen,
    )
    found = secret_file_requests.extract_sensitive_file_read_request(
        "Read", {"file_path": "~/.ssh/id_rsa"}, cwd=tmp_path, home_dir=tmp_path
    )
    assert found is not None
    assert found.path_match.family == "ssh_private_key"
    assert found.path_match.sensitivity == "critical"
    body = seen[0]["body"]
    assert body["query"] == "file_read"
    assert body["input"]["home_dir"] == str(tmp_path)
    assert "verdict" not in body["input"]


def test_unknown_sensitivity_is_not_presented(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path_match = {"family": "x", "path": "/x", "reason": "x", "requested_path": "x", "sensitivity": "low"}
    _answer(
        monkeypatch,
        _reply("file_read", {"tool_name": "Read", "normalized_tool_name": "read", "path_match": path_match}),
    )
    with pytest.raises(client.NativeSensitiveRequestError):
        secret_file_requests.extract_sensitive_file_read_request("Read", {"file_path": "x"}, cwd=tmp_path)


def test_boolean_answers_must_be_booleans(monkeypatch: pytest.MonkeyPatch) -> None:
    _answer(monkeypatch, _reply("read_only_lookup_target_is_safe", 1))
    with pytest.raises(client.NativeSensitiveRequestError):
        secret_file_requests._read_only_lookup_target_is_safe("README.md", allow_dirs=False)


def test_command_list_texts_are_a_tuple_of_strings(monkeypatch: pytest.MonkeyPatch) -> None:
    _answer(monkeypatch, _reply("command_list_candidate_texts", ["cat README.md"]))
    assert secret_file_requests.command_list_candidate_texts(["cat", "README.md"]) == ("cat README.md",)
