from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_secrets
from codex_plugin_scanner.guard.native_secrets import NativeSecretsError, SecretsRefusedError
from codex_plugin_scanner.guard.secrets.cli import main as secrets_main

BOUNDS = {
    "include_history": False,
    "max_commits": 500,
    "max_files": 5000,
    "max_file_bytes": 2 * 1024 * 1024,
    "max_total_bytes": 128 * 1024 * 1024,
    "max_findings": 500,
}
FINDING = {
    "commit": None,
    "confidence": "high",
    "family": "GitHub token",
    "line": 3,
    "path": "config.env",
    "severity": "critical",
}


def _scan_payload(**overrides: object) -> dict[str, object]:
    return {
        "errors": [],
        "files_scanned": 1,
        "commits_scanned": 0,
        "findings": [FINDING],
        "truncated": False,
        **overrides,
    }


def _serve(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, reply: dict[str, object], **overrides: object
) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []

    def fake_request(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        request = kwargs["request"]
        assert isinstance(request, dict)
        return {
            "schema": "guard-secrets-scan-result.v1",
            "request_id": request["request_id"],
            "request_sha256": native_secrets._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": None,
            "message": None,
            **reply,
            **overrides,
        }

    monkeypatch.setattr(native_secrets, "_resolve_digest_home", lambda _home: tmp_path)
    monkeypatch.setattr(native_secrets, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_secrets.native_execution, "_resident_request", fake_request)
    return calls


def test_scan_sends_an_absolute_target_and_every_bound(monkeypatch, tmp_path, capsys) -> None:
    calls = _serve(monkeypatch, tmp_path, {"payload": _scan_payload()})
    monkeypatch.chdir(tmp_path)

    exit_code = secrets_main(["scan", "--fail-on-findings"])

    request = calls[0]["request"]
    assert isinstance(request, dict)
    assert calls[0]["operation"] == "secrets_scan"
    assert calls[0]["required_feature"] == "secrets-scan-v1"
    assert request["action"] == "scan"
    assert Path(str(request["target"])).is_absolute()
    assert Path(str(request["target"])).samefile(tmp_path)
    assert request["bounds"] == BOUNDS
    assert exit_code == 3
    output = capsys.readouterr().out
    assert "GitHub token at config.env:3" in output
    assert "Raw secret values are intentionally omitted." in output


def test_staged_scan_never_requests_history(monkeypatch, tmp_path) -> None:
    calls = _serve(monkeypatch, tmp_path, {"payload": _scan_payload(findings=[])})

    assert secrets_main(["scan", str(tmp_path), "--staged"]) == 0

    request = calls[0]["request"]
    assert isinstance(request, dict)
    assert request["action"] == "staged"
    assert isinstance(request["bounds"], dict)
    assert request["bounds"]["include_history"] is False


def test_partial_scan_is_an_infrastructure_error(monkeypatch, tmp_path, capsys) -> None:
    _serve(
        monkeypatch,
        tmp_path,
        {"payload": _scan_payload(findings=[], truncated=True, errors=["git_staged_enumeration_failed"])},
    )

    assert secrets_main(["scan", str(tmp_path), "--staged"]) == 2

    captured = capsys.readouterr()
    assert "Scan coverage is partial" in captured.out
    assert "git_staged_enumeration_failed" in captured.err


def test_json_output_is_sorted_and_carries_no_candidate(monkeypatch, tmp_path, capsys) -> None:
    _serve(monkeypatch, tmp_path, {"payload": _scan_payload()})

    assert secrets_main(["scan", str(tmp_path), "--json"]) == 0

    out = capsys.readouterr().out
    assert out == json.dumps(_scan_payload(), sort_keys=True) + "\n"


def test_refusal_is_reported_and_exits_two(monkeypatch, tmp_path, capsys) -> None:
    _serve(
        monkeypatch,
        tmp_path,
        {"status": "error", "code": "secrets_scan_refused", "message": "custom core.hooksPath is configured"},
    )

    assert secrets_main(["install-hook", str(tmp_path)]) == 2
    assert "Error: custom core.hooksPath is configured" in capsys.readouterr().err


def test_hook_install_and_uninstall_render_the_public_result(monkeypatch, tmp_path, capsys) -> None:
    payload = {"status": "installed", "hook": ".git/hooks/pre-commit", "chained_existing": True}
    calls = _serve(monkeypatch, tmp_path, {"payload": payload})

    assert secrets_main(["install-hook", str(tmp_path)]) == 0
    assert secrets_main(["uninstall-hook", str(tmp_path)]) == 0

    actions = [call["request"]["action"] for call in calls]  # type: ignore[index]
    assert actions == ["install_hook", "uninstall_hook"]
    output = capsys.readouterr().out
    assert "pre-commit hook installed: installed" in output
    assert "chained before the staged secret scan" in output
    request = calls[0]["request"]
    assert isinstance(request, dict)
    assert request["bounds"] is None


def test_rules_come_from_the_native_owner(monkeypatch, tmp_path, capsys) -> None:
    calls = _serve(monkeypatch, tmp_path, {"payload": {"json": '{"rules": []}\n', "text": "HOL Guard Secrets\n"}})

    assert secrets_main(["rules", "--json"]) == 0
    assert capsys.readouterr().out == '{"rules": []}\n'
    assert secrets_main(["rules"]) == 0
    assert capsys.readouterr().out == "HOL Guard Secrets\n"
    request = calls[0]["request"]
    assert isinstance(request, dict)
    assert request["target"] == ""


@pytest.mark.parametrize(
    "overrides",
    [
        {"request_id": "someone-else"},
        {"request_sha256": "0" * 64},
        {"status": "error", "code": "native_secrets_scan_internal", "payload": None},
        {"payload": None},
        {"payload": _scan_payload(), "message": "unexpected"},
        {"unexpected": 1},
    ],
)
def test_any_unbound_or_malformed_reply_fails_closed(monkeypatch, tmp_path, overrides) -> None:
    _serve(monkeypatch, tmp_path, {"payload": _scan_payload()}, **overrides)

    with pytest.raises(NativeSecretsError):
        native_secrets.native_secrets_scan(str(tmp_path), staged=False, bounds=BOUNDS)


def test_unavailable_resident_fails_closed(monkeypatch, tmp_path, capsys) -> None:
    _serve(monkeypatch, tmp_path, {"payload": _scan_payload()})
    monkeypatch.setattr(native_secrets, "ensure_resident_prerequisite", lambda _home: False)

    assert secrets_main(["scan", str(tmp_path)]) == 2
    assert "native_secrets_scan_unavailable" in capsys.readouterr().err


def test_refusal_requires_a_message_and_no_payload(monkeypatch, tmp_path) -> None:
    _serve(monkeypatch, tmp_path, {"status": "error", "code": "secrets_scan_refused", "message": "no"})
    with pytest.raises(SecretsRefusedError):
        native_secrets.native_secrets_hook(str(tmp_path), install=True)

    _serve(monkeypatch, tmp_path, {"status": "error", "code": "secrets_scan_refused", "message": None})
    with pytest.raises(NativeSecretsError):
        native_secrets.native_secrets_hook(str(tmp_path), install=True)
