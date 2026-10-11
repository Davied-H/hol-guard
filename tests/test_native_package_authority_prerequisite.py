from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_package_authority as package_authority


def _ready_status(tmp_path):
    return SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "runtime", sha256="a" * 64),
        capabilities=SimpleNamespace(features=("resident-protocol-v2", "package-authority-v1")),
    )


@pytest.mark.parametrize("prepared", [True, False])
def test_resident_request_prepares_guard_home_before_contacting_the_runtime(tmp_path, monkeypatch, prepared):
    guard_home = tmp_path / "guard-home"
    calls: list[str] = []

    def prerequisite(home):
        assert home == guard_home
        calls.append("prerequisite")
        return prepared

    def request(**kwargs):
        calls.append("request")
        return None

    monkeypatch.setattr(package_authority, "native_runtime_status", lambda: _ready_status(tmp_path))
    monkeypatch.setattr(package_authority, "ensure_resident_prerequisite", prerequisite)
    monkeypatch.setattr(package_authority, "native_resident_client_request", request)
    monkeypatch.setattr(package_authority, "_isolated_environment", lambda: {})
    monkeypatch.setattr(package_authority, "native_record_resident_failure", lambda *args, **kwargs: None)

    result = package_authority._resident_request(
        operation="package_intent_parse",
        request={},
        guard_home=guard_home,
        timeout_seconds=1.0,
    )

    assert result is None
    assert calls == (["prerequisite", "request"] if prepared else ["prerequisite"])
