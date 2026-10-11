"""Client contract for the native effective-policy composer."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_policy_effective as client
from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError

_BASE = {"protection_posture": "protected", "security_level": "balanced", "mode": "prompt"}


def _status(*, features: tuple[str, ...] = (client.POLICY_EFFECTIVE_FEATURE,), available: bool = True):
    return SimpleNamespace(
        available=available,
        compatible=True,
        identity=SimpleNamespace(path=Path("/tmp/hol-guard-runtime"), sha256="a" * 64),
        capabilities=SimpleNamespace(features=features),
    )


def _install(monkeypatch: pytest.MonkeyPatch, reply: object, *, status: object | None = None) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda **_: status or _status())

    def run(path: Path, args: tuple[str, ...], *, input_text: str, timeout_seconds: float) -> str | None:
        assert args == (client.POLICY_EFFECTIVE_COMMAND, "--stdin")
        assert 0 < timeout_seconds <= client.POLICY_EFFECTIVE_TIMEOUT_SECONDS
        seen.append(json.loads(input_text))
        return reply if isinstance(reply, str) or reply is None else json.dumps(reply)

    monkeypatch.setattr(native_runtime, "_run_native_process", run)
    return seen


def test_mapping_config_sends_only_known_fields_without_guard_defaults(monkeypatch) -> None:
    seen = _install(monkeypatch, {"ok": True, "policy": {"default_action": "warn"}})

    result = client.effective_native_policy_v3({**_BASE, "unrelated": object, "risk_actions": {"a": "block"}})

    assert result == {"default_action": "warn"}
    request = seen[0]
    assert request["schema"] == client.POLICY_EFFECTIVE_SCHEMA
    assert request["op"] == "effective"
    assert request["guard_config"] is False
    assert request["configs"] == [{**_BASE, "risk_actions": {"a": "block"}}]


def test_guard_config_sends_loaded_fields_and_requests_defaults(monkeypatch, tmp_path: Path) -> None:
    seen = _install(monkeypatch, {"ok": True, "policy": {}})
    config = GuardConfig(
        guard_home=tmp_path,
        workspace=None,
        protection_posture="extra_careful",
        protection_posture_explicit=True,
        managed_locked_settings=("security_level",),
        harness_postures={"codex": "watch"},
        risk_actions=None,
    )

    client.effective_native_policy_v3(config)

    request = seen[0]
    assert request["guard_config"] is True
    fields = request["configs"][0]
    assert fields["protection_posture"] == "extra_careful"
    assert fields["protection_posture_explicit"] is True
    assert fields["managed_locked_settings"] == ["security_level"]
    assert fields["harness_postures"] == {"codex": "watch"}
    assert fields["risk_actions"] is None
    # Observed MCP actions are not part of a loaded GuardConfig.
    assert "mcp_tool_actions" not in fields
    assert "guard_home" not in fields


def test_compose_sends_every_config_in_order(monkeypatch) -> None:
    seen = _install(monkeypatch, {"ok": True, "policy": {"mode": "enforce"}})

    result = client.compose_effective_native_policies(({**_BASE, "mode": "enforce"}, {**_BASE, "mode": "observe"}))

    assert result == {"mode": "enforce"}
    assert seen[0]["op"] == "compose"
    assert [config["mode"] for config in seen[0]["configs"]] == ["enforce", "observe"]


def test_compose_requires_a_config(monkeypatch) -> None:
    seen = _install(monkeypatch, {"ok": True, "policy": {}})
    with pytest.raises(NativePolicySnapshotError, match="native_policy_snapshot_policy_invalid"):
        client.compose_effective_native_policies(())
    assert seen == []


@pytest.mark.parametrize(
    "status",
    [
        _status(available=False),
        _status(features=("resident-protocol-v2",)),
        SimpleNamespace(available=True, compatible=False, identity=None, capabilities=None),
        SimpleNamespace(available=True, compatible=True, identity=None, capabilities=None),
    ],
)
def test_missing_runtime_or_capability_fails_closed(monkeypatch, status) -> None:
    seen = _install(monkeypatch, {"ok": True, "policy": {}}, status=status)
    with pytest.raises(NativePolicySnapshotError, match="native_policy_effective_unavailable"):
        client.effective_native_policy_v3(_BASE)
    assert seen == []


@pytest.mark.parametrize(
    ("reply", "reason"),
    [
        (None, "native_policy_effective_unavailable"),
        ("not json", "native_policy_effective_invalid"),
        ("[]", "native_policy_effective_invalid"),
        ({"ok": True}, "native_policy_effective_invalid"),
        ({"ok": False}, "native_policy_effective_invalid"),
        ({"ok": False, "error": "native_policy_snapshot_policy_invalid"}, "native_policy_snapshot_policy_invalid"),
        ({"ok": False, "error": "native_provider_catalog_hash_invalid"}, "native_provider_catalog_hash_invalid"),
    ],
)
def test_bad_native_replies_raise_the_native_reason(monkeypatch, reply, reason) -> None:
    _install(monkeypatch, reply)
    with pytest.raises(NativePolicySnapshotError, match=reason):
        client.effective_native_policy_v3(_BASE)


def test_unserializable_configuration_is_rejected_before_spawning(monkeypatch) -> None:
    seen = _install(monkeypatch, {"ok": True, "policy": {}})
    with pytest.raises(NativePolicySnapshotError, match="native_policy_snapshot_policy_invalid"):
        client.effective_native_policy_v3({**_BASE, "risk_actions": {"a": object()}})
    assert seen == []
