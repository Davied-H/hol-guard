"""Client-side behavior of the native settings/hook-copy owner (no resident needed)."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_execution, native_guard_support


def _fake(monkeypatch: pytest.MonkeyPatch, result: object, seen: list[tuple[str, dict]] | None = None) -> None:
    def native(subop: str, payload: dict, *, guard_home: Path, timeout_seconds: float = 10.0) -> object:
        if seen is not None:
            seen.append((subop, payload))
        return result

    monkeypatch.setattr(native_execution, "guard_support_native", native)


def test_unreachable_owner_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _fake(monkeypatch, None)
    with pytest.raises(native_guard_support.NativeGuardSupportError):
        native_guard_support.render_toml({"mode": "prompt"}, guard_home=tmp_path)


def test_rejected_setting_raises_user_facing_message(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _fake(monkeypatch, {"error": "Invalid Guard mode.", "repr": False})
    with pytest.raises(ValueError, match="Invalid Guard mode"):
        native_guard_support.coerce_setting("mode", "bogus", max_wait_seconds=600, guard_home=tmp_path)


def test_repr_flag_appends_the_rejected_value(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _fake(monkeypatch, {"error": "Invalid receipt redaction level", "repr": True})
    with pytest.raises(ValueError, match="level: 'x'"):
        native_guard_support.coerce_setting("receipt_redaction_level", "x", max_wait_seconds=600, guard_home=tmp_path)


def test_unserializable_value_is_sent_as_an_invalid_sentinel(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: list[tuple[str, dict]] = []
    _fake(monkeypatch, {"ok": True}, seen)
    native_guard_support.coerce_setting("telemetry", object(), max_wait_seconds=600, guard_home=tmp_path)
    assert seen[0][1]["value"] == "<unserializable>"


def test_toml_render_rejects_unserializable_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _fake(monkeypatch, "unused")
    with pytest.raises(ValueError, match="cannot be written"):
        native_guard_support.render_toml({"x": float("nan")}, guard_home=tmp_path)


def test_batch_length_mismatch_is_invalid(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _fake(monkeypatch, ["only-one"])
    with pytest.raises(native_guard_support.NativeGuardSupportError):
        native_guard_support.coerce_loaded([{"kind": "bool"}, {"kind": "bool"}], guard_home=tmp_path)
