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


def test_batch_length_mismatch_is_invalid(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _fake(monkeypatch, ["only-one"])
    with pytest.raises(native_guard_support.NativeGuardSupportError):
        native_guard_support.coerce_loaded([{"kind": "bool"}, {"kind": "bool"}], guard_home=tmp_path)


def test_unavailable_error_is_a_value_error_with_a_clear_message(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _fake(monkeypatch, None)
    with pytest.raises(ValueError, match="native runtime is unavailable"):
        native_guard_support.coerce_setting("mode", "prompt", max_wait_seconds=600, guard_home=tmp_path)


def test_hook_copy_degrades_without_a_traceback_when_the_resident_is_down(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from codex_plugin_scanner.guard.cli import commands_support_prompts as prompts
    from codex_plugin_scanner.guard.models import GuardArtifact

    _fake(monkeypatch, None)
    artifact = GuardArtifact(
        artifact_id="a",
        name="n",
        harness="claude-code",
        artifact_type="prompt_request",
        source_scope="harness",
        config_path="",
        metadata={},
    )
    reason = prompts._runtime_artifact_native_reason(artifact, {"policy_action": "block"})
    assert "native runtime is unavailable" in reason
    assert (
        prompts._claude_prompt_system_message(
            event_name="PreToolUse", policy_action="block", artifact=artifact, native_reason=reason
        )
        is None
    )
    assert prompts._codex_prompt_block_system_message(policy_action="block", native_reason="Open HOL Guard") is None


def test_toml_value_matches_the_previous_writer_for_unusual_values() -> None:
    import datetime

    shaped = native_guard_support._toml_value(
        {"nan": float("nan"), "when": datetime.date(2026, 1, 2), 7: "dropped", "inner": {"inf": float("-inf")}}
    )
    assert shaped == {
        "nan": {"\0float": "nan"},
        "when": "2026-01-02",
        "inner": {"inf": {"\0float": "-inf"}},
    }
