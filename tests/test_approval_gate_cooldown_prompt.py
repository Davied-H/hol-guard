"""The configured approval cooldown is honoured by the terminal prompt and the gate."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    public_config,
    require_approval_decision,
    update_settings,
)
from codex_plugin_scanner.guard.cli.approval_gate_prompt import prompt_for_approval_gate

PASSWORD = "correct horse battery staple"
GETPASS = "codex_plugin_scanner.guard.cli.approval_gate_prompt.getpass.getpass"


def _enable(guard_home: Path, *, cooldown_seconds: int, strict_all_decisions: bool = False) -> None:
    update_settings(
        guard_home,
        {
            "enabled": True,
            "new_password": PASSWORD,
            "confirm_password": PASSWORD,
            "cooldown_seconds": cooldown_seconds,
            "strict_all_decisions": strict_all_decisions,
        },
    )


def _open_window(guard_home: Path) -> None:
    grant = require_approval_decision(
        guard_home,
        action="allow",
        scope="artifact",
        subject="open-window",
        approval_gate_input=ApprovalGateInput(password=PASSWORD, use_cooldown=True),
    )
    assert grant is not None and grant.used_cooldown is False
    assert public_config(guard_home).cooldown_active is True


@pytest.fixture
def tty_prompts(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    asked: list[str] = []
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    def fake_getpass(prompt: str) -> str:
        asked.append(prompt)
        return PASSWORD

    monkeypatch.setattr(GETPASS, fake_getpass)
    return asked


def test_prompt_asks_for_password_before_a_window_is_open(tmp_path: Path, tty_prompts: list[str]) -> None:
    _enable(tmp_path, cooldown_seconds=900)
    result = prompt_for_approval_gate(tmp_path)
    assert result is not None and result.password == PASSWORD and result.use_cooldown is True
    assert tty_prompts == ["Approval password: "]


def test_prompt_skips_password_while_cooldown_window_is_open(tmp_path: Path, tty_prompts: list[str]) -> None:
    _enable(tmp_path, cooldown_seconds=900)
    _open_window(tmp_path)
    assert prompt_for_approval_gate(tmp_path) is None
    assert tty_prompts == []


def test_prompt_still_asks_for_strict_global_and_cooldown_off_callers(tmp_path: Path, tty_prompts: list[str]) -> None:
    _enable(tmp_path, cooldown_seconds=900)
    _open_window(tmp_path)
    assert prompt_for_approval_gate(tmp_path, strict=True) is not None
    assert prompt_for_approval_gate(tmp_path, use_cooldown=False) is not None
    assert len(tty_prompts) == 2


def test_prompt_still_asks_when_strict_all_decisions_is_on(tmp_path: Path, tty_prompts: list[str]) -> None:
    _enable(tmp_path, cooldown_seconds=900, strict_all_decisions=True)
    _open_window(tmp_path)
    assert prompt_for_approval_gate(tmp_path) is not None
    assert tty_prompts == ["Approval password: "]


def test_gate_honours_cooldown_for_artifact_scope_but_not_global(tmp_path: Path) -> None:
    _enable(tmp_path, cooldown_seconds=900)
    _open_window(tmp_path)

    second = require_approval_decision(tmp_path, action="allow", scope="artifact", subject="second")
    assert second is not None and second.used_cooldown is True

    with pytest.raises(ApprovalGateError) as global_error:
        require_approval_decision(tmp_path, action="allow", scope="global", subject="global")
    assert global_error.value.code == "approval_gate_required"
