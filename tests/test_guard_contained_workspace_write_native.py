"""The workspace-write wrapper hands execution to the resident and never decides in Python."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import contained_workspace_write_execution

_SENTINEL = object()


def _dirs(tmp_path: Path) -> tuple[Path, Path]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    return workspace, guard_home


def test_workspace_write_unavailable_workspace_or_resident_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, guard_home = _dirs(tmp_path)
    monkeypatch.setattr(
        contained_workspace_write_execution._native_execution,
        "contained_workspace_write_execute_native",
        lambda *a, **k: None,
    )
    assert (
        contained_workspace_write_execution.try_execute_contained_workspace_write(
            "copy-generated", workspace=workspace, guard_home=guard_home, source="a.txt", target="b.txt"
        )
        is None
    )
    assert (
        contained_workspace_write_execution.try_execute_contained_workspace_write(
            "copy-generated",
            workspace=tmp_path / "missing",
            guard_home=guard_home,
            source="a.txt",
            target="b.txt",
        )
        is None
    )


def test_workspace_write_passes_canonical_workspace_and_scrubbed_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, guard_home = _dirs(tmp_path)
    seen: dict[str, Any] = {}

    def native(canonical: Path, **kwargs: Any) -> object:
        seen["workspace"] = canonical
        seen.update(kwargs)
        return _SENTINEL

    monkeypatch.setattr(
        contained_workspace_write_execution._native_execution, "contained_workspace_write_execute_native", native
    )
    result = contained_workspace_write_execution.try_execute_contained_workspace_write(
        "format-write",
        workspace=workspace,
        guard_home=guard_home,
        source="m.py",
        target="m.py",
        environment={"PATH": "/usr/bin", "GITHUB_TOKEN": "synthetic-secret"},
    )
    assert result is _SENTINEL
    assert seen["workspace"] == workspace.resolve()
    assert seen["operation"] == "format-write"
    assert "GITHUB_TOKEN" not in seen["environment"]
