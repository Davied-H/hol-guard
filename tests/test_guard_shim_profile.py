"""Tests for Guard-managed shell profile PATH writes.

Regression coverage for two defects:

1. The profile writers only de-duplicated on an exact ``shim_dir`` match, so
   each distinct shim dir (one per pytest temp run) appended a fresh line to the
   shell profile. The profile accumulated dozens of stale PATH entries pointing
   at deleted temp dirs, which shadowed the real package-manager binaries.
2. Transient (temp / pytest) shim dirs were written into the long-lived shell
   profile, leaving broken entries behind after cleanup.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard.shims import (
    ensure_guard_shim_path_in_shell_profile,
    ensure_package_shim_path_in_shell_profile,
    prepare_guard_shim_shell_profile,
    remove_guard_profile_blocks,
)


def _context(home: Path, guard_home: Path) -> MagicMock:
    ctx = MagicMock()
    ctx.home_dir = home
    ctx.guard_home = guard_home
    ctx.workspace_dir = None
    return ctx


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell profiles")
@pytest.mark.parametrize(
    "shell,relative",
    [
        ("zsh", ".zshrc"),
        ("bash", ".bashrc"),
        ("fish", ".config/fish/config.fish"),
    ],
)
def test_prepared_shell_profile_matches_normal_renderer_without_writes(tmp_path, monkeypatch, shell, relative):
    from codex_plugin_scanner.guard import shims

    ctx = _context(tmp_path / "home", tmp_path / "guard")
    monkeypatch.setattr(shims, "_is_transient_path", lambda path: False)
    monkeypatch.setenv("SHELL", f"/bin/{shell}")
    path = ctx.home_dir / relative
    path.parent.mkdir(parents=True)
    path.write_text("# user profile content\n")
    path.chmod(0o640)
    before = path.stat()
    prepared = prepare_guard_shim_shell_profile(ctx)
    assert len(prepared.files) == 1
    assert path.read_text() == "# user profile content\n"
    assert path.stat().st_ino == before.st_ino
    assert path.stat().st_mtime_ns == before.st_mtime_ns
    assert ensure_guard_shim_path_in_shell_profile(ctx) == prepared.manifest
    assert path.read_bytes() == prepared.files[0].after
    repeated = prepare_guard_shim_shell_profile(ctx)
    assert repeated.manifest["changed"] is False
    assert repeated.files[0].before == repeated.files[0].after


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell profiles")
def test_shell_profile_preparation_rejects_parent_outside_home_before_reading(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard import codex_hook_recovery, shims

    home, outside = tmp_path / "home", tmp_path / "outside"
    home.mkdir()
    outside.mkdir()
    (home / ".config").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(shims, "_is_transient_path", lambda path: False)
    monkeypatch.setenv("SHELL", "/bin/fish")

    def refuse_read(path):
        pytest.fail("An escaped profile must be rejected before any snapshot read")

    monkeypatch.setattr(codex_hook_recovery, "_snapshot", refuse_read)
    with pytest.raises(ValueError, match="escapes the managed root"):
        prepare_guard_shim_shell_profile(_context(home, tmp_path / "guard"))
    assert list(outside.iterdir()) == []


@pytest.fixture(autouse=True)
def _force_zsh(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHELL", "/bin/zsh")


class TestEnsureSkipsTransientShimDir:
    def test_package_shim_transient_dir_not_written(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        home.mkdir()
        # guard_home under tmp_path -> transient on macOS (/var/folders/...).
        ctx = _context(home, tmp_path / "guard-home")
        ctx.guard_home.mkdir(parents=True)
        result = ensure_package_shim_path_in_shell_profile(ctx)
        assert result["changed"] is False
        assert result["manual_path_required"] is True
        assert not (home / ".zshrc").exists()

    def test_guard_shim_transient_dir_not_written(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        home.mkdir()
        ctx = _context(home, tmp_path / "guard-home")
        ctx.guard_home.mkdir(parents=True)
        result = ensure_guard_shim_path_in_shell_profile(ctx)
        assert result["changed"] is False
        assert result["manual_path_required"] is True
        assert not (home / ".zshrc").exists()


class TestEnsureSkipsOnWindows:
    """Both profile writers must short-circuit on Windows before touching .zshrc."""

    def _stable_ctx(self, tmp_path: Path) -> MagicMock:
        home = tmp_path / "home"
        home.mkdir()
        guard_home = home / ".hol-guard"
        (guard_home / "bin").mkdir(parents=True)
        (guard_home / "package-shims" / "bin").mkdir(parents=True)
        return _context(home, guard_home)

    def test_guard_shim_skipped_on_windows(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ctx = self._stable_ctx(tmp_path)
        monkeypatch.setattr("codex_plugin_scanner.guard.shims.os.name", "nt")
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.shims._is_transient_path",
            lambda path: False,
        )
        result = ensure_guard_shim_path_in_shell_profile(ctx)
        assert result["changed"] is False
        assert result["manual_path_required"] is True
        assert not (ctx.home_dir / ".zshrc").exists()


class TestRemoveGuardProfileBlocks:
    def test_removes_guard_markers_across_common_shell_profiles(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        home.mkdir()
        fish_config = home / ".config" / "fish" / "config.fish"
        bash_profile = home / ".bashrc"
        zsh_profile = home / ".zshrc"
        bash_profile.write_text(
            "\n".join(
                [
                    "export KEEP=1",
                    "# HOL Guard harness launchers",
                    'export PATH="/tmp/guard-home/bin:$PATH"',
                    "",
                ]
            ),
            encoding="utf-8",
        )
        zsh_profile.write_text(
            "\n".join(
                [
                    "# HOL Guard package manager shims",
                    'export PATH="/tmp/guard-home/package-shims/bin:$PATH"',
                    "alias ll='ls -l'",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        fish_config.parent.mkdir(parents=True, exist_ok=True)
        fish_config.write_text(
            "# HOL Guard harness launchers\nfish_add_path --prepend /tmp/guard-home/bin\n",
            encoding="utf-8",
        )

        result = remove_guard_profile_blocks(_context(home, home / ".hol-guard"))

        assert result["changed"] is True
        assert sorted(Path(path).name for path in result["changed_paths"]) == [
            ".bashrc",
            ".zshrc",
            "config.fish",
        ]
        assert Path(fish_config) == Path(result["removed_paths"][0])
        assert "# HOL Guard" not in bash_profile.read_text(encoding="utf-8")
        assert bash_profile.read_text(encoding="utf-8") == "export KEEP=1\n"
        assert "# HOL Guard" not in zsh_profile.read_text(encoding="utf-8")
        assert "alias ll='ls -l'" in zsh_profile.read_text(encoding="utf-8")
        assert not fish_config.exists()
