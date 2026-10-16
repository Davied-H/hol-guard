"""Group write is trusted only through the group that can already write the checker."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import group_write_trust as trust
from codex_plugin_scanner.guard import native_binary_identity as identity

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and permission semantics")


def _checker(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, file_mode: int = 0o664, dir_mode: int = 0o775) -> int:
    package = tmp_path / "package"
    package.mkdir()
    module = package / "group_write_trust.py"
    _ = module.write_text("# checker\n", encoding="utf-8")
    module.chmod(file_mode)
    package.chmod(dir_mode)
    monkeypatch.setattr(trust, "__file__", str(module))
    return module.stat().st_gid


def _metadata(mode: int, *, uid: int, gid: int) -> os.stat_result:
    return os.stat_result((stat.S_IFREG | mode, 1, 1, 1, uid, gid, 0, 0, 0, 0))


def test_group_write_through_the_checkers_group_is_accepted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    gid = _checker(monkeypatch, tmp_path)

    assert trust.writable_only_by_owner(_metadata(0o775, uid=os.getuid(), gid=gid), os.getuid()) is True


def test_group_write_through_another_group_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    gid = _checker(monkeypatch, tmp_path)

    assert trust.writable_only_by_owner(_metadata(0o775, uid=os.getuid(), gid=gid + 1), os.getuid()) is False


@pytest.mark.parametrize(("file_mode", "dir_mode"), [(0o644, 0o775), (0o664, 0o755)], ids=["module", "folder"])
def test_checker_without_group_write_keeps_rejecting(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, file_mode: int, dir_mode: int
) -> None:
    gid = _checker(monkeypatch, tmp_path, file_mode=file_mode, dir_mode=dir_mode)

    assert trust.writable_only_by_owner(_metadata(0o775, uid=os.getuid(), gid=gid), os.getuid()) is False


@pytest.mark.parametrize("mode", [0o777, 0o757], ids=["group-and-world", "world-only"])
def test_world_write_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: int) -> None:
    gid = _checker(monkeypatch, tmp_path)

    assert trust.writable_only_by_owner(_metadata(mode, uid=os.getuid(), gid=gid), os.getuid()) is False


def test_file_owned_by_another_account_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    gid = _checker(monkeypatch, tmp_path)

    assert trust.writable_only_by_owner(_metadata(0o775, uid=os.getuid() + 1, gid=gid), os.getuid()) is False
    assert trust.trusted_owner_and_mode(_metadata(0o755, uid=os.getuid() + 1, gid=gid)) is False


def test_checker_owned_by_another_account_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    gid = _checker(monkeypatch, tmp_path)
    other = os.getuid() + 1

    assert trust.writable_only_by_owner(_metadata(0o775, uid=other, gid=gid), other) is False


def test_checker_without_a_source_file_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    gid = _checker(monkeypatch, tmp_path)
    monkeypatch.delattr(trust, "__file__")

    assert trust.writable_only_by_owner(_metadata(0o775, uid=os.getuid(), gid=gid), os.getuid()) is False


def test_no_group_write_needs_no_checker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(trust, "__file__")

    assert trust.writable_only_by_owner(_metadata(0o755, uid=os.getuid(), gid=0), os.getuid()) is True


@pytest.mark.parametrize(("checker_mode", "trusted"), [(0o664, True), (0o644, False)])
def test_native_runtime_installed_under_umask_0002(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, checker_mode: int, trusted: bool
) -> None:
    _ = _checker(monkeypatch, tmp_path, file_mode=checker_mode)
    runtime = tmp_path / "package" / "hol-guard-runtime"
    _ = runtime.write_bytes(b"native-runtime")
    runtime.chmod(0o775)

    assert (identity.validate_native_binary(runtime) is not None) is trusted
