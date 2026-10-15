from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import _set_private_mode
from tests.native_policy_snapshot_test_fixtures import _ack, _status

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX modes and ctimes")


def test_a_widened_mode_is_still_narrowed(tmp_path: Path) -> None:
    target = tmp_path / "guard.db"
    target.write_bytes(b"")
    target.chmod(0o644)

    _set_private_mode(target, 0o600)

    assert target.stat().st_mode & 0o7777 == 0o600


def _publisher(store: GuardStore) -> NativePolicySnapshotPublisher:
    return NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=lambda **kwargs: _ack(kwargs["payload"]),
        poll_interval_seconds=0.05,
    )


def test_an_idle_store_read_does_not_change_the_policy_inputs(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    publisher = _publisher(store)
    with store._connect() as connection:
        connection.execute("select 1").fetchone()
    before = publisher._current_policy_input_stats()
    time.sleep(0.05)

    for _ in range(3):
        with store._connect() as connection:
            connection.execute("select 1").fetchone()

    # SQLite moves the database ctime when an mmap connection closes, and a
    # ctime move used to wake the publisher into a full policy rebuild.
    assert publisher._current_policy_input_stats() == before


def test_a_config_metadata_change_is_still_an_input_change(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    config = guard_home / "config.toml"
    config.write_text('mode = "enforce"\n', encoding="utf-8")
    config.chmod(0o600)
    publisher = _publisher(store)
    before = publisher._current_policy_input_stats()
    time.sleep(0.05)

    config.chmod(0o644)

    assert publisher._current_policy_input_stats() != before


def test_windows_directory_repair_is_not_repeated_for_the_same_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard import native_policy_snapshot_windows_state, store_base

    bound: list[Path] = []
    monkeypatch.setattr(native_policy_snapshot_windows_state, "_windows_ensure_private_directory", bound.append)
    monkeypatch.setattr(store_base, "_windows_private_directory_bound", {})
    clock = [100.0]
    monkeypatch.setattr(store_base.time, "monotonic", lambda: clock[0])
    home = tmp_path / "guard-home"
    home.mkdir()

    store_base._set_windows_private_directory(home)
    store_base._set_windows_private_directory(home)
    assert bound == [home]

    clock[0] += store_base._WINDOWS_PRIVATE_DIRECTORY_RECHECK_SECONDS
    store_base._set_windows_private_directory(home)
    assert bound == [home, home]

    # A directory swapped in under the same path is bound again at once.
    home.rename(tmp_path / "guard-home-old")
    home.mkdir()
    store_base._set_windows_private_directory(home)
    assert bound == [home, home, home]

    def fail(path: Path) -> None:
        bound.append(path)
        raise OSError("denied")

    monkeypatch.setattr(native_policy_snapshot_windows_state, "_windows_ensure_private_directory", fail)
    clock[0] += store_base._WINDOWS_PRIVATE_DIRECTORY_RECHECK_SECONDS
    store_base._set_windows_private_directory(home)
    store_base._set_windows_private_directory(home)
    assert len(bound) == 5
