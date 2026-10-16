"""Stop the native residents a test started for its own Guard homes.

Production runs one resident per Guard home for the life of its owner. A test
session creates a fresh home under each test's ``tmp_path``, and that home's
resident (with its supervisor and pooled client stream) otherwise stays up
until the pytest process exits, or until the client pool evicts it inside a
later test's request budget. On a small runner dozens of idle residents then
compete with the one the current test is timing.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

import pytest

# Upper bound for retiring one test's residents; each stop is itself bounded.
_TEARDOWN_BUDGET_SECONDS = 10.0


def _test_owned_guard_homes(tmp_path: Path) -> tuple[Path, ...]:
    from codex_plugin_scanner.guard import native_resident_client

    root = tmp_path.resolve()
    with native_resident_client._RESIDENTS_LOCK:
        state_dirs = [state_dir for (_executable, state_dir) in native_resident_client._RESIDENTS]
    homes: dict[Path, None] = {}
    for state_dir in state_dirs:
        if state_dir.resolve().is_relative_to(root):
            homes[state_dir.parent] = None
    return tuple(homes)


_TMP_PATH_KEY = pytest.StashKey[Path]()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_setup(item: pytest.Item) -> Iterator[None]:
    yield
    tmp_path = getattr(item, "funcargs", {}).get("tmp_path")
    if isinstance(tmp_path, Path):
        item.stash[_TMP_PATH_KEY] = tmp_path


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_teardown(item: pytest.Item) -> Iterator[None]:
    # Every fixture, including monkeypatch, is finalized first, so the stop
    # uses the real resident client rather than a test's doubles.
    yield
    tmp_path = item.stash.get(_TMP_PATH_KEY, None)
    if tmp_path is None:
        return
    homes = _test_owned_guard_homes(tmp_path)
    if not homes:
        return
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents

    deadline = time.monotonic() + _TEARDOWN_BUDGET_SECONDS
    for guard_home in homes:
        close_native_residents(guard_home, deadline_monotonic=deadline)
