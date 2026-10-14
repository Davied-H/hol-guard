"""Overlap may fan out to several streams, but only one idle stream stays parked."""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_resident_client import (
    _PersistentNativeClient,
    _PersistentNativeClientPool,
)


def _pool(tmp_path: Path) -> _PersistentNativeClientPool:
    return _PersistentNativeClientPool(
        executable=tmp_path / "runtime",
        state_dir=tmp_path / "native-runtime",
        environment={},
    )


def _spawning_request(
    monkeypatch: pytest.MonkeyPatch,
    spawned: list[subprocess.Popen[bytes]],
    overlap: threading.Barrier | None,
) -> None:
    """Give each stream a real child so the production close path must reap it."""

    def fake_request(client: _PersistentNativeClient, payload: bytes, *, deadline_monotonic: float) -> bytes:
        del deadline_monotonic
        if client._process is None:  # pyright: ignore[reportPrivateUsage]
            process = subprocess.Popen(
                (sys.executable, "-c", "import sys; sys.stdin.read()"),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            client._process = process  # pyright: ignore[reportPrivateUsage]
            spawned.append(process)
        if overlap is not None:
            overlap.wait(timeout=5)
        return payload

    monkeypatch.setattr(_PersistentNativeClient, "request", fake_request)


def _overlap_two_requests(pool: _PersistentNativeClientPool) -> list[bytes | None]:
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(pool.request, f"request-{index}".encode(), deadline_monotonic=time.monotonic() + 5)
            for index in range(2)
        ]
        return [future.result(timeout=10) for future in futures]


def test_overlap_parks_one_stream_and_reaps_the_surplus_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spawned: list[subprocess.Popen[bytes]] = []
    _spawning_request(monkeypatch, spawned, threading.Barrier(2))
    pool = _pool(tmp_path)
    try:
        assert _overlap_two_requests(pool) == [b"request-0", b"request-1"]
        assert len(spawned) == 2, "overlapping requests must each get their own stream"
        assert len(pool._clients) == 1  # pyright: ignore[reportPrivateUsage]
        assert len(pool._idle) == 1  # pyright: ignore[reportPrivateUsage]
        assert not pool._retiring  # pyright: ignore[reportPrivateUsage]
        parked = pool._idle[0]._process  # pyright: ignore[reportPrivateUsage]
        assert parked is not None and parked.poll() is None
        (surplus,) = [process for process in spawned if process is not parked]
        # wait() inside the close path collected the exit status: no zombie.
        assert surplus.returncode is not None

        _spawning_request(monkeypatch, spawned, None)
        assert pool.request(b"single", deadline_monotonic=time.monotonic() + 5) == b"single"
        assert len(spawned) == 2, "a lone request must reuse the parked stream"
        assert pool._idle[0]._process is parked  # pyright: ignore[reportPrivateUsage]
        assert len(pool._clients) == 1  # pyright: ignore[reportPrivateUsage]
    finally:
        assert pool.close() is True
    assert all(process.returncode is not None for process in spawned)


def test_surplus_return_replaces_a_parked_stream_whose_child_exited(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spawned: list[subprocess.Popen[bytes]] = []
    gate = threading.Barrier(2)
    _spawning_request(monkeypatch, spawned, gate)
    pool = _pool(tmp_path)
    first_done = threading.Event()
    release_second = threading.Event()
    real_request = _PersistentNativeClient.request

    def ordered_request(client: _PersistentNativeClient, payload: bytes, *, deadline_monotonic: float) -> bytes:
        response = real_request(client, payload, deadline_monotonic=deadline_monotonic)
        if payload == b"second":
            assert first_done.wait(timeout=5)
            assert release_second.wait(timeout=5)
        return response  # pyright: ignore[reportReturnType]

    monkeypatch.setattr(_PersistentNativeClient, "request", ordered_request)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            second = executor.submit(pool.request, b"second", deadline_monotonic=time.monotonic() + 5)
            assert pool.request(b"first", deadline_monotonic=time.monotonic() + 5) == b"first"
            first_done.set()
            (parked,) = pool._idle  # pyright: ignore[reportPrivateUsage]
            dead = parked._process  # pyright: ignore[reportPrivateUsage]
            assert dead is not None
            dead.kill()
            dead.wait(timeout=5)
            release_second.set()
            assert second.result(timeout=10) == b"second"
        (kept,) = pool._idle  # pyright: ignore[reportPrivateUsage]
        assert kept is not parked
        assert kept._process is not None and kept._process.poll() is None  # pyright: ignore[reportPrivateUsage]
        assert parked not in pool._clients  # pyright: ignore[reportPrivateUsage]
        assert len(pool._clients) == 1  # pyright: ignore[reportPrivateUsage]
    finally:
        assert pool.close() is True
    assert all(process.returncode is not None for process in spawned)
