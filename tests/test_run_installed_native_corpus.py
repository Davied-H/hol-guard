"""Installed native corpus worker errors retain their worker context."""

from __future__ import annotations

import subprocess

import pytest

from scripts import run_installed_native_corpus


def test_timeout_detail_keeps_recent_frames_when_later_progress_is_noisy() -> None:
    blocked = 'Thread 0x123 (most recent call first):\n  File "worker.py", line 10 in blocked_native_batch'
    stderr = "corpus_phase native-batch batch=1 started\n" + blocked
    stderr += "\n" + ('  File "caller.py", line 20 in older_frame\n' * 100)
    stderr += "\n" + ("corpus_phase native-batch batch=99 elapsed=0.1\n" * 100)
    detail = run_installed_native_corpus._failure_detail(stderr)
    assert "blocked_native_batch" in detail
    assert detail.startswith("corpus_phase native-batch batch=99 elapsed=0.1\nThread 0x123")
    assert len(detail) < 1400


def test_invalid_worker_report_identifies_the_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        run_installed_native_corpus.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "not-json", ""),
    )

    with pytest.raises(ValueError, match="worker 3 emitted an invalid report"):
        run_installed_native_corpus._run_installed_worker(3)


@pytest.mark.parametrize("platform,expected_timeout", [("win32", 180), ("linux", 60)])
def test_installed_worker_keeps_platform_specific_hard_timeout(monkeypatch, platform, expected_timeout):
    monkeypatch.setattr(run_installed_native_corpus.sys, "platform", platform)
    captured = []

    def launch(*args, **kwargs):
        captured.append(kwargs["timeout"])
        return subprocess.CompletedProcess([], 0, "not-json", "")

    monkeypatch.setattr(run_installed_native_corpus.subprocess, "run", launch)
    with pytest.raises(ValueError, match="invalid report"):
        run_installed_native_corpus._run_installed_worker(0)
    assert captured == [expected_timeout]
