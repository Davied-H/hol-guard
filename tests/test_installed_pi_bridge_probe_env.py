"""The installed Pi probe keeps the bridge on the daemon route it measures."""

from __future__ import annotations

import sys
from pathlib import Path

from ci.native_runtime.probe_installed_pi_output import _isolated_env


def test_bridge_probe_disables_the_resident_direct_hook(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOL_GUARD_PI_DIRECT_HOOK", "1")
    monkeypatch.setenv("HOL_GUARD_UNRELATED", "secret")
    env = _isolated_env(home=tmp_path, python_path=Path(sys.executable))
    assert env["HOL_GUARD_PI_DIRECT_HOOK"] == "0"
    assert "HOL_GUARD_UNRELATED" not in env
