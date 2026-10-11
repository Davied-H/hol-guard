"""Point the test session's user home at a private directory.

Guard code defaults to ``Path.home()`` for harness configuration (``~/.codex``,
``~/.claude``, package shims) and ``~/.hol-guard`` for its own state. A test that
omits ``--home`` would otherwise install hooks into the developer's real
configuration, which can leave Codex pointing at a deleted checkout. This runs
at conftest import time so module-level defaults and spawned subprocesses see
the private home too.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

# Toolchains located under the real home keep working after HOME moves.
_TOOL_HOMES = {
    "CARGO_HOME": ".cargo",
    "RUSTUP_HOME": ".rustup",
    "UV_CACHE_DIR": ".cache/uv",
}

# Inherited overrides would send writes back to the real installation.
_HOME_OVERRIDES = ("CODEX_HOME", "HOL_GUARD_HOME", "CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME")


def isolate_user_home() -> Path:
    existing = os.environ.get("HOL_GUARD_TEST_PRIVATE_HOME")
    if existing and os.environ.get("HOME") == existing:
        return Path(existing)
    real_home = Path.home()
    for variable, relative in _TOOL_HOMES.items():
        candidate = real_home / relative
        if variable not in os.environ and candidate.is_dir():
            os.environ[variable] = str(candidate)
    for variable in _HOME_OVERRIDES:
        os.environ.pop(variable, None)
    # Outside the temp root: path-trust code treats the two differently, as on a real machine.
    # Some parametrize IDs embed the home, and CI plans shards in a separate job,
    # so the path must be the same for every session in this checkout.
    checkout = str(Path(__file__).resolve().parents[1])
    name = "home-" + hashlib.sha256(checkout.encode()).hexdigest()[:12]
    private_home = real_home / ".cache" / "hol-guard-tests" / name
    private_home.mkdir(parents=True, exist_ok=True)
    private_home = private_home.resolve()
    os.environ["HOME"] = str(private_home)
    if os.name == "nt":
        os.environ["USERPROFILE"] = str(private_home)
    os.environ["HOL_GUARD_TEST_PRIVATE_HOME"] = str(private_home)
    return private_home
