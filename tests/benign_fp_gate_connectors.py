"""Synthetic connectors for the benign false-positive gate.

A connector is a program or server Guard has no allow or block decision for
until the local admin sets it up. Two shapes are written under the fixture HOME,
with synthetic names only:

* a local CLI, ``lanectl``, installed as an executable ``#!/bin/sh`` script in
  ``~/.local/bin`` beside its ``~/.lanectl`` state directory. ``lanectl-ready``
  is a second install of the same shape that the local admin has allowed;
* a harness MCP config naming a stdio server, ``echo-mcp``, and a remote one,
  ``https://mcp.example.test/mcp``, in the place the Codex adapter reads it.

The cases pass a path under ``~/.lanectl``. A bare ``lanectl status`` stays in the
workspace, where hosts with a sandbox run it contained and never review it; a command that
reaches the connector's state outside the workspace is the one that needs a decision.
No case replays an MCP call: connector setup groups local CLIs and package scripts only,
so the MCP config is written for the day it groups servers too.

Nothing here runs: the gate only decides on the commands it replays.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.blocked_request_mode import SAFE_ALTERNATIVE_GUIDANCE, connector_setup_reason
from codex_plugin_scanner.guard.local_cli_trust import utc_now
from codex_plugin_scanner.guard.native_context import bound_context_digest_home
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity, identify_unlisted_cli
from codex_plugin_scanner.guard.store import GuardStore
from tests.benign_fp_gate_projects import _write

UNSET_CLI = "lanectl"
ALLOWED_CLI = "lanectl-ready"
REMOTE_MCP_URL = "https://mcp.example.test/mcp"

# A review held only because Guard does not recognise the command carries this reason on its row.
SETUP_ROW_REASON = "native_command_review_required"
_GROUP_ID = re.compile(r"connector:(?P<identity>[0-9a-f]{64}):(?P<action>[0-9a-f]{16})")
# Default mode neither links to the review nor tells the agent to ask the user for anything.
_FORBIDDEN_WORDING = ("http", "inbox", "approv", "ask the user", "ask your", "ask them")

_MCP_CONFIG = f"""[mcp_servers.echo-mcp]
command = "node"
args = ["echo-mcp.js"]

[mcp_servers.remote-example]
url = "{REMOTE_MCP_URL}"
"""


def write_connectors(home: Path) -> None:
    """Install the synthetic CLIs, their state directory and the harness MCP config."""
    for name in (UNSET_CLI, ALLOWED_CLI):
        program = home / ".local" / "bin" / name
        _write(program, f'#!/bin/sh\necho "{name} $*"\n')
        program.chmod(0o755)
    _write(home / ".lanectl" / "state.json", '{"lane": "example", "ready": true}\n')
    _write(home / ".lanectl" / "config.toml", 'endpoint = "local"\n')
    _write(home / ".codex" / "config.toml", _MCP_CONFIG)


def _identify(name: str, home: Path, guard_home: Path) -> UnlistedCliIdentity | None:
    """Identify ``name`` as Guard's own hook does: ``~/.local/bin`` on PATH, no loader overrides, this guard home."""
    with pytest.MonkeyPatch.context() as patch:
        for variable in list(os.environ):
            if variable.upper().startswith(("LD_", "DYLD_")):
                patch.delenv(variable)
        patch.setenv("PATH", os.pathsep.join([str(home / ".local" / "bin"), os.environ.get("PATH", "")]))
        with bound_context_digest_home(guard_home):
            return identify_unlisted_cli(name, cwd=home, home_dir=home)


def allow_ready_cli(store: GuardStore, home: Path) -> None:
    """Record the local admin's allow for ``lanectl-ready`` through the store's grant API."""
    identity = _identify(ALLOWED_CLI, home, store.guard_home)
    assert identity is not None, f"{ALLOWED_CLI} must identify as a local CLI"
    seen_at = utc_now()
    store.record_local_cli_observation(identity, seen_at=seen_at)
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=store.read_local_cli_revision(),
        updated_at=seen_at,
    )


def _strings(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _identity_hash(home: Path, guard_home: Path) -> str:
    identity = _identify(UNSET_CLI, home, guard_home)
    assert identity is not None, f"{UNSET_CLI} must identify as a local CLI"
    return identity.identity_hash


def assert_connector_setup(
    rows: list[dict[str, object]], result: dict[str, object], description: str, *, home: Path, guard_home: Path
) -> None:
    """A never-decided CLI is held as setup: grouped row, setup wording, no link, no ask."""
    assert result.get("policy_action") == "block", f"connector setup must block the call: {description}"
    assert result.get("prompted") is not True, f"connector setup must not prompt the agent: {description}"
    text = " ".join(_strings(result))
    # A generic per-action review reads "requires review"; setup names the connector and
    # carries the default-mode guidance verbatim.
    assert connector_setup_reason(UNSET_CLI, "cli", ask=False) in text, f"not worded as setup: {description}"
    assert SAFE_ALTERNATIVE_GUIDANCE in text, f"setup lost the safe-alternative guidance: {description}"
    leaked = [word for word in _FORBIDDEN_WORDING if word in text.lower()]
    assert not leaked, f"default-mode setup text carries {leaked}: {description}"
    assert len(rows) == 1, f"setup must queue exactly one approval row, got {len(rows)}: {description}"
    row = rows[0]
    assert row["reason_code"] == SETUP_ROW_REASON, f"setup row lost its non-recognition reason: {description}"
    group = _GROUP_ID.fullmatch(str(row["queue_group_id"]))
    assert group is not None, f"setup row is not under a connector group ({row['queue_group_id']!r}): {description}"
    assert group["identity"] == _identity_hash(home, guard_home), f"group names another connector: {description}"


def connector_groups(queue_rows: Iterable[dict[str, object]]) -> dict[str, set[str]]:
    """Connector identity hash to the action digests queued under it."""
    groups: dict[str, set[str]] = {}
    for row in queue_rows:
        match = _GROUP_ID.fullmatch(str(row.get("queue_group_id") or ""))
        if match is not None:
            groups.setdefault(match["identity"], set()).add(match["action"])
    return groups
