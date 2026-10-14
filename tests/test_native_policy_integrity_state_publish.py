"""The daemon publishes the policy-integrity state the store holds now.

The resident accepts a saved decision only while the published state equals
the stored row, and refuses an MCP relay binding without the exact-action
state. A fresh home has no row, and a policy write advances the generation
after refreshing it, so the publisher refreshes the row before binding it.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_direct_lane_saved as saved
from codex_plugin_scanner.guard import store as guard_store_module
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_policy_snapshot_direct_lane import (
    DIRECT_HOOK_SAVED_DECISION_FEATURE,
    direct_lane_integrity_key,
)
from codex_plugin_scanner.guard.store import GuardStore

FEATURES = (DIRECT_HOOK_SAVED_DECISION_FEATURE,)


@pytest.fixture(autouse=True)
def _daemon(monkeypatch: pytest.MonkeyPatch, install_fake_system_keyring) -> None:
    install_fake_system_keyring()
    monkeypatch.setattr(guard_store_module.sys, "platform", "linux", raising=False)
    monkeypatch.setattr(saved, "current_extension_control_binding_digest", lambda: "e" * 64)
    monkeypatch.setattr(saved, "os", SimpleNamespace(environ={"HOME": "/home/dev", "PATH": "/usr/bin"}))


def _daemon_store(guard_home: Path) -> GuardStore:
    # As `daemon serve` opens it: never primed, never the system keyring.
    return GuardStore(guard_home, source="default", prime_policy_integrity=False, allow_system_keyring=False)


def _stored(store: GuardStore) -> object:
    with store._connect() as connection:
        return store._load_policy_integrity_state(connection)


def _published(store: GuardStore) -> dict[str, object]:
    saved.refresh_integrity_state(store)
    bound = saved.with_saved_decision_state({}, store=store, features=FEATURES)
    assert bound is not None
    return bound


def test_a_fresh_home_binds_the_state_its_store_writes(tmp_path: Path) -> None:
    store = _daemon_store(tmp_path / "guard-home")
    assert _stored(store) is None
    assert saved.with_saved_decision_state({}, store=store, features=FEATURES) == {}

    bound = _published(store)

    assert bound["exact_action_control_digest"] == "e" * 64
    assert bound["policy_integrity_state"] == _stored(store)
    assert _published(store) == bound
    # Without a key the state is degraded and no integrity key binds, so the
    # resident defers any saved row rather than deciding it
    # (mcp_relay_decide_saved_tests::an_unpublished_or_moved_integrity_state_defers).
    state = bound["policy_integrity_state"]
    assert isinstance(state, dict)
    assert state["mode"] == "degraded"
    assert state["degraded_reasons"]
    assert state["generation"] is None
    assert direct_lane_integrity_key(store, FEATURES) is None


def _save_decision(store: GuardStore) -> int:
    """Save one local decision from another store; return the generation it signed."""

    writer = GuardStore(store.guard_home, prime_policy_integrity=False)
    writer.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id="codex:project:workspace-skill",
            artifact_hash="hash-123",
            reason="reviewed",
            source="local",
        ),
        "2026-06-14T00:00:00Z",
    )
    with sqlite3.connect(store.path) as connection:
        (signed_generation,) = connection.execute("select integrity_generation from policy_decisions").fetchone()
    return int(signed_generation)


def test_a_policy_write_republishes_the_state_it_leaves(tmp_path: Path) -> None:
    store = _daemon_store(tmp_path / "guard-home")
    before = _published(store)["policy_integrity_state"]
    signed_generation = _save_decision(store)

    after = _published(store)["policy_integrity_state"]

    # The resident refuses the earlier binding, whose state no longer matches
    # the row, and verifies rows against the generation it now carries.
    assert isinstance(after, dict)
    assert after != before
    assert after == _stored(store)
    assert after["mode"] == "protected"
    assert after["generation"] == signed_generation


class _Lane(saved.NativePolicySnapshotSavedStateMixin):
    """The publisher surface the reconcile recheck uses."""

    def __init__(self, store: GuardStore) -> None:
        self.store = store
        self.guard_home = Path(store.guard_home)
        self._direct_lane_ack_target: tuple[int, str] | None = (1, "ack")
        self.rebinds = 0

    def _bind_mcp_relay_view(self, binding: object, features: object) -> None:
        return None

    def _rebind_direct_lane(self) -> None:
        self.rebinds += 1


def test_a_saved_decision_rebinds_the_lane_from_the_reconcile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A saved decision leaves the effective policy unchanged, so it queues no
    # republish; only this recheck carries the state it leaves to the lane.
    store = _daemon_store(tmp_path / "guard-home")
    lane = _Lane(store)
    lane._bind_relay_and_saved_state(_published(store), FEATURES)
    lane._recheck_direct_lane_saved_state()
    assert lane.rebinds == 0

    signed_generation = _save_decision(store)
    lane._recheck_direct_lane_saved_state()
    assert lane.rebinds == 1
    stored = _stored(store)
    assert isinstance(stored, dict)
    assert stored["mode"] == "protected"
    assert stored["generation"] == signed_generation

    # With no write since, the recheck costs two stats and refreshes nothing,
    # including after its own refresh wrote the row.
    refreshes: list[object] = []
    monkeypatch.setattr(saved, "refresh_integrity_state", refreshes.append)
    lane._recheck_direct_lane_saved_state()
    assert (lane.rebinds, refreshes) == (1, [])

    # A closed lane has nothing to rebind.
    lane._direct_lane_ack_target = None
    _save_decision(store)
    lane._recheck_direct_lane_saved_state()
    assert (lane.rebinds, refreshes) == (1, [])


@pytest.mark.parametrize("error", [OSError("gone"), sqlite3.OperationalError("locked"), RuntimeError("resident")])
def test_a_refresh_that_fails_leaves_the_row_alone(error: Exception) -> None:
    class _Failing:
        def _connect(self):
            raise error

        def _refresh_policy_integrity_state(self, connection: object, *, now: str, create_key: bool) -> None:
            raise AssertionError("never reached")

    saved.refresh_integrity_state(_Failing())
    saved.refresh_integrity_state(object())
