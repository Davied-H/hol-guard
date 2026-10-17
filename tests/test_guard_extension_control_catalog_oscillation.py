"""Two Guard installs sharing a home must not migrate the catalog forever.

Reading the authority under a catalog the store was not written with rebinds
the controls and commits a revision. When two installs with different catalogs
read the same home, each one undoes the other's migration, so the committed
revision climbs on every read. A dashboard draft is built on the revision it
read and applied against the revision the store holds, so a home in that state
rejects every policy change with an authority conflict. The first move in each
direction still commits, because it records what the other install retired;
after that the reader rebinds in memory and leaves the revision alone.
"""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.store import GuardStore

from .guard_extension_control_authority_fixtures import (
    MemorySecretStore,
    _allow_local_terminal_confirmation,  # noqa: F401  (autouse fixture)
    _commit,
    _disabled_layer,
    _store,
    _upgraded_registry,
)


def _stored_revision(store: GuardStore) -> int:
    with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
        row = connection.execute("select revision from extension_control_authority_snapshot").fetchone()
    assert row is not None
    return int(row["revision"])


def _controlled_home(tmp_path: Path) -> GuardStore:
    """An enrolled home holding one committed local control."""

    store = _store(tmp_path, MemorySecretStore())
    store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    _commit(store)
    return store


def test_the_first_migration_in_each_direction_still_commits(tmp_path: Path) -> None:
    store = _controlled_home(tmp_path)
    upgraded = _upgraded_registry()

    store.read_extension_control_authority_for_registry(upgraded)
    forward = _stored_revision(store)
    store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert forward == 2
    assert _stored_revision(store) == 3


def test_an_install_rereading_its_own_undone_migration_commits_nothing(tmp_path: Path) -> None:
    store = _controlled_home(tmp_path)
    upgraded = _upgraded_registry()
    store.read_extension_control_authority_for_registry(upgraded)
    store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    settled = _stored_revision(store)

    for _ in range(3):
        store.read_extension_control_authority_for_registry(upgraded)
        store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert _stored_revision(store) == settled


def test_the_rebound_view_still_protects_under_the_reading_catalog(tmp_path: Path) -> None:
    store = _controlled_home(tmp_path)
    upgraded = _upgraded_registry()
    store.read_extension_control_authority_for_registry(upgraded)
    store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    settled = _stored_revision(store)

    view = store.read_extension_control_authority_for_registry(upgraded)

    assert view.health is AuthorityHealth.PROTECTED
    assert view.revision == settled
    assert view.catalog_digest == upgraded.catalog_digest
    assert len(view.layers) == 1
    assert view.layers[0].catalog_digest == upgraded.catalog_digest
    assert view.layers[0].controls == _disabled_layer().controls


def test_a_mutation_under_the_other_catalog_still_reaches_this_one(tmp_path: Path) -> None:
    """Settling must not freeze the loser's controls out of the shared home.

    The rebind is only a view. A control committed from the catalog that owns
    the stored snapshot has to show up for the install serving the rebound one,
    or the two installs would enforce different policy indefinitely.
    """

    store = _controlled_home(tmp_path)
    upgraded = _upgraded_registry()
    store.read_extension_control_authority_for_registry(upgraded)
    store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    settled = _stored_revision(store)

    _commit(store, revision=settled, key="change-2")

    view = store.read_extension_control_authority_for_registry(upgraded)
    assert view.revision >= settled + 1
    assert view.catalog_digest == upgraded.catalog_digest
    assert view.layers[0].controls == _disabled_layer().controls
