"""Pack journal integration with real control proofs and private anchors.

The transport/native compiler fixture is synthetic; these cases qualify the
transaction boundaries, independently of native matcher admission tests.
"""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.catalog_delivery import activation_store, activation_transition, preparation
from codex_plugin_scanner.guard.native_command_control_authority_store import _key
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    AuthorityPhase,
    ExtensionControlAuthorityError,
)
from codex_plugin_scanner.guard.runtime.generated_command_catalog import GeneratedCommandCatalog
from tests.guard_extension_control_authority_fixtures import (
    MemorySecretStore,
    _proof,
    _store,
)
from tests.guard_extension_control_authority_fixtures import (
    _allow_local_terminal_confirmation as _allow_local_terminal_confirmation,
)
from tests.test_extension_pack_preparation import delivery as delivery
from tests.test_native_command_control_binding_publisher import (
    _pinned_integrity_material_and_resident_key as _pinned_integrity_material_and_resident_key,
)


@pytest.mark.parametrize("crash_after_anchor", [False, True])
def test_approved_control_commit_and_anchored_retry_install_the_same_pack_record(
    delivery, tmp_path, monkeypatch, crash_after_anchor
):
    store = _store(tmp_path, MemorySecretStore())
    prepared = preparation.prepare(
        delivery.verified(),
        [],
        activation_store.prepare_directory_for_store(store),
        engine="1" * 64,
        now=1500,
        fetch=delivery.fetch,
    )
    draft = activation_transition.stage(
        None, prepared, verifier_key=_key(store), installed_source=prepared.source_sha, now=1500
    )
    # Reuse the strict production target metadata in this transaction-only
    # fixture; no fabricated matcher is installed or evaluated by this test.
    registry = GeneratedCommandCatalog(
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions, catalog_digest=prepared.metadata.catalog_digest
    )
    proof = _proof(
        store,
        (),
        revision=0,
        key="pack-transition",
        actor_id="unit-admin",
        nonce="pack-nonce",
        catalog_digest=registry.catalog_digest,
    )
    arguments = dict(
        catalog_digest=registry.catalog_digest,
        actor_id="unit-admin",
        expected_revision=0,
        idempotency_key="pack-transition",
        nonce="pack-nonce",
        proof=proof,
        migration_registry=registry,
        pack_activation=draft,
    )
    monkeypatch.setattr("codex_plugin_scanner.guard.catalog_delivery.activation_journal.time.time", lambda: 1500)
    write_anchor = store._write_and_verify_anchor
    if crash_after_anchor:

        def crash(anchor, *, key):
            write_anchor(anchor, key=key)
            if anchor.phase is AuthorityPhase.ANCHORED:
                raise RuntimeError("crash after private anchor")

        monkeypatch.setattr(store, "_write_and_verify_anchor", crash)
        with pytest.raises(ExtensionControlAuthorityError, match="anchor unavailable"):
            store.commit_extension_control_layers((), **arguments)
        assert activation_store.read(store) is None
        monkeypatch.setattr(store, "_write_and_verify_anchor", write_anchor)
    view = store.commit_extension_control_layers((), **arguments)
    assert view.health is AuthorityHealth.PROTECTED
    assert view.revision == 1
    active = activation_store.read(store)
    assert active.record_digest == draft.digest
    assert active.metadata == prepared.metadata
    with store._connect() as connection:
        assert connection.execute("select count(*) from extension_command_pack_pending").fetchone()[0] == 0
        assert connection.execute("select version from extension_control_schema_migration").fetchone()[0] == 5
