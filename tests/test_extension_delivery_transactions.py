"""Failure boundaries leave publication pointers and legacy protections intact."""

from __future__ import annotations

import hashlib
import importlib
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def modules(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return SimpleNamespace(
        **{
            name: importlib.import_module(name)
            for name in (
                "publish_extension_delivery",
                "extension_delivery_github",
                "extension_delivery_selector",
                "extension_delivery_legacy",
                "build_native_command_program",
            )
        }
    )


@pytest.mark.parametrize("failure", [None, "data", "root"])
def test_only_complete_publication_advances_pointer(modules, monkeypatch, tmp_path, failure):
    publisher = modules.publish_extension_delivery
    from extension_delivery_assets import AssetPlan
    from extension_delivery_objects import encoded

    source, publication = "1" * 40, "12.1"
    plan = AssetPlan(tmp_path / "assets", source, publication_id=publication)
    target = plan.asset(b"public metadata", "object")
    row = plan.pending[0]
    (tmp_path / "asset-plan.jsonl").write_bytes(encoded(row) + b"\n")
    data = b"prepared root bytes"
    (tmp_path / "extension-distribution.v2.json").write_bytes(data)
    (tmp_path / "extension-distribution.intoto.jsonl").write_bytes(b"unit proof")
    root = {"publication_id": publication, "legacy": {"status": "unsupported-oversize", "code": "program-bytes"}}
    verified = SimpleNamespace(manifest=lambda: root, digest=hashlib.sha256(data).hexdigest())
    events = []

    def verify(*args, **kwargs):
        events.append("authenticate")
        assert args == (data, b"unit proof") and kwargs["expected_source_sha"] == source
        return verified

    def upload(tag, *args, **kwargs):
        kind = "root" if tag.startswith("extension-distribution-") else "data"
        events.append(kind)
        if failure == kind:
            raise ValueError("interrupted " + kind)

    monkeypatch.setattr(publisher, "verify_distribution", verify)
    monkeypatch.setattr(publisher, "verify_sources", lambda *args: events.append("source"))
    monkeypatch.setattr(
        publisher,
        "publication_inventory",
        lambda *args: {
            (target["tag"], target["asset"]): {
                "kind": "container",
                "location": row["location"],
                "members": {
                    target["member"]: {"sha256": hashlib.sha256(b"public metadata").hexdigest(), "length": 15},
                },
            }
        },
    )
    monkeypatch.setattr(publisher.provider, "verify_repository", lambda: events.append("repository"))
    monkeypatch.setattr(publisher.provider, "publish_assets", upload)
    monkeypatch.setattr(publisher, "select", lambda value: events.append("selected") or True)
    if failure is not None:
        with pytest.raises(ValueError, match="interrupted"):
            publisher.publish(tmp_path, source, publication)
        assert "selected" not in events
    else:
        assert publisher.publish(tmp_path, source, publication) is True
        assert events == ["authenticate", "source", "repository", "data", "root", "selected"]


def test_bad_provenance_causes_no_public_mutation(modules, monkeypatch, tmp_path):
    publisher = modules.publish_extension_delivery
    (tmp_path / "extension-distribution.v2.json").write_bytes(b"root")
    (tmp_path / "extension-distribution.intoto.jsonl").write_bytes(b"invalid")

    def reject(*args, **kwargs):
        raise ValueError("untrusted publisher")

    monkeypatch.setattr(publisher, "verify_distribution", reject)
    monkeypatch.setattr(
        publisher.provider, "verify_repository", lambda: pytest.fail("invalid provenance reached remote publication")
    )
    with pytest.raises(ValueError, match="untrusted publisher"):
        publisher.publish(tmp_path, "1" * 40, "12.1")


def test_pointer_commit_contains_only_fixed_public_selection_metadata(modules, monkeypatch):
    selector = modules.extension_delivery_selector
    payloads = []

    def github(*args, input_data=None):
        payloads.append(json.loads(input_data))
        return json.dumps({"sha": "2" * 40})

    monkeypatch.setattr(selector, "github", github)
    value = {
        "schema": "guard.extension-distribution-selector.v2",
        "source_sha": "1" * 40,
        "publication_id": "12.1",
        "root_sha256": "3" * 64,
    }
    assert selector.pointer_commit("4" * 40, value) == "2" * 40
    assert payloads[0]["tree"] == [
        {
            "path": "extension-distribution-current.json",
            "mode": "100644",
            "type": "blob",
            "content": json.dumps(value, sort_keys=True, separators=(",", ":")),
        }
    ]
    assert payloads[1]["parents"] == ["4" * 40]
    assert payloads[1]["author"]["email"].endswith("@users.noreply.github.com")


def test_release_download_stops_at_its_bound(modules, monkeypatch, tmp_path):
    provider = modules.extension_delivery_github
    real_popen = subprocess.Popen
    processes = []

    def popen(command, **kwargs):
        assert command[:2] == ["gh", "api"]
        process = real_popen([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 1000000)"], **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(provider.subprocess, "Popen", popen)
    path = tmp_path / "bounded"
    with pytest.raises(ValueError, match="exceeds byte limit"):
        provider.download_asset({"id": 1}, path, 100)
    assert path.stat().st_size == 101
    assert all(process.poll() is not None for process in processes)


def test_legacy_oversize_is_explicit_and_other_admission_failures_remain_fatal(modules, monkeypatch, tmp_path):
    legacy = modules.extension_delivery_legacy
    compiler = modules.build_native_command_program
    assert legacy.preflight(tmp_path, {"extensions": 513}) == "extension-count"
    monkeypatch.setattr(legacy, "preflight", lambda *args: None)

    def reject(*args):
        raise compiler.NativeCompilationError("native_command_program_bounds_invalid", "invalid admission")

    monkeypatch.setattr(compiler, "main", reject)
    with pytest.raises(compiler.NativeCompilationError, match="invalid admission"):
        legacy.prepare(tmp_path, tmp_path, tmp_path, {}, Path("compiler"), "1" * 40, resolve_claimants=False)
