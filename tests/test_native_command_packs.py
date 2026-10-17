"""Immutable compiler objects cannot replace a complete root on failed builds."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def generator(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("pack_builder_test", ROOT / "scripts/build_native_command_packs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.legacy, "ROOT", tmp_path)
    (tmp_path / "contributions/command-sources").mkdir(parents=True)
    (tmp_path / "contributions/mcp-servers").mkdir(parents=True)
    (tmp_path / "contracts/extensions/trust").mkdir(parents=True)
    (tmp_path / "contributions/command-sources/command.one.json").write_text(
        '{"extension":{"extension_id":"command.one"}}'
    )
    (tmp_path / "contracts/extensions/trust/command.one.v1.json").write_text(
        json.dumps(
            {
                "schemaVersion": "guard.extension-trust-binding.v1",
                "extension": "command.one",
                "trustClass": "external",
            }
        )
    )
    return module


def fake_compiler(generator, monkeypatch, rows, status=0):
    data = b"".join(json.dumps(row).encode() + b"\n" for row in rows)

    class Process:
        stdout = io.BytesIO(data)

        def wait(self):
            return status

        def poll(self):
            return status

    monkeypatch.setattr(generator.subprocess, "Popen", lambda *args, **kwargs: Process())


def object_row(data=b'{"schema":"test"}'):
    return {
        "kind": "object",
        "sha256": hashlib.sha256(data).hexdigest(),
        "length": len(data),
        "data": base64.b64encode(data).decode(),
    }


def root_row():
    return {"kind": "root", "schema": "guard.command-pack-release.v1", "extensions": 1, "engine": "test"}


def test_unchanged_objects_are_verified_and_reused(generator, monkeypatch, tmp_path):
    output = tmp_path / "packs"
    fake_compiler(generator, monkeypatch, [object_row(), root_row()])
    first = generator.stage(Path("compiler"), output)
    fake_compiler(generator, monkeypatch, [object_row(), root_row()])
    second = generator.stage(Path("compiler"), output)
    assert first["release_sha256"] == second["release_sha256"]
    assert (first["created_objects"], second["created_objects"], second["reused_objects"]) == (1, 0, 1)
    assert second["changed_object_bytes"] == 0


@pytest.mark.parametrize(
    "rows,status",
    [
        ([object_row()], 0),
        ([object_row(), root_row()], 1),
        ([object_row(), root_row(), root_row()], 0),
        ([object_row(), {**root_row(), "extensions": 2}], 0),
        ([{**object_row(), "sha256": "0" * 64}, root_row()], 0),
        ([{**object_row(), "length": 0}, root_row()], 0),
    ],
)
def test_failed_builds_preserve_previous_complete_root(generator, monkeypatch, tmp_path, rows, status):
    output = tmp_path / "packs"
    output.mkdir()
    previous = b'{"previous":"complete"}\n'
    (output / "release.json").write_bytes(previous)
    fake_compiler(generator, monkeypatch, rows, status)
    with pytest.raises(ValueError):
        generator.stage(Path("compiler"), output)
    assert (output / "release.json").read_bytes() == previous


def test_poisoned_cache_cannot_substitute_a_pack(generator, monkeypatch, tmp_path):
    output = tmp_path / "packs"
    fake_compiler(generator, monkeypatch, [object_row(), root_row()])
    generator.stage(Path("compiler"), output)
    previous = (output / "release.json").read_bytes()
    (output / "objects" / f"{object_row()['sha256']}.json").write_bytes(b"poison")
    fake_compiler(generator, monkeypatch, [object_row(), root_row()])
    with pytest.raises(ValueError, match="failed integrity"):
        generator.stage(Path("compiler"), output)
    assert (output / "release.json").read_bytes() == previous


def test_mcp_source_uses_its_existing_native_trust_identity(generator, tmp_path):
    (tmp_path / "contributions/mcp-servers/mcp.example.json").write_text('{"id":"mcp.example"}')
    (tmp_path / "contracts/extensions/trust/command.mcp-example.v1.json").write_text(
        json.dumps(
            {
                "schemaVersion": "guard.extension-trust-binding.v1",
                "extension": "command.mcp-example",
                "trustClass": "external",
            }
        )
    )
    output = io.BytesIO()
    assert generator.input_stream(tmp_path, output) == 2
    assert b"command.mcp-example" in output.getvalue()
    assert b'{"id":"mcp.example"}' in output.getvalue()


def test_symlink_output_is_rejected_before_compilation(generator, tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    output = tmp_path / "packs"
    output.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinks"):
        generator.stage(Path("compiler"), output)
