"""Fail-closed behaviour of the native package context build transport."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_package_context_build as transport
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.package_execution_context import build_package_execution_context


def _artifact(metadata: object) -> GuardArtifact:
    return GuardArtifact(
        artifact_id="context-transport",
        name="npm install",
        harness="guard-cli",
        artifact_type="package_request",
        source_scope="project",
        config_path="hol-guard.toml",
        metadata=metadata,  # type: ignore[arg-type]
    )


def _stub_guard_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(transport, "_resolve_digest_home", lambda _home: tmp_path)
    monkeypatch.setattr(transport, "ensure_resident_prerequisite", lambda _home: True)


def _call(tmp_path: Path, **overrides: object) -> dict[str, object]:
    arguments: dict[str, object] = {
        "workspace_dir": tmp_path,
        "metadata": {},
        "executable": None,
        "executable_args": (),
        "environment": {"PATH": "/usr/bin"},
    }
    arguments.update(overrides)
    return transport.native_build_package_context(**arguments)  # type: ignore[arg-type]


def test_build_fails_closed_without_a_resident(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(transport, "_resolve_digest_home", lambda _home: tmp_path)
    monkeypatch.setattr(transport, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(ValueError, match="native_package_context_build_unavailable"):
        build_package_execution_context(workspace_dir=tmp_path, artifact=_artifact({}))


def test_build_fails_closed_when_the_resident_returns_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _stub_guard_home(monkeypatch, tmp_path)
    monkeypatch.setattr(transport, "_resident_request", lambda **_kwargs: None)
    with pytest.raises(ValueError, match="native_package_context_build_unavailable"):
        _call(tmp_path)


def test_build_rejects_a_result_not_bound_to_the_request(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _stub_guard_home(monkeypatch, tmp_path)
    monkeypatch.setattr(
        transport,
        "_resident_request",
        lambda **_kwargs: {"schema": transport._RESULT_SCHEMA, "request_id": "other", "status": "ok", "code": "ok"},
    )
    with pytest.raises(ValueError, match="native_package_context_build_unbound"):
        _call(tmp_path)


def test_build_surfaces_a_typed_native_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _stub_guard_home(monkeypatch, tmp_path)

    def respond(**kwargs: object) -> dict[str, object]:
        request = kwargs["request"]
        assert isinstance(request, dict)
        return {
            "schema": transport._RESULT_SCHEMA,
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + transport._canonical_request_sha256(request),
            "status": "error",
            "code": "native_package_context_build_failed",
        }

    monkeypatch.setattr(transport, "_resident_request", respond)
    with pytest.raises(ValueError, match="native_package_context_build_failed"):
        _call(tmp_path)


def test_request_carries_typed_metadata_and_process_facts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _stub_guard_home(monkeypatch, tmp_path)
    seen: dict[str, object] = {}

    def respond(**kwargs: object) -> dict[str, object]:
        request = kwargs["request"]
        assert isinstance(request, dict)
        seen.update(request)
        return {
            "schema": transport._RESULT_SCHEMA,
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + transport._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "context": {"digest": "d", "portable": True, "components": [], "non_portable_reason": None},
        }

    monkeypatch.setattr(transport, "_resident_request", respond)
    context = _call(
        tmp_path,
        metadata={
            "package_manager": "npm",
            "package_executable": 7,
            "flags": ("-g", 3, "--save"),
            "manifest_paths": "package.json",
            "unrelated": {"secret": "value"},
        },
    )
    assert context["digest"] == "d"
    assert seen["metadata"] == {
        "package_manager": "npm",
        "package_executable": None,
        "flags": ["-g", "--save"],
        "manifest_paths": [],
        "lockfile_paths": [],
    }
    assert seen["process_cwd"] and seen["process_home"]
    assert seen["environment"] == {"PATH": "/usr/bin"}


def test_non_string_environment_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="native_package_context_build_invalid_environment"):
        _call(tmp_path, environment={"PATH": 1})
