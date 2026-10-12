"""Native preparation stays profile-bound and terminal on transport failure."""

import base64
import gzip
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_restricted_pytest as transport
from codex_plugin_scanner.guard.runtime import restricted_inline_eval, restricted_node_test, restricted_vitest
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError


def reply(tmp_path, profile):
    return {
        "value": {
            "profile_version": profile,
            "backend": "macos-seatbelt",
            "backend_executable": "/usr/bin/true",
            "workspace": str(tmp_path),
            "cwd": str(tmp_path),
            "executable": "/usr/bin/node",
            "command": ["/usr/bin/node"],
            "allowed_executables": ["/usr/bin/node"],
            "denied_capabilities": ["network", "workspace-write"],
        }
    }


@pytest.mark.parametrize(
    "module,method,profile",
    [
        (restricted_node_test, "prepare_restricted_node_test", "node-test-readonly-v1"),
        (restricted_vitest, "prepare_restricted_vitest", "vitest-readonly-v1"),
        (restricted_inline_eval, "prepare_restricted_inline_eval", "node-eval-readonly-v1"),
    ],
)
def test_preparation_is_one_bound_call(monkeypatch, tmp_path, module, method, profile):
    calls = []

    def call(action, **kwargs):
        calls.append(action)
        return reply(tmp_path, profile)

    monkeypatch.setattr(transport, "_call", call)
    plan = getattr(module, method)(["node", "--test"], workspace=tmp_path)
    assert plan.profile_version == profile
    assert len(calls) == 1
    assert calls[0]["kind"] == "restricted_pytest"
    assert not {"allow", "verdict", "decision"}.intersection(calls[0]["body"]["input"])


@pytest.mark.parametrize("profile", ["pytest-restricted-v1", "node-build-output-v1", "allow"])
def test_reply_cannot_lower_requested_readonly_profile(monkeypatch, tmp_path, profile):
    monkeypatch.setattr(transport, "_call", lambda *a, **k: reply(tmp_path, profile))
    with pytest.raises(RestrictedPytestError):
        restricted_node_test.prepare_restricted_node_test(["node", "--test"], workspace=tmp_path)


@pytest.mark.parametrize(
    "module,method",
    [
        (restricted_node_test, "prepare_restricted_node_test"),
        (restricted_vitest, "prepare_restricted_vitest"),
        (restricted_inline_eval, "prepare_restricted_inline_eval"),
    ],
)
def test_unavailable_native_cannot_launch(monkeypatch, tmp_path, module, method):
    monkeypatch.setattr(transport, "_call", lambda *a, **k: None)
    with pytest.raises(RestrictedPytestError, match="execution was not started"):
        getattr(module, method)(["node"], workspace=tmp_path)


def test_mapping_codec_preserves_full_index_without_python_inspection(monkeypatch, tmp_path):
    observed = []

    def call(action, **kwargs):
        observed.append(action)
        return {"value": []}

    monkeypatch.setattr(transport, "_call", call)
    paths = [tmp_path / f"module-{i}.so" for i in range(10000)]
    assert transport.restricted_native("mapping_evidence", {"read_files": paths}, list) == []
    packed = observed[0]["body"]["input"]
    raw = gzip.decompress(base64.b64decode(packed["packed_json_gzip_v1"]))
    assert len(raw) == packed["decoded_bytes"]
    assert json.loads(raw)["read_files"] == list(map(str, paths))


def test_native_domain_refusal_is_preserved(monkeypatch):
    monkeypatch.setattr(
        transport,
        "_call",
        lambda *a, **k: {
            "reason_code": "vitest_restricted_dependency_unavailable",
            "message": "Local dependency unavailable.",
        },
    )
    with pytest.raises(RestrictedPytestError) as caught:
        restricted_vitest.vitest_arguments(["vitest", "run"])
    assert caught.value.reason_code == "vitest_restricted_dependency_unavailable"
