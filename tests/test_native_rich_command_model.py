"""Real caller replay of outcomes captured before native cutover."""

from __future__ import annotations

import dataclasses
import json
import os
import time
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_rich_command_model as client
from codex_plugin_scanner.guard.runtime import command_model, command_tokens, env_wrapper

FIXTURE = json.loads((Path(__file__).parent / "fixtures/native_rich_command_model.json").read_text())


def wire(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: wire(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (tuple, list)):
        return [wire(item) for item in value]
    return value


def invoke(vector: dict[str, Any]) -> Any:
    args = dict(vector["args"])
    action = vector["action"]
    if action == "parse":
        for key in ("cwd", "home_dir"):
            if key in args:
                args[key] = Path(args[key]) if args[key] is not None else None
        model = command_model.parse_shell_command(**args)
        return {
            "raw_text": model.raw_text,
            **model.to_dict(),
            "embedded_commands": [{**item.to_dict(), "text": item.text} for item in model.embedded_commands],
        }
    if action == "tokens":
        return command_tokens.shell_tokens(**args)
    if action == "executable":
        return command_tokens.executable_name(**args)
    if action == "leading_environment":
        return command_tokens.leading_environment(tuple(args["tokens"]))
    if action == "env":
        args["cwd"] = Path(args["cwd"])
        return env_wrapper.parse_env_wrapper(**args)
    raise AssertionError(action)


@pytest.mark.skipif(os.name == "nt", reason="Original fixture records POSIX tokenization")
@pytest.mark.parametrize("vector", FIXTURE["vectors"], ids=lambda v: v["action"])
def test_original_outcomes_through_public_callers(vector: dict[str, Any]) -> None:
    if "error" in vector:
        with pytest.raises(ValueError, match="Command text cannot be empty"):
            invoke(vector)
    else:
        assert wire(invoke(vector)) == vector["result"]


def test_native_outage_has_no_python_parser_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _: False)
    with pytest.raises(client.NativeCommandModelError):
        command_model.parse_shell_command("echo hi")
    with pytest.raises(client.NativeCommandModelError):
        env_wrapper.parse_env_wrapper(["echo", "hi"])


def test_identity_cache_is_bound_to_complete_structure(monkeypatch: pytest.MonkeyPatch) -> None:
    model = command_model.parse_shell_command("echo hi")
    identity = model.security_identity
    assert dataclasses.replace(model).security_identity == identity
    changed = dataclasses.replace(model, normalized_text="echo bye")
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _: False)
    with pytest.raises(client.NativeCommandModelError):
        _ = changed.security_identity


@pytest.mark.parametrize("damage", ["digest", "request_id", "schema", "shape", "status", "surrogate"])
def test_transport_rejects_unbound_or_malformed_replies(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    damage: str,
) -> None:
    from types import SimpleNamespace

    monkeypatch.setattr(client, "_resolve_digest_home", lambda _: tmp_path)
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _: True)
    monkeypatch.setattr(client, "native_resident_client_ready", lambda *_: True)
    monkeypatch.setattr(
        client,
        "native_runtime_status",
        lambda: SimpleNamespace(
            available=True,
            compatible=True,
            identity=SimpleNamespace(path="/fixture/runtime"),
            capabilities=SimpleNamespace(features=[client.FEATURE, "resident-protocol-v2"]),
        ),
    )

    def respond(**kwargs: Any) -> bytes:
        assert damage != "surrogate", "Invalid UTF-8 must be rejected before transport"
        assert 0 < kwargs["deadline_monotonic"] - time.monotonic() <= 1.0
        material = json.loads(kwargs["payload"])["request"]
        reply = {
            "schema": client.RESULT_SCHEMA,
            "request_id": material["request_id"],
            "request_sha256": client._canonical_request_sha256(material),
            "status": "ok",
            "error": None,
            "result": [["echo", "hi"], True],
        }
        if damage == "shape":
            reply["result"] = [[42], True]
        else:
            key = "request_sha256" if damage == "digest" else damage
            reply[key] = "invalid"
        return json.dumps(reply).encode()

    monkeypatch.setattr(client, "native_resident_client_request", respond)
    with pytest.raises(ValueError):
        command_tokens.shell_tokens("echo \udc80" if damage == "surrogate" else "echo hi")


@pytest.mark.parametrize("setup_seconds", [2.0, 9.0, 11.0])
def test_cold_helper_setup_and_spawn_share_bounded_overall_deadline(monkeypatch, tmp_path, setup_seconds):
    from types import SimpleNamespace

    now = [100.0]
    monkeypatch.setattr(client, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(client, "_resolve_digest_home", lambda _: tmp_path)

    def prerequisite(_):
        now[0] += setup_seconds
        return True

    monkeypatch.setattr(client, "ensure_resident_prerequisite", prerequisite)
    monkeypatch.setattr(client, "native_resident_client_ready", lambda *_: False)
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "runtime", sha256="fixture"),
        capabilities=SimpleNamespace(features=[client.FEATURE, "resident-protocol-v2"]),
    )
    monkeypatch.setattr(client, "native_runtime_status", lambda: status)

    def respond(**kwargs):
        assert setup_seconds < 10
        assert kwargs["deadline_monotonic"] <= 110.0
        assert kwargs["deadline_monotonic"] - now[0] == min(4.0, 10.0 - setup_seconds)
        material = json.loads(kwargs["payload"])["request"]
        return json.dumps(
            {
                "schema": client.RESULT_SCHEMA,
                "request_id": material["request_id"],
                "request_sha256": client._canonical_request_sha256(material),
                "status": "ok",
                "error": None,
                "result": [["echo"], True],
            }
        ).encode()

    monkeypatch.setattr(client, "native_resident_client_request", respond)
    if setup_seconds > 10:
        with pytest.raises(client.NativeCommandModelError, match="deadline"):
            command_tokens.shell_tokens("echo")
    else:
        assert command_tokens.shell_tokens("echo") == (("echo",), True)


def test_executable_reuse_is_bounded_and_bound_to_available_native_identity(monkeypatch, tmp_path):
    from types import SimpleNamespace

    client._EXECUTABLE_CACHE.clear()
    monkeypatch.setattr(client, "_resolve_digest_home", lambda _: tmp_path)
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _: True)
    monkeypatch.setattr(client, "native_resident_client_ready", lambda *_: True)
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "runtime", sha256="fixture-a"),
        capabilities=SimpleNamespace(features=[client.FEATURE, "resident-protocol-v2"]),
    )
    monkeypatch.setattr(client, "native_runtime_status", lambda: status)
    calls = []

    def respond(**kwargs):
        material = json.loads(kwargs["payload"])["request"]
        calls.append(material)
        return json.dumps(
            {
                "schema": client.RESULT_SCHEMA,
                "request_id": material["request_id"],
                "request_sha256": client._canonical_request_sha256(material),
                "status": "ok",
                "error": None,
                "result": status.identity.sha256,
            }
        ).encode()

    monkeypatch.setattr(client, "native_resident_client_request", respond)
    assert command_tokens.executable_name("/fixture/echo") == "fixture-a"
    assert command_tokens.executable_name("/fixture/echo") == "fixture-a"
    assert len(calls) == 1
    status.identity.sha256 = "fixture-b"
    assert command_tokens.executable_name("/fixture/echo") == "fixture-b"
    assert len(calls) == 2
    status.available = False
    with pytest.raises(client.NativeCommandModelError):
        command_tokens.executable_name("/fixture/echo")
    status.available = True
    for i in range(257):
        command_tokens.executable_name(f"tool-{i}")
    assert len(client._EXECUTABLE_CACHE) <= 256
    client._EXECUTABLE_CACHE.clear()
