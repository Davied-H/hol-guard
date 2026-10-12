"""The request the Codex detection facade sends the native resident."""

from __future__ import annotations

import datetime
from pathlib import Path

from codex_plugin_scanner.guard.adapters import codex
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.models import HarnessDetection


def test_wire_bindings_drop_values_json_cannot_carry() -> None:
    keep = {"event": "Stop", "group": {"matcher": None}, "handler": {"command": "a", "timeout": 3}}
    stamp = {"event": "Stop", "group": {}, "handler": {"command": "b", "when": datetime.datetime(2020, 1, 1)}}
    nan = {"event": "Stop", "group": {}, "handler": {"command": "c", "ratio": float("nan")}}

    wire = codex._wire_bindings([keep, stamp, nan])

    assert wire == [keep]
    assert wire[0] is not keep


def test_detect_sends_scoped_sources_and_inline_captures(tmp_path: Path, monkeypatch) -> None:
    sent: list[tuple[str, dict[str, object]]] = []

    def fake_native(kind: str, request: dict[str, object]):
        sent.append((kind, request))
        return (), ("/seen",), ("warned",)

    monkeypatch.setattr(codex, "native_adapter_detection_with_warnings", fake_native)
    monkeypatch.setattr(codex, "load_hook_manifest_baseline", lambda _spec: None)
    monkeypatch.setattr(codex, "_hook_manifest_spec", lambda _context: None)
    monkeypatch.setattr(codex, "extend_detection_with_workspace_aibom", lambda detection, **_kwargs: detection)
    monkeypatch.setattr(codex, "extend_codex_runtime_inventory", lambda detection, **_kwargs: detection)
    home = tmp_path / "home"
    work = tmp_path / "work"
    context = HarnessContext(home_dir=home, workspace_dir=work, guard_home=tmp_path / "guard")
    (home / ".codex").mkdir(parents=True)
    (home / ".codex" / "config.toml").write_text('[mcp_servers.a]\ncommand = "x"\n', encoding="utf-8")

    detection = codex.CodexHarnessAdapter().detect(context)

    assert isinstance(detection, HarnessDetection)
    assert detection.config_paths == ("/seen",)
    assert detection.warnings == ("warned",)
    kind, request = sent[0]
    assert kind == "codex_detect"
    assert request["harness"] == "codex"
    assert request["authenticated_bindings"] == []
    assert request["contents"] is None
    sources = request["sources"]
    assert [(entry["config_scope"], entry["hooks_scope"], entry["authenticated"]) for entry in sources] == [
        ("global", "global", True),
        ("project", "project", False),
    ]
    assert sources[0]["config_path"] == str(home / ".codex" / "config.toml")
    assert sources[1]["hooks_path"] == str(work / ".codex" / "hooks.json")

    pairs = codex.CodexHarnessAdapter._config_hook_pairs(context)
    captured = {path: None for pair in pairs for path in pair}
    captured[home / ".codex" / "config.toml"] = b'[mcp_servers.a]\ncommand = "x"\n'
    codex.CodexHarnessAdapter().detect(context, config_contents=captured)

    inline = sent[1][1]["contents"]
    assert inline[str(home / ".codex" / "config.toml")] == b'[mcp_servers.a]\ncommand = "x"\n'.hex()
    assert inline[str(work / ".codex" / "hooks.json")] is None
