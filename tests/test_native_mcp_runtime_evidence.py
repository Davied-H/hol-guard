"""Transport contract for the native MCP runtime-evidence owner."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_mcp_runtime_evidence as module
from codex_plugin_scanner.guard.native_mcp_runtime_evidence import argument_entries


def test_argument_entries_projects_only_consumed_keys_in_order() -> None:
    assert argument_entries({"a": "x", "path": "p", "cmd": 2, 1: 2}, mapping_type=dict) == [
        ["path", "p"],
        ["cmd", None],
    ]
    assert argument_entries(["a"], mapping_type=dict) is None


def test_large_unconsumed_argument_is_not_shipped(monkeypatch: pytest.MonkeyPatch) -> None:
    entries = argument_entries({"content": "x" * (512 * 1024), "command": "ls"}, mapping_type=dict)
    assert entries == [["command", "ls"]]


def test_python_key_sets_mirror_the_rust_contract() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "rust/crates/guard-contracts/src/mcp_runtime_evidence.rs"
    ).read_text(encoding="utf-8")

    def rust_keys(name: str) -> tuple[str, ...]:
        match = re.search(rf"pub const {name}: &\[&str\] = &\[(.*?)\];", source, re.S)
        assert match is not None, name
        return tuple(re.findall(r'"([^"]+)"', match.group(1)))

    assert rust_keys("MCP_RUNTIME_EVIDENCE_COMMAND_ARGUMENT_KEYS") == module._COMMAND_ARGUMENT_KEYS
    assert rust_keys("MCP_RUNTIME_EVIDENCE_PATH_ARGUMENT_KEYS") == module._PATH_ARGUMENT_KEYS
    assert rust_keys("MCP_RUNTIME_EVIDENCE_PATH_TOKENS") == module._PATH_TOKENS
