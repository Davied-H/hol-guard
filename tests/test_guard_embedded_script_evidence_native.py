"""Native embedded-script evidence replays the vectors recorded from the Python owner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.embedded_script_evidence import embedded_script_evidence_entries

_VECTORS = json.loads(
    (
        Path(__file__).resolve().parents[1] / "rust/crates/guard-command/testdata/embedded_script_evidence/vectors.json"
    ).read_text(encoding="utf-8")
)


@pytest.mark.parametrize("vector", _VECTORS, ids=[vector["name"] for vector in _VECTORS])
def test_native_embedded_script_evidence_matches_recorded_vector(vector: dict[str, object]) -> None:
    assert embedded_script_evidence_entries(vector["command"]) == vector["entries"]


def test_non_string_command_has_no_evidence() -> None:
    assert embedded_script_evidence_entries(None) == []
