"""The TOML the native writer emits must still parse with the Python reader (downgrade safety)."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import tomllib

_FIXTURE = (
    Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/tests/fixtures/guard_support_vectors.json.gz"
)


def _vectors() -> list[dict]:
    return json.loads(gzip.decompress(_FIXTURE.read_bytes()))["toml"]


def test_recorded_writer_output_round_trips_through_tomllib() -> None:
    cases = _vectors()
    assert len(cases) >= 15
    for case in cases:
        parsed = tomllib.loads(case["expected"])
        assert parsed == _normalize(case["config"]), case["config"]


def test_non_bmp_escape_form_parses_to_the_original_character() -> None:
    # The native writer emits this form; the previous surrogate-pair form is rejected by tomllib.
    assert tomllib.loads('k = "a\\U0001f600b"\n"\\U0001f600" = 1\n') == {"k": "a\U0001f600b", "\U0001f600": 1}


def test_non_finite_floats_round_trip() -> None:
    parsed = tomllib.loads("a = nan\nb = inf\nc = -inf\n")
    assert parsed["a"] != parsed["a"]
    assert parsed["b"] == float("inf")
    assert parsed["c"] == float("-inf")


def _normalize(value: object) -> object:
    if value is None:
        return "None"
    if isinstance(value, dict):
        return {key: _normalize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    return value
