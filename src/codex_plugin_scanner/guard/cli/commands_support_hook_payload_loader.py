"""Raw hook payload loading and compatibility normalization."""

from __future__ import annotations

import json
from pathlib import Path

from ..adapters.hook_input_reader import read_stdin_text
from ..native_cli_runtime_support import cli_runtime_support


def _canonical_harness_name(value: str) -> str:
    from .commands_support_runtime_resolution import _canonical_harness_name as resolve

    return resolve(value)


def load_hook_payload(
    event_file: str | None,
    *,
    input_text: str | None = None,
    harness: str | None = None,
    normalize: bool = True,
) -> dict[str, object]:
    """Load one bounded hook payload and normalize only when requested."""

    if event_file:
        raw = Path(event_file).read_text(encoding="utf-8")
    else:
        raw = input_text.strip() if isinstance(input_text, str) else read_stdin_text()[0].strip()
    if not raw:
        return {}
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        return {}
    if normalize:
        return normalize_hook_payload(payload, harness=harness)
    return payload


def normalize_hook_payload(payload: dict[str, object], *, harness: str | None = None) -> dict[str, object]:
    return cli_runtime_support(
        "normalize_payload",
        {"payload": payload, "harness": _canonical_harness_name(harness) if harness is not None else None},
    )


def normalize_hook_arguments(*values: object | None) -> object | None:
    return cli_runtime_support("normalize_arguments", {"values": list(values)})


def normalize_hook_argument_value(value: object | None) -> object | None:
    return cli_runtime_support("normalize_argument", {"value": value})


def first_hook_tool_call(
    value: object | None, *, expected_tool_name: object | None = None
) -> tuple[str | None, object | None]:
    result = cli_runtime_support("first_tool_call", {"value": value, "expected": expected_tool_name})
    return result[0], result[1]


_load_hook_payload = load_hook_payload
_normalize_hook_payload = normalize_hook_payload
_normalize_hook_arguments = normalize_hook_arguments
_normalize_hook_argument_value = normalize_hook_argument_value
_first_hook_tool_call = first_hook_tool_call


__all__ = [
    "_first_hook_tool_call",
    "_load_hook_payload",
    "_normalize_hook_argument_value",
    "_normalize_hook_arguments",
    "_normalize_hook_payload",
    "first_hook_tool_call",
    "load_hook_payload",
    "normalize_hook_argument_value",
    "normalize_hook_arguments",
    "normalize_hook_payload",
]
