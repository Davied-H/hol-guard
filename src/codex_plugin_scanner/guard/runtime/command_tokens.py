"""DTO transport for native command token and environment parsing."""

from __future__ import annotations

import os

from ..native_rich_command_model import request, string_tuple


def executable_name(value: str | None) -> str | None:
    return request("executable", {"value": value})


def _windows_shell_tokens(command: str) -> tuple[str, ...]:
    result = request("windows_tokens", {"command": command})
    if not result[1]:
        raise ValueError("malformed shell quoting")
    return string_tuple(result[0])


def shell_tokens(command: str) -> tuple[tuple[str, ...], bool]:
    result = request("windows_tokens" if os.name == "nt" else "tokens", {"command": command})
    return string_tuple(result[0]), result[1]


def leading_environment(tokens: tuple[str, ...]) -> tuple[tuple[str, ...], int, tuple[str, ...]]:
    result = request("leading_environment", {"tokens": tokens})
    return string_tuple(result[0]), result[1], string_tuple(result[2])


def _after_sudo_options(tokens: tuple[str, ...], index: int) -> int:
    return request("sudo_options", {"tokens": tokens, "index": index})
