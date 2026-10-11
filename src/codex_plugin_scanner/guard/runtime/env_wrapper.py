"""Exact, side-effect-free parsing for the supported Unix ``env`` contract."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..native_rich_command_model import request, string_tuple

__all__ = [
    "ENV_SPLIT_MAX_BYTES",
    "ENV_SPLIT_MAX_EXPANSIONS",
    "ENV_TOKEN_MAX_COUNT",
    "EnvEnvironmentDelta",
    "EnvOptionEffects",
    "EnvSplitExpansion",
    "EnvWrapperParseResult",
    "parse_env_wrapper",
]

ENV_SPLIT_MAX_BYTES = 8192
ENV_SPLIT_MAX_EXPANSIONS = 4
ENV_TOKEN_MAX_COUNT = 256


@dataclass(frozen=True, slots=True)
class EnvEnvironmentDelta:
    clear: bool
    unset_names: tuple[str, ...]
    assignments: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class EnvOptionEffects:
    ignore_environment: bool
    unset_names: tuple[str, ...]
    chdir: str | None
    search_path: str | None
    verbose: bool
    null_output: bool


@dataclass(frozen=True, slots=True)
class EnvSplitExpansion:
    payload: str
    source_index: int
    tokens: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EnvWrapperParseResult:
    complete: bool
    error: str | None
    original_tokens: tuple[str, ...]
    expanded_tokens: tuple[str, ...]
    option_effects: EnvOptionEffects
    environment_delta: EnvEnvironmentDelta
    effective_environment: tuple[tuple[str, str], ...] | None
    effective_cwd: Path | None
    command_index: int | None
    executable_argv: tuple[str, ...]
    split_expansions: tuple[EnvSplitExpansion, ...]

    def environment_dict(self) -> dict[str, str] | None:
        if self.effective_environment is None:
            return None
        return dict(self.effective_environment)


def parse_env_wrapper(
    tokens: Sequence[str],
    *,
    inherited_environment: Mapping[str, str] | None = None,
    cwd: Path | None = None,
) -> EnvWrapperParseResult:
    """Present the native env parser result; never infer an executable locally."""
    value = request(
        "env",
        {
            "tokens": list(tokens),
            "inherited_environment": dict(inherited_environment) if inherited_environment is not None else None,
            "cwd": str(cwd) if cwd is not None else None,
        },
    )
    effects, delta = value["option_effects"], value["environment_delta"]
    return EnvWrapperParseResult(
        complete=value["complete"],
        error=value["error"],
        original_tokens=string_tuple(value["original_tokens"]),
        expanded_tokens=string_tuple(value["expanded_tokens"]),
        option_effects=EnvOptionEffects(
            effects["ignore_environment"],
            string_tuple(effects["unset_names"]),
            effects["chdir"],
            effects["search_path"],
            effects["verbose"],
            effects["null_output"],
        ),
        environment_delta=EnvEnvironmentDelta(
            delta["clear"], string_tuple(delta["unset_names"]), tuple(tuple(pair) for pair in delta["assignments"])
        ),
        effective_environment=(
            None
            if value["effective_environment"] is None
            else tuple(tuple(pair) for pair in value["effective_environment"])
        ),
        effective_cwd=Path(value["effective_cwd"]) if value["effective_cwd"] is not None else None,
        command_index=value["command_index"],
        executable_argv=string_tuple(value["executable_argv"]),
        split_expansions=tuple(
            EnvSplitExpansion(e["payload"], e["source_index"], string_tuple(e["tokens"]))
            for e in value["split_expansions"]
        ),
    )
