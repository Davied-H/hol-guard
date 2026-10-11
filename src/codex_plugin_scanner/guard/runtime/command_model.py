"""Canonical, side-effect-free command model shared by Guard extensions."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from ..native_rich_command_model import request, string_tuple
from .command_structure import CommandRedirect, EmbeddedCommand, build_command_security_identity

CommandDialect = Literal["posix", "powershell", "cmd", "argv", "unknown"]
CommandTransport = Literal["shell_string", "argv", "embedded_script"]
ParseConfidence = Literal["exact", "fallback", "uncertain"]

MAX_COMMAND_BYTES = 32_768
MAX_COMMAND_SEGMENTS = 128
MAX_COMMAND_TOKENS = 2_048


@dataclass(frozen=True, slots=True)
class CommandSegment:
    """One executable segment from a normalized command string."""

    text: str
    tokens: tuple[str, ...]
    executable: str | None
    arguments: tuple[str, ...]
    environment_names: tuple[str, ...]
    wrapper_chain: tuple[str, ...]
    path_overridden: bool
    execution_context: str
    pipeline_index: int
    start: int
    end: int

    def to_dict(self) -> dict[str, object]:
        return {
            "text": self.text,
            "tokens": list(self.tokens),
            "executable": self.executable,
            "arguments": list(self.arguments),
            "environment_names": list(self.environment_names),
            "wrapper_chain": list(self.wrapper_chain),
            "path_overridden": self.path_overridden,
            "execution_context": self.execution_context,
            "pipeline_index": self.pipeline_index,
            "span": {"source": "normalized", "start": self.start, "end": self.end},
        }


@dataclass(frozen=True, slots=True)
class CanonicalCommand:
    """Normalized command representation that never executes shell input."""

    raw_text: str
    normalized_text: str
    dialect: CommandDialect
    transport: CommandTransport
    extraction_provenance: str
    wrapper_chain: tuple[str, ...]
    segments: tuple[CommandSegment, ...]
    redirects: tuple[CommandRedirect, ...]
    embedded_commands: tuple[EmbeddedCommand, ...]
    confidence: ParseConfidence
    uncertainty_reason: str | None = None
    _bound_identity: tuple[object, str] | None = field(default=None, repr=False, compare=False)

    @property
    def path_overridden(self) -> bool:
        return any(segment.path_overridden for segment in self.segments)

    @property
    def security_identity(self) -> str:
        """Return a versioned identity over the complete executable structure."""

        material = self._identity_material()
        if self._bound_identity is not None and self._bound_identity[0] == material:
            return self._bound_identity[1]
        return build_command_security_identity(
            normalized_text=self.normalized_text,
            dialect=self.dialect,
            transport=self.transport,
            wrapper_chain=self.wrapper_chain,
            segments=self.segments,
            redirects=self.redirects,
            embedded_commands=self.embedded_commands,
        )

    def _identity_material(self) -> object:
        return (
            self.normalized_text,
            self.dialect,
            self.transport,
            self.wrapper_chain,
            tuple(
                (s.tokens, s.environment_names, s.wrapper_chain, s.execution_context, s.pipeline_index)
                for s in self.segments
            ),
            tuple((r.operator, r.target) for r in self.redirects),
            tuple((e.kind, e.text, e.execution_context) for e in self.embedded_commands),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "normalized_text": self.normalized_text,
            "dialect": self.dialect,
            "transport": self.transport,
            "extraction_provenance": self.extraction_provenance,
            "wrapper_chain": list(self.wrapper_chain),
            "segments": [segment.to_dict() for segment in self.segments],
            "redirects": [redirect.to_dict() for redirect in self.redirects],
            "embedded_commands": [embedded.to_dict() for embedded in self.embedded_commands],
            "security_identity": self.security_identity,
            "confidence": self.confidence,
            "uncertainty_reason": self.uncertainty_reason,
            "path_overridden": self.path_overridden,
        }


def parse_shell_command(
    command: str,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    dialect: CommandDialect = "posix",
    transport: CommandTransport = "shell_string",
    extraction_provenance: str = "guard-shell",
    normalize_wrappers: bool = True,
) -> CanonicalCommand:
    """Parse through the resident; native unavailability has no semantic fallback."""
    value = request(
        "parse",
        {
            "command": command,
            "cwd": str(cwd) if cwd is not None else None,
            "home_dir": str(home_dir) if home_dir is not None else None,
            "dialect": dialect,
            "transport": transport,
            "extraction_provenance": extraction_provenance,
            "normalize_wrappers": normalize_wrappers,
        },
    )
    segments = tuple(
        CommandSegment(
            text=s["text"],
            tokens=string_tuple(s["tokens"]),
            executable=s["executable"],
            arguments=string_tuple(s["arguments"]),
            environment_names=string_tuple(s["environment_names"]),
            wrapper_chain=string_tuple(s["wrapper_chain"]),
            path_overridden=s["path_overridden"],
            execution_context=s["execution_context"],
            pipeline_index=s["pipeline_index"],
            start=s["span"]["start"],
            end=s["span"]["end"],
        )
        for s in value["segments"]
    )
    redirects = tuple(
        CommandRedirect(r["operator"], r["target"], r["span"]["start"], r["span"]["end"]) for r in value["redirects"]
    )
    embedded = tuple(
        EmbeddedCommand(e["kind"], e["text"], e["execution_context"], e["span"]["start"], e["span"]["end"])
        for e in value["embedded_commands"]
    )
    model = CanonicalCommand(
        raw_text=value["raw_text"],
        normalized_text=value["normalized_text"],
        dialect=value["dialect"],
        transport=value["transport"],
        extraction_provenance=value["extraction_provenance"],
        wrapper_chain=string_tuple(value["wrapper_chain"]),
        segments=segments,
        redirects=redirects,
        embedded_commands=embedded,
        confidence=value["confidence"],
        uncertainty_reason=value["uncertainty_reason"],
    )
    object.__setattr__(model, "_bound_identity", (model._identity_material(), value["security_identity"]))
    return model
