"""Runtime Guard evaluation for MCP tool calls."""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .action_lattice import normalize_guard_action
from .approval_gate import ApprovalGateGrant
from .collections_support import dedupe_preserving_order
from .config import GuardConfig
from .models import GuardAction, GuardArtifact, GuardReceipt, PolicyDecision
from .native_approval_proof import (
    ApprovalReuseClaimDisposition,
)
from .native_mcp_tool_call_identity import NativeToolCallIdentity, native_tool_call_identity, server_identity_dto
from .native_mcp_tool_call_record import prepare_tool_call_record
from .native_mcp_tool_evidence import native_tool_risk_evidence
from .runtime.approval_context import (
    current_extension_control_binding_digest,
)
from .runtime.approval_reuse import (
    APPROVAL_REUSE_NO_SAVED_DECISION,
    ApprovalReuseStatus,
)
from .runtime.composio_contract import composio_requires_action_review
from .runtime.mcp_protection import (
    McpServerIdentity,
)
from .store import GuardStore


@dataclass(frozen=True, slots=True)
class ToolCallAuthority:
    """Fresh execution identity selected at the post-claim boundary."""

    config: GuardConfig
    artifact: GuardArtifact
    artifact_hash: str
    arguments: object


@dataclass(frozen=True, slots=True)
class ToolCallDecision:
    """Decision for one MCP tool call."""

    action: GuardAction
    source: str
    signals: tuple[str, ...]
    summary: str
    risk_categories: tuple[str, ...] = ()
    normalization_reason_code: str | None = None
    original_action: str | None = None
    approval_reuse_status: ApprovalReuseStatus | None = None
    approval_reuse_reason_code: str | None = None
    current_action: GuardAction | None = None
    saved_action: GuardAction | None = None
    pending_approval_reuse_decision: Mapping[str, object] | None = None
    approval_reuse_claim_disposition: ApprovalReuseClaimDisposition | None = None
    post_claim_revalidated: bool = False
    post_claim_authority: ToolCallAuthority | None = None


def resolve_tool_call_policy_action(
    decision: ToolCallDecision,
    *,
    action: object | None = None,
) -> GuardAction:
    """Resolve the exact action enforced for a tool-call decision.

    A first-time review remains ``review``.  A rejected attempt to reuse prior
    authority is a genuine fresh-approval boundary and is therefore surfaced as
    ``require-reapproval`` instead of silently making every review look stale.
    """

    normalized = normalize_guard_action(decision.action if action is None else action)
    stale_prior_authority = (
        decision.approval_reuse_status == "rejected"
        and decision.approval_reuse_reason_code not in {None, APPROVAL_REUSE_NO_SAVED_DECISION}
    )
    if normalized == "review" and stale_prior_authority:
        return "require-reapproval"
    return normalized


def _build_dto(
    *,
    harness: str,
    server_name: str,
    tool_name: str,
    source_scope: str,
    config_path: str,
    transport: str,
    server_id: str | None,
    server_fingerprint: object | None,
    server_identity: McpServerIdentity | None,
    tool_schema: object | None,
    tool_description: str | None,
    tool_definition: Mapping[str, object] | None,
    provider_catalog_hash: str | None,
) -> dict[str, object]:
    if tool_definition is None:
        tool: dict[str, object] = {"kind": "explicit", "schema": tool_schema, "description": tool_description}
    else:
        entry = dict(tool_definition)
        if tool_schema is not None:
            entry.pop("input_schema", None)
            entry["inputSchema"] = tool_schema
        if tool_description is not None:
            entry["description"] = tool_description
        tool = {"kind": "catalog", "entry": entry or None}
    return {
        "harness": harness,
        "server_name": server_name,
        "tool_name": tool_name,
        "source_scope": source_scope,
        "config_path": config_path,
        "transport": transport,
        "server_id": server_id,
        "server_fingerprint": server_fingerprint,
        "server_identity": server_identity_dto(server_identity),
        "provider_catalog_hash": provider_catalog_hash,
        "tool": tool,
    }


def _hash_input(
    arguments: object,
    *,
    workspace: Path | str | None,
    config: GuardConfig | None,
) -> dict[str, object]:
    return {
        "arguments": arguments,
        "config": None
        if config is None
        else {
            **_tool_call_configuration(config),
            "managed_policy_hash": config.managed_policy_hash,
            "managed_policy_status": config.managed_policy_status,
            "sandbox_analysis": config.sandbox_analysis,
        },
        "workspace": _normalized_tool_call_workspace(workspace) if workspace is not None else None,
        "extension_control_digest": None if config is None else current_extension_control_binding_digest(),
    }


def build_tool_call_identity(
    *,
    arguments: object,
    workspace: Path | str | None,
    config: GuardConfig | None,
    guard_home: Path | None = None,
    harness: str,
    server_name: str,
    tool_name: str,
    source_scope: str,
    config_path: str,
    transport: str,
    server_id: str | None = None,
    server_fingerprint: object | None = None,
    server_identity: McpServerIdentity | None = None,
    tool_schema: object | None = None,
    tool_description: str | None = None,
    tool_definition: Mapping[str, object] | None = None,
    provider_catalog_hash: str | None = None,
) -> NativeToolCallIdentity:
    """The artifact, its private bindings and approval hash in one resident call."""
    return native_tool_call_identity(
        build=_build_dto(
            harness=harness,
            server_name=server_name,
            tool_name=tool_name,
            source_scope=source_scope,
            config_path=config_path,
            transport=transport,
            server_id=server_id,
            server_fingerprint=server_fingerprint,
            server_identity=server_identity,
            tool_schema=tool_schema,
            tool_description=tool_description,
            tool_definition=tool_definition,
            provider_catalog_hash=provider_catalog_hash,
        ),
        hash_input=_hash_input(arguments, workspace=workspace, config=config),
        guard_home=guard_home,
    )


def build_tool_call_artifact(**facts: Any) -> GuardArtifact:
    """Build the artifact only (native); see :func:`build_tool_call_identity`."""
    unset: dict[str, Any] = dict.fromkeys(
        (
            "server_id",
            "server_fingerprint",
            "server_identity",
            "tool_schema",
            "tool_description",
            "tool_definition",
            "provider_catalog_hash",
        )
    )
    return native_tool_call_identity(build=_build_dto(**{**unset, **facts})).artifact


def build_tool_call_hash(
    artifact: GuardArtifact,
    arguments: object,
    *,
    workspace: Path | str | None = None,
    config: GuardConfig | None = None,
) -> str:
    identity = native_tool_call_identity(
        artifact=artifact, hash_input=_hash_input(arguments, workspace=workspace, config=config)
    )
    if identity.artifact_hash is None:
        raise ValueError("native_mcp_tool_approval_hash_unavailable")
    return identity.artifact_hash


def _tool_call_configuration(config: GuardConfig) -> dict[str, object]:
    """Raw configuration DTO; policy resolution and versioning are native."""
    return {
        field: getattr(config, field)
        for field in (
            "mode",
            "default_action",
            "artifact_actions",
            "publisher_actions",
            "harness_actions",
            "risk_actions",
            "harness_risk_actions",
            "security_level",
            "protection_posture",
            "protection_posture_explicit",
            "managed_locked_settings",
        )
    }


def _normalized_tool_call_workspace(workspace: Path | str) -> str:
    candidate = Path(workspace).expanduser()
    try:
        return str(candidate.resolve(strict=False))
    except (OSError, RuntimeError):
        return str(candidate.absolute())


def evaluate_tool_call(
    *,
    store: GuardStore,
    config: GuardConfig,
    artifact: GuardArtifact,
    artifact_hash: str,
    arguments: object,
    claim_saved_approval: bool = True,
    fresh_authority_provider: (Callable[[], tuple[GuardConfig, GuardArtifact, str, object] | None] | None) = None,
    proxy_input: Mapping[str, object] | None = None,
    proxy_out: MutableMapping[str, Any] | None = None,
) -> ToolCallDecision:
    from .mcp_tool_call_evaluation import evaluate_tool_call as evaluate

    return evaluate(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=artifact_hash,
        arguments=arguments,
        claim_saved_approval=claim_saved_approval,
        fresh_authority_provider=fresh_authority_provider,
        proxy_input=proxy_input,
        proxy_out=proxy_out,
    )


def tool_call_risk_categories(artifact: GuardArtifact, arguments: object) -> tuple[str, ...]:
    """Return Rust-owned Cloud risk categories for one MCP tool call."""
    return native_tool_risk_evidence(artifact, arguments)[0]


def tool_call_risk_summary(artifact: GuardArtifact, arguments: object) -> str:
    """Return the Rust-owned risk summary for one MCP tool call."""
    return native_tool_risk_evidence(artifact, arguments)[2]


_NON_EXECUTED_ACTIONS = frozenset({"review", "require-reapproval", "sandbox-required", "block"})


def allow_tool_call(
    *,
    store: GuardStore,
    artifact: GuardArtifact,
    artifact_hash: str,
    decision_source: str,
    now: str,
    signals: tuple[str, ...],
    remember: bool,
    risk_categories: tuple[str, ...] = (),
    approval_gate_grant: ApprovalGateGrant | None = None,
    arguments: object = None,
    policy_workspace: str | None = None,
    additional_scanner_evidence: tuple[dict[str, object], ...] = (),
    policy_action: GuardAction = "allow",
    emit_runtime_evidence: bool = True,
) -> GuardReceipt | None:
    """Remember the allow when asked, then record the call; ``None`` when no evidence is emitted."""
    if remember:
        if composio_requires_action_review(artifact.command or ""):
            raise ValueError("verified_account_required_for_remembered_provider_action")
        store.upsert_policy(
            PolicyDecision(
                harness=artifact.harness,
                scope="artifact",
                action="allow",
                artifact_id=artifact.artifact_id,
                artifact_hash=artifact_hash,
                workspace=policy_workspace,
                reason=f"Approved via Guard runtime ({decision_source})",
                source="runtime-inline",
            ),
            now,
            approval_gate_grant=approval_gate_grant,
        )
    if not emit_runtime_evidence:
        return None
    return prepare_tool_call_record(
        store=store,
        kind="allow",
        artifact=artifact,
        artifact_hash=artifact_hash,
        decision_source=decision_source,
        now=now,
        signals=signals,
        risk_categories=risk_categories,
        policy_action=policy_action,
        arguments=arguments,
        additional_scanner_evidence=additional_scanner_evidence,
    ).commit()


def block_tool_call(
    *,
    store: GuardStore,
    artifact: GuardArtifact,
    artifact_hash: str,
    decision_source: str,
    now: str,
    signals: tuple[str, ...],
    risk_categories: tuple[str, ...] = (),
    arguments: object = None,
    additional_scanner_evidence: tuple[dict[str, object], ...] = (),
    policy_action: GuardAction = "block",
) -> GuardReceipt:
    if policy_action not in _NON_EXECUTED_ACTIONS:
        raise ValueError(f"block_tool_call cannot record executing action {policy_action!r}.")
    return prepare_tool_call_record(
        store=store,
        kind="block",
        artifact=artifact,
        artifact_hash=artifact_hash,
        decision_source=decision_source,
        now=now,
        signals=signals,
        risk_categories=risk_categories,
        policy_action=policy_action,
        arguments=arguments,
        additional_scanner_evidence=additional_scanner_evidence,
    ).commit()


_dedupe = dedupe_preserving_order
