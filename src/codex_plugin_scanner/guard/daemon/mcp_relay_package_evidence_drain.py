"""Record the receipt of a package call the native relay decided.

A relayed ``tools/call`` the resident answers through its package lane leaves a
different receipt from a plain tool call: ``_record_package_block``
(``runtime_mcp.py:2327``) and ``_record_package_forward`` (:2025) write the
block and allow receipts against the *package request's* artifact and the
approval-context token that request hashed to, with the evaluation's reason
signals and the package scanner evidence. The tool legs of the same lane are
recorded as the plain tool-policy blocks they are, so they keep the
``mcp_tool_call`` record :mod:`mcp_relay_evidence_drain` writes.

The resident cannot ship the artifact itself -- ``GuardArtifact.to_dict``
redacts args, url and metadata, and a receipt written from redacted fields is
not the receipt the proxy writes. So its record names the artifact by id and
carries the workspace the intent was parsed against, and the artifact is
rebuilt here from the same parser input the resident read
(``_package_request_artifact``). A record whose rebuilt artifact is not the one
the resident decided is dropped, never recorded against a different package.

That parser input includes the ``PATH`` the intent was resolved under, which
decides the manager a command names. This runs in the daemon, whose own
``PATH`` is not the relaying proxy's, so the record carries the proxy's and the
parse here binds it. A record naming none is dropped: the resident parsed that
call with no search path at all, and ``_resident_environment`` has no way to
ask for the same.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .mcp_relay_evidence_drain import (
    _BLOCK_SOURCE,
    _FORWARD_ACTIONS,
    _RELAY_HARNESSES,
    _decision,
    _ordered_params,
)

MCP_PACKAGE_CALL_EVIDENCE_KIND = "mcp_package_call"
_RECORD_KEYS = frozenset(
    {
        "kind",
        "harness",
        "outcome",
        "decision_source",
        "policy_action",
        "tool_name",
        "params",
        "arguments",
        "identity",
        "decision",
        "package",
    }
)
# The package facts the receipt is written from. `path` is always stated, as
# `null` when the relay parsed under none. `policy_workspace` is bound only by
# the allow receipt, so only a forward's record carries it.
_PACKAGE_KEYS = frozenset(
    {
        "artifact_id",
        "artifact_hash",
        "workspace",
        "path",
        "evaluation",
        "evidence",
        "signals",
    }
)
_POLICY_WORKSPACE_KEY = "policy_workspace"


def is_mcp_relay_package_evidence(record: object) -> bool:
    return isinstance(record, Mapping) and record.get("kind") == MCP_PACKAGE_CALL_EVIDENCE_KIND


def record_mcp_relay_package_evidence(store: object, guard_home: Path, record: object) -> bool:
    """Record one relayed package call as the proxy records it."""

    from ..mcp_tool_calls import allow_tool_call, block_tool_call
    from ..native_mcp_tool_call_identity import _decode  # pyright: ignore[reportPrivateUsage]
    from ..proxy.runtime_mcp_projection import McpCallProjector
    from ..tool_decision_evidence import tool_decision_scanner_evidence

    if not isinstance(record, Mapping) or set(record) != _RECORD_KEYS:
        return False
    harness, outcome = record["harness"], record["outcome"]
    source, policy_action = record["decision_source"], record["policy_action"]
    tool_name, params = record["tool_name"], record["params"]
    package = record["package"]
    if (
        record["kind"] != MCP_PACKAGE_CALL_EVIDENCE_KIND
        or not isinstance(harness, str)
        or harness not in _RELAY_HARNESSES
        or not isinstance(source, str)
        or not isinstance(policy_action, str)
        or not isinstance(tool_name, str)
        or not isinstance(params, dict)
        or params.get("name") != tool_name
    ):
        return False
    forwarded = outcome == "forward"
    if forwarded:
        # The proxy forwards under the action it permitted the call with, and
        # records the receipt under that same action.
        if policy_action not in _FORWARD_ACTIONS or source != f"policy-{policy_action}":
            return False
    elif outcome != "block" or policy_action in _FORWARD_ACTIONS or source != _BLOCK_SOURCE:
        return False
    facts = _package_facts(package, forwarded=forwarded)
    if facts is None:
        return False
    try:
        identity = _decode(record["identity"], expect_hash=True, token=True)
        decision = _decision(record["decision"])
        ordered = _ordered_params(params, record["arguments"])
        if identity.artifact.harness != harness:
            return False
        artifact = _package_artifact(
            harness=harness,
            tool_name=tool_name,
            arguments=ordered.get("arguments"),
            workspace=Path(facts["workspace"]),
            path=facts["path"],
            guard_home=guard_home,
            config_path=identity.artifact.config_path,
            source_scope=identity.artifact.source_scope,
        )
        # The resident decided one package request; a parse that rebuilds
        # another one is not that request's receipt.
        if artifact is None or artifact.artifact_id != facts["artifact_id"]:
            return False
        recorded: dict[str, Any] = {
            "store": store,
            "artifact": artifact,
            "artifact_hash": facts["artifact_hash"],
            "decision_source": source,
            "now": datetime.now(timezone.utc).isoformat(),
            "signals": facts["signals"],
            "arguments": McpCallProjector(guard_home).project(tool_name, ordered).safe_arguments,
            "additional_scanner_evidence": (
                *tool_decision_scanner_evidence(decision),
                *facts["evidence"],
            ),
            "policy_action": policy_action,
        }
        if forwarded:
            # `_record_package_forward`: the allow receipt alone, since the
            # relay never spends a saved approval and so remembers nothing.
            allow_tool_call(
                remember=False,
                policy_workspace=facts[_POLICY_WORKSPACE_KEY],
                **recorded,
            )
        else:
            # `_record_package_block`: no risk categories and no policy
            # workspace, as the proxy writes it.
            block_tool_call(**recorded)
    except Exception:
        # A record the proxy could not have written is dropped, never guessed.
        return False
    return True


def _package_facts(package: object, *, forwarded: bool) -> dict[str, Any] | None:
    """The package half of the record, or ``None`` when it is not the proxy's."""

    if not isinstance(package, Mapping):
        return None
    keys = set(package)
    workspace_bound = _POLICY_WORKSPACE_KEY in keys
    if keys - {_POLICY_WORKSPACE_KEY} != _PACKAGE_KEYS or workspace_bound != forwarded:
        return None
    artifact_id, artifact_hash = package["artifact_id"], package["artifact_hash"]
    workspace, evaluation = package["workspace"], package["evaluation"]
    path = package["path"]
    evidence, signals = package["evidence"], package["signals"]
    policy_workspace = package.get(_POLICY_WORKSPACE_KEY)
    if (
        not isinstance(artifact_id, str)
        or not isinstance(artifact_hash, str)
        or not isinstance(workspace, str)
        or not isinstance(path, str)
        or not isinstance(evaluation, dict)
        or not isinstance(evidence, list)
        or not all(isinstance(item, dict) for item in evidence)
        or not isinstance(signals, list)
        or not all(isinstance(item, str) for item in signals)
        or not isinstance(policy_workspace, (str, type(None)))
        or not all(field.strip() for field in (artifact_id, artifact_hash, workspace, path))
    ):
        return None
    return {
        "artifact_id": artifact_id,
        "artifact_hash": artifact_hash,
        "workspace": workspace,
        "path": path,
        "evaluation": evaluation,
        "evidence": tuple(evidence),
        "signals": tuple(signals),
        _POLICY_WORKSPACE_KEY: policy_workspace,
    }


def _package_artifact(
    *,
    harness: str,
    tool_name: str,
    arguments: object,
    workspace: Path,
    path: str,
    guard_home: Path,
    config_path: str,
    source_scope: str,
) -> Any | None:
    """``_package_request_artifact`` for the call the record carries.

    ``path`` is the relay's own search path, bound here so the resident
    resolves the command's manager exactly as it did for the decision.
    """

    from ..proxy.runtime_mcp import _command_argument  # pyright: ignore[reportPrivateUsage]
    from ..runtime.package_intent_common import build_package_request_artifact
    from ..runtime.package_intent_parser import extract_package_intent_request

    intent = extract_package_intent_request(
        tool_name,
        arguments,
        action_envelope_command=_command_argument(arguments),
        workspace=workspace,
        guard_home=guard_home,
        environment={"PATH": path},
    )
    if intent is None:
        return None
    return build_package_request_artifact(
        harness=harness,
        intent=intent,
        config_path=config_path,
        source_scope=source_scope,
    )
