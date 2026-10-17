from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest

from codex_plugin_scanner.guard import mcp_tool_calls, native_mcp_tool_call_identity
from codex_plugin_scanner.guard.daemon import hook_direct_evidence_drain, mcp_relay_package_evidence_drain
from codex_plugin_scanner.guard.daemon.mcp_relay_package_evidence_drain import (
    is_mcp_relay_package_evidence,
    record_mcp_relay_package_evidence,
)
from codex_plugin_scanner.guard.proxy import runtime_mcp_projection
from codex_plugin_scanner.guard.runtime import package_intent_common, package_intent_parser

COMMAND = "npm install left-pad"
CONFIG_PATH = "/work/.codex/config.toml"
SOURCE_SCOPE = "project"
ARTIFACT_ID = "package-request:npm:left-pad"
ARTIFACT = SimpleNamespace(harness="codex", config_path=CONFIG_PATH, source_scope=SOURCE_SCOPE)
TOKEN = "guard-approval-context:v1:token"
WORKSPACE = "package-request-workspace:v2:abc"
EVIDENCE = [{"kind": "package_execution_context", "portable": True}]
PATH = "/usr/bin:/bin"


def _decision(action: str = "allow", **fields: object) -> dict[str, object]:
    return {
        "action": action,
        "source": "policy",
        "signals": ["tool signal"],
        "summary": "summary",
        "risk_categories": ["network"],
        "normalization_reason_code": None,
        "original_action": None,
        "approval_reuse_status": None,
        "approval_reuse_reason_code": None,
        "current_action": None,
        "saved_action": None,
        "pending_approval_reuse_decision": None,
        "approval_reuse_claim_disposition": None,
        "post_claim_revalidated": False,
        "post_claim_authority": None,
        **fields,
    }


def _package(**fields: object) -> dict[str, object]:
    return {
        "artifact_id": ARTIFACT_ID,
        "artifact_hash": TOKEN,
        "workspace": "/work",
        "path": PATH,
        "evaluation": {"decision": "warn"},
        "evidence": EVIDENCE,
        "signals": ["left-pad has an advisory"],
        "policy_workspace": WORKSPACE,
        **fields,
    }


def _record(**fields: object) -> dict[str, object]:
    return {
        "kind": "mcp_package_call",
        "harness": "codex",
        "outcome": "forward",
        "decision_source": "policy-warn",
        "policy_action": "warn",
        "tool_name": "shell",
        "params": {"name": "shell", "arguments": {"command": COMMAND, "cwd": "/work"}},
        "arguments": {"format": "mapping", "entries": [["cwd", "/work"], ["command", COMMAND]]},
        "identity": {"wire": True},
        "decision": _decision(),
        "package": _package(),
        **fields,
    }


class _Projector:
    projected: ClassVar[list[tuple[str, object, object]]] = []

    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home

    def project(self, tool_name: str, params: object, artifact: object = None) -> SimpleNamespace:
        _Projector.projected.append((tool_name, params, artifact))
        # The proxy projects a call with its artifact to carry risk
        # categories; a projection without one carries none.
        return SimpleNamespace(
            safe_arguments={"safe": True, "artifact": artifact is not None},
            risk_categories=["supply-chain"] if artifact is not None else [],
        )


@pytest.fixture
def parsed() -> dict[str, Any]:
    """What the drain asks the package parser and artifact builder for."""

    return {"extract": [], "build": [], "intent": SimpleNamespace(package_manager="npm"), "artifact_id": ARTIFACT_ID}


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch, parsed: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    recorded: list[tuple[str, dict[str, Any]]] = []
    _Projector.projected = []

    def decode(payload: object, *, expect_hash: bool, token: bool) -> SimpleNamespace:
        assert payload == {"wire": True} and expect_hash and token
        return SimpleNamespace(artifact=ARTIFACT, artifact_hash=TOKEN)

    def extract(tool_name: object, arguments: object, **kwargs: object) -> object:
        parsed["extract"].append((tool_name, arguments, kwargs))
        return parsed["intent"]

    def build(*, harness: str, intent: object, config_path: str, source_scope: str) -> SimpleNamespace:
        parsed["build"].append((harness, intent, config_path, source_scope))
        return SimpleNamespace(artifact_id=parsed["artifact_id"], artifact_type="package_request")

    monkeypatch.setattr(native_mcp_tool_call_identity, "_decode", decode)
    monkeypatch.setattr(package_intent_parser, "extract_package_intent_request", extract)
    monkeypatch.setattr(package_intent_common, "build_package_request_artifact", build)
    monkeypatch.setattr(runtime_mcp_projection, "McpCallProjector", _Projector)
    monkeypatch.setattr(mcp_tool_calls, "allow_tool_call", lambda **kwargs: recorded.append(("allow", kwargs)))
    monkeypatch.setattr(mcp_tool_calls, "block_tool_call", lambda **kwargs: recorded.append(("block", kwargs)))
    return recorded


def test_only_a_package_record_is_this_drains() -> None:
    assert is_mcp_relay_package_evidence(_record())
    assert not is_mcp_relay_package_evidence({"kind": "mcp_tool_call"})
    assert not is_mcp_relay_package_evidence("mcp_package_call")


def test_a_forward_is_recorded_against_the_package_artifact(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any]
) -> None:
    store = object()

    assert record_mcp_relay_package_evidence(store, tmp_path, _record())

    [(kind, recorded)] = calls
    assert kind == "allow"
    assert recorded["store"] is store
    # The package request, rebuilt from the same parser input the resident read.
    assert recorded["artifact"].artifact_id == ARTIFACT_ID
    assert recorded["artifact_hash"] == TOKEN
    assert recorded["remember"] is False
    assert recorded["decision_source"] == "policy-warn"
    assert recorded["policy_action"] == "warn"
    assert recorded["policy_workspace"] == WORKSPACE
    # The evaluation's reason signals, not the tool decision's.
    assert recorded["signals"] == ("left-pad has an advisory",)
    assert recorded["arguments"] == {"safe": True, "artifact": False}
    assert recorded["additional_scanner_evidence"] == tuple(EVIDENCE)
    # `_record_package_forward` passes no risk categories of its own.
    assert "risk_categories" not in recorded
    [(tool_name, params, artifact)] = _Projector.projected
    assert tool_name == "shell" and artifact is None
    # The host's own key order, which the proxy projects the call from.
    assert isinstance(params, dict) and list(params["arguments"]) == ["cwd", "command"]


def test_the_artifact_is_rebuilt_from_the_recorded_call(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any]
) -> None:
    assert record_mcp_relay_package_evidence(object(), tmp_path, _record())

    [(tool_name, arguments, kwargs)] = parsed["extract"]
    assert tool_name == "shell"
    # The arguments in host key order, and the command the action envelope names.
    assert list(arguments) == ["cwd", "command"]
    assert kwargs["action_envelope_command"] == COMMAND
    # The workspace and search path the resident decided against, not the
    # daemon's own.
    assert kwargs["workspace"] == Path("/work")
    assert kwargs["environment"] == {"PATH": PATH}
    assert kwargs["guard_home"] == tmp_path
    # The scope and config path the call's own identity states.
    assert parsed["build"] == [("codex", parsed["intent"], CONFIG_PATH, SOURCE_SCOPE)]


def test_a_call_the_relay_decided_without_a_search_path_is_still_recorded(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any]
) -> None:
    """The gate states an absent ``PATH`` as ``None``; the rebuild binds it empty."""

    assert record_mcp_relay_package_evidence(object(), tmp_path, _record(package=_package(path=None)))

    [(_, _, kwargs)] = parsed["extract"]
    assert kwargs["environment"] == {"PATH": ""}
    [(kind, _)] = calls
    assert kind == "allow"


def test_a_search_path_the_relay_could_not_have_written_is_dropped(tmp_path: Path) -> None:
    """An empty string is neither a path nor the absence the gate states."""

    assert not record_mcp_relay_package_evidence(object(), tmp_path, _record(package=_package(path="")))


def test_a_block_is_recorded_without_a_policy_workspace(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any]
) -> None:
    package = _package()
    del package["policy_workspace"]
    record = _record(
        outcome="block",
        decision_source="policy-block",
        policy_action="block",
        decision=_decision("block"),
        package=package,
    )

    assert record_mcp_relay_package_evidence(object(), tmp_path, record)

    [(kind, recorded)] = calls
    assert kind == "block"
    assert recorded["artifact"].artifact_id == ARTIFACT_ID
    assert recorded["policy_action"] == "block"
    # `_record_package_block` binds no workspace and no risk categories.
    assert "policy_workspace" not in recorded
    assert "risk_categories" not in recorded


def _reviewed(**fields: object) -> dict[str, object]:
    """The record a request blocked in place under `safe-alternative` leaves."""

    package = _package()
    del package["policy_workspace"]
    queued: dict[str, object] = {
        "outcome": "block",
        "decision_source": "policy-safe-alternative",
        "policy_action": "review",
        "decision": _decision("review"),
        "package": package,
        "review": {"redaction_level": "partial"},
    }
    queued.update(fields)
    return _record(**queued)


@pytest.fixture
def reviews(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """The inbox rows the drain writes after a queued request's receipt."""

    written: list[dict[str, Any]] = []

    def record_review(
        store: object,
        artifact: object,
        artifact_hash: str,
        projection: object,
        signals: object,
        **kwargs: object,
    ) -> None:
        written.append(
            {
                "store": store,
                "artifact": artifact,
                "artifact_hash": artifact_hash,
                "projection": projection,
                "signals": signals,
                **kwargs,
            }
        )

    monkeypatch.setattr(mcp_relay_package_evidence_drain, "_record_unprompted_review", record_review)
    return written


def test_a_queued_request_is_blocked_in_place_and_left_in_the_inbox(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    reviews: list[dict[str, Any]],
) -> None:
    store = object()

    assert record_mcp_relay_package_evidence(store, tmp_path, _reviewed())

    [(kind, recorded)] = calls
    assert kind == "block"
    assert recorded["decision_source"] == "policy-safe-alternative"
    assert recorded["policy_action"] == "review"
    # `_queue_approval_center_response` projects the call with its artifact,
    # so the receipt carries that projection's risk categories and arguments.
    assert recorded["risk_categories"] == ["supply-chain"]
    assert recorded["arguments"] == {"safe": True, "artifact": True}
    assert "policy_workspace" not in recorded
    # The inbox row follows the receipt, written with the bound level.
    [review] = reviews
    assert review["store"] is store
    assert review["artifact"] is recorded["artifact"]
    assert review["artifact_hash"] == TOKEN
    assert review["signals"] == ("left-pad has an advisory",)
    assert review["policy_action"] == "review"
    assert review["redaction_level"] == "partial"
    assert review["scanner_evidence"] == recorded["additional_scanner_evidence"]
    assert review["projection"].risk_categories == ["supply-chain"]


@pytest.mark.parametrize(
    "fields",
    [
        # A level the proxy never writes a receipt with.
        {"review": {"redaction_level": "summary"}},
        {"review": {"redaction_level": None}},
        # The row is the level alone.
        {"review": {"redaction_level": "full", "extra": True}},
        {"review": "full"},
        # Only the safe-alternative branch leaves a row.
        {"decision_source": "policy-block", "policy_action": "block"},
    ],
)
def test_an_inbox_row_the_proxy_could_not_have_written_is_dropped(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    reviews: list[dict[str, Any]],
    fields: dict[str, object],
) -> None:
    assert not record_mcp_relay_package_evidence(object(), tmp_path, _reviewed(**fields))
    assert calls == [] and reviews == []


def test_a_receipt_recorded_without_its_inbox_row_is_dropped(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    reviews: list[dict[str, Any]],
) -> None:
    # A block the lane answers through the queue route always leaves the row.
    record = _reviewed()
    del record["review"]

    assert not record_mcp_relay_package_evidence(object(), tmp_path, record)
    # A forward never leaves one.
    assert not record_mcp_relay_package_evidence(object(), tmp_path, _record(review={"redaction_level": "full"}))
    assert calls == [] and reviews == []


def test_a_record_naming_another_package_is_dropped(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any]
) -> None:
    # The resident decided one package request; a parse of these arguments that
    # rebuilds a different one is not that request's receipt.
    parsed["artifact_id"] = "package-request:npm:right-pad"

    assert not record_mcp_relay_package_evidence(object(), tmp_path, _record())
    assert calls == []


def test_a_call_that_is_no_package_request_is_dropped(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any]
) -> None:
    parsed["intent"] = None

    assert not record_mcp_relay_package_evidence(object(), tmp_path, _record())
    assert calls == []


def test_arguments_the_record_does_not_match_are_dropped(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any]
) -> None:
    # `_ordered_params` rejects host entries that are not the params' arguments.
    record = _record(arguments={"format": "mapping", "entries": [["command", "npm install right-pad"]]})

    assert not record_mcp_relay_package_evidence(object(), tmp_path, record)
    assert calls == []


@pytest.mark.parametrize(
    "fields",
    [
        # A forward under an action the proxy never forwards on.
        {"policy_action": "block", "decision_source": "policy-block"},
        # A forward whose source is not the action it was permitted under.
        {"decision_source": "policy-allow"},
        # A block that still claims a forwarding action.
        {"outcome": "block", "decision_source": "policy-block", "policy_action": "warn"},
        # A block recorded under a source the package lane never answers with.
        {"outcome": "block", "decision_source": "inline-denied", "policy_action": "block"},
        # An outcome the lane never answers with.
        {"outcome": "deferred"},
        # A harness the relay does not serve.
        {"harness": "claude-code"},
        # Params that are not the call the record names.
        {"params": {"name": "install", "arguments": {"command": COMMAND}}},
        # A record that is not the shape the resident writes.
        {"kind": "mcp_tool_call"},
        {"remember": True},
    ],
)
def test_a_record_the_proxy_could_not_have_written_is_dropped(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any], fields: dict[str, object]
) -> None:
    assert not record_mcp_relay_package_evidence(object(), tmp_path, _record(**fields))
    assert calls == []


@pytest.mark.parametrize(
    "mutate",
    [
        # A forward must state the workspace its allow is bound to.
        lambda package: package.pop("policy_workspace"),
        # The package half is the receipt's facts, all of them.
        lambda package: package.pop("artifact_hash"),
        lambda package: package.update(extra=True),
        lambda package: package.update(signals=[{"message": "not a string"}]),
        lambda package: package.update(evidence=[["not", "a", "mapping"]]),
        lambda package: package.update(evaluation="warn"),
        lambda package: package.update(workspace="  "),
        lambda package: package.update(path="  "),
        lambda package: package.pop("path"),
    ],
)
def test_a_package_half_the_proxy_could_not_have_written_is_dropped(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any], mutate: Any
) -> None:
    package = _package()
    mutate(package)

    assert not record_mcp_relay_package_evidence(object(), tmp_path, _record(package=package))
    assert calls == []


def test_the_direct_drain_routes_a_package_record_here(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], parsed: dict[str, Any]
) -> None:
    store = object()
    host = SimpleNamespace(store=store, guard_home=tmp_path)

    assert hook_direct_evidence_drain.record_direct_hook_evidence(host, _record())

    [(kind, recorded)] = calls
    assert kind == "allow"
    assert recorded["store"] is store
    assert recorded["artifact"].artifact_id == ARTIFACT_ID


NOTICE = {
    "request_id": "req-1",
    "harness": "codex",
    "workspace": "/work",
    "approval_url": "http://127.0.0.1:8787/requests/req-1",
    "artifact_name": "left-pad",
    "risk_headline": "left-pad has a known advisory",
    "trigger_summary": "npm install left-pad",
}


def _asked(**fields: object) -> dict[str, object]:
    """The record a request the `ask` mode queued leaves."""

    package = _package()
    del package["policy_workspace"]
    queued: dict[str, object] = {
        "outcome": "block",
        "decision_source": "approval-center-pending",
        "policy_action": "review",
        "decision": _decision("review"),
        "package": package,
        "approval": {
            "approval_center_url": "http://127.0.0.1:8787",
            "review_url": "http://127.0.0.1:8787/requests/req-1",
            "request_id": "req-1",
            "workspace": "/work",
            "notices": [dict(NOTICE)],
        },
    }
    queued.update(fields)
    return _record(**queued)


@pytest.fixture
def surfaces(monkeypatch: pytest.MonkeyPatch) -> list[tuple[object, Path, str, object]]:
    """The approval surfaces the drain raises after a queued request's receipt."""

    raised: list[tuple[object, Path, str, object]] = []
    monkeypatch.setattr(
        mcp_relay_package_evidence_drain,
        "_raise_approval_surface",
        lambda store, guard_home, harness, queued: raised.append((store, guard_home, harness, queued)),
    )
    return raised


def test_a_request_the_ask_mode_queued_is_blocked_on_its_approval_row(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    reviews: list[dict[str, Any]],
    surfaces: list[tuple[object, Path, str, object]],
) -> None:
    store = object()

    assert record_mcp_relay_package_evidence(store, tmp_path, _asked())

    [(kind, recorded)] = calls
    assert kind == "block"
    assert recorded["decision_source"] == "approval-center-pending"
    assert recorded["policy_action"] == "review"
    assert recorded["signals"] == ("left-pad has an advisory",)
    # The `ask` branch projects the call without its artifact, so the receipt
    # carries no risk categories and the plain safe arguments.
    assert "risk_categories" not in recorded
    assert recorded["arguments"] == {"safe": True, "artifact": False}
    assert "policy_workspace" not in recorded
    # It writes no inbox row; the approval request answers the call instead.
    assert reviews == []
    [(raised_store, guard_home, harness, queued)] = surfaces
    assert raised_store is store
    assert guard_home == tmp_path
    assert harness == "codex"
    assert queued.request_id == "req-1"
    assert queued.review_url == "http://127.0.0.1:8787/requests/req-1"
    assert queued.notices == (NOTICE,)


@pytest.mark.parametrize(
    "fields",
    [
        # A surface the proxy never raises.
        {"approval": {**_asked()["approval"], "request_id": " "}},  # pyright: ignore[reportGeneralTypeIssues]
        {"approval": {**_asked()["approval"], "notices": [{"request_id": "req-1"}]}},  # pyright: ignore[reportGeneralTypeIssues]
        {"approval": {"request_id": "req-1"}},
        # Only the ask branch is recorded as pending.
        {"decision_source": "policy-safe-alternative"},
        # The two queue routes are never both taken.
        {"review": {"redaction_level": "partial"}},
    ],
)
def test_an_approval_surface_the_proxy_could_not_have_raised_is_dropped(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    reviews: list[dict[str, Any]],
    surfaces: list[tuple[object, Path, str, object]],
    fields: dict[str, object],
) -> None:
    assert not record_mcp_relay_package_evidence(object(), tmp_path, _asked(**fields))
    assert calls == [] and reviews == [] and surfaces == []


def test_a_forwarded_call_never_carries_an_approval_surface(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    surfaces: list[tuple[object, Path, str, object]],
) -> None:
    assert not record_mcp_relay_package_evidence(object(), tmp_path, _record(approval=_asked()["approval"]))
    # And a pending block with no row to point at is not that branch's receipt.
    record = _asked()
    del record["approval"]
    assert not record_mcp_relay_package_evidence(object(), tmp_path, record)
    assert calls == [] and surfaces == []


def _observed(**fields: object) -> dict[str, object]:
    """The record a forward under `mode = "observe"` leaves."""

    forwarded: dict[str, object] = {
        "decision_source": "policy-observe",
        "policy_action": "allow",
        "observed": {"notices": [dict(NOTICE)]},
    }
    forwarded.update(fields)
    return _record(**forwarded)


@pytest.fixture
def notices(monkeypatch: pytest.MonkeyPatch) -> list[tuple[object, object]]:
    """The desktop notices the drain raises for the observed requests."""

    raised: list[tuple[object, object]] = []
    monkeypatch.setattr(
        mcp_relay_package_evidence_drain,
        "_raise_notices",
        lambda store, queued: raised.append((store, queued)),
    )
    return raised


def test_an_observed_forward_is_recorded_under_the_mode_it_forwarded_in(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    notices: list[tuple[object, object]],
    surfaces: list[tuple[object, Path, str, object]],
) -> None:
    store = object()

    assert record_mcp_relay_package_evidence(store, tmp_path, _observed())

    [(kind, recorded)] = calls
    # The call reached the child, so the receipt is the ordinary allow receipt
    # under the action it was executed with, named by the mode rather than it.
    assert kind == "allow"
    assert recorded["decision_source"] == "policy-observe"
    assert recorded["policy_action"] == "allow"
    assert recorded["policy_workspace"] == WORKSPACE
    assert recorded["remember"] is False
    # The observed rows raise their desktop notices and nothing else: nothing
    # is waiting on an answer, so there is no approval center to open.
    assert notices == [(store, (NOTICE,))]
    assert surfaces == []


def test_an_observation_that_queued_no_row_still_names_the_mode(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    notices: list[tuple[object, object]],
) -> None:
    # Both policies permitted the call, so the observation has nothing to
    # raise; the receipt is still the one this mode writes.
    assert record_mcp_relay_package_evidence(object(), tmp_path, _observed(observed={"notices": []}))

    [(kind, recorded)] = calls
    assert kind == "allow" and recorded["decision_source"] == "policy-observe"
    assert notices == []


@pytest.mark.parametrize(
    "fields",
    [
        # A notice the proxy never raises.
        {"observed": {"notices": [{"request_id": "req-1"}]}},
        {"observed": {"notices": "none"}},
        # The observation is the notices alone.
        {"observed": {"notices": [], "extra": True}},
        {"observed": []},
        # The mode's source belongs to an observed forward and to nothing else.
        {"observed": None},
        # A block is never the receipt an observed forward leaves.
        {"outcome": "block", "policy_action": "block", "decision": _decision("block")},
        # The forward is never queued on a row of its own.
        {"review": {"redaction_level": "partial"}},
        {"approval": _asked()["approval"]},
    ],
)
def test_an_observation_the_proxy_could_not_have_written_is_dropped(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    notices: list[tuple[object, object]],
    reviews: list[dict[str, Any]],
    surfaces: list[tuple[object, Path, str, object]],
    fields: dict[str, object],
) -> None:
    assert not record_mcp_relay_package_evidence(object(), tmp_path, _observed(**fields))
    assert calls == [] and notices == [] and reviews == [] and surfaces == []


def test_an_enforced_forward_is_never_recorded_under_the_observed_mode(
    tmp_path: Path,
    calls: list[tuple[str, dict[str, Any]]],
    parsed: dict[str, Any],
    notices: list[tuple[object, object]],
) -> None:
    # The source names the mode only where the observation it left is stated.
    record = _observed()
    del record["observed"]
    assert not record_mcp_relay_package_evidence(object(), tmp_path, record)
    # And an observed forward recorded under its action is the enforced one.
    assert not record_mcp_relay_package_evidence(object(), tmp_path, _observed(decision_source="policy-allow"))
    assert calls == [] and notices == []
