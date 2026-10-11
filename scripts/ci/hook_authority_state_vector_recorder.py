"""Record parity vectors for the signed Claude/Cursor hook authority state.

Run against the Python implementation that preceded the resident
``hook_authority_state`` op (base commit ``d3bf08bbca``)::

    python scripts/ci/hook_authority_state_vector_recorder.py

Each scenario replays a sequence of actions on a fresh store: raw writes that
plant or tamper state, and ``op`` actions that call one retired helper of
``commands_support_hook_state``. After every ``op`` the recorder snapshots the
``sync_state`` rows and the ``guard_events`` audit rows, so the Rust replay can
assert the result and every persisted side effect byte for byte. The integrity
key and the clock are pinned; the approval code is passed to the resident, so no
randomness is recorded.

The output is gzip JSON at
``rust/crates/guard-runtime/tests/fixtures/hook_authority_state_vectors.json.gz``.
"""

from __future__ import annotations

import base64
import gzip
import json
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from codex_plugin_scanner.guard.cli import commands_support_hook_state as hook_state  # noqa: E402
from codex_plugin_scanner.guard.models import GuardArtifact  # noqa: E402
from codex_plugin_scanner.guard.store import GuardStore  # noqa: E402

OUT = ROOT / "rust/crates/guard-runtime/tests/fixtures/hook_authority_state_vectors.json.gz"
KEY = bytes(range(32))
KEY_ID = "vector-key-1"
OTHER_KEY_ID = "vector-key-2"
T0 = "2026-10-11T12:00:00.250000+00:00"
T1 = "2026-10-11T12:10:00.500000+00:00"
T2 = "2026-10-11T12:30:00.250000+00:00"
T3 = "2026-10-11T12:30:00.250001+00:00"
T4 = "2026-10-11T12:40:00.000000+00:00"
CODE = "0123456789ab"


def key_b64() -> str:
    return base64.urlsafe_b64encode(KEY).rstrip(b"=").decode("ascii")


class Clock:
    now = T0


def snapshot(store: GuardStore) -> dict[str, object]:
    with sqlite3.connect(store.path) as connection:
        sync = {
            row[0]: {"payload_json": row[1], "updated_at": row[2]}
            for row in connection.execute("select state_key, payload_json, updated_at from sync_state order by 1")
        }
        events = [
            {"event_name": row[0], "payload": json.loads(row[1]), "occurred_at": row[2]}
            for row in connection.execute(
                "select event_name, payload_json, occurred_at from guard_events order by 1, 2"
            )
        ]
    parsed = {}
    for key, row in sync.items():
        try:
            payload = json.loads(row["payload_json"])
        except ValueError:
            payload = {"__raw__": row["payload_json"]}
        parsed[key] = {"payload": payload, "updated_at": row["updated_at"]}
    return {"sync_state": parsed, "events": events}


def artifact_from(spec: dict[str, object]) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=str(spec["artifact_id"]),
        name=str(spec.get("name", "Bash")),
        harness=str(spec.get("harness", "claude-code")),
        artifact_type=str(spec.get("artifact_type", "tool_action_request")),
        source_scope=str(spec.get("source_scope", "project")),
        config_path=str(spec.get("config_path", "/workspace/.env")),
        command=spec.get("command"),  # type: ignore[arg-type]
        metadata=dict(spec.get("metadata", {})),  # type: ignore[arg-type]
    )


def call_op(store: GuardStore, op: str, args: dict[str, object]) -> object:
    """Call the retired helper that ``op`` replaces and return its JSON result."""

    now = str(args["now"])
    Clock.now = now
    if op == "claude_record_notice":
        spied: list[dict[str, object]] = []
        original = hook_state._store_signed_hook_authority_payload

        def spy(store, *, state_key, payload, purpose, now):
            spied.append(dict(payload))
            return original(store, state_key=state_key, payload=payload, purpose=purpose, now=now)

        hook_state._store_signed_hook_authority_payload = spy
        try:
            payload: dict[str, object] = {"session_id": args["session_id"]}
            if args.get("tool_name") is not None:
                payload["tool_name"] = args["tool_name"]
            hook_state._record_claude_permission_notice(
                store=store,
                payload=payload,
                reason=str(args["reason"]),
                artifact=artifact_from(args["artifact"]),  # type: ignore[arg-type]
                artifact_hash=str(args["artifact_hash"]),
            )
        finally:
            hook_state._store_signed_hook_authority_payload = original
        # The resident receives the notice body the Python wrapper assembles;
        # it is the unsigned payload the first signed store saw.
        return {"notice_payload": spied[0] if spied else None}
    if op == "claude_load_notice":
        payload = {"session_id": args["session_id"]}
        if args.get("tool_name") is not None:
            payload["tool_name"] = args["tool_name"]
        return {"notice": hook_state._load_verified_claude_permission_notice(store, payload)}
    if op == "claude_mark_prompt_seen":
        hook_state._mark_claude_pending_permission_prompt_seen(
            store=store,
            payload={"session_id": args["session_id"]},
            notice={
                "artifact_id": args["artifact_id"],
                "artifact_hash": args["artifact_hash"],
                "command": args["command"],
            },
        )
        return {}
    if op == "claude_load_single_pending":
        pair = hook_state._load_single_claude_pending_permission(store, {"session_id": args["session_id"]})
        if pair is None:
            return {"pending_key": None, "pending": None}
        return {"pending_key": pair[0], "pending": pair[1]}
    if op == "claude_load_pending":
        return {
            "pending": hook_state._load_verified_claude_pending_permission(
                store,
                session_id=str(args["session_id"]),
                pending_key=str(args["pending_key"]),
                expected_artifact_id=args.get("expected_artifact_id"),  # type: ignore[arg-type]
                expected_artifact_hash=args.get("expected_artifact_hash"),  # type: ignore[arg-type]
                expected_command=args.get("expected_command"),  # type: ignore[arg-type]
                now=now,
            )
        }
    if op == "claude_remove_pending":
        hook_state._remove_claude_pending_permission(
            store, session_id=str(args["session_id"]), pending_key=str(args["pending_key"])
        )
        return {}
    if op == "claude_load_index":
        return {
            "pending_keys": hook_state._load_claude_pending_permission_index(
                store, session_id=str(args["session_id"]), now=now
            )
        }
    if op == "cursor_load_index":
        return {
            "pending_keys": hook_state._load_cursor_pending_shell_index(
                store, conversation_id=str(args["conversation_id"]), now=now
            )
        }
    if op == "cursor_store_index":
        return {
            "stored": hook_state._store_cursor_pending_shell_index(
                store,
                conversation_id=str(args["conversation_id"]),
                pending_keys=list(args["pending_keys"]),  # type: ignore[arg-type]
                now=now,
            )
        }
    if op == "cursor_append_key":
        return {
            "stored": hook_state._append_cursor_pending_shell_key(
                store,
                conversation_id=str(args["conversation_id"]),
                pending_key=str(args["pending_key"]),
                now=now,
            )
        }
    if op == "cursor_store_pending_state":
        return {
            "stored": hook_state._store_cursor_pending_shell_state(
                store,
                conversation_id=str(args["conversation_id"]),
                command=str(args["command"]),
                payload=dict(args["payload"]),  # type: ignore[arg-type]
                now=now,
            )
        }
    if op == "cursor_load_pending_state":
        return {
            "pending": hook_state._load_verified_cursor_pending_shell_state(
                store,
                conversation_id=str(args["conversation_id"]),
                command=str(args["command"]),
                state_key=args.get("state_key"),  # type: ignore[arg-type]
                now=now,
            )
        }
    if op == "cursor_record_allow":
        return {
            "stored": hook_state._record_cursor_native_shell_allow_state(
                store=store,
                conversation_id=str(args["conversation_id"]),
                command=str(args["command"]),
                artifact=artifact_from(args["artifact"]),  # type: ignore[arg-type]
                artifact_hash=str(args["artifact_hash"]),
                now=now,
            )
        }
    if op == "cursor_load_allowance":
        return {
            "allowance": hook_state._load_cursor_native_shell_allowance(
                store, {"conversation_id": args["conversation_id"], "command": args["command"], "tool_name": "Shell"}
            )
        }
    if op == "state_is_fresh":
        return {
            "fresh": hook_state._hook_authority_state_is_fresh(
                {"saved_at": args["saved_at"]} if args["saved_at"] is not None else {},
                now=now,
                max_age_seconds=int(args["max_age_seconds"]),  # type: ignore[arg-type]
            )
        }
    raise SystemExit(f"unknown op {op}")


def wire_args(op: str, args: dict[str, object], result: object) -> dict[str, object]:
    """The fields the resident op receives for ``op`` (what the Python wrapper sends)."""

    from codex_plugin_scanner.guard.adapters.cursor_native_approval import normalize_cursor_shell_command

    wire = {name: value for name, value in args.items() if name not in {"artifact", "reason"}}
    if op == "claude_record_notice":
        wire = {"session_id": args["session_id"], "now": args["now"], "payload": dict(result["notice_payload"])}  # type: ignore[index]
        if args.get("tool_name") is not None:
            wire["tool_name"] = args["tool_name"]
    elif op == "cursor_store_pending_state":
        wire = {
            "conversation_id": args["conversation_id"],
            "state_key": hook_state._cursor_pending_shell_state_key(str(args["conversation_id"]), str(args["command"])),
            "payload": args["payload"],
            "now": args["now"],
        }
    elif op == "cursor_load_pending_state":
        normalized = normalize_cursor_shell_command(str(args["command"]))
        expected = hook_state._cursor_pending_shell_state_key(str(args["conversation_id"]), normalized)
        wire = {
            "conversation_id": args["conversation_id"],
            "command": normalized,
            "state_key": args.get("state_key") or expected,
            "expected_key": expected,
            "now": args["now"],
        }
    elif op == "cursor_record_allow":
        normalized = normalize_cursor_shell_command(str(args["command"]))
        artifact = args["artifact"]
        wire = {
            "conversation_id": args["conversation_id"],
            "state_key": hook_state._cursor_native_shell_allow_state_key(str(args["conversation_id"]), normalized),
            "command": normalized,
            "artifact_id": artifact["artifact_id"],  # type: ignore[index]
            "artifact_hash": args["artifact_hash"],
            "artifact_name": artifact["name"],  # type: ignore[index]
            "now": args["now"],
        }
    elif op == "cursor_load_allowance":
        command = hook_state._cursor_shell_command_from_payload({"command": args["command"]})
        wire = {
            "conversation_id": args["conversation_id"],
            "command": command,
            "state_key": hook_state._cursor_native_shell_allow_state_key(str(args["conversation_id"]), str(command)),
            "now": args["now"],
        }
    return wire


def pending_keys(session_id: str, *artifact_ids: str) -> list[str]:
    return [hook_state._claude_pending_permission_state_key(session_id, artifact_id) for artifact_id in artifact_ids]


def record(scenario_name: str, actions: list[dict[str, object]]) -> dict[str, object]:
    recorded: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory() as tmp:
        store = GuardStore(Path(tmp) / "home")
        key_state = {"present": True, "key_id": KEY_ID}

        def material(*, create: bool) -> tuple[bytes | None, str | None]:
            if not key_state["present"]:
                return None, None
            return KEY, str(key_state["key_id"])

        store._policy_integrity_secret_material = material  # type: ignore[method-assign]
        hook_state._now = lambda: Clock.now  # type: ignore[assignment]
        for action in actions:
            kind = action["do"]
            if kind == "raw_set":
                store.set_sync_payload(str(action["key"]), action["payload"], str(action.get("now", T0)))  # type: ignore[arg-type]
                recorded.append(dict(action))
            elif kind == "raw_set_text":
                with sqlite3.connect(store.path) as connection:
                    connection.execute(
                        "insert or replace into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)",
                        (action["key"], action["text"], action.get("now", T0)),
                    )
                recorded.append(dict(action))
            elif kind == "raw_copy":
                value = store.get_sync_payload(str(action["from"]))
                store.set_sync_payload(str(action["to"]), value, T0)  # type: ignore[arg-type]
                recorded.append({"do": "raw_set", "key": action["to"], "payload": value})
            elif kind == "raw_mutate":
                value = store.get_sync_payload(str(action["key"]))
                assert isinstance(value, dict)
                for name, replacement in dict(action["set"]).items():  # type: ignore[arg-type]
                    value[name] = replacement
                for name in action.get("drop", []):  # type: ignore[union-attr]
                    value.pop(name, None)
                store.set_sync_payload(str(action["key"]), value, T0)
                recorded.append({"do": "raw_set", "key": action["key"], "payload": value})
            elif kind == "raw_delete":
                store.delete_sync_payload(str(action["key"]))
                recorded.append(dict(action))
            elif kind == "key":
                key_state["present"] = bool(action["present"])
                key_state["key_id"] = action.get("key_id", KEY_ID)
                recorded.append(dict(action))
            elif kind == "op":
                args = dict(action["args"])  # type: ignore[arg-type]
                result = call_op(store, str(action["op"]), args)
                recorded.append(
                    {
                        "do": "op",
                        "op": action["op"],
                        "args": wire_args(str(action["op"]), args, result),
                        "key_present": key_state["present"],
                        "key_id": key_state["key_id"],
                        "result": result,
                        "after": snapshot(store),
                    }
                )
            else:
                raise SystemExit(f"unknown action {kind}")
    return {"name": scenario_name, "actions": recorded}


def claude_artifact(artifact_id: str = "claude-code:runtime:file-read:.env", **extra: object) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "name": "Read",
        "artifact_type": "file_read_request",
        "config_path": "/workspace/.env",
        **extra,
    }


def record_notice(session: str = "s1", tool: str | None = "Read", artifact: dict | None = None, now: str = T0) -> dict:
    args: dict[str, object] = {
        "session_id": session,
        "reason": "HOL Guard intercepted Claude's attempt to read .env.",
        "artifact": artifact or claude_artifact(),
        "artifact_hash": "hash-authentic",
        "now": now,
    }
    if tool is not None:
        args["tool_name"] = tool
    return {"do": "op", "op": "claude_record_notice", "args": args}


def op(name: str, now: str = T0, **args: object) -> dict[str, object]:
    return {"do": "op", "op": name, "args": {"now": now, **args}}


def claude_scenarios() -> list[tuple[str, list[dict[str, object]]]]:
    art = "claude-code:runtime:file-read:.env"
    pk = pending_keys("s1", art)[0]
    cmd = "artifact:" + art
    scenarios: list[tuple[str, list[dict[str, object]]]] = []

    def notice_flow(tool_name: str | None, load_tool: str | None, label: str) -> None:
        scenarios.append(
            (
                label,
                [
                    record_notice(tool=tool_name),
                    op("claude_load_index", session_id="s1"),
                    op("claude_load_notice", T1, session_id="s1", tool_name=load_tool),
                    op(
                        "claude_load_pending",
                        T1,
                        session_id="s1",
                        pending_key=pk,
                        expected_artifact_id=art,
                        expected_artifact_hash="hash-authentic",
                        expected_command=cmd,
                    ),
                    op("claude_load_pending", T1, session_id="s1", pending_key=pk),
                    op("claude_load_single_pending", T1, session_id="s1"),
                    op(
                        "claude_mark_prompt_seen",
                        T1,
                        session_id="s1",
                        artifact_id=art,
                        artifact_hash="hash-authentic",
                        command=cmd,
                    ),
                    op("claude_load_single_pending", T1, session_id="s1"),
                    op("claude_remove_pending", T1, session_id="s1", pending_key=pk),
                    op("claude_load_index", T1, session_id="s1"),
                    op("claude_load_single_pending", T1, session_id="s1"),
                ],
            )
        )

    notice_flow("Read", "Read", "claude_notice_flow_tool_match")
    notice_flow("Read", "Write", "claude_notice_flow_tool_mismatch_no_fallback")
    notice_flow(None, "Read", "claude_notice_flow_session_fallback")
    notice_flow(None, None, "claude_notice_flow_no_tool")

    metadata_artifact = claude_artifact(
        command="git push --force",
        metadata={"raw_command_text": "git push --force origin main", "wrapper_chain": ["bash", "", 3, "sudo"]},
    )
    scenarios.append(
        (
            "claude_notice_command_binding_and_wrapper_chain",
            [
                record_notice(artifact=metadata_artifact),
                op("claude_load_notice", T1, session_id="s1", tool_name="Read"),
                record_notice(artifact=claude_artifact(artifact_id="a2", command="ls -la"), tool="Bash"),
                op("claude_load_notice", T1, session_id="s1", tool_name="Bash"),
                record_notice(
                    artifact=claude_artifact(artifact_id="a3", metadata={"wrapper_chain": "oops"}), tool="Edit"
                ),
                op("claude_load_notice", T1, session_id="s1", tool_name="Edit"),
                op("claude_load_index", T1, session_id="s1"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_two_pending_prompt_seen_selection",
            [
                record_notice(artifact=claude_artifact("a1")),
                record_notice(artifact=claude_artifact("a2"), tool="Bash"),
                op("claude_load_single_pending", T1, session_id="s1"),
                op("claude_load_index", T1, session_id="s1"),
                op(
                    "claude_mark_prompt_seen",
                    T1,
                    session_id="s1",
                    artifact_id="a2",
                    artifact_hash="hash-authentic",
                    command="artifact:a2",
                ),
                op("claude_load_single_pending", T1, session_id="s1"),
                op(
                    "claude_mark_prompt_seen",
                    T1,
                    session_id="s1",
                    artifact_id="a1",
                    artifact_hash="hash-authentic",
                    command="artifact:a1",
                ),
                op("claude_load_single_pending", T1, session_id="s1"),
                op("claude_remove_pending", T1, session_id="s1", pending_key=pending_keys("s1", "a1")[0]),
                op("claude_load_index", T1, session_id="s1"),
                op("claude_load_single_pending", T1, session_id="s1"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_mark_prompt_seen_mismatch_and_missing",
            [
                record_notice(),
                op(
                    "claude_mark_prompt_seen", T1, session_id="s1", artifact_id=art, artifact_hash="forged", command=cmd
                ),
                op("claude_load_index", T1, session_id="s1"),
                op(
                    "claude_mark_prompt_seen",
                    T1,
                    session_id="s1",
                    artifact_id="missing",
                    artifact_hash="x",
                    command="y",
                ),
                op("claude_load_single_pending", T1, session_id="s1"),
            ],
        )
    )
    expiry_flow: list[dict[str, object]] = [
        record_notice(),
        op("claude_load_notice", T2, session_id="s1", tool_name="Read"),
        op("claude_load_notice", T3, session_id="s1", tool_name="Read"),
        op("claude_load_index", T3, session_id="s1"),
        op("claude_load_single_pending", T3, session_id="s1"),
    ]
    scenarios.append(("claude_expiry_boundary", expiry_flow))
    scenarios.append(
        (
            "claude_pending_expired_after_notice_kept",
            [
                record_notice(),
                {"do": "raw_mutate", "key": pk, "set": {}},
                op("claude_load_pending", T3, session_id="s1", pending_key=pk),
                op("claude_load_notice", T3, session_id="s1", tool_name="Read"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_tampered_pending_hash",
            [
                record_notice(),
                {"do": "raw_mutate", "key": pk, "set": {"artifact_hash": "hash-forged"}},
                op("claude_load_notice", T1, session_id="s1", tool_name="Read"),
                op("claude_load_pending", T1, session_id="s1", pending_key=pk),
                op("claude_load_index", T1, session_id="s1"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_tampered_notice",
            [
                record_notice(),
                {"do": "raw_mutate", "key": "claude_permission_notice:s1:Read", "set": {"approval_code": "forged"}},
                op("claude_load_notice", T1, session_id="s1", tool_name="Read"),
                op("claude_load_pending", T1, session_id="s1", pending_key=pk),
            ],
        )
    )
    scenarios.append(
        (
            "claude_missing_integrity_and_json_garbage",
            [
                record_notice(),
                {"do": "raw_mutate", "key": pk, "set": {}, "drop": ["integrity"]},
                op("claude_load_pending", T1, session_id="s1", pending_key=pk),
                {"do": "raw_set_text", "key": "claude_pending_permissions:s1", "text": "{not json"},
                op("claude_load_index", T1, session_id="s1"),
                {"do": "raw_set", "key": "claude_pending_permissions:s1", "payload": ["list"]},
                op("claude_load_index", T1, session_id="s1"),
                {"do": "raw_set_text", "key": "claude_pending_permissions:s1", "text": "42"},
                op("claude_load_index", T1, session_id="s1"),
                {"do": "raw_set", "key": "claude_pending_permissions:s1", "payload": {"integrity": "nope"}},
                op("claude_load_index", T1, session_id="s1"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_state_key_mismatch_copy",
            [
                record_notice(),
                {"do": "raw_copy", "from": pk, "to": pending_keys("s1", "other")[0]},
                op("claude_load_pending", T1, session_id="s1", pending_key=pending_keys("s1", "other")[0]),
                {
                    "do": "raw_copy",
                    "from": "claude_permission_notice:s1:Read",
                    "to": "claude_permission_notice:s2:Read",
                },
                op("claude_load_notice", T1, session_id="s2", tool_name="Read"),
                op("claude_load_notice", T1, session_id="s1", tool_name="Read"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_session_context_mismatch",
            [
                record_notice(),
                op("claude_load_pending", T1, session_id="s2", pending_key=pk),
                op("claude_load_pending", T1, session_id="s1", pending_key=pk, expected_artifact_id="different"),
                op("claude_load_pending", T1, session_id="s1", pending_key=pk, expected_artifact_hash="different"),
                op("claude_load_pending", T1, session_id="s1", pending_key=pk, expected_command="different"),
                op("claude_load_notice", T1, session_id="s1", tool_name="Read"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_index_context_mismatch",
            [
                record_notice(),
                {"do": "raw_mutate", "key": "claude_pending_permissions:s1", "set": {"session_id": "s9"}},
                op("claude_load_index", T1, session_id="s1"),
                record_notice(),
                {
                    "do": "raw_mutate",
                    "key": "claude_pending_permissions:s1",
                    "set": {"pending_keys": ["claude_pending_permission:other:x"]},
                },
                op("claude_load_index", T1, session_id="s1"),
                {
                    "do": "raw_set",
                    "key": "claude_pending_permissions:s1",
                    "payload": {"session_id": "s1", "pending_keys": "x", "saved_at": T0},
                },
                op("claude_load_index", T1, session_id="s1"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_index_duplicates_deduped_and_notice_pending_removed",
            [
                record_notice(),
                record_notice(),
                op("claude_load_index", T1, session_id="s1"),
                {"do": "raw_delete", "key": pk},
                op("claude_load_notice", T1, session_id="s1", tool_name="Read"),
                op("claude_load_index", T1, session_id="s1"),
                op("claude_load_single_pending", T1, session_id="s1"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_pending_with_one_tampered_one_valid",
            [
                record_notice(artifact=claude_artifact("a1")),
                record_notice(artifact=claude_artifact("a2"), tool="Bash"),
                {"do": "raw_mutate", "key": pending_keys("s1", "a1")[0], "set": {"artifact_hash": "forged"}},
                op("claude_load_single_pending", T1, session_id="s1"),
                op("claude_load_index", T1, session_id="s1"),
            ],
        )
    )
    scenarios.append(
        (
            "claude_key_unavailable",
            [
                {"do": "key", "present": False},
                record_notice(),
                op("claude_load_index", T1, session_id="s1"),
                {"do": "key", "present": True},
                record_notice(),
                {"do": "key", "present": False},
                op("claude_load_notice", T1, session_id="s1", tool_name="Read"),
                op("claude_load_pending", T1, session_id="s1", pending_key=pk),
                {"do": "key", "present": True, "key_id": OTHER_KEY_ID},
                op("claude_load_notice", T1, session_id="s1", tool_name="Read"),
                {"do": "key", "present": True},
                record_notice(),
                op(
                    "claude_mark_prompt_seen",
                    T4,
                    session_id="s1",
                    artifact_id=art,
                    artifact_hash="hash-authentic",
                    command=cmd,
                ),
            ],
        )
    )
    scenarios.append(
        (
            "claude_remove_pending_leaves_other_and_drops_empty_index",
            [
                record_notice(artifact=claude_artifact("a1")),
                record_notice(artifact=claude_artifact("a2"), tool="Bash"),
                op("claude_remove_pending", T1, session_id="s1", pending_key=pending_keys("s1", "a2")[0]),
                op("claude_load_index", T1, session_id="s1"),
                op("claude_remove_pending", T1, session_id="s1", pending_key=pending_keys("s1", "a1")[0]),
                op("claude_load_index", T1, session_id="s1"),
                op("claude_remove_pending", T1, session_id="s1", pending_key=pending_keys("s1", "absent")[0]),
            ],
        )
    )
    scenarios.append(
        (
            "claude_unicode_artifact_fields",
            [
                record_notice(artifact=claude_artifact("claude-code:runtime:é:.env", name="Lire ☃")),
                op("claude_load_notice", T1, session_id="s1", tool_name="Read"),
            ],
        )
    )
    return scenarios


def cursor_scenarios() -> list[tuple[str, list[dict[str, object]]]]:
    conv = "conv-1"
    command = "git push origin main"
    state_key = hook_state._cursor_pending_shell_state_key(conv, command)
    allow_key = hook_state._cursor_native_shell_allow_state_key(conv, command)
    artifact = {"artifact_id": "cursor:runtime:shell:1", "name": "Shell", "harness": "cursor"}

    def pending_payload(**extra: object) -> dict[str, object]:
        return {
            "conversation_id": conv,
            "saved_at": T0,
            "artifact_id": "cursor:runtime:shell:1",
            "artifact_hash": "hash-authentic",
            "command": command,
            **extra,
        }

    scenarios: list[tuple[str, list[dict[str, object]]]] = []
    scenarios.append(
        (
            "cursor_pending_lifecycle",
            [
                op("cursor_store_pending_state", conversation_id=conv, command=command, payload=pending_payload()),
                op("cursor_append_key", conversation_id=conv, pending_key=state_key),
                op("cursor_append_key", conversation_id=conv, pending_key=state_key),
                op("cursor_load_index", T1, conversation_id=conv),
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command),
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command, state_key=state_key),
                op(
                    "cursor_store_pending_state",
                    T1,
                    conversation_id=conv,
                    command=command,
                    payload=pending_payload(approval_request_ids=["r1"], saved_at=T1),
                ),
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command),
                op("cursor_store_index", T1, conversation_id=conv, pending_keys=[state_key, state_key]),
                op("cursor_load_index", T1, conversation_id=conv),
                op("cursor_store_index", T1, conversation_id=conv, pending_keys=[]),
                op("cursor_load_index", T1, conversation_id=conv),
            ],
        )
    )
    scenarios.append(
        (
            "cursor_pending_context_mismatch_and_expiry",
            [
                op("cursor_store_pending_state", conversation_id=conv, command=command, payload=pending_payload()),
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command, state_key=state_key + "x"),
                op(
                    "cursor_store_pending_state",
                    conversation_id=conv,
                    command=command,
                    payload=pending_payload(conversation_id="conv-2"),
                ),
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command),
                op(
                    "cursor_store_pending_state",
                    conversation_id=conv,
                    command=command,
                    payload=pending_payload(command="other"),
                ),
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command),
                op(
                    "cursor_store_pending_state",
                    conversation_id=conv,
                    command=command,
                    payload=pending_payload(artifact_hash=None),
                ),
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command),
                op("cursor_store_pending_state", conversation_id=conv, command=command, payload=pending_payload()),
                op("cursor_load_pending_state", T3, conversation_id=conv, command=command),
                op("cursor_load_pending_state", T3, conversation_id=conv, command=command),
            ],
        )
    )
    scenarios.append(
        (
            "cursor_pending_tampered_and_unsigned",
            [
                op("cursor_store_pending_state", conversation_id=conv, command=command, payload=pending_payload()),
                {"do": "raw_mutate", "key": state_key, "set": {"artifact_hash": "forged"}},
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command),
                {"do": "raw_set", "key": state_key, "payload": pending_payload()},
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command),
                {"do": "raw_set_text", "key": state_key, "text": "not json at all"},
                op("cursor_load_pending_state", T1, conversation_id=conv, command=command),
            ],
        )
    )
    scenarios.append(
        (
            "cursor_index_integrity",
            [
                op("cursor_append_key", conversation_id=conv, pending_key=state_key),
                {
                    "do": "raw_mutate",
                    "key": "cursor_pending_shells:conv-1",
                    "set": {"pending_keys": ["cursor_pending_shell:other:abc"]},
                },
                op("cursor_load_index", T1, conversation_id=conv),
                op("cursor_append_key", conversation_id=conv, pending_key=state_key),
                {"do": "raw_mutate", "key": "cursor_pending_shells:conv-1", "set": {"conversation_id": "conv-9"}},
                op("cursor_load_index", T1, conversation_id=conv),
                op("cursor_append_key", conversation_id=conv, pending_key=state_key),
                op("cursor_load_index", T3, conversation_id=conv),
                {"do": "key", "present": False},
                op("cursor_append_key", conversation_id=conv, pending_key=state_key),
                op("cursor_store_index", conversation_id=conv, pending_keys=[state_key]),
                op("cursor_store_pending_state", conversation_id=conv, command=command, payload=pending_payload()),
            ],
        )
    )
    scenarios.append(
        (
            "cursor_allowance_lifecycle",
            [
                op(
                    "cursor_record_allow",
                    conversation_id=conv,
                    command=command,
                    artifact=artifact,
                    artifact_hash="hash-authentic",
                ),
                op("cursor_load_allowance", T1, conversation_id=conv, command=command),
                op("cursor_load_allowance", T1, conversation_id=conv, command="git status"),
                op("cursor_load_allowance", T1, conversation_id="conv-2", command=command),
                op("cursor_load_allowance", T2, conversation_id=conv, command=command),
                op("cursor_load_allowance", T3, conversation_id=conv, command=command),
                op("cursor_load_allowance", T3, conversation_id=conv, command=command),
            ],
        )
    )
    scenarios.append(
        (
            "cursor_allowance_tampering",
            [
                op(
                    "cursor_record_allow",
                    conversation_id=conv,
                    command=command,
                    artifact=artifact,
                    artifact_hash="hash-authentic",
                ),
                {"do": "raw_mutate", "key": allow_key, "set": {"artifact_hash": "forged"}},
                op("cursor_load_allowance", T1, conversation_id=conv, command=command),
                op(
                    "cursor_record_allow",
                    conversation_id=conv,
                    command=command,
                    artifact=artifact,
                    artifact_hash="hash-authentic",
                ),
                {"do": "raw_mutate", "key": allow_key, "set": {}, "drop": ["integrity"]},
                op("cursor_load_allowance", T1, conversation_id=conv, command=command),
                op(
                    "cursor_record_allow",
                    conversation_id=conv,
                    command=command,
                    artifact=artifact,
                    artifact_hash="hash-authentic",
                ),
                {"do": "raw_mutate", "key": allow_key, "set": {"action": "deny"}},
                op("cursor_load_allowance", T1, conversation_id=conv, command=command),
                {"do": "raw_set_text", "key": allow_key, "text": "{broken"},
                op("cursor_load_allowance", T1, conversation_id=conv, command=command),
                {"do": "raw_set", "key": allow_key, "payload": ["x"]},
                op("cursor_load_allowance", T1, conversation_id=conv, command=command),
                op(
                    "cursor_record_allow",
                    conversation_id=conv,
                    command=command,
                    artifact=artifact,
                    artifact_hash="hash-authentic",
                ),
                {
                    "do": "raw_copy",
                    "from": allow_key,
                    "to": hook_state._cursor_native_shell_allow_state_key(conv, "git status"),
                },
                op("cursor_load_allowance", T1, conversation_id=conv, command="git status"),
                {"do": "key", "present": False},
                op("cursor_load_allowance", T1, conversation_id=conv, command=command),
                op(
                    "cursor_record_allow",
                    conversation_id=conv,
                    command=command,
                    artifact=artifact,
                    artifact_hash="hash-authentic",
                ),
            ],
        )
    )
    scenarios.append(
        (
            "cursor_allowance_wrong_key_id_and_unsigned",
            [
                op(
                    "cursor_record_allow",
                    conversation_id=conv,
                    command=command,
                    artifact=artifact,
                    artifact_hash="hash-authentic",
                ),
                {"do": "key", "present": True, "key_id": OTHER_KEY_ID},
                op("cursor_load_allowance", T1, conversation_id=conv, command=command),
                {"do": "key", "present": True},
                {
                    "do": "raw_set",
                    "key": allow_key,
                    "payload": {
                        "state_key": allow_key,
                        "conversation_id": conv,
                        "saved_at": T0,
                        "action": "allow",
                        "command": command,
                        "artifact_id": "a",
                    },
                },
                op("cursor_load_allowance", T1, conversation_id=conv, command=command),
            ],
        )
    )
    scenarios.append(
        (
            "cursor_lean_ctx_command_keys",
            [
                op(
                    "cursor_record_allow",
                    conversation_id=conv,
                    command="lean-ctx -c 'git status'",
                    artifact=artifact,
                    artifact_hash="h",
                ),
                op("cursor_load_allowance", T1, conversation_id=conv, command="git status"),
                op("cursor_load_allowance", T1, conversation_id=conv, command="lean-ctx -c 'git status'"),
            ],
        )
    )
    return scenarios


def freshness_scenario() -> tuple[str, list[dict[str, object]]]:
    cases = [
        ("2026-10-11T12:00:00+00:00", "2026-10-11T12:30:00+00:00", 1800),
        ("2026-10-11T12:00:00+00:00", "2026-10-11T12:30:00.000001+00:00", 1800),
        ("2026-10-11T12:00:00Z", "2026-10-11T12:00:00Z", 1800),
        ("2026-10-11T12:00:00", "2026-10-11T12:10:00+00:00", 1800),
        ("2026-10-11T12:00:00+00:00", "2026-10-11T12:10:00", 1800),
        ("2026-10-11T14:00:00+02:00", "2026-10-11T12:10:00+00:00", 1800),
        ("2026-10-11T12:10:00+00:00", "2026-10-11T12:00:00+00:00", 1800),
        ("2026-10-11T12:00:00.123456+00:00", "2026-10-11T12:00:00.123455+00:00", 1800),
        ("not-a-time", "2026-10-11T12:00:00+00:00", 1800),
        ("", "2026-10-11T12:00:00+00:00", 1800),
        (None, "2026-10-11T12:00:00+00:00", 1800),
        ("2026-10-11T12:00:00+00:00", "garbage", 1800),
        ("2026-10-11T12:00:00+00:00", "2026-10-11T12:00:00+00:00", 0),
        ("2026-10-11T12:00:00.5+00:00", "2026-10-11T12:00:01+00:00", 0),
        ("2026-10-11 12:00:00+00:00", "2026-10-11 12:00:30+00:00", 60),
    ]
    actions = [
        {"do": "op", "op": "state_is_fresh", "args": {"saved_at": saved, "now": now, "max_age_seconds": max_age}}
        for saved, now, max_age in cases
    ]
    return "freshness_matrix", actions


def main() -> None:
    import secrets

    secrets.token_hex = lambda _count=0: CODE  # type: ignore[assignment]
    scenarios = claude_scenarios() + cursor_scenarios() + [freshness_scenario()]
    document = {
        "recorded_from": "d3bf08bbca",
        "key_b64": key_b64(),
        "key_id": KEY_ID,
        "approval_code": CODE,
        "scenarios": [record(name, actions) for name, actions in scenarios],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with gzip.GzipFile(OUT, "wb", mtime=0) as handle:
        handle.write(json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    print(f"recorded {len(document['scenarios'])} scenarios -> {OUT}")


if __name__ == "__main__":
    main()
