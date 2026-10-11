"""Record portable policy behavior from pinned pre-cutover Python sources."""

from __future__ import annotations

import argparse
import copy
import hashlib
import itertools
import json
import subprocess
import sys
import types
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "codex_plugin_scanner.guard"
OWNERS = (
    "policy_document",
    "policy_document_compile",
    "policy_document_diff",
    "policy_document_business_bounds",
    "policy_document_yaml",
)
DIFF_FIELDS = (
    "additions",
    "modifications",
    "removals",
    "impacted_scopes",
    "impacted_harnesses",
    "impacted_artifact_families",
    "conflict_warnings",
    "broadened_rules",
    "narrowed_rules",
    "unchanged_rules",
    "effective_action_changes",
    "broad_relaxing_changes",
)


def original_sources(base: str):
    sys.path.insert(0, str(ROOT / "src"))
    __import__(PACKAGE)
    modules, hashes = {}, {}
    for owner in OWNERS:
        path = f"src/codex_plugin_scanner/guard/{owner}.py"
        raw = subprocess.check_output(["git", "show", f"{base}:{path}"], cwd=ROOT)
        hashes[path] = hashlib.sha256(raw).hexdigest()
        name = f"{PACKAGE}.{owner}"
        module = types.ModuleType(name)
        module.__file__ = str(ROOT / path)
        module.__package__ = PACKAGE
        sys.modules[name] = module
        exec(compile(raw, path, "exec"), module.__dict__)
        modules[owner] = module
    return modules, hashes


def rule(rule_id="rule-1", effect="block", enabled=True, match=None, lifetime=None):
    return {
        "id": rule_id,
        "enabled": enabled,
        "effect": effect,
        "match": {} if match is None else match,
        "lifetime": {"mode": "permanent", "expiresAt": None} if lifetime is None else lifetime,
        "provenance": {"source": "local", "createdAt": "2026-01-01T00:00:00Z"},
    }


def document(rules=(), defaults=None):
    return {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {"id": "parity-policy", "name": "Parity policy", "revision": 0},
        "spec": {"defaults": {"mode": "prompt"} if defaults is None else defaults, "rules": list(rules)},
    }


def record(base: str):
    modules, hashes = original_sources(base)
    dto = modules["policy_document"]
    compiler = modules["policy_document_compile"]
    diff = modules["policy_document_diff"]
    vectors = []

    def add(query, body):
        try:
            if query == "compile":
                doc = dto.GuardPolicyDocument.from_mapping(body["document"])
                result = [asdict(item) for item in compiler.compile_policy_document(doc)]
            elif query == "rows":
                result = compiler.build_policy_document_from_rows(**body).to_mapping()
            elif query == "diff":
                before = dto.GuardPolicyDocument.from_mapping(body["baseline"])
                after = dto.GuardPolicyDocument.from_mapping(body["candidate"])
                values = (*diff._semantic_policy_diff(before, after), *diff._classify_rule_changes(before, after))
                result = dict(zip(DIFF_FIELDS, values, strict=True))
            elif query == "from_mapping":
                result_dto = getattr(dto, body["class_name"]).from_mapping(body["value"])
                result = {"dto": asdict(result_dto), "mapping": result_dto.to_mapping()}
            elif query == "canonical":
                result = dto.canonical_json_bytes(body["value"]).decode("utf-8")
            elif query == "bounds":
                result = modules["policy_document_business_bounds"].oversized_business_selector_path(body["value"])
            elif query in {"validate_ids", "validate_timestamps"}:
                loader = modules["policy_document_yaml"]
                result = None
                try:
                    getattr(loader, "_validate_rule_ids" if query == "validate_ids" else "_validate_timestamps")(
                        body["value"]
                    )
                except loader.PolicyDocumentError as exc:
                    result = {"code": exc.diagnostics[0].code, "path": exc.diagnostics[0].path}
            else:
                raise AssertionError(query)
            expected = {"ok": result}
        except (KeyError, TypeError, ValueError) as exc:
            expected = {"error": {"type": type(exc).__name__, "message": str(exc)}}
            if hasattr(exc, "code"):
                expected["error"].update(code=exc.code, rule_id=exc.rule_id)
        vectors.append({"query": query, "body": body, "expected": expected})

    matches = (
        {},
        {"harnesses": ["pi"]},
        {"harnesses": ["pi", "omp"]},
        {"artifacts": ["file-read:x"]},
        {"artifacts": ["pkg/x", "pkg/y"]},
        {"tools": ["shell"]},
        {"workspaces": ["project"]},
        {"publishers": ["publisher"]},
    )
    for previous, current, before_enabled, after_enabled, match in itertools.product(
        ("allow", "block", "review", "ignore"),
        ("allow", "block", "review", "ignore"),
        (False, True),
        (False, True),
        matches,
    ):
        add(
            "diff",
            {
                "baseline": document([rule(effect=previous, enabled=before_enabled, match=match)]),
                "candidate": document([rule(effect=current, enabled=after_enabled)]),
            },
        )
    lifetimes = (
        {"mode": "permanent", "expiresAt": None},
        {"mode": "until", "expiresAt": "2026-01-01T00:00:00.1Z"},
        {"mode": "until", "expiresAt": "2026-01-01T00:00:00.100000001Z"},
        {"mode": "until", "expiresAt": "2027-01-01T00:00:00Z"},
        {"mode": "until", "expiresAt": None},
        {"mode": "session", "expiresAt": None},
    )
    for previous, current in itertools.product(lifetimes, repeat=2):
        add("diff", {"baseline": document([rule(lifetime=previous)]), "candidate": document([rule(lifetime=current)])})
    for previous, current in itertools.product(
        ("allow", "block", "observe", "warn", "prompt", "enforce", "require-reapproval"),
        repeat=2,
    ):
        add(
            "diff",
            {"baseline": document(defaults={"mode": previous}), "candidate": document(defaults={"mode": current})},
        )
    for before, after in (
        ([], [rule(effect="allow")]),
        ([rule()], []),
        ([rule("a")], [rule("b")]),
        ([], [rule("a"), rule("b", effect="allow")]),
        ([], [rule("z"), rule("z", effect="ignore")]),
    ):
        add("diff", {"baseline": document(before), "candidate": document(after)})

    for effect, enabled, match, lifetime in itertools.product(
        ("allow", "block", "review", "ignore"),
        (False, True),
        matches,
        lifetimes[:4],
    ):
        add("compile", {"document": document([rule(effect=effect, enabled=enabled, match=match, lifetime=lifetime)])})
    for selector in (None, [], [""], [None], [1], ["pi", "pi"], "pi"):
        for key in ("artifacts", "harnesses", "publishers", "workspaces", "tools", "paths"):
            add("compile", {"document": document([rule(match={key: selector})])})
    for match in (
        {"tools": ["SHELL"]},
        {"tools": ["unknown"]},
        {"tools": ["shell"], "publishers": []},
        {"artifacts": ["pkg:x"], "tools": ["shell"]},
        {"x-note": {"retained": True}},
        {"paths": ["x"]},
    ):
        add("compile", {"document": document([rule(match=match)])})
    for preferred in ("artifact", "workspace", "publisher", "harness", "global", "unknown", None):
        for match in matches:
            value = rule(match=match)
            value["x-hol-local"] = {"scope": preferred, "artifactHash": "fixture-hash"}
            add("compile", {"document": document([value])})
    for budgets in ({}, None, [], {"limit": 1}):
        value = document([rule()])
        value["spec"]["budgets"] = budgets
        add("compile", {"document": value})
    commands = {
        "combinator": "all",
        "conditions": [{"field": "command", "operator": "exact", "value": "echo hello", "caseSensitive": False}],
    }
    add("compile", {"document": document([rule(match={"commands": commands})])})
    add("compile", {"document": document([rule(match={"harnesses": ["pi"] * 101, "artifacts": ["pkg:x"] * 100})])})

    base_row = {
        "action": "block",
        "harness": "pi",
        "scope": "harness",
        "decision_id": 2,
        "updated_at": "2026-01-01T00:00:00+00:00",
        "source": "local",
    }
    for key, values in {
        "decision_id": (-1, 0, True, None, "2", 2**80, -(2**80)),
        "policy_rule_id": ("valid-id", "", "bad id", None),
        "action": ("allow", "review", None),
        "source": ("cloud-sync", "policy-yaml-import", "builder", None),
        "updated_at": (None, "bad", "2026-02-31T00:00:00Z", "2026-01-01T00:00:00.123456789Z"),
        "expires_at": (None, "bad", "2027-01-01T00:00:00+00:00", 1),
        "workspace": ("project", "", None),
        "owner": ("fixture-owner", "", None),
        "reason": ("fixture reason", "", None),
        "artifact_id": ("pkg:x", "", None),
    }.items():
        for value, provenance in itertools.product(values, (False, True)):
            row = {**base_row, key: value}
            add("rows", {"rows": [row], "include_provenance": provenance})
    for identifier in ("local-policy", "", "bad id", "a" * 129):
        add("rows", {"rows": [base_row], "document_id": identifier})
    add(
        "rows",
        {
            "rows": [base_row, {**base_row, "harness": "omp", "decision_id": 1}],
            "name": "N" * 300,
            "revision": 3,
            "include_provenance": True,
        },
    )
    add("rows", {"rows": [{**base_row, "decision_id": identifier} for identifier in [2**80, -1, 0, -(2**80), 1]]})

    examples = {
        "PolicyMetadata": document()["metadata"],
        "PolicyDefaults": {"mode": "prompt"},
        "PolicyMatch": {"harnesses": ["pi"]},
        "PolicyLifetime": rule()["lifetime"],
        "PolicyProvenance": rule()["provenance"],
        "PolicyRule": rule(),
        "GuardPolicyDocument": document([rule()]),
    }
    for class_name, value in examples.items():
        add("from_mapping", {"class_name": class_name, "value": value})
        for key in value:
            for mutation in (None, True, 1, "", [], {}):
                changed = copy.deepcopy(value)
                changed[key] = mutation
                add("from_mapping", {"class_name": class_name, "value": changed})
        changed = copy.deepcopy(value)
        changed["x-extension"] = {"astral": "\U0001f600", "integer": 2**80}
        add("from_mapping", {"class_name": class_name, "value": changed})
    for value in (
        None,
        False,
        True,
        0,
        -1,
        2**80,
        "text",
        [],
        {},
        1.0,
        {"\ue000": 1, "\U0001f600": 2},
        {"newline": "a\nb", "nul": "\x00"},
        {"z": [True, None, -2], "a": {"unicode": "é"}},
    ):
        add("canonical", {"value": value})
    for length, text in itertools.product((0, 65_500, 65_520, 65_536, 65_540), ("a", "é", "\n", "\\")):
        add("bounds", {"value": document([rule(match={"business": {"label": text * length}})])})
    for value in ({}, {"spec": None}, {"spec": {"rules": None}}, {"spec": {"rules": [None, {"match": None}]}}):
        add("bounds", {"value": value})
    for values in (
        [],
        [rule("a")],
        [rule("a"), rule("b")],
        [rule("a"), rule("a")],
        [None, {"id": 1}, rule("a"), rule("a")],
    ):
        add("validate_ids", {"value": document(values)})
    for stamp in (
        None,
        1,
        "bad",
        "2026-02-31T00:00:00Z",
        "2024-02-29T00:00:00Z",
        "2026-02-29T00:00:00Z",
        "0000-01-01T00:00:00Z",
        "9999-12-31T23:59:59Z",
        "2026-01-01T24:00:00Z",
        "2026-01-01T00:60:00Z",
        "2026-01-01T00:00:60Z",
        "2026-01-01T00:00:00.123456789Z",
        "2026-01-01",
    ):
        value = rule(lifetime={"mode": "until", "expiresAt": stamp})
        add("validate_timestamps", {"value": document([value])})
        value = rule()
        value["provenance"]["createdAt"] = stamp
        add("validate_timestamps", {"value": document([value])})
    return {"schema": "guard-policy-document-parity.v1", "base": base, "source_sha256": hashes, "vectors": vectors}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = record(args.base)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Recorded {len(payload['vectors'])} original policy-document outcomes")


if __name__ == "__main__":
    main()
