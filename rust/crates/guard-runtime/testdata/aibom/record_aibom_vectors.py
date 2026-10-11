#!/usr/bin/env python3
"""Record AIBOM discovery vectors from the ORIGINAL Python implementation.

Run against a checkout that still holds `guard/aibom_detection.py` and
`guard/codex_skill_config.py` (the base of the commit that introduced the
native `aibom_*` runner-authority kinds), never from Rust output:

    cd <base-worktree>
    HOL_GUARD_NATIVE_BINARY=<release hol-guard-runtime> \\
        PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each case materializes a fixture tree under a temporary root (files, modes,
symlinks), runs the original Python function against it and records the
expected result. Paths are written with `<ROOT>` for the fixture root and
`<MID>` for the marketplace id (a digest of the marketplace file path, which
depends on the root); the Rust replay substitutes both before comparing.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path

from codex_plugin_scanner.guard import aibom_detection as old
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection

if not hasattr(old, "discover_shared_workspace_aibom_artifacts") or hasattr(old, "NativeAibomError"):
    sys.exit("refusing to record: the original Python AIBOM implementation is gone")
if not os.environ.get("HOL_GUARD_NATIVE_BINARY"):
    sys.exit("set HOL_GUARD_NATIVE_BINARY to a release hol-guard-runtime")


def provision_native(guard_home: Path) -> None:
    """Point every native transport at one keyed resident, as the test harness does."""

    from codex_plugin_scanner.guard import native_context
    from codex_plugin_scanner.guard.native_policy_snapshot import provision_native_policy_verifier_key
    from codex_plugin_scanner.guard.runtime import approval_context

    (guard_home / "native-runtime").mkdir(mode=0o700, parents=True)
    provision_native_policy_verifier_key(guard_home, b"\x07" * 32)
    os.environ.update(
        {
            "HOL_GUARD_NATIVE": "force",
            "HOL_GUARD_TEST_MODE": "1",
            "HOL_GUARD_NATIVE_DIAGNOSTIC": "1",
            "HOL_GUARD_RESIDENT_TEST_SEAMS": "1",
        }
    )
    native_context.context_digest_guard_home = lambda: guard_home
    approval_context._context_digest_guard_home = lambda _home: guard_home
    probe = native_context.native_context_digest(
        "launch_argv_digest", {"argv": ["guard-context-warmup"]}, guard_home=guard_home
    )
    if not probe:
        sys.exit("native resident did not answer; refusing to record unbound hashes")


SKILL = "---\nname: {name}\n---\n{name} instructions.\n"
MARKETPLACE = ".agents/plugins/marketplace.json"
HOME = "home"
WORK = "work"
USER_HOME = "uhome"


def file(path: str, text: str = "content\n", mode: int = 0o644) -> dict:
    return {"path": path, "text": text, "mode": mode}


def link(path: str, target: str) -> dict:
    return {"path": path, "target": target}


def skill(base: str, name: str, *extra: dict) -> list[dict]:
    return [file(f"{base}/{name}/SKILL.md", SKILL.format(name=name)), *extra]


def artifact_dict(artifact: GuardArtifact) -> dict:
    payload = dataclasses.asdict(artifact)
    payload.pop("runtime_private_metadata", None)
    payload["args"] = list(artifact.args)
    return payload


def materialize(root: Path, case: dict) -> None:
    (root / WORK).mkdir(parents=True)
    (root / HOME).mkdir()
    (root / USER_HOME).mkdir()
    for entry in case.get("files", []):
        target = root / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(entry["text"], encoding="utf-8")
        target.chmod(entry["mode"])
    for entry in case.get("symlinks", []):
        target = root / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(entry["target"].replace("<ROOT>", str(root)))
    for relative in case.get("dirs", []):
        (root / relative).mkdir(parents=True, exist_ok=True)


def scrub(value: object, root: Path, marketplace_ids: dict[str, str]) -> object:
    text = json.dumps(value, ensure_ascii=False)
    for identifier, placeholder in marketplace_ids.items():
        text = text.replace(identifier, placeholder)
    return json.loads(text.replace(str(root), "<ROOT>"))


def marketplace_ids(root: Path, case: dict) -> dict[str, str]:
    found: dict[str, str] = {}
    for relative in case.get("marketplace_files", []):
        resolved = (root / relative).resolve()
        found[hashlib.sha256(str(resolved).encode()).hexdigest()[:12]] = "<MID>"
    return found


def run_case(case: dict) -> dict:
    root = Path(tempfile.mkdtemp(prefix="aibom-vec-")).resolve()
    saved_home = os.environ.get("HOME")
    os.environ["HOME"] = str(root / USER_HOME)
    try:
        materialize(root, case)
        home_dir, workspace_dir = root / HOME, root / WORK
        kind = case["kind"]
        args = {"harness": case["harness"]}
        outcome: dict
        try:
            if kind == "workspace_artifacts":
                args["workspace_dir"] = "<ROOT>/" + WORK
                found = old.discover_shared_workspace_aibom_artifacts(
                    case["harness"], home_dir=home_dir, workspace_dir=workspace_dir
                )
                outcome = {"artifacts": [artifact_dict(item) for item in found]}
            elif kind == "merge_plan":
                existing = [GuardArtifact(**item) for item in resolve_existing(case["existing"], root)]
                detection = HarnessDetection(
                    harness=case["harness"],
                    installed=True,
                    command_available=True,
                    config_paths=tuple(case.get("config_paths", [])),
                    artifacts=tuple(existing),
                    warnings=(),
                )
                merged = old.extend_detection_with_workspace_aibom(
                    detection, home_dir=home_dir, workspace_dir=workspace_dir
                )
                args["workspace_dir"] = "<ROOT>/" + WORK
                args["existing"] = [
                    {key: item.get(key) for key in ("artifact_id", "artifact_type", "harness", "config_path")}
                    for item in case["existing"]
                ]
                outcome = {
                    "artifacts": [artifact_dict(item) for item in merged.artifacts],
                    "config_paths": list(merged.config_paths),
                }
            elif kind == "codex_skills":
                args["home_dir"] = "<ROOT>/" + HOME
                args["workspace_dir"] = None if case.get("no_workspace") else "<ROOT>/" + WORK
                args["user_home"] = "<ROOT>/" + USER_HOME
                found = old.discover_codex_skill_artifacts(
                    case["harness"],
                    home_dir=home_dir,
                    workspace_dir=None if case.get("no_workspace") else workspace_dir,
                )
                outcome = {"artifacts": [artifact_dict(item) for item in found]}
            else:
                raise AssertionError(kind)
        except ValueError:
            outcome = {"refused": True}
        record = {
            "name": case["name"],
            "kind": kind,
            "files": case.get("files", []),
            "symlinks": case.get("symlinks", []),
            "dirs": case.get("dirs", []),
            "marketplace_files": case.get("marketplace_files", []),
            "args": args,
        }
        if kind == "merge_plan":
            record["existing_artifacts"] = scrub(
                [artifact_dict(GuardArtifact(**item)) for item in resolve_existing(case["existing"], root)],
                root,
                {},
            )
            record["existing_config_paths"] = case.get("config_paths", [])
        record.update(scrub(outcome, root, marketplace_ids(root, case)))
        return record
    finally:
        if saved_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = saved_home
        shutil.rmtree(root, ignore_errors=True)


def resolve_existing(existing: list[dict], root: Path) -> list[dict]:
    return [
        {
            "artifact_id": item["artifact_id"],
            "name": item.get("name", "existing"),
            "harness": item["harness"],
            "artifact_type": item["artifact_type"],
            "source_scope": item.get("source_scope", "project"),
            "config_path": (item["config_path"] or "").replace("<ROOT>", str(root)),
            "metadata": item.get("metadata", {}),
        }
        for item in existing
    ]


def mcp_case(name: str, metadata: dict, *, command=None, args=(), url=None, transport=None, env=None, headers=None):
    enriched = old.enrich_mcp_server_metadata(
        dict(metadata),
        command=command,
        args=tuple(args),
        url=url,
        transport=transport,
        configured_environment=env,
        configured_headers=headers,
    )
    owned = ("env_keys", "headers_keys", "env_values_hash", "header_values_hash", "content_hash", "versionInfo")
    raw_env = env if env is not None else metadata.get("env")
    raw_headers = headers if headers is not None else metadata.get("headers")
    return {
        "name": name,
        "kind": "mcp_metadata",
        "args": {
            "command": command,
            "args": list(args),
            "url": url,
            "transport": transport,
            "env_keys": string_list(metadata.get("env_keys")),
            "headers_keys": string_list(metadata.get("headers_keys")),
            "env": pairs(raw_env),
            "headers": pairs(raw_headers),
            "env_values_hash": string_or_none(metadata.get("env_values_hash")),
            "header_values_hash": string_or_none(metadata.get("header_values_hash")),
            "label": str(metadata.get("name", "mcp")),
        },
        "expected": {key: enriched[key] for key in owned},
    }


def string_list(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, (list, tuple)) else []


def string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def pairs(value: object) -> list[list[str]] | None:
    if not isinstance(value, Mapping):
        return None
    return [[key, item] for key, item in value.items() if isinstance(key, str) and isinstance(item, str)]


def cases() -> list[dict]:
    w = f"{WORK}/"
    out: list[dict] = []

    def add(name: str, kind: str, harness: str, **fields: object) -> None:
        out.append({"name": name, "kind": kind, "harness": harness, **fields})

    add("workspace_empty", "workspace_artifacts", "codex")
    add(
        "workspace_standards_claude_code",
        "workspace_artifacts",
        "claude-code",
        files=[
            file(w + "AGENTS.md", "agents\n"),
            file(w + "CLAUDE.md", "claude\n"),
            file(w + "DESIGN.md"),
            file(w + "PRODUCT.md"),
            file(w + "ROADMAP.md"),
            file(w + "SECURITY.md"),
            file(w + "POLICY.md"),
            file(w + "POLICIES.md"),
            file(w + "STANDARDS.md"),
            file(w + "docs/ROADMAP.md", "docs roadmap\n"),
            file(w + "docs/SECURITY.md", "docs security\n"),
            file(w + ".agents/context/PRODUCT.md", "context product\n"),
            file(w + ".agents/context/STANDARDS.md", "context standards\n"),
        ],
    )
    add(
        "workspace_standards_other_harness_has_no_legacy_claude_id",
        "workspace_artifacts",
        "gemini",
        files=[file(w + "CLAUDE.md", "claude\n"), file(w + "AGENTS.md", "agents\n")],
    )
    add(
        "workspace_doc_directories",
        "workspace_artifacts",
        "codex",
        files=[
            file(w + "docs/design/a.md", "a\n"),
            file(w + "docs/design/sub/b.md", "b\n"),
            file(w + "docs/design/sub/deeper/z.md", "z\n"),
            file(w + "docs/design/skip.txt", "not markdown\n"),
            file(w + "docs/standards/x.md", "x\n"),
            file(w + "docs/policy/p.md", "p\n"),
            file(w + "docs/policies/q.md", "q\n"),
            file(w + "docs/security/s.md", "s\n"),
            file(w + "docs/roadmap/r.md", "r\n"),
            file(w + "docs/product/pr.md", "pr\n"),
            file(w + "docs/Design/upper.md", "upper\n"),
            file(w + ".agents/context/docs/design/c.md", "context docs\n"),
            file(w + "docs/docs/design/nested.md", "nested docs\n"),
            file(w + "docs/design/B.md", "B\n"),
            file(w + "docs/design/b2.md", "b2\n"),
        ],
    )
    add(
        "workspace_doc_directory_symlinks_are_skipped",
        "workspace_artifacts",
        "codex",
        files=[
            file(w + "docs/design/real.md", "real\n"),
            file(w + "docs/product/p.md", "product\n"),
            file(w + "AGENTS.md", "agents\n"),
            file("outside/secret.md", "outside\n"),
        ],
        symlinks=[
            link(w + "docs/design/link.md", "../../AGENTS.md"),
            link(w + "docs/design/linkdir", "../product"),
            link(w + "docs/design/escape.md", "<ROOT>/outside/secret.md"),
        ],
    )
    add(
        "workspace_symlink_instruction_files_are_skipped",
        "workspace_artifacts",
        "claude-code",
        files=[file("outside/AGENTS.md", "outside\n"), file(w + "real/CLAUDE.md", "inside\n")],
        symlinks=[
            link(w + "AGENTS.md", "<ROOT>/outside/AGENTS.md"),
            link(w + "CLAUDE.md", "real/CLAUDE.md"),
            link(w + "docs", "<ROOT>/outside"),
        ],
    )
    add(
        "workspace_cursor_rules",
        "workspace_artifacts",
        "cursor",
        files=[
            file(w + ".cursor/rules/alpha.mdc", "alpha\n"),
            file(w + ".cursor/rules/beta.md", "beta\n"),
            file(w + ".cursor/rules/Gamma.mdc", "gamma\n"),
            file(w + ".cursor/rules/sub/delta.mdc", "delta\n"),
            file(w + ".cursor/rules/notes.txt", "ignored\n"),
            file("outside/escape.mdc", "escape\n"),
        ],
        symlinks=[link(w + ".cursor/rules/escape.mdc", "<ROOT>/outside/escape.mdc")],
    )
    add(
        "workspace_cursor_rules_symlinked_directory_escapes",
        "workspace_artifacts",
        "cursor",
        files=[file("outside/rules/a.mdc", "a\n")],
        symlinks=[link(w + ".cursor/rules", "<ROOT>/outside/rules")],
    )
    skills_root = w + ".agents/skills"
    add(
        "workspace_skills_codex",
        "workspace_artifacts",
        "codex",
        files=[
            *skill(skills_root, "review", file(skills_root + "/review/scripts/run.sh", "#!/bin/sh\nexit 0\n", 0o755)),
            *skill(skills_root, "nested/deep"),
            *skill(skills_root, "zeta", file(skills_root + "/zeta/notes.md", "notes\n")),
        ],
    )
    add(
        "workspace_skill_directly_at_the_root_is_named_dot",
        "workspace_artifacts",
        "codex",
        files=[
            file(skills_root + "/SKILL.md", SKILL.format(name="root-skill")),
            *skill(skills_root, "shadowed"),
        ],
    )
    add(
        "workspace_skills_claude_code_with_instructions",
        "workspace_artifacts",
        "claude-code",
        files=[file(w + "AGENTS.md", "agents\n"), *skill(skills_root, "one")],
    )
    for harness in ("hermes", "copilot", "zcode"):
        add(
            f"workspace_skills_excluded_for_{harness}",
            "workspace_artifacts",
            harness,
            files=[file(w + "AGENTS.md", "agents\n"), *skill(skills_root, "one")],
        )
    add(
        "workspace_skills_incomplete_identity",
        "workspace_artifacts",
        "codex",
        files=[
            *skill(skills_root, "sealed", file(skills_root + "/sealed/secret.txt", "hidden\n", 0o000)),
            *skill(skills_root, "outward"),
            file("outside/target.txt", "outside\n"),
        ],
        symlinks=[link(skills_root + "/outward/escape.txt", "<ROOT>/outside/target.txt")],
    )
    add(
        "workspace_skills_symlinked_skill_directory_is_not_followed",
        "workspace_artifacts",
        "codex",
        files=[*skill("outside/skills", "linked")],
        symlinks=[link(skills_root + "/linked", "<ROOT>/outside/skills/linked")],
    )
    market = w + MARKETPLACE
    plugins = {
        "plugins": [
            {"name": "alpha", "source": {"source": "local", "path": "./plugins/alpha"}},
            {"name": "beta", "source": {"source": "local", "path": "./plugins/beta"}, "enabled": False},
            {"source": "github:example/gamma"},
            {"name": "  ", "source": {"path": "./plugins/missing"}},
            "not-a-dict",
            {"name": "escape", "source": {"source": "local", "path": "./../outside"}},
            {"name": "absolute", "source": {"source": "local", "path": "/etc"}},
            {"name": "no-source"},
            {"name": "emptyref", "source": {"source": "", "path": ""}},
            {"name": "dirmanifest", "source": {"source": "local", "path": "./plugins/dir"}},
            {"name": "enabled-null", "enabled": None, "source": "x"},
        ]
    }
    add(
        "workspace_marketplace_plugins",
        "workspace_artifacts",
        "codex",
        files=[
            file(market, json.dumps(plugins, indent=2)),
            file(w + "plugins/alpha/plugin.json", '{"name": "alpha"}\n'),
            file(w + "plugins/beta/.codex-plugin/plugin.json", '{"name": "beta"}\n'),
            file(w + "plugins/dir/plugin.json/inner.txt", "plugin.json is a directory\n"),
        ],
        marketplace_files=[market],
    )
    add(
        "workspace_marketplace_legacy_root_file",
        "workspace_artifacts",
        "codex",
        files=[file(w + "marketplace.json", json.dumps({"plugins": [{"name": "legacy", "source": "x"}]}))],
        marketplace_files=[w + "marketplace.json"],
    )
    add(
        "workspace_marketplace_preferred_beats_legacy",
        "workspace_artifacts",
        "codex",
        files=[
            file(market, json.dumps({"plugins": [{"name": "preferred", "source": "x"}]})),
            file(w + "marketplace.json", json.dumps({"plugins": [{"name": "legacy", "source": "x"}]})),
        ],
        marketplace_files=[market],
    )
    add(
        "workspace_marketplace_plugins_not_a_list",
        "workspace_artifacts",
        "codex",
        files=[file(market, json.dumps({"plugins": 3}))],
    )
    add(
        "workspace_marketplace_invalid_json_is_refused",
        "workspace_artifacts",
        "codex",
        files=[file(market, "{not json")],
    )
    add(
        "workspace_marketplace_not_an_object_is_refused",
        "workspace_artifacts",
        "codex",
        files=[file(market, "[]")],
    )
    add(
        "workspace_marketplace_symlink_escape_is_refused",
        "workspace_artifacts",
        "codex",
        files=[file("outside/marketplace.json", json.dumps({"plugins": []}))],
        symlinks=[link(market, "<ROOT>/outside/marketplace.json")],
    )
    add(
        "workspace_marketplace_empty_plugins_has_root_artifact",
        "workspace_artifacts",
        "codex",
        files=[file(market, json.dumps({"plugins": []}))],
        marketplace_files=[market],
    )

    existing_mcp = {
        "artifact_id": "claude-code:project:mcp:server",
        "artifact_type": "mcp_server",
        "harness": "claude-code",
        "config_path": "<ROOT>/work/.mcp.json",
    }
    add("merge_no_extra_returns_detection_unchanged", "merge_plan", "codex", existing=[existing_mcp])
    add(
        "merge_appends_new_artifacts",
        "merge_plan",
        "codex",
        existing=[existing_mcp],
        config_paths=["<ROOT>/work/.mcp.json"],
        files=[file(w + "AGENTS.md", "agents\n"), file(w + "docs/SECURITY.md", "sec\n")],
    )
    add(
        "merge_skips_duplicate_artifact_id",
        "merge_plan",
        "codex",
        existing=[
            {
                "artifact_id": "codex:project:instruction:agents_md:AGENTS.md",
                "artifact_type": "instruction",
                "harness": "codex",
                "config_path": "<ROOT>/work/AGENTS.md",
            }
        ],
        config_paths=["<ROOT>/work/AGENTS.md", "<ROOT>/other"],
        files=[file(w + "AGENTS.md", "agents\n"), file(w + "DESIGN.md", "design\n")],
    )
    legacy_id = "claude-code:project:instruction:claude-md"
    add(
        "merge_claude_md_replaces_legacy_rules_collision",
        "merge_plan",
        "claude-code",
        existing=[
            {
                "artifact_id": legacy_id,
                "artifact_type": "instruction",
                "harness": "claude-code",
                "config_path": "<ROOT>/work/.claude/rules/claude-md.md",
            }
        ],
        config_paths=["<ROOT>/work/.claude/rules/claude-md.md"],
        files=[file(w + "CLAUDE.md", "claude\n"), file(w + ".claude/rules/claude-md.md", "rules\n")],
    )
    add(
        "merge_claude_md_does_not_replace_mcp_server",
        "merge_plan",
        "claude-code",
        existing=[
            {
                "artifact_id": legacy_id,
                "artifact_type": "mcp_server",
                "harness": "claude-code",
                "config_path": "<ROOT>/work/.claude/rules/claude-md.md",
            }
        ],
        files=[file(w + "CLAUDE.md", "claude\n"), file(w + ".claude/rules/claude-md.md", "rules\n")],
    )
    add(
        "merge_claude_md_does_not_replace_instruction_outside_rules",
        "merge_plan",
        "claude-code",
        existing=[
            {
                "artifact_id": legacy_id,
                "artifact_type": "instruction",
                "harness": "claude-code",
                "config_path": "<ROOT>/work/elsewhere/claude-md.md",
            }
        ],
        files=[file(w + "CLAUDE.md", "claude\n")],
    )
    add(
        "merge_claude_md_does_not_replace_other_harness_instruction",
        "merge_plan",
        "claude-code",
        existing=[
            {
                "artifact_id": legacy_id,
                "artifact_type": "instruction",
                "harness": "codex",
                "config_path": "<ROOT>/work/.claude/rules/claude-md.md",
            }
        ],
        files=[file(w + "CLAUDE.md", "claude\n")],
    )
    add(
        "merge_non_claude_md_collision_never_replaces",
        "merge_plan",
        "claude-code",
        existing=[
            {
                "artifact_id": "claude-code:project:instruction:agents_md:AGENTS.md",
                "artifact_type": "instruction",
                "harness": "claude-code",
                "config_path": "<ROOT>/work/.claude/rules/a.md",
            }
        ],
        files=[file(w + "AGENTS.md", "agents\n"), file(w + ".claude/rules/a.md", "rules\n")],
    )
    add(
        "merge_existing_without_config_path",
        "merge_plan",
        "codex",
        existing=[{**existing_mcp, "config_path": None}],
        files=[file(w + "AGENTS.md", "agents\n")],
    )

    h = f"{HOME}/"
    codex_home_skills = h + ".codex/skills"
    agents_home_skills = h + ".agents/skills"
    add(
        "codex_skills_global_only_without_workspace",
        "codex_skills",
        "codex",
        no_workspace=True,
        files=[*skill(codex_home_skills, "lint"), *skill(agents_home_skills, "shared")],
    )
    add(
        "codex_skills_project_and_global_without_rules",
        "codex_skills",
        "codex",
        files=[
            *skill(skills_root, "proj"),
            *skill(codex_home_skills, "lint"),
            *skill(agents_home_skills, "shared"),
            *skill(agents_home_skills, "proj"),
        ],
    )
    toml_home = (
        '[[skills.config]]\npath = "home-skill"\nenabled = false\n\n'
        '[[skills.config]]\nname = "LINT"\nenabled = false\n\n'
        '[[skills.config]]\nname = "ignored-no-enabled"\n\n'
        "[[skills.config]]\nenabled = false\n\n"
        '[[skills.config]]\nname = "string-false"\nenabled = "false"\n\n'
        '[[skills.config]]\npath = "~/tilde-skill"\nenabled = false\n'
    )
    toml_work = (
        '[[skills.config]]\nname = "proj"\nenabled = false\n\n'
        '[[skills.config]]\nname = "lint"\nenabled = true\n\n'
        '[[skills.config]]\npath = "  .agents/skills/spaced  "\nenabled = false\n'
    )
    add(
        "codex_skills_rules_from_home_and_workspace",
        "codex_skills",
        "codex",
        files=[
            file(h + ".codex/config.toml", toml_home),
            file(w + ".codex/config.toml", toml_work),
            *skill(skills_root, "proj"),
            *skill(skills_root, "spaced"),
            *skill(skills_root, "string-false"),
            *skill(codex_home_skills, "lint"),
            *skill(codex_home_skills, "home-skill"),
            *skill(agents_home_skills, "shared"),
            *skill(USER_HOME, "tilde-skill"),
        ],
    )
    add(
        "codex_skills_path_rules_match_directory_and_suffix",
        "codex_skills",
        "codex",
        files=[
            file(
                h + ".codex/config.toml",
                '[[skills.config]]\npath = "<ROOT>/home/.codex/skills/exact"\nenabled = false\n\n'
                '[[skills.config]]\npath = "skills/suffix"\nenabled = false\n\n'
                '[[skills.config]]\npath = "<ROOT>/home/.codex/skills/by-file/SKILL.md"\nenabled = false\n',
            ),
            *skill(codex_home_skills, "exact"),
            *skill(codex_home_skills, "suffix"),
            *skill(codex_home_skills, "by-file"),
            *skill(codex_home_skills, "untouched"),
        ],
    )
    add(
        "codex_skills_invalid_toml_means_no_rules",
        "codex_skills",
        "codex",
        files=[file(h + ".codex/config.toml", "[[skills.config\nbroken"), *skill(codex_home_skills, "lint")],
    )
    add(
        "codex_skills_rules_without_skills_table",
        "codex_skills",
        "codex",
        files=[file(h + ".codex/config.toml", "[other]\nvalue = 1\n"), *skill(codex_home_skills, "lint")],
    )
    add(
        "codex_skills_incomplete_identity_is_inventory_artifact",
        "codex_skills",
        "codex",
        files=[
            file(h + ".codex/config.toml", '[[skills.config]]\nname = "Incomplete skill discovery"\nenabled = false\n'),
            *skill(codex_home_skills, "sealed", file(codex_home_skills + "/sealed/secret.txt", "hidden\n", 0o000)),
        ],
    )
    add(
        "codex_skills_later_rule_overrides_earlier",
        "codex_skills",
        "codex",
        files=[
            file(
                h + ".codex/config.toml",
                '[[skills.config]]\nname = "lint"\nenabled = false\n\n'
                '[[skills.config]]\nname = "lint"\nenabled = true\n',
            ),
            *skill(codex_home_skills, "lint"),
        ],
    )

    mcp: list[dict] = [
        mcp_case("mcp_minimal", {}, command="npx", args=("-y", "server"), transport="stdio"),
        mcp_case("mcp_labelled", {"name": "docs"}, url="https://example.invalid/mcp", transport="http"),
        mcp_case("mcp_label_non_string", {"name": 5}, command="x"),
        mcp_case("mcp_label_none", {"name": None}, command="x"),
        mcp_case(
            "mcp_env_keys_are_stripped_deduped_sorted",
            {"env_keys": [" B ", "A", "A", "", "   ", 7, None, "C"]},
            command="x",
        ),
        mcp_case(
            "mcp_env_values_derive_keys_and_hash",
            {},
            command="x",
            env={"B": "2", "A": "1", " C ": "3", "": "empty", 9: "num", "D": 4},
        ),
        mcp_case(
            "mcp_env_duplicate_stripped_key_last_wins",
            {},
            command="x",
            env={"A": "first", " A": "second"},
        ),
        mcp_case(
            "mcp_metadata_env_used_when_configured_is_absent",
            {"env": {"TOKEN": "value"}, "name": "from-metadata"},
            command="x",
        ),
        mcp_case(
            "mcp_configured_env_overrides_metadata_env",
            {"env": {"TOKEN": "metadata"}},
            command="x",
            env={"TOKEN": "configured"},
        ),
        mcp_case(
            "mcp_prefilled_hashes_are_stripped_and_kept",
            {"env_values_hash": "  sha256:abc  ", "header_values_hash": "\theader-hash\n"},
            command="x",
            env={"A": "1"},
            headers={"H": "v"},
        ),
        mcp_case(
            "mcp_blank_and_non_string_hashes_are_recomputed",
            {"env_values_hash": "   ", "header_values_hash": 12},
            command="x",
            env={"A": "1"},
            headers={"H": "v"},
        ),
        mcp_case(
            "mcp_headers_keys_and_values",
            {"headers_keys": ["X-B", " X-A ", "X-A"]},
            url="https://example.invalid/mcp",
            transport="sse",
            headers={"Authorization": "Bearer placeholder", "X-A": "1"},
        ),
        mcp_case(
            "mcp_unicode_and_empty_values",
            {"name": "ünï"},
            command="câ",
            args=("--flag", "", "ü"),
            env={"É": "ü", "E": ""},
        ),
        mcp_case("mcp_explicit_empty_env_mapping", {"env": {"A": "1"}}, command="x", env={}),
        mcp_case("mcp_non_mapping_env_is_empty", {"env": ["A=1"]}, command="x"),
    ]
    return out + mcp


def main() -> None:
    destination = Path(sys.argv[1])
    guard_home = Path(tempfile.mkdtemp(prefix="aibom-guard-home-")).resolve()
    provision_native(guard_home)
    recorded = []
    for case in cases():
        recorded.append(case if case["kind"] == "mcp_metadata" else run_case(case))
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents

    close_native_residents(guard_home)
    shutil.rmtree(guard_home, ignore_errors=True)
    document = {"schema": "guard-aibom-vectors.v1", "cases": recorded}
    destination.write_text(json.dumps(document, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(f"recorded {len(recorded)} cases")


if __name__ == "__main__":
    main()
