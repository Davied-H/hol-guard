"""File, read and Guard-CLI cases for earlier false-positive fixes.

Every command is ordinary developer work in the disposable project: reading dotfiles and
migrations, copying and editing workspace files, reading agent plan and memory documents, and
Guard's own read-only CLI. Files hold synthetic text only. The ``gh`` stub prints a masked token
the way ``gh auth status`` does; no value here is a credential.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .fp_spec import Check, FpCase, absent, exact_file

DOTFILES_CASE = "project-dotfile-reads"
_GITIGNORE = "node_modules/\ndist/\n.env\n"
_NVMRC = "22\n"
_EDITORCONFIG = "root = true\n\n[*]\nindent_style = space\nindent_size = 2\n"

MIGRATION_CASE = "table-named-migration-read"
_MIGRATION = (
    "CREATE TABLE api_keys (\n  id integer PRIMARY KEY,\n  label text NOT NULL,\n  created_at timestamp NOT NULL\n);\n"
)

MASKED_STATUS_CASE = "masked-token-status"
_GH_STATUS = (
    "github.com\n  ✓ Logged in to github.com account example-user (keyring)\n  - Active account: true\n"
    "  - Git operations protocol: https\n  - Token: gho_************************************\n"
    "  - Token scopes: 'gist', 'read:org', 'repo'\n"
)

FEATURE_DIRS_CASE = "secret-named-feature-dirs"
_FEATURE_LISTING = "index.ts\npanel.ts\n"
_TOKENS = "export const designTokens = { spacing: 4, radius: 8 };\n"

GLOB_COPY_CASE = "recursive-glob-copy"

SED_CASE = "sed-inplace-workspace"
_SED_BEFORE = "const label = 'foo';\nsecond-line\n"
_SED_AFTER = "const label = 'bar';\nsecond-line\n"

REMOVE_LINK_CASE = "workspace-rm-and-symlink"

DISK_CASE = "disk-and-diff-reads"

PRINTENV_CASE = "printenv-reads"

HEREDOC_CASE = "quoted-heredoc-file-write"

PLANS_CASE = "agent-plan-memory-doc-reads"
_PLAN = "# Release plan\n- cut the release branch\n- run the checks\n"
_MEMORY = "- [release-checklist](release-checklist.md) - run the checks before tagging\n"

SAFETY_CASE = "safety-guide-read-and-list"

GUARD_CLI_CASE = "guard-self-cli-reads"

SIBLING_CASE = "sibling-relative-glob-reads"
MISSING_PROBE = "du -sh ../missing 2>/dev/null"

JQ_CASE = "jq-builtins"
_JQ_MANIFEST = (
    '{\n  "name": "fixture-app",\n  "version": "1.0.0",\n  "dependencies": {\n    "left-pad": "1.3.0",\n'
    '    "zod": "3.23.8"\n  }\n}\n'
)


def _source_files() -> dict[str, str]:
    # Deferred: fixtures imports this package while it loads.
    from .fixtures import SOURCE_FILES

    return SOURCE_FILES


def _copied(workspace: Path, _home: Path) -> bool:
    return all(exact_file(workspace / "dist" / Path(name).name, text) for name, text in _source_files().items())


def _symlinked(workspace: Path, _home: Path) -> bool:
    link = workspace / "docs/README.md"
    return (
        link.is_symlink()
        and os.readlink(link) == "../README.md"
        and link.resolve() == (workspace / "README.md").resolve()
    )


def _install_safety_guide(_workspace: Path, home: Path) -> None:
    from codex_plugin_scanner.guard.agent_safety_guidance import install_agent_safety_guidance

    install_agent_safety_guidance(home)


def _safety_listing(text: str) -> bool:
    return "HOL GUARD MANAGED SAFETY DOCUMENT" in text and "README.md" in text.splitlines()


def _checks(**checks: Check) -> dict[str, Check]:
    return {name.replace("_", "-"): check for name, check in checks.items()}


FILE_CASES: dict[str, FpCase] = {
    DOTFILES_CASE: FpCase(
        files={".gitignore": _GITIGNORE, ".nvmrc": _NVMRC, ".editorconfig": _EDITORCONFIG},
        outputs=(_GITIGNORE, _NVMRC + _EDITORCONFIG),
    ),
    MIGRATION_CASE: FpCase(
        files={"db/migrations/003_create_api_keys.sql": _MIGRATION},
        outputs=(_MIGRATION,),
    ),
    MASKED_STATUS_CASE: FpCase(
        stubs={"gh": [("auth status", _GH_STATUS)]},
        outputs=(_GH_STATUS,),
    ),
    FEATURE_DIRS_CASE: FpCase(
        files={
            "src/features/secrets/index.ts": "export const secretsFeature = { enabled: true };\n",
            "src/features/secrets/panel.ts": "export const panelTitle = 'Vault settings';\n",
            "src/tokens/index.ts": _TOKENS,
        },
        outputs=(_FEATURE_LISTING, _TOKENS),
    ),
    GLOB_COPY_CASE: FpCase(
        outputs=(None,),
        checks=_checks(recursive_glob_copy_exact=_copied),
    ),
    SED_CASE: FpCase(
        files={"src/one.ts": _SED_BEFORE},
        outputs=(None,),
        checks=_checks(
            sed_inplace_exact=lambda workspace, _home: exact_file(workspace / "src/one.ts", _SED_AFTER),
            sed_backup_removed=lambda workspace, _home: absent(workspace / "src/one.ts.bak"),
        ),
    ),
    REMOVE_LINK_CASE: FpCase(
        files={"build/out/a.o": "object\n"},
        outputs=(None, None),
        checks=_checks(
            object_file_removed=lambda workspace, _home: absent(workspace / "build/out/a.o"),
            docs_readme_link_exact=_symlinked,
        ),
    ),
    DISK_CASE: FpCase(
        outputs=(re.compile(r"\A\S+\s+src\n\Z"), re.compile(r"\AFilesystem\s"), None),
    ),
    PRINTENV_CASE: FpCase(
        environment={"NODE_ENV": "development"},
        outputs=(re.compile(r"\A/[^\n]*\n\Z"), "development\n"),
    ),
    HEREDOC_CASE: FpCase(
        outputs=(None,),
        checks=_checks(notes_file_exact=lambda workspace, _home: exact_file(workspace / "notes.md", "# Notes\n")),
    ),
    PLANS_CASE: FpCase(
        home_files={".codex/plans/release.md": _PLAN, ".claude/projects/app/memory/MEMORY.md": _MEMORY},
        outputs=(_PLAN, _MEMORY),
    ),
    SAFETY_CASE: FpCase(
        outputs=(_safety_listing,),
        setup=_install_safety_guide,
    ),
    GUARD_CLI_CASE: FpCase(
        outputs=(None, re.compile(r"usage: hol-guard"), None, None),
    ),
    SIBLING_CASE: FpCase(
        home_files={
            "other-project/src/a.ts": "export const a = 1;\n",
            "other-project/src/b.ts": "export const b = 2;\n",
            "other-project/node_modules/.bin/vite": "#!/usr/bin/env node\n",
        },
        repositories=("other-project",),
        outputs=("../other-project/src/a.ts\n../other-project/src/b.ts\n", "vite\n", None),
        expected_failures=frozenset({MISSING_PROBE}),
    ),
    JQ_CASE: FpCase(
        files={"package.json": _JQ_MANIFEST},
        outputs=('[\n  "dependencies",\n  "name",\n  "version"\n]\n', "2\n"),
    ),
}
