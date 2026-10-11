#!/usr/bin/env python3
"""Record `hol-guard-secrets` command vectors from the retired Python scanner.

The expected answers come only from ``guard/secrets`` as it existed before the
resident owned the command surface (``secret_detection``,
``secret_repository_scanner``, ``secret_staged_scanner`` and ``precommit``).
Run it against a checkout of the base commit; the vectors are never produced
by the Rust op, so they stay an independent oracle for it.

Each scenario builds a repository from ``steps`` (``write``, ``rm``, ``mkdir``,
``git``) under a pinned Git identity and clock, so commit ids are identical
for every implementation, then runs ``calls`` in order. A call records the
public result (or the refusal text) and the content and mode of the listed
files after it ran.

Usage:
    PYTHONPATH=<base-checkout>/src record_secrets_vectors.py --output <file>.json.gz
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import subprocess
import tempfile
from pathlib import Path

from codex_plugin_scanner.guard.secrets.precommit import install_precommit_hook, uninstall_precommit_hook
from codex_plugin_scanner.guard.secrets.public_rule_catalog import PUBLIC_RULES_JSON, PUBLIC_RULES_TEXT
from codex_plugin_scanner.guard.secrets.secret_repository_scanner import (
    DEFAULT_MAX_COMMITS,
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_FINDINGS,
    DEFAULT_MAX_TOTAL_BYTES,
    scan_repository_secrets,
)
from codex_plugin_scanner.guard.secrets.secret_staged_scanner import scan_staged_secrets

GIT_ENV = {
    "GIT_AUTHOR_NAME": "Guard Test",
    "GIT_AUTHOR_EMAIL": "guard@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-02T03:04:05+00:00",
    "GIT_COMMITTER_NAME": "Guard Test",
    "GIT_COMMITTER_EMAIL": "guard@example.invalid",
    "GIT_COMMITTER_DATE": "2026-01-02T03:04:05+00:00",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}
HOOK_FILES = (".git/hooks/pre-commit", ".git/hooks/pre-commit.hol-guard-user")

DEFAULTS = {
    "include_history": False,
    "max_commits": DEFAULT_MAX_COMMITS,
    "max_files": DEFAULT_MAX_FILES,
    "max_file_bytes": DEFAULT_MAX_FILE_BYTES,
    "max_total_bytes": DEFAULT_MAX_TOTAL_BYTES,
    "max_findings": DEFAULT_MAX_FINDINGS,
}


def _parts(*values: str) -> str:
    return "".join(values)


def _github_token() -> str:
    return "ghp_" + ("A" * 40)


def _fixture_github_token() -> str:
    return _parts("gh", "p_", "Ab3d", "Ef5h", "Ij7l", "Mn9p", "Qr2t", "Uv4x", "Yz6B", "cd8F", "gh1J", "kl3N")


def _google_key() -> str:
    return _parts("AI", "za", "Ab3d", "Ef5h", "Ij7l", "Mn9p", "Qr2t", "Uv4x", "Yz6B", "cd8F", "gh1")


def _pem(kind: str) -> str:
    return _parts("-----", kind, " ", "OPENSSH", " ", "PRIVATE", " ", "KEY", "-----")


def _generic() -> str:
    return "Q7v9K2mX4pR8sT6wY3nB5cD1fG0hJ9kL"


def _literal() -> str:
    return _parts("v1_", "R4nd0mCred3ntial_8Zk9Qp2Lm7")


def _snippets() -> list[tuple[str, str, str]]:
    """``(name, path, text)`` detection corpus, one file per working-tree scan."""

    pem_body = _parts("AbCd", "Ef12", "3456", "7890", "AbCd", "Ef12", "3456", "7890")
    cases: list[tuple[str, str, str]] = [
        ("github-env", "src/config.py", f"GITHUB_TOKEN={_github_token()}\n"),
        ("github-doc", "docs/example.md", f"token = {_github_token()}\n"),
        ("contextual-assignment", "app/settings.py", f"PAYMENTS_API_SECRET={_generic()}\n"),
        ("no-context-random", "app/settings.py", f"BUILD_CACHE_KEY={_generic()}\n"),
        ("doc-placeholder", "docs/configuration.md", "API_SECRET=replace_me_with_your_secret\n"),
        ("database-url", ".env.production", f"DATABASE_URL=postgres://service:{_generic()}@db.internal/app\n"),
        ("basic-auth-url", "src/client.py", f"URL = 'https://admin:{_generic()}@host.example.test/x'\n"),
        ("aws-and-github", "config.env", f"AWS_ACCESS_KEY_ID=AKIA{'B' * 16}\nGITHUB_TOKEN={_github_token()}\n"),
        ("gitlab", "ci.env", "GITLAB=glpat-" + "a1B2c3D4e5F6g7H8i9J0" + "\n"),
        ("slack-token", "chat.env", "SLACK=xoxb-" + "123456789012-123456789012-" + "AbCdEfGhIjKlMnOpQrStUvWx" + "\n"),
        (
            "slack-webhook",
            "hooks.env",
            "HOOK=https://hooks.slack.com/services/T00000000/B00000000/" + "XXXXXXXXXXXXXXXXXXXXXXXX" + "\n",
        ),
        ("stripe", "pay.env", "STRIPE=sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc" + "\n"),
        ("openai", "ai.env", "OPENAI=sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4" + "\n"),
        ("anthropic", "ai2.env", "ANTHROPIC=sk-ant-api03-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6" + "\n"),
        ("huggingface", "hf.env", "HF=hf_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789" + "\n"),
        ("npm", ".npmrc", "//registry.npmjs.org/:_authToken=npm_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789" + "\n"),
        ("pypi", ".pypirc", "password: pypi-" + "AgEIcHlwaS5vcmc" + "A" * 60 + "\n"),
        ("sendgrid", "mail.env", "SG=SG." + "A" * 22 + "." + "B" * 43 + "\n"),
        ("google-env", ".env.production", f"GOOGLE_API_KEY={_google_key()}\n"),
        ("google-client-config", "android/google-services.json", f'{{"current_key": "{_google_key()}"}}'),
        (
            "jwt",
            "src/auth.py",
            "TOKEN=eyJhbGciOiJIUzI1NiJ9."
            + "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            + "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
            + "\n",
        ),
        ("pem-production", "config/id_ed25519", _parts(_pem("BEGIN"), "\n", pem_body, "\n", _pem("END"))),
        (
            "pem-fixture",
            "src/benchmark-scenarios.ts",
            _parts(
                "fixtureContents: {\n  key: '",
                _pem("BEGIN"),
                "\\nfixture-not-real-key-content\\n",
                _pem("END"),
                "',\n}",
            ),
        ),
        (
            "indirect-ts",
            "src/auth.ts",
            "\n".join(
                (
                    'const authToken = request.headers.get("authorization");',
                    "const apiKey = process.env.OPENAI_API_KEY;",
                    "const clientSecret = config.auth.clientSecret;",
                    "const password = crypto.randomUUID();",
                    "const webhookToken = values.webhookToken;",
                    "const bearerToken = tokenFromRequest;",
                )
            ),
        ),
        (
            "indirect-py",
            "src/auth.py",
            "\n".join(
                (
                    "api_key = os.getenv('OPENAI_API_KEY')",
                    "password = settings.database_password",
                    "auth_token = context.secrets.auth_token",
                )
            ),
        ),
        (
            "indirect-schema",
            "src/schema.ts",
            "\n".join(
                (
                    "apiKey: z.string().min(20)",
                    "clientSecret: schema.clientSecret",
                    "accessToken: request?.auth?.accessToken",
                )
            ),
        ),
        ("quoted-env-ref", "src/auth.ts", 'const apiKey = "process.env.OPENAI_API_KEY";'),
        ("quoted-literal", "src/auth.ts", f'const apiKey = "{_literal()}";'),
        ("dotenv-literal", ".env", f"AUTH_TOKEN={_literal()}"),
        ("client-secret-literal", "src/auth.ts", f'const clientSecret = "{_literal()}";'),
        (
            "yaml-secret",
            "deploy/secrets.yaml",
            'SECRET_KEY: "' + _parts("a9F3", "c7E1", "b5D8", "f2A6", "c4E9", "b7D1", "f5A8", "c2E6") + '"',
        ),
        (
            "public-identifier",
            "src/indexnow.ts",
            "const INDEXNOW_API_KEY = '" + _parts("5098d5ba", "65ef838b", "bd6d3f29", "3327884b") + "';",
        ),
        (
            "redaction-test-context",
            "__tests__/redaction.test.ts",
            "\n".join(
                (
                    "describe('redaction', () => {",
                    "  it('removes provider tokens', () => {",
                    f"    expect(redact('token {_fixture_github_token()}'))"
                    f".not.toContain('{_fixture_github_token()}');",
                    "  });",
                    "});",
                )
            ),
        ),
        ("accidental-env", "tests/accidental.env", f"GITHUB_TOKEN={_fixture_github_token()}"),
        ("dup-line", "dup.env", f"A={_github_token()}\nB={_github_token()}\n"),
        ("crlf", "win.env", f"GITHUB_TOKEN={_github_token()}\r\nOTHER=1\r\n"),
        ("bom", "bom.env", "﻿" + f"GITHUB_TOKEN={_github_token()}\n"),
        ("unicode", "uni.env", "ключ=значение\n" + f"GITHUB_TOKEN={_github_token()}\n"),
    ]
    for index, (source, path) in enumerate(
        (
            ("export type GuardSecretsOverview = Awaited<ReturnType<typeof loadSecretOverview>>;", "src/contracts.ts"),
            ("const GUARD_SECRET_API_VERSION = 'guard-secrets-api.v1' as const;", "src/contracts.ts"),
            ("const passwordInputId = 'email-auth-password';", "src/login.tsx"),
            ("const TOKEN_URL = 'https://oauth.example.test/token';", "src/oauth.ts"),
            ("secretName: points-staging-tls-secret", "deploy/ingress.yaml"),
            ('implementation "androidx.credentials:credentials:1.5.0"', "android/app/build.gradle"),
            ("handoff_token = $script:HANDOFF_TOKEN", "public/install.ps1"),
        )
    ):
        cases.append((f"metadata-{index}", path, source + "\n"))
    for index, source in enumerate(
        (
            _parts("POSTGRES_", "PASSWORD", ': "<', "password", '>"'),
            _parts("API_", "KEY", ': "', "replace-with-", "api-key", '"'),
            _parts("SESSION_TOKEN_", "SECRET", ': "', "super-secret-", "session-key", '"'),
            _parts("AUTH_", "TOKEN", ': "', "invalid-", "token", '"'),
            _parts("PASS", "WORD", ': "', "Password", "123!", '"'),
        )
    ):
        cases.append((f"placeholder-{index}", "deploy/secret.example.yaml", source))
    return cases


def _scenarios() -> list[dict[str, object]]:
    scenarios: list[dict[str, object]] = []
    for name, path, text in _snippets():
        scenarios.append(
            {
                "name": f"snippet-{name}",
                "steps": [["write", path, text]],
                "calls": [{"action": "scan", "target": ".", "bounds": dict(DEFAULTS)}],
            }
        )
    # One tree holding the whole corpus: dedupe, ordering and the finding cap.
    corpus_steps = [["write", f"{index:02d}/{path}", text] for index, (_, path, text) in enumerate(_snippets())]
    scenarios.append(
        {
            "name": "corpus-working-tree",
            "steps": corpus_steps,
            "calls": [
                {"action": "scan", "target": ".", "bounds": dict(DEFAULTS)},
                {"action": "scan", "target": ".", "bounds": {**DEFAULTS, "max_findings": 3}},
                {"action": "scan", "target": ".", "bounds": {**DEFAULTS, "max_files": 5}},
                {"action": "scan", "target": ".", "bounds": {**DEFAULTS, "max_total_bytes": 400}},
                {"action": "scan", "target": ".", "bounds": {**DEFAULTS, "max_file_bytes": 60}},
            ],
        }
    )
    scenarios.append(
        {
            "name": "corpus-git-working-tree",
            "steps": [["git", "init", "-q"], *corpus_steps, ["git", "add", "-A"]],
            "calls": [
                {"action": "scan", "target": ".", "bounds": dict(DEFAULTS)},
                {"action": "staged", "target": ".", "bounds": dict(DEFAULTS)},
                {"action": "staged", "target": ".", "bounds": {**DEFAULTS, "max_findings": 2}},
            ],
        }
    )
    scenarios.append(
        {
            "name": "single-file-target",
            "steps": [
                ["write", "config.env", f"GITHUB_TOKEN={_github_token()}\n"],
                ["write", "other.env", f"GITHUB_TOKEN={_github_token()}0\n"],
            ],
            "calls": [{"action": "scan", "target": "config.env", "bounds": dict(DEFAULTS)}],
        }
    )
    scenarios.append(
        {
            "name": "binary-and-skipped-dirs",
            "steps": [
                ["write", "config.py", f"TOKEN={_github_token()}\n"],
                ["write", "node_modules/pkg/index.js", f"TOKEN={_github_token()}\n"],
                ["write", ".venv/lib/x.py", f"TOKEN={_github_token()}\n"],
                ["write", "image.png", "\x00PNG\x00" + _github_token()],
                ["write", "bin.dat", "ab\x00cd" + _github_token()],
            ],
            "calls": [{"action": "scan", "target": ".", "bounds": dict(DEFAULTS)}],
        }
    )
    scenarios.append(
        {
            "name": "finding-limit",
            "steps": [["write", f"secret-{index}.txt", f"TOKEN={_github_token()}{index}\n"] for index in range(5)],
            "calls": [{"action": "scan", "target": ".", "bounds": {**DEFAULTS, "max_findings": 2}}],
        }
    )
    history_steps = [
        ["git", "init", "-q"],
        ["write", "config.py", f"TOKEN={_github_token()}\n"],
        ["git", "add", "config.py"],
        ["git", "commit", "-q", "-m", "add config"],
        ["write", "config.py", "TOKEN_FROM_ENV = True\n"],
        ["git", "add", "config.py"],
        ["git", "commit", "-q", "-m", "remove credential"],
    ]
    scenarios.append(
        {
            "name": "history-removed-secret",
            "steps": history_steps,
            "calls": [
                {"action": "scan", "target": ".", "bounds": dict(DEFAULTS)},
                {"action": "scan", "target": ".", "bounds": {**DEFAULTS, "include_history": True, "max_commits": 2}},
                {"action": "scan", "target": ".", "bounds": {**DEFAULTS, "include_history": True, "max_commits": 1}},
                {"action": "scan", "target": ".", "bounds": {**DEFAULTS, "include_history": True}},
            ],
        }
    )
    scenarios.append(
        {
            "name": "history-multi-commit",
            "steps": [
                *history_steps,
                ["write", "other.env", f"AWS_ACCESS_KEY_ID=AKIA{'B' * 16}\n"],
                ["write", "src/app.py", f"PAYMENTS_API_SECRET={_generic()}\n"],
                ["git", "add", "-A"],
                ["git", "commit", "-q", "-m", "more secrets"],
                ["git", "rm", "-q", "other.env"],
                ["git", "commit", "-q", "-m", "drop"],
            ],
            "calls": [
                {"action": "scan", "target": ".", "bounds": {**DEFAULTS, "include_history": True}},
                {"action": "scan", "target": ".", "bounds": {**DEFAULTS, "include_history": True, "max_findings": 2}},
                {"action": "scan", "target": ".", "bounds": {**DEFAULTS, "include_history": True, "max_files": 2}},
                {
                    "action": "scan",
                    "target": ".",
                    "bounds": {**DEFAULTS, "include_history": True, "max_file_bytes": 20},
                },
            ],
        }
    )
    scenarios.append(
        {
            "name": "history-non-git-and-empty",
            "steps": [["write", "a.txt", "hello\n"]],
            "calls": [{"action": "scan", "target": ".", "bounds": {**DEFAULTS, "include_history": True}}],
        }
    )
    scenarios.append(
        {
            "name": "history-empty-repository",
            "steps": [["git", "init", "-q"]],
            "calls": [{"action": "scan", "target": ".", "bounds": {**DEFAULTS, "include_history": True}}],
        }
    )
    scenarios.append(
        {
            "name": "missing-target",
            "steps": [],
            "calls": [{"action": "scan", "target": "missing", "bounds": dict(DEFAULTS)}],
        }
    )
    scenarios.append(
        {
            "name": "staged-reads-index-not-worktree",
            "steps": [
                ["git", "init", "-q"],
                ["write", "config.env", "SAFE_VALUE=hello\n"],
                ["git", "add", "config.env"],
                ["write", "config.env", f"GITHUB_TOKEN={_github_token()}\n"],
            ],
            "calls": [{"action": "staged", "target": ".", "bounds": dict(DEFAULTS)}],
        }
    )
    scenarios.append(
        {
            "name": "staged-secret",
            "steps": [
                ["git", "init", "-q"],
                ["write", "config.env", f"GITHUB_TOKEN={_github_token()}\n"],
                ["write", "keep.txt", "plain\n"],
                ["git", "add", "config.env", "keep.txt"],
                ["write", "unstaged.env", f"GITHUB_TOKEN={_github_token()}1\n"],
            ],
            "calls": [
                {"action": "staged", "target": ".", "bounds": dict(DEFAULTS)},
                {"action": "staged", "target": ".", "bounds": {**DEFAULTS, "max_files": 1}},
                {"action": "staged", "target": ".", "bounds": {**DEFAULTS, "max_file_bytes": 10}},
                {"action": "staged", "target": ".", "bounds": {**DEFAULTS, "max_total_bytes": 10}},
            ],
        }
    )
    scenarios.append(
        {
            "name": "staged-non-git",
            "steps": [["write", "a.txt", "x\n"]],
            "calls": [{"action": "staged", "target": ".", "bounds": dict(DEFAULTS)}],
        }
    )
    scenarios.append(
        {
            "name": "staged-deleted-and-renamed",
            "steps": [
                ["git", "init", "-q"],
                ["write", "old.env", f"GITHUB_TOKEN={_github_token()}\n"],
                ["git", "add", "old.env"],
                ["git", "commit", "-q", "-m", "base"],
                ["git", "mv", "old.env", "new.env"],
                ["write", "gone.env", "x\n"],
                ["git", "add", "gone.env"],
                ["git", "rm", "-q", "-f", "gone.env"],
            ],
            "calls": [{"action": "staged", "target": ".", "bounds": dict(DEFAULTS)}],
        }
    )
    hook_calls = [
        {"action": "install_hook", "target": "."},
        {"action": "install_hook", "target": "."},
        {"action": "uninstall_hook", "target": "."},
        {"action": "uninstall_hook", "target": "."},
    ]
    scenarios.append({"name": "hook-install-idempotent", "steps": [["git", "init", "-q"]], "calls": hook_calls})
    scenarios.append(
        {
            "name": "hook-chains-existing",
            "steps": [
                ["git", "init", "-q"],
                ["write", ".git/hooks/pre-commit", "#!/bin/sh\necho user-hook\n"],
                ["chmod", ".git/hooks/pre-commit", 0o755],
            ],
            "calls": hook_calls,
        }
    )
    scenarios.append(
        {
            "name": "hook-custom-hooks-path",
            "steps": [["git", "init", "-q"], ["git", "config", "core.hooksPath", "custom-hooks"]],
            "calls": [{"action": "install_hook", "target": "."}, {"action": "uninstall_hook", "target": "."}],
        }
    )
    scenarios.append(
        {
            "name": "hook-symlinked-hooks-dir",
            "steps": [
                ["git", "init", "-q"],
                ["mkdir", "elsewhere"],
                ["rm", ".git/hooks"],
                ["symlink", ".git/hooks", "../elsewhere"],
            ],
            "calls": [{"action": "install_hook", "target": "."}, {"action": "uninstall_hook", "target": "."}],
        }
    )
    scenarios.append(
        {
            "name": "hook-foreign-hook-not-removed",
            "steps": [
                ["git", "init", "-q"],
                ["write", ".git/hooks/pre-commit", "#!/bin/sh\necho foreign\n"],
                ["chmod", ".git/hooks/pre-commit", 0o755],
            ],
            "calls": [{"action": "uninstall_hook", "target": "."}],
        }
    )
    scenarios.append(
        {
            "name": "hook-missing-hooks-dir",
            "steps": [["git", "init", "-q"], ["rm", ".git/hooks"]],
            "calls": [{"action": "uninstall_hook", "target": "."}, {"action": "install_hook", "target": "."}],
        }
    )
    scenarios.append(
        {
            "name": "hook-backup-exists",
            "steps": [
                ["git", "init", "-q"],
                ["write", ".git/hooks/pre-commit", "#!/bin/sh\necho user-hook\n"],
                ["chmod", ".git/hooks/pre-commit", 0o755],
                ["write", ".git/hooks/pre-commit.hol-guard-user", "#!/bin/sh\necho older\n"],
            ],
            "calls": [{"action": "install_hook", "target": "."}],
        }
    )
    scenarios.append(
        {
            "name": "hook-non-git-target",
            "steps": [["write", "a.txt", "x\n"]],
            "calls": [{"action": "install_hook", "target": "."}, {"action": "uninstall_hook", "target": "."}],
        }
    )
    scenarios.append(
        {
            "name": "hook-missing-target",
            "steps": [],
            "calls": [{"action": "install_hook", "target": "missing"}],
        }
    )
    scenarios.append({"name": "rules", "steps": [], "calls": [{"action": "rules", "target": ""}]})
    return scenarios


def _run_steps(root: Path, steps: list[list[object]]) -> None:
    for step in steps:
        kind = str(step[0])
        if kind == "write":
            path = root / str(step[1])
            path.parent.mkdir(parents=True, exist_ok=True)
            text = str(step[2])
            path.write_bytes(text.encode("utf-8", "surrogateescape"))
        elif kind == "rm":
            path = root / str(step[1])
            if path.is_symlink() or path.is_file():
                path.unlink()
            else:
                import shutil

                shutil.rmtree(path)
        elif kind == "mkdir":
            (root / str(step[1])).mkdir(parents=True, exist_ok=True)
        elif kind == "chmod":
            (root / str(step[1])).chmod(int(step[2]))  # type: ignore[arg-type]
        elif kind == "symlink":
            (root / str(step[1])).symlink_to(str(step[2]), target_is_directory=True)
        elif kind == "git":
            subprocess.run(
                ["git", "-C", str(root), "-c", "commit.gpgsign=false", *map(str, step[1:])],
                check=True,
                capture_output=True,
                env={**os.environ, **GIT_ENV},
            )
        else:
            raise ValueError(kind)


def _file_state(root: Path) -> dict[str, object]:
    state: dict[str, object] = {}
    for relative in HOOK_FILES:
        path = root / relative
        if path.is_file():
            state[relative] = {"content": path.read_text(encoding="utf-8"), "mode": path.stat().st_mode & 0o777}
        else:
            state[relative] = None
    return state


def _run_call(root: Path, call: dict[str, object]) -> dict[str, object]:
    target = root / str(call["target"])
    action = str(call["action"])
    try:
        if action == "rules":
            expected = {"json": PUBLIC_RULES_JSON, "text": PUBLIC_RULES_TEXT}
        elif action == "scan":
            bounds = dict(call["bounds"])  # type: ignore[arg-type]
            expected = scan_repository_secrets(target, **bounds).to_public_dict()
        elif action == "staged":
            bounds = dict(call["bounds"])  # type: ignore[arg-type]
            bounds.pop("include_history")
            bounds.pop("max_commits")
            expected = scan_staged_secrets(target, **bounds).to_public_dict()
        elif action == "install_hook":
            expected = install_precommit_hook(target).to_public_dict()
        else:
            expected = uninstall_precommit_hook(target).to_public_dict()
        recorded: dict[str, object] = {"expected": expected}
    except (OSError, ValueError) as error:
        recorded = {"refused": str(error)}
    serialized = json.dumps(recorded)
    if str(root) in serialized:
        raise SystemExit(f"{action}: result carries the temporary root")
    return {**call, **recorded, "files_after": _file_state(root)}


def record(output: Path) -> None:
    # The scan and hook paths spawn Git too; isolate them from user config.
    os.environ.update(GIT_ENV)
    vectors: list[dict[str, object]] = []
    for scenario in _scenarios():
        with tempfile.TemporaryDirectory(prefix="guard-secrets-vec-") as raw:
            root = Path(raw).resolve()
            _run_steps(root, scenario["steps"])  # type: ignore[arg-type]
            calls = [_run_call(root, call) for call in scenario["calls"]]  # type: ignore[union-attr]
        vectors.append({"name": scenario["name"], "steps": scenario["steps"], "calls": calls})
    rendered = json.dumps(vectors, sort_keys=True, separators=(",", ":")).encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as handle, gzip.GzipFile(fileobj=handle, mode="wb", mtime=0) as archive:
        archive.write(rendered)
    findings = sum(
        call["expected"]["finding_count"]  # type: ignore[index]
        for vector in vectors
        for call in vector["calls"]  # type: ignore[union-attr]
        if "expected" in call and "finding_count" in call["expected"]  # type: ignore[operator]
    )
    print(f"recorded {len(vectors)} scenarios, {findings} findings -> {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    record(parser.parse_args().output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
