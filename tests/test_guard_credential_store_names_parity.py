"""The credential-store screen the Python and Rust read paths share.

The lists are written twice, once per language, so the test reads the Rust
source and fails if either copy moves without the other. A store guarded
against `ls` and open to `cat` is the drift this is here to catch.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.credential_store_names import (
    CREDENTIAL_STORE_NAMES,
    HARNESS_DIRECTORIES,
    HARNESS_HOME_NAMES,
    HARNESS_SHARED_NAMES,
    NESTED_CREDENTIAL_STORE_NAMES,
    SECRET_BEARING_STEMS,
    SECRET_BEARING_SUFFIXES,
    hidden_content_read_allowed,
    lowered_names,
)

_ROOT = Path(__file__).resolve().parents[1]
_RUST = _ROOT / "rust/crates/guard-command/src/credential_store_names.rs"
_HARNESS_RUST = _ROOT / "rust/crates/guard-command/src/harness_config_names.rs"


def _rust_array(source: Path, name: str) -> frozenset[str]:
    text = source.read_text(encoding="utf-8")
    match = re.search(rf"{re.escape(name)}\s*:[^=]*=\s*(?:&)?\[(.*?)\];", text, re.DOTALL)
    assert match is not None, f"{name} not found in {source.name}"
    return frozenset(re.findall(r'"([^"]*)"', match.group(1)))


@pytest.mark.parametrize(
    ("name", "python_value", "source"),
    [
        ("CREDENTIAL_STORE_NAMES", CREDENTIAL_STORE_NAMES, _RUST),
        ("HARNESS_SHARED_NAMES", HARNESS_SHARED_NAMES, _RUST),
        ("HARNESS_HOME_NAMES", HARNESS_HOME_NAMES, _RUST),
        ("NESTED_CREDENTIAL_STORE_NAMES", NESTED_CREDENTIAL_STORE_NAMES, _RUST),
        ("SECRET_BEARING_STEMS", SECRET_BEARING_STEMS, _RUST),
        ("SECRET_BEARING_SUFFIXES", frozenset(SECRET_BEARING_SUFFIXES), _RUST),
        ("HARNESS_DIRECTORIES", HARNESS_DIRECTORIES, _HARNESS_RUST),
    ],
)
def test_python_lists_match_the_rust_source(name: str, python_value: frozenset[str], source: Path) -> None:
    assert python_value == _rust_array(source, name)


# Reads an ordinary developer answers from the home directory and never sees a
# secret: a Node toolchain inventory, a shared skill script, a repository's own
# workflow, a harness's plugin tree.
ALLOWED = [
    "/Users/dev/.nvm/versions/node/v25.2.1/lib/node_modules",
    "/Users/dev/.agents/skills/release-check/scripts/run.sh",
    "/Users/dev/.github/workflows/ci.yml",
    "/Users/dev/.local/share/pnpm/store",
    "/Users/dev/.cargo/registry/src/index.crates.io/serde-1.0.0/src/lib.rs",
    "/Users/dev/.zcode/cli/plugins/cache/manifest.json",
    "/Users/dev/.vscode/extensions/extensions.json",
]

# Every one of these returns a live credential to whoever reads it.
REFUSED = [
    "/Users/dev/.ssh/id_ed25519",
    "/Users/dev/.ssh/config",
    "/Users/dev/.aws/credentials",
    "/Users/dev/.codex/auth.json",
    "/Users/dev/.claude/.credentials.json",
    "/Users/dev/.config/gh/hosts.yml",
    "/Users/dev/.config/doctl/config.yaml",
    "/Users/dev/.config/github-copilot/apps.json",
    "/Users/dev/.gemini/oauth_creds.json",
    "/Users/dev/.local/share/opencode/auth.json",
    "/Users/dev/.hol-guard/guard.db",
    "/Users/dev/.gnupg/private-keys-v1.d/key.key",
    "/Users/dev/.kube/config",
    "/Users/dev/.docker/config.json",
    "/Users/dev/.envrc",
    "/Users/dev/.certs/server.pem",
    "/Users/dev/.secrets/service-account.json",
]


@pytest.mark.parametrize("path", ALLOWED)
def test_ordinary_hidden_reads_clear_the_screen(path: str) -> None:
    assert hidden_content_read_allowed(lowered_names(path)) is True


@pytest.mark.parametrize("path", REFUSED)
def test_credential_reads_stay_refused(path: str) -> None:
    assert hidden_content_read_allowed(lowered_names(path)) is False


def test_a_visible_path_is_not_screened_as_hidden() -> None:
    assert hidden_content_read_allowed(lowered_names("/Users/dev/projects/app/src/main.rs")) is True


def test_a_store_below_a_benign_hidden_directory_still_refuses() -> None:
    assert hidden_content_read_allowed(lowered_names("/Users/dev/.agents/skills/.ssh/id_rsa")) is False
