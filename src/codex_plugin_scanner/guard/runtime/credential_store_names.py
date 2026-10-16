"""The hidden directories that hold credentials, and the file names that hold them directly.

Mirrors ``rust/crates/guard-command/src/credential_store_names.rs``. The native
runtime owns the live decision; this copy keeps the Python path from refusing
what native allows, which is what turns an ordinary ``cat ~/.agents/skills/...``
into an approval nobody answers.

``tests/test_guard_credential_store_names_parity.py`` reads the Rust source and
fails if either list moves without the other.
"""

from __future__ import annotations

from pathlib import PurePath

CREDENTIAL_STORE_NAMES: frozenset[str] = frozenset(
    {
        ".aws",
        ".azure",
        ".bitcoin",
        ".docker",
        ".electrum",
        ".ethereum",
        ".gcloud",
        ".gnupg",
        ".hol-guard",
        ".kube",
        ".mozilla",
        ".password-store",
        ".pki",
        ".ssh",
        ".terraform",
        ".terraform.d",
        ".thunderbird",
        ".vault-token",
    }
)
"""Hidden directories holding credentials, keys, wallets, browser profiles or Guard state."""

HARNESS_SHARED_NAMES: frozenset[str] = frozenset({".agent", ".agents", ".clinerules", ".githooks", ".husky"})
"""Harness directories that share skills, rules or Git hooks rather than an agent login."""

HARNESS_HOME_NAMES: frozenset[str] = frozenset({".claude", ".codex"})
"""Harness homes whose login lives in files the file-name screen already refuses."""

HARNESS_DIRECTORIES: frozenset[str] = frozenset(
    {
        ".agent",
        ".agents",
        ".amazonq",
        ".antigravity",
        ".augment",
        ".claude",
        ".cline",
        ".clinerules",
        ".codex",
        ".continue",
        ".copilot",
        ".crush",
        ".cursor",
        ".devin",
        ".gemini",
        ".githooks",
        ".goose",
        ".grok",
        ".hermes",
        ".husky",
        ".junie",
        ".kimi",
        ".kiro",
        ".omp",
        ".openclaw",
        ".opencode",
        ".openhands",
        ".paseo",
        ".pi",
        ".qwen",
        ".roo",
        ".trae",
        ".windsurf",
        ".zcode",
        ".zed",
    }
)
"""Mirror of the Rust ``harness_config_names::HARNESS_DIRECTORIES`` list."""

NESTED_CREDENTIAL_STORE_NAMES: frozenset[str] = frozenset(
    {
        "1password",
        "bravesoftware",
        "chromium",
        "gcloud",
        "gh",
        "github-copilot",
        "gnupg",
        "google-chrome",
        "gopass",
        "hub",
        "keyrings",
        "microsoft-edge",
        "op",
        "opencode",
        "password-store",
        "solana",
    }
)
"""Stores kept directly below ``~/.config`` or ``~/.local/share``."""

SECRET_BEARING_STEMS: frozenset[str] = frozenset(
    {
        "account",
        "accounts",
        "apps",
        "auth",
        "client_secret",
        "config",
        "configuration",
        "cookie",
        "cookies",
        "credential",
        "credentials",
        "hosts",
        "identity",
        "key",
        "keyring",
        "keyrings",
        "keys",
        "oauth_creds",
        "service-account",
        "serviceaccount",
        "token",
        "tokens",
    }
)
"""File stems a token, key or session is conventionally written under."""

SECRET_BEARING_SUFFIXES: tuple[str, ...] = (
    ".cer",
    ".crt",
    ".jks",
    ".key",
    ".keystore",
    ".p12",
    ".pem",
    ".pfx",
)
"""Suffixes that carry a key or certificate whatever the file is called."""


def _harness_login_store(name: str) -> bool:
    """A harness directory other than the shared skill and hook trees."""
    return name in HARNESS_DIRECTORIES and name not in HARNESS_SHARED_NAMES and name not in HARNESS_HOME_NAMES


def names_hold_credential_store(names: list[str]) -> bool:
    """Whether any component of the already-lowercased ``names`` is a credential store."""
    for index, name in enumerate(names):
        parent = names[index - 1] if index >= 1 else None
        grandparent = names[index - 2] if index >= 2 else None
        config_child = parent == ".config" or (parent == "share" and grandparent == ".local")
        if (
            name in CREDENTIAL_STORE_NAMES
            or (_harness_login_store(name) and "plugins" not in names[index + 1 :])
            or name.startswith(".env")
            or (config_child and name in NESTED_CREDENTIAL_STORE_NAMES)
        ):
            return True
    return False


def lowered_names(path: str) -> list[str]:
    """The lowercased ordinary components of ``path``."""
    return [part.lower() for part in PurePath(path).parts if part not in {"", "/", "."}]


def secret_bearing_file_name(name: str) -> bool:
    """Whether the lowercased ``name`` is one a secret is normally written under."""
    if name.endswith(SECRET_BEARING_SUFFIXES) or name.startswith("id_"):
        # `id_ed25519`, `id_rsa.pub`: a private key is named for the algorithm,
        # not for what it is.
        return True
    # `.credentials.json` names the same thing `credentials.json` does, so the
    # leading dot is stripped before the stem is read.
    bare = name[1:] if name.startswith(".") else name
    return bare.split(".")[0] in SECRET_BEARING_STEMS


def hidden_content_read_allowed(lowered: list[str]) -> bool:
    """Whether a content read may cross the hidden components of ``lowered``.

    Every hidden component must clear the credential-store screen, and the
    file's own name must not be one a secret is normally written under. Harness
    homes are refused: their logins live beside the notes, and the harness-notes
    path answers the documents that are safe to read there.
    """
    if not any(part.startswith(".") for part in lowered):
        return True
    if names_hold_credential_store(lowered) or any(name in HARNESS_HOME_NAMES for name in lowered):
        return False
    return not lowered or not secret_bearing_file_name(lowered[-1])
