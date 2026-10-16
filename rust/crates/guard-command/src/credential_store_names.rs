//! The hidden directories that hold credentials, and the file names that hold
//! them directly.
//!
//! Two screens read these lists. A listing prints entry names and nothing else,
//! so it refuses only the directories whose names reveal which accounts, hosts
//! and keys exist. A content read returns the bytes, so it refuses those same
//! directories and, on top of them, the file names a token is normally written
//! under. Keeping both lists here is what stops the two from drifting apart,
//! which is how a directory ends up guarded against listing and open to `cat`.

use std::path::{Component, Path};

/// Hidden directories that hold credentials, keys, wallets, browser profiles
/// or Guard's own state. Their entry names alone reveal which accounts, hosts
/// and keys exist.
pub(crate) const CREDENTIAL_STORE_NAMES: [&str; 18] = [
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
];

/// Harness directories that share skills, rules or Git hooks rather than an
/// agent login. Every other harness directory (`~/.gemini`, `~/.omp`,
/// `~/.copilot`) may hold login tokens under names Guard does not know, so it
/// keeps review.
pub(crate) const HARNESS_SHARED_NAMES: [&str; 5] =
    [".agent", ".agents", ".clinerules", ".githooks", ".husky"];

/// Harness homes whose login and secret-bearing config live in files the
/// credential and hidden-name screens already refuse to read
/// (`auth.json`, `.credentials.json`, `config.toml`, `settings.json`).
/// Listing them prints plan, memory and session names, never a secret.
pub(crate) const HARNESS_HOME_NAMES: [&str; 2] = [".claude", ".codex"];

/// Credential, password-manager, keyring, browser-profile and agent-login
/// stores kept directly below `~/.config` or `~/.local/share`. A tool whose
/// directory holds only fixed-name config files (`~/.config/doctl/config.yaml`,
/// with its tokens inside the file) is not listed: its entry names reveal no
/// account, host or key, and content reads of the file stay guarded by
/// [`secret_bearing_file_name`].
pub(crate) const NESTED_CREDENTIAL_STORE_NAMES: [&str; 16] = [
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
];

/// File stems a token, key or session is conventionally written under. Below a
/// hidden directory this is where a tool's own secret lives, whatever the
/// directory is called: `~/.config/doctl/config.yaml` holds an API token, and
/// `doctl` is not a name any directory screen can be expected to know.
const SECRET_BEARING_STEMS: [&str; 22] = [
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
];

/// Suffixes that carry a key or certificate whatever the file is called.
const SECRET_BEARING_SUFFIXES: [&str; 8] = [
    ".cer",
    ".crt",
    ".jks",
    ".key",
    ".keystore",
    ".p12",
    ".pem",
    ".pfx",
];

/// A harness directory other than the shared skill and hook trees. Its
/// `plugins` subtree (`~/.zcode/cli/plugins/cache`) holds installed plugin
/// code rather than the login, so listings below it are screened like any
/// other dot-directory.
fn harness_login_store(name: &str) -> bool {
    crate::harness_config_names::HARNESS_DIRECTORIES.contains(&name)
        && !HARNESS_SHARED_NAMES.contains(&name)
        && !HARNESS_HOME_NAMES.contains(&name)
}

/// Whether any component of `names` is a credential store, where `names` is
/// already lowercased. Shared by the listing and content screens so a store
/// added to one list is refused by both.
pub(crate) fn names_hold_credential_store(names: &[String]) -> bool {
    names.iter().enumerate().any(|(index, name)| {
        let parent = index.checked_sub(1).map(|at| names[at].as_str());
        let grandparent = index.checked_sub(2).map(|at| names[at].as_str());
        let config_child =
            parent == Some(".config") || (parent == Some("share") && grandparent == Some(".local"));
        CREDENTIAL_STORE_NAMES.contains(&name.as_str())
            || (harness_login_store(name) && !names[index + 1..].iter().any(|n| n == "plugins"))
            || name.starts_with(".env")
            || (config_child && NESTED_CREDENTIAL_STORE_NAMES.contains(&name.as_str()))
    })
}

/// No component below the home directory is a credential store, and no store
/// sits directly below `.config` or `.local/share` on the way.
pub(crate) fn clears_store_screen(path: &Path) -> bool {
    !names_hold_credential_store(&lowered_names(path))
}

/// The lowercased ordinary components of `path`.
pub(crate) fn lowered_names(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

/// Whether `name`, a lowercased file name, is one a secret is normally written
/// under. A content read below a hidden directory refuses these; a listing does
/// not need to, because it never returns what is inside them.
pub(crate) fn secret_bearing_file_name(name: &str) -> bool {
    if SECRET_BEARING_SUFFIXES
        .iter()
        .any(|suffix| name.ends_with(suffix))
        // `id_ed25519`, `id_rsa.pub`: a private key is named for the algorithm,
        // not for what it is.
        || name.starts_with("id_")
    {
        return true;
    }
    // `.credentials.json` names the same thing `credentials.json` does, so the
    // leading dot is stripped before the stem is read.
    let bare = name.strip_prefix('.').unwrap_or(name);
    SECRET_BEARING_STEMS.contains(&bare.split('.').next().unwrap_or(bare))
}

/// The directories and files below a harness home that hold documents rather
/// than an account. A harness home mixes the two: `~/.codex/skills` and
/// `~/.claude/settings.json` are what an agent is asked to read all day, while
/// `sessions/`, `projects/` and `shell-snapshots/` hold whole transcripts and
/// captured environments, and the login sits in `auth.json` beside them. Naming
/// the document side is what lets an ordinary
/// `ls ~/.codex/plans/order-intake` through without opening the rest.
pub(crate) const HARNESS_HOME_DOCUMENT_NAMES: [&str; 11] = [
    "agents",
    "agents.md",
    "claude.md",
    "commands",
    "docs",
    "plans",
    "plugins",
    "prompts",
    "settings.json",
    "settings.local.json",
    "skills",
];

/// Whether every harness home on `lowered` is entered at its document side.
///
/// The home itself is refused: its entry names are the account surface. So is
/// any child this list does not name, because a harness writes its login and
/// its saved conversations beside the notes under names that change with the
/// harness version.
fn harness_home_reads_a_document(lowered: &[String]) -> bool {
    lowered.iter().enumerate().all(|(index, name)| {
        !HARNESS_HOME_NAMES.contains(&name.as_str())
            || lowered
                .get(index + 1)
                .is_some_and(|child| HARNESS_HOME_DOCUMENT_NAMES.contains(&child.as_str()))
    })
}

/// Whether a content read of `path` may cross its hidden components. Every
/// hidden component must clear the store screen, and the file's own name must
/// not be one a secret is normally written under. A harness home is entered
/// only at its document side: its login and its saved conversations live beside
/// the notes, so the home itself and every child outside
/// [`HARNESS_HOME_DOCUMENT_NAMES`] keep review.
pub(crate) fn hidden_content_read_allowed(lowered: &[String]) -> bool {
    if !lowered.iter().any(|part| part.starts_with('.')) {
        return true;
    }
    if names_hold_credential_store(lowered) || !harness_home_reads_a_document(lowered) {
        return false;
    }
    lowered
        .last()
        .is_none_or(|name| !secret_bearing_file_name(name))
}
