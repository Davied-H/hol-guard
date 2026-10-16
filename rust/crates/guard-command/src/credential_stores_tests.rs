//! A hidden path is read as configuration unless it names a credential store.
use super::credential_stores::{credential_store_part, credential_store_path};

fn parts(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|part| !part.is_empty())
        .map(str::to_lowercase)
        .collect()
}

#[test]
fn credential_stores_are_named() {
    for path in [
        "users/o/.aws/credentials",
        "users/o/.ssh/id_ed25519",
        "users/o/.ssh/known_hosts",
        "users/o/.config/gh/hosts.yml",
        "users/o/.config/gcloud/application_default_credentials.json",
        "users/o/.config/doctl/config.yaml",
        "users/o/.codex/auth.json",
        "users/o/.docker/config.json",
        "users/o/.hol-guard/guard.db",
        "users/o/library/keychains/login.keychain-db",
        "users/o/.local/share/keyrings/login.keyring",
        "srv/app/.env.production",
        "srv/app/certs/server.pem",
        "srv/app/certs/bundle.p12",
        "users/o/.gnupg/pubring.kbx",
        "users/o/.password-store/github.gpg",
        "users/o/cascadeprojects/app/.git/config",
        "tmp$(rm/~/.ssh)",
    ] {
        assert!(credential_store_path(&parts(path)), "{path}");
    }
}

#[test]
fn ordinary_hidden_configuration_is_not_a_credential_store() {
    for path in [
        "users/o/.claude/settings.json",
        "users/o/.claude/projects/p/memory/notes.md",
        "users/o/.zcode/agents",
        "users/o/.codex/plans/release.md",
        "users/o/.agents/skills/review/skill.md",
        "users/o/cascadeprojects/app/.github/workflows/ci.yml",
        "users/o/cascadeprojects/app/.vscode/settings.json",
        "users/o/cascadeprojects/app/.cargo/config.toml",
        "users/o/cascadeprojects/app/.git/head",
        "users/o/.nvmrc",
        "users/o/.config/nvim/init.lua",
        "users/o/.local/share/fonts",
    ] {
        assert!(!credential_store_path(&parts(path)), "{path}");
    }
}

#[test]
fn a_store_is_recognised_by_its_own_name() {
    for part in [
        ".env",
        ".env.local",
        "credentials",
        "credentials.toml",
        "id_rsa.pub",
    ] {
        assert!(credential_store_part(part), "{part}");
    }
    for part in [
        ".github",
        ".claude",
        "config.toml",
        "settings.json",
        "envelope.rs",
    ] {
        assert!(!credential_store_part(part), "{part}");
    }
}
