#![cfg(unix)]
//! Content reads below a hidden directory in the home directory.
//!
//! A hidden component used to end the lookup on its own, so an ordinary
//! `cat ~/.agents/skills/release-check/scripts/run.sh` collected an approval
//! nobody answered. What a hidden component has to clear is the credential
//! screen: the stores the listing screen refuses, the harness homes whose
//! login sits beside the notes, and the file names a token is normally
//! written under.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home with a Node toolchain, shared skills, a repository's own workflows,
/// a vendored crate, and the credential stores those reads must not reach. The
/// root stays below the target directory: `$TMPDIR` on macOS resolves under
/// `/private/var`, which the sensitive-root screen rejects.
fn home(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-home-dotdir-content-reads")
        .join(format!(
            "{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let home = root.join("home");
    for directory in [
        ".agents/skills/release-check/scripts",
        ".cargo/registry/src/index.crates.io/serde-1.0.0/src",
        ".certs",
        ".claude",
        ".codex",
        ".config/doctl",
        ".config/gcloud",
        ".config/gh",
        ".config/github-copilot",
        ".gemini",
        ".github/workflows",
        ".local/share/opencode",
        ".nvm/versions/node/v25.2.1/lib/node_modules/pkg",
        ".hol-support",
        ".secrets",
        ".ssh",
        "work/project/.git",
    ] {
        std::fs::create_dir_all(home.join(directory)).unwrap();
    }
    for (path, contents) in [
        (".agents/skills/release-check/SKILL.md", "# Release\n"),
        (".hol-support/SAFETY.md", "# Safety\n"),
        (".agents/skills/release-check/config.json", "{}\n"),
        (".agents/skills/release-check/scripts/run.sh", "#!/bin/sh\n"),
        (
            ".cargo/registry/src/index.crates.io/serde-1.0.0/src/lib.rs",
            "pub fn parse() {}\n",
        ),
        (".certs/server.pem", "-----BEGIN CERTIFICATE-----\n"),
        (".claude/.credentials.json", "{}\n"),
        (".codex/auth.json", "{}\n"),
        (".config/doctl/config.yaml", "access-token: x\n"),
        (".config/gcloud/credentials.db", "x\n"),
        (".config/gh/hosts.yml", "example.com:\n"),
        (".config/github-copilot/apps.json", "{}\n"),
        (".envrc", "export TOKEN=x\n"),
        (".gemini/oauth_creds.json", "{}\n"),
        (".github/workflows/ci.yml", "name: ci\n"),
        (".local/share/opencode/auth.json", "{}\n"),
        (
            ".nvm/versions/node/v25.2.1/lib/node_modules/pkg/package.json",
            "{\"name\": \"pkg\"}\n",
        ),
        (".secrets/service-account.json", "{}\n"),
        (".ssh/config", "Host example\n"),
        ("work/project/.git/HEAD", "ref: refs/heads/main\n"),
    ] {
        std::fs::write(home.join(path), contents).unwrap();
    }
    std::fs::canonicalize(home).unwrap()
}

fn action(home: &Path, harness: &str, command: &str) -> String {
    let cwd = home.join("work/project");
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .minimum_action
}

#[test]
fn ordinary_source_below_a_hidden_directory_reads() {
    let home = home("allowed");
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "cat ~/.agents/skills/release-check/scripts/run.sh",
            "head -20 ~/.agents/skills/release-check/scripts/run.sh",
            "cat ~/.github/workflows/ci.yml",
            "cat ~/.nvm/versions/node/v25.2.1/lib/node_modules/pkg/package.json",
            "cat ~/.cargo/registry/src/index.crates.io/serde-1.0.0/src/lib.rs",
        ] {
            assert_eq!(
                action(&home, harness, command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

#[test]
fn credential_stores_and_harness_logins_keep_review() {
    let home = home("stores");
    for harness in ["claude-code", "codex", "omp"] {
        for command in [
            "cat ~/.ssh/config",
            "cat ~/.config/gh/hosts.yml",
            "cat ~/.config/doctl/config.yaml",
            "cat ~/.config/github-copilot/apps.json",
            "cat ~/.config/gcloud/credentials.db",
            "cat ~/.local/share/opencode/auth.json",
            "cat ~/.codex/auth.json",
            "cat ~/.claude/.credentials.json",
            "cat ~/.gemini/oauth_creds.json",
        ] {
            assert_ne!(
                action(&home, harness, command),
                "allow",
                "{harness}: {command}"
            );
        }
    }
}

/// A token is written under its own name whatever directory holds it, so the
/// file name is screened even where every component cleared the store list.
#[test]
fn secret_bearing_file_names_keep_review_in_benign_directories() {
    let home = home("names");
    for command in [
        "cat ~/.agents/skills/release-check/config.json",
        "cat ~/.secrets/service-account.json",
        "cat ~/.certs/server.pem",
        "cat ~/.envrc",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
}

/// A narrower rule owns the agent guidance documents, with bounds a target
/// screen cannot see: the line range it was asked for, and whether the path
/// stays inside the home. Its verdict stands either way.
#[test]
fn agent_guidance_documents_keep_their_own_rule() {
    let home = home("guidance");
    assert_eq!(
        action(
            &home,
            "codex",
            "cat ~/.agents/skills/release-check/SKILL.md"
        ),
        "allow"
    );
    for command in [
        "sed -n '1,501p' ~/.hol-support/SAFETY.md",
        "sed -n '20,1p' ~/.hol-support/SAFETY.md",
    ] {
        assert_ne!(action(&home, "codex", command), "allow", "{command}");
    }
}
