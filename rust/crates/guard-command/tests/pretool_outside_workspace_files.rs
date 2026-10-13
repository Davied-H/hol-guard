#![cfg(unix)]

//! Reads, listings and new files outside the session workspace: sibling
//! checkouts and new home directories are ordinary working space, while
//! credential contents, home dotfiles and tool configuration stay reviewed.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn fixture(name: &str) -> Fixture {
    // Avoid macOS's protected /private/var temporary root.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-outside-workspace-files")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    for repository in ["project", "sibling"] {
        let path = home.join("code").join(repository);
        std::fs::create_dir_all(&path).unwrap();
        assert!(Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(&path)
            .status()
            .unwrap()
            .success());
    }
    let sibling = home.join("code/sibling");
    write(
        &sibling.join("package.json"),
        "{\"scripts\":{\"build\":\"tsc\"}}\n",
    );
    write(&sibling.join("src/index.ts"), "export {};\n");
    write(&sibling.join("tests/index.test.ts"), "export {};\n");
    write(&sibling.join("existing.txt"), "keep\n");
    write(&sibling.join(".env"), "SYNTHETIC_ONLY=fixture\n");
    write(
        &home.join("kubeconfig.yaml"),
        "apiVersion: v1\nkind: Config\n",
    );
    write(&home.join(".ssh/id_rsa"), "synthetic fixture\n");
    write(
        &home.join(".bun/install/global/node_modules/vite/package.json"),
        "{}\n",
    );
    write(&home.join(".bun/install/cache/entry.json"), "{}\n");
    write(
        &home.join(".nvm/.cache/node_modules/left-pad/package.json"),
        "{}\n",
    );
    write(
        &home.join(".nvm/versions/node/v1.0.0/lib/node_modules/npm/package.json"),
        "{}\n",
    );
    let home = std::fs::canonicalize(&home).unwrap();
    Fixture {
        root,
        project: home.join("code/project"),
        home,
    }
}

fn decision(fixture: &Fixture, harness: &str, input: Value) -> String {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &input,
        None,
        None,
        fixture.home.to_str(),
        fixture.project.to_str(),
    )
    .minimum_action
}

fn shell_allowed(fixture: &Fixture, command: &str) -> bool {
    let input = json!({"toolName": "Bash", "toolInput": {"command": command}});
    let zcode = decision(fixture, "zcode", input.clone());
    assert_eq!(
        zcode,
        decision(fixture, "omp", input),
        "host policy drift: {command}"
    );
    zcode == "allow"
}

fn write_allowed(fixture: &Fixture, path: &str) -> bool {
    let input = json!({"toolName": "Write", "toolInput": {"file_path": path, "content": "x\n"}});
    decision(fixture, "claude-code", input) == "allow"
}

fn check(fixture: &Fixture, allowed: &[&str], reviewed: &[&str]) {
    for command in allowed {
        assert!(shell_allowed(fixture, command), "{command}");
    }
    for command in reviewed {
        assert!(!shell_allowed(fixture, command), "{command}");
    }
}

#[test]
fn new_files_and_directories_outside_the_workspace() {
    let fixture = fixture("creates");
    check(
        &fixture,
        &[
            "mkdir -p ~/deliverables",
            "mkdir ~/code/sibling/reports",
            "touch ~/code/sibling/notes.txt",
            "touch -- ~/code/sibling/src/new.ts",
        ],
        &[
            "mkdir -p ~/.deliverables",
            "mkdir -p ~/bin",
            "mkdir -p ~/code/sibling/.husky",
            "mkdir -p ~/code/sibling/.git/hooks",
            "touch ~/.probe",
            "touch ~/code/sibling/.envrc",
            "touch ~/Library/LaunchAgents/probe.plist",
            "touch ~/code/sibling/existing.txt && rm ~/code/sibling/existing.txt",
        ],
    );
}

#[test]
fn plain_dot_scratch_writes_in_sibling_checkouts() {
    let fixture = fixture("dot-scratch");
    let sibling = fixture.home.join("code/sibling");
    for name in [".write-test", ".tmp/validate.mjs", ".scratch/notes.md"] {
        let path = sibling.join(name);
        assert!(write_allowed(&fixture, path.to_str().unwrap()), "{name}");
    }
    let code = fixture.home.join("code/.probe.txt");
    assert!(write_allowed(&fixture, code.to_str().unwrap()), "org probe");
    for name in [
        ".envrc",
        ".env.local",
        ".npmrc",
        ".yarnrc.yml",
        ".bunfig.toml",
        ".gitattributes",
        ".gitmodules",
        ".git/hooks/pre-commit",
        ".husky/pre-commit",
        ".pre-commit-config.yaml",
        ".vscode/tasks.json",
        ".github/workflows/ci.yml",
        ".claude/settings.json",
        ".codex/config.toml",
        ".cursor/mcp.json",
        ".mcp.json",
        ".tmp/.envrc",
    ] {
        let path = sibling.join(name);
        assert!(!write_allowed(&fixture, path.to_str().unwrap()), "{name}");
    }
    for name in [".probe", ".tmp/probe.txt", ".bashrc"] {
        let path = fixture.home.join(name);
        assert!(!write_allowed(&fixture, path.to_str().unwrap()), "{name}");
    }
}

#[test]
fn credential_files_allow_metadata_but_not_contents() {
    let fixture = fixture("metadata");
    check(
        &fixture,
        &[
            "ls -la ~/kubeconfig.yaml",
            "ls -la ~/kubeconfig.yaml 2>&1 | head -2",
        ],
        &[
            "cat ~/kubeconfig.yaml",
            "head -5 ~/kubeconfig.yaml",
            "ls -la ~/.ssh/id_rsa",
            "ls -la ~/.ssh",
            "cat ~/code/sibling/.env",
        ],
    );
}

#[test]
fn global_package_trees_list_without_their_tool_state() {
    let fixture = fixture("global-packages");
    check(
        &fixture,
        &[
            "ls ~/.bun/install/global/node_modules",
            "ls ~/.bun/install/global/node_modules 2>/dev/null",
            "ls ~/.nvm/versions/node/v1.0.0/lib/node_modules/",
            "ls -la ~/.nvm/versions/node/v1.0.0/lib/node_modules/npm",
        ],
        &[
            "ls ~/.bun/install/cache",
            "ls ~/.bun",
            "ls ~/.nvm/.cache/node_modules",
            "ls -R ~/.bun/install/global/node_modules",
        ],
    );
}

#[test]
fn jq_pipelines_reshape_without_reaching_input_or_environment() {
    let fixture = fixture("jq");
    check(
        &fixture,
        &[
            "jq -r '.scripts | keys | length' ~/code/sibling/package.json",
            "jq '.scripts|keys_unsorted|sort' ~/code/sibling/package.json",
        ],
        &[
            "jq -r '.scripts | env' ~/code/sibling/package.json",
            "jq -r '.scripts | input' ~/code/sibling/package.json",
            "jq -r '.scripts | $ENV' ~/code/sibling/package.json",
            "jq -r '.scripts | keys' ~/code/sibling/.env",
        ],
    );
}

#[test]
fn write_probe_removes_only_the_file_it_created() {
    let fixture = fixture("probe");
    check(
        &fixture,
        &[
            "touch ~/code/sibling/probe.txt && echo ok || echo fail; rm -f ~/code/sibling/probe.txt 2>/dev/null",
            "touch ~/code/sibling/probe.txt && rm ~/code/sibling/probe.txt",
        ],
        &[
            "touch ~/code/sibling/existing.txt && echo ok; rm -f ~/code/sibling/existing.txt",
            "touch ~/code/sibling/probe.txt; rm -f ~/code/sibling/existing.txt",
            "touch ~/code/sibling/probe.txt && cat ~/code/sibling/.env; rm -f ~/code/sibling/probe.txt",
            "touch ~/code/sibling/probe.txt | rm -f ~/code/sibling/probe.txt",
            "touch ~/.probe && rm -f ~/.probe",
            "rm -f ~/code/sibling/existing.txt",
        ],
    );
}

#[test]
fn cd_sequences_prove_reads_in_both_directories() {
    let fixture = fixture("cd-sequence");
    check(
        &fixture,
        &[
            "cd ~/code/sibling && ls src; ls tests",
            "cd ~/code/sibling && ls src; ls tests; ls",
        ],
        &[
            "cd ~/code/sibling && ls src; cat .env",
            "cd ~/code/sibling && ls src; rm -f existing.txt",
            "cd ~/code/sibling; ls src",
            "cd ~/code/sibling || ls src; ls tests",
            "cd ~/.ssh && ls; ls",
        ],
    );
}
