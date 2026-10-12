//! A template-free `mktemp` only creates a fresh owner-only scratch entry.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};

fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-mktemp-scratch")
        .join(format!("home-{}", std::process::id()));
    let project = root.join("home/project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::canonicalize(root.join("home")).unwrap()
}

fn shell(home: &Path, command: &str) -> String {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        home.to_str(),
        home.join("project").to_str(),
    )
    .minimum_action
}

#[test]
fn template_free_mktemp_proceeds() {
    let home = home();
    for command in ["mktemp", "mktemp -d", "mktemp -d -q", "mktemp -dq"] {
        assert_eq!(shell(&home, command), "allow", "{command}");
    }
}

#[test]
fn templated_or_redirected_mktemp_is_not_proven() {
    let home = home();
    for command in [
        "mktemp ~/.ssh/authorized_keys.XXXX",
        "mktemp -p ~/.ssh",
        "mktemp -t scratch",
        "mktemp --tmpdir=/etc",
        "TMPDIR=~/.ssh mktemp -d",
        "mktemp -d > ~/.bashrc",
    ] {
        assert_ne!(shell(&home, command), "allow", "{command}");
    }
}
