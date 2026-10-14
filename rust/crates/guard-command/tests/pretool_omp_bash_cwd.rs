#![cfg(unix)]

use crate::git_helper_fixture::evaluate_pre_tool_envelope_with_context;
use crate::pretool_git_session_ops::{default_controls, session, Session};
use guard_contracts::PreToolResultV1;
use serde_json::{json, Value};

const REVIEW: &str = "native_omp_bash_cwd_review";

fn omp(session: &Session, input: Value) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": input}),
        Some(&default_controls()),
        None,
        session.home.to_str(),
        session.org.to_str(),
    )
}

fn outcome(result: &PreToolResultV1) -> (String, String) {
    (result.minimum_action.clone(), result.reason_code.clone())
}

#[test]
fn bash_cwd_below_the_session_directory_is_the_command_directory() {
    let session = session("omp-cwd-within");
    let primary = session.primary.to_str().unwrap();
    let chain = "git fetch origin main && git log -6 --oneline --decorate origin/main \
        && git merge-base --is-ancestor HEAD origin/main; printf 'exit=%s\\n' \"$?\"";
    for cwd in [primary, "app-portal", "./app-portal/", "~/org/app-portal"] {
        for command in ["git fetch origin main", chain] {
            let result = omp(&session, json!({"command": command, "cwd": cwd}));
            assert_eq!(
                result.minimum_action, "allow",
                "{cwd}: {command}: {}",
                result.reason_code
            );
        }
    }
    // The command stays judged in that directory, not the session one.
    std::fs::write(session.primary.join(".env"), "TOKEN=fixture\n").unwrap();
    let result = omp(
        &session,
        json!({"command": "cat .env", "cwd": "app-portal"}),
    );
    assert_ne!(result.minimum_action, "allow", "{}", result.reason_code);
}

#[test]
fn bash_cwd_naming_the_session_directory_changes_nothing() {
    let session = session("omp-cwd-session");
    for command in ["git status --short", "git fetch origin main", "rm -rf ~/x"] {
        let bare = outcome(&omp(&session, json!({"command": command})));
        for cwd in ["", ".", "/", "//", session.org.to_str().unwrap()] {
            let result = omp(&session, json!({"command": command, "cwd": cwd}));
            assert_eq!(outcome(&result), bare, "{cwd:?}: {command}");
        }
    }
}

#[test]
fn bash_cwd_outside_the_session_directory_is_judged_as_a_leading_cd() {
    let session = session("omp-cwd-outside");
    let ssh = session.home.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::write(ssh.join("config"), "Host fixture\n").unwrap();
    // A link inside the session directory still runs in its target.
    std::os::unix::fs::symlink(&ssh, session.org.join("keys")).unwrap();
    for cwd in ["~/.ssh", ssh.to_str().unwrap(), "../.ssh", "keys"] {
        let result = omp(&session, json!({"command": "cat config", "cwd": cwd}));
        assert_ne!(
            result.minimum_action, "allow",
            "{cwd}: {}",
            result.reason_code
        );
        let result = omp(&session, json!({"command": "rm -rf build", "cwd": cwd}));
        assert_ne!(
            result.minimum_action, "allow",
            "{cwd}: {}",
            result.reason_code
        );
    }
    let worktree = session.worktree.to_str().unwrap();
    let projected = omp(
        &session,
        json!({"command": format!("cd '{worktree}' && git status --short")}),
    );
    let result = omp(
        &session,
        json!({"command": "git status --short", "cwd": worktree}),
    );
    assert_eq!(outcome(&result), outcome(&projected));
}

#[test]
fn unmodeled_bash_cwd_forms_require_review() {
    let session = session("omp-cwd-unresolved");
    let primary = session.primary.to_str().unwrap();
    for cwd in [
        json!("@app-portal"),
        json!(format!(":{primary}")),
        json!(format!("file://{primary}")),
        json!("skill://example"),
        json!("missing"),
        json!("tracked.txt"),
        json!("~other"),
        json!("app\\portal"),
        json!("app\u{00a0}portal"),
        json!(5),
        json!(null),
    ] {
        let result = omp(
            &session,
            json!({"command": "git status --short", "cwd": cwd}),
        );
        assert_eq!(outcome(&result), ("review".into(), REVIEW.into()), "{cwd}");
    }
    let conflicting = evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({
            "tool_name": "bash",
            "tool_input": {"command": "git status --short", "cwd": "app-portal"},
            "toolInput": {"command": "git status --short", "cwd": "."},
        }),
        Some(&default_controls()),
        None,
        session.home.to_str(),
        session.org.to_str(),
    );
    assert_eq!(outcome(&conflicting), ("review".into(), REVIEW.into()));
}
