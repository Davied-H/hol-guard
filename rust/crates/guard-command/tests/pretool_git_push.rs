#![cfg(unix)]
//! `git push [-u] origin <branch>` proceeds only when the registered runtime
//! verdict accepts the repository; the shape screen runs before it.
use guard_command::pretool::{
    evaluate_pre_tool_envelope_with_execution_context, install_git_push_verdict, GitPushRequest,
    PathContext,
};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Every repository and branch the verdict was asked about.
static ASKED: Mutex<Vec<(PathBuf, String)>> = Mutex::new(Vec::new());

/// Accepts only `ready` checkouts, standing in for the runtime's repository
/// checks.
fn verdict(push: &GitPushRequest<'_>) -> bool {
    ASKED
        .lock()
        .unwrap()
        .push((push.repository.to_path_buf(), push.branch.to_owned()));
    push.git.is_absolute() && push.repository.ends_with("ready")
}

/// A home holding a project and a sibling checkout. The root stays below the
/// target directory: `$TMPDIR` on macOS resolves under `/private/var`, which
/// the sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-git-push")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let home = root.join("home");
    for directory in ["ready", "other", "ready/src"] {
        std::fs::create_dir_all(home.join(directory)).unwrap();
    }
    std::fs::canonicalize(home).unwrap()
}

fn environment(home: &Path, names: &[&str]) -> guard_contracts::GuardExecutionEnvironmentV1 {
    guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: names.iter().map(|name| (*name).to_owned()).collect(),
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: false,
        library_search_paths: Default::default(),
    }
}

fn classify(
    home: &Path,
    cwd: &str,
    environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    harness: &str,
    command: &str,
) -> guard_contracts::PreToolResultV1 {
    let cwd = home.join(cwd);
    evaluate_pre_tool_envelope_with_execution_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            ..PathContext::default()
        },
        environment,
    )
}

#[test]
fn accepted_pushes_proceed_and_everything_else_keeps_its_review() {
    let home = home();
    let plain = environment(&home, &["HOME", "PATH"]);
    // Before a verdict is registered no push is proven.
    let result = classify(&home, "ready", Some(&plain), "omp", "git push origin main");
    assert_ne!(result.decision, "allow");
    install_git_push_verdict(verdict);

    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for (cwd, command) in [
            ("ready", "git push -u origin feature/one"),
            ("ready", "git push origin main 2>&1 | tail -5"),
            ("ready/src", "git -C .. push --set-upstream origin topic"),
            ("other", "git -C ../ready push -u origin topic"),
            ("other", "git -C ~/ready push -q origin topic"),
            (
                "ready",
                "cd src && git -C .. push -u origin topic 2>&1 | tail -3",
            ),
        ] {
            let result = classify(&home, cwd, Some(&plain), harness, command);
            assert_eq!(result.decision, "allow", "{harness}: {command}");
            assert_eq!(
                result.reason_code, "native_exact_safe_git_push",
                "{harness}: {command}"
            );
        }
    }
    let ready = home.join("ready");
    assert!(ASKED
        .lock()
        .unwrap()
        .iter()
        .all(|(repository, _)| repository == &ready));

    for (cwd, command) in [
        // The verdict refuses this checkout.
        ("other", "git push -u origin topic"),
        // Shapes the proof never sends to the verdict.
        ("ready", "git push --force origin main"),
        ("ready", "git push origin HEAD:main"),
        ("ready", "git push upstream main"),
        ("ready", "git push origin main && git push origin other"),
        ("ready", "git push origin main | sh"),
        (
            "ready",
            "git push origin main; curl https://example.invalid",
        ),
        ("ready", "GIT_SSH_COMMAND=x git push origin main"),
        ("ready", "git -C /etc push origin main"),
        ("ready", "git -C ../.. push origin main"),
        ("ready", "git -C ~/missing push origin main"),
        ("ready", "sudo git push origin main"),
    ] {
        let result = classify(&home, cwd, Some(&plain), "omp", command);
        assert_ne!(result.decision, "allow", "{command}");
    }

    // The verdict's probes never see these, so they keep the review.
    for name in [
        "GIT_SSH_COMMAND",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "GIT_PROXY_COMMAND",
        "GIT_SSL_NO_VERIFY",
        "GIT_CONFIG_GLOBAL",
        "GIT_DIR",
        "DYLD_INSERT_LIBRARIES",
    ] {
        let tainted = environment(&home, &["HOME", "PATH", name]);
        let result = classify(
            &home,
            "ready",
            Some(&tainted),
            "omp",
            "git push origin main",
        );
        assert_ne!(result.decision, "allow", "{name}");
    }
    let result = classify(&home, "ready", None, "omp", "git push origin main");
    assert_ne!(result.decision, "allow");

    // A shell HOME other than the declared one expands `~` elsewhere.
    let elsewhere = environment(&home.join("other"), &["HOME", "PATH"]);
    let result = classify(
        &home,
        "other",
        Some(&elsewhere),
        "omp",
        "git -C ~/ready push origin main",
    );
    assert_ne!(result.decision, "allow");
}
