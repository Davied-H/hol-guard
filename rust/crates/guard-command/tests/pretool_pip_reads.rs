#![cfg(unix)]
//! Installed-metadata reads with pip.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home holding one project. The root stays below the target directory:
/// `$TMPDIR` on macOS resolves under `/private/var`, which the sensitive-root
/// screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-pip-reads")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let project = root.join("home/project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("pyproject.toml"),
        "[project]\nname = \"fixture\"\n",
    )
    .unwrap();
    std::fs::canonicalize(root.join("home")).unwrap()
}

/// The decision every shell harness reaches, or the disagreement.
fn decide(home: &Path, command: &str) -> String {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: Vec::new(),
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: false,
        library_search_paths: Default::default(),
    };
    let project = home.join("project");
    let decisions: Vec<String> = ["omp", "claude-code", "codex"]
        .iter()
        .map(|harness| {
            evaluate_pre_tool_envelope_with_execution_context(
                harness,
                "PreToolUse",
                &json!({"tool_name": "bash", "tool_input": {"command": command}}),
                None,
                None,
                PathContext {
                    home_dir: home.to_str(),
                    cwd: project.to_str(),
                    cdpath_unset: false,
                    rustup_override_absent: false,
                    npm_config_inert: false,
                    shell_home_matches: false,
                    ripgrep_config_absent: false,
                    psql_environment: Default::default(),
                },
                Some(&environment),
            )
            .minimum_action
        })
        .collect();
    if decisions.iter().all(|decision| decision == &decisions[0]) {
        decisions[0].clone()
    } else {
        format!("mixed: {decisions:?}")
    }
}

// Agents check what an environment already holds before and after real work.
// None of these resolves, downloads or installs anything.
#[test]
fn installed_metadata_queries_proceed() {
    let home = home();
    for command in [
        "pip list",
        "pip list --format=json",
        "pip list --format=freeze",
        "pip list --local --not-required",
        "pip3 list",
        "pip list | head -20",
        "pip list 2>&1 | tail -5",
        "pip freeze",
        "pip freeze --exclude setuptools",
        "pip freeze | grep requests",
        "pip show requests",
        "pip show -f requests",
        "pip show requests urllib3",
        "pip check",
        "pip cache dir",
        "pip cache info",
        "pip cache list requests",
        "pip --version",
    ] {
        assert_eq!(decide(&home, command), "allow", "{command}");
    }
}

// Installs, index queries and cache deletions keep their review.
#[test]
fn installs_index_queries_and_cache_writes_stay_reviewed() {
    let home = home();
    for command in [
        "pip install requests",
        "pip install -r requirements.txt",
        "pip install -e .",
        "pip uninstall -y requests",
        "pip download requests",
        "pip wheel .",
        "pip list --outdated",
        "pip list -o",
        "pip list --index-url https://example.invalid/simple",
        "pip list --path /tmp/site-packages",
        "pip --log /tmp/pip.log list",
        "pip config list",
        "pip config set global.index-url https://example.invalid/simple",
        "pip debug",
        "pip freeze -r requirements.txt",
        "pip show ./local-dir",
        "pip cache purge",
        "pip cache remove requests",
    ] {
        assert_ne!(decide(&home, command), "allow", "{command}");
    }
}
