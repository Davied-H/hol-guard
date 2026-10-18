//! uv's local verbs run inside the workspace sandbox; its installing verbs
//! keep the admission they have.
use crate::pretool::workspace_contained_tests::{controls, workspace, CONTAINED};

const PROJECT: &str = "[project]\nname = \"app-portal\"\nversion = \"0.1.0\"\n";

fn outcome(harness: &str, command: &str, cwd: &std::path::Path) -> (String, String) {
    let controls = controls();
    let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
        Some(&controls),
        None,
        Some("/Users/nobody"),
        cwd.to_str(),
    );
    (result.reason_code, result.minimum_action)
}

/// A project whose environment uv has already materialized.
fn project(name: &str) -> std::path::PathBuf {
    let ws = workspace(name, true);
    std::fs::write(ws.join("pyproject.toml"), PROJECT).unwrap();
    std::fs::write(ws.join("uv.lock"), "version = 1\n").unwrap();
    std::fs::create_dir_all(ws.join(".venv/bin")).unwrap();
    ws
}

#[test]
fn uv_runs_the_project_environment_inside_the_sandbox() {
    let ws = project("uv-local");
    for command in [
        "uv run pytest -q",
        "uv run pytest -q 2>&1 | tail -15",
        "uv run python -c \"print(1)\"",
        "uv tree --depth 2",
        "uv export --no-dev",
        "uv version",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_eq!(reason, CONTAINED, "{harness}: {command}");
        }
    }
}

#[test]
fn uv_installs_and_unmaterialized_projects_keep_their_review() {
    let ws = project("uv-registry");
    for command in [
        "uv add requests",
        "uv pip install requests",
        "uv sync",
        "uv lock",
        "uv tool install ruff",
        "uvx ruff check .",
        "uv run pytest -q && uv add requests",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
    // Without `.venv` the run would have to install, and the sandbox has no
    // network, so it keeps the admission that can ask for one.
    let bare = workspace("uv-bare", true);
    std::fs::write(bare.join("pyproject.toml"), PROJECT).unwrap();
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "uv run pytest -q", &bare);
        assert_ne!(reason, CONTAINED, "{harness}");
    }
}

#[test]
fn the_other_python_managers_keep_their_review() {
    let ws = project("uv-managers");
    for command in [
        "pip install requests",
        "pip3 install -r requirements.txt",
        "pipx install ruff",
        "pipenv install",
        "poetry add requests",
        "poetry install",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
        }
    }
}
