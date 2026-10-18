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

#[test]
fn the_options_that_make_uv_fetch_keep_their_review() {
    let ws = project("uv-fetching");
    for command in [
        "uv run --with httpx pytest",
        "uv run --with-requirements extra.txt pytest",
        "uv run --python 3.13 pytest",
        "uv run -p 3.13 pytest",
        "uv run --isolated pytest",
        "uv run --refresh pytest",
        "uv run --reinstall pytest",
        "uv run -U pytest",
        "uv run --find-links ./wheels pytest",
        "uv version --bump patch",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
    // An index the command names is read over the network, which the sandbox
    // has none of; what that remote host earns the command is not this
    // module's to say, only that the sandbox is not where it belongs.
    for command in [
        "uv run --index-url=https://example.invalid/simple pytest",
        "uv run --default-index https://example.invalid/simple pytest",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
        }
    }
}

#[test]
fn a_script_carrying_its_own_dependencies_keeps_its_review() {
    let ws = project("uv-script");
    std::fs::write(
        ws.join("report.py"),
        "#!/usr/bin/env python3\n# /// script\n# dependencies = [\"httpx\"]\n# ///\nprint(1)\n",
    )
    .unwrap();
    std::fs::write(ws.join("plain.py"), "print(1)\n").unwrap();
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, minimum) = outcome(harness, "uv run report.py", &ws);
        assert_ne!(reason, CONTAINED, "{harness}");
        assert_eq!(minimum, "review", "{harness} ({reason})");
        let (reason, _) = outcome(harness, "uv run plain.py", &ws);
        assert_eq!(reason, CONTAINED, "{harness}");
    }
}

#[test]
fn the_options_of_the_program_uv_starts_are_not_uvs_own() {
    let ws = project("uv-program");
    // `-p`, `-s` and `-f` mean an index, a script and a link source to uv,
    // but pytest and python spell their own options the same way.
    for command in [
        "uv run pytest -p no:cacheprovider",
        "uv run pytest -s tests/",
        "uv run python -i -c \"print(1)\"",
        "uv run ruff check -f github .",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_eq!(reason, CONTAINED, "{harness}: {command}");
        }
    }
}

#[test]
fn the_global_options_before_a_verb_are_read_past() {
    let ws = project("uv-global");
    for command in [
        "uv --offline run pytest",
        "uv -q run pytest",
        "uv --no-cache --quiet run pytest",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_eq!(reason, CONTAINED, "{harness}: {command}");
        }
    }
    // An option this module does not know could move or re-resolve the
    // project, so the command keeps the admission it has.
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "uv --mystery run pytest", &ws);
        assert_ne!(reason, CONTAINED, "{harness}");
    }
}

#[test]
fn the_project_a_verb_works_on_moves_with_the_command() {
    let ws = project("uv-nested");
    std::fs::create_dir_all(ws.join("api/.venv/bin")).unwrap();
    std::fs::write(ws.join("api/pyproject.toml"), PROJECT).unwrap();
    std::fs::create_dir_all(ws.join("web")).unwrap();
    std::fs::write(ws.join("web/pyproject.toml"), PROJECT).unwrap();
    for command in [
        "uv --directory api run pytest",
        "uv --project=api run pytest",
        "cd api && uv run pytest",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_eq!(reason, CONTAINED, "{harness}: {command}");
        }
    }
    // `web` has no environment of its own, so a run there would install.
    for command in ["uv --directory web run pytest", "cd web && uv run pytest"] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
        }
    }
}
