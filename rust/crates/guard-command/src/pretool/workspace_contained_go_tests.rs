//! Go's local verbs build and test inside the workspace sandbox; the verbs
//! that fetch keep the admission they have.
use crate::pretool::workspace_contained_tests::{controls, workspace, CONTAINED};

const MODULE: &str = "module example.com/app\n\ngo 1.22\n";

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

/// A checkout that is a Go module.
fn module(name: &str) -> std::path::PathBuf {
    let ws = workspace(name, true);
    std::fs::write(ws.join("go.mod"), MODULE).unwrap();
    std::fs::write(ws.join("go.sum"), "").unwrap();
    ws
}

#[test]
fn go_builds_and_tests_the_module_inside_the_sandbox() {
    let ws = module("go-local");
    for command in [
        "go build ./...",
        "go test ./... 2>&1 | tail -15",
        "go vet ./...",
        "go run ./cmd/app",
        "go list -m",
        "go env GOCACHE",
        "go version",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_eq!(reason, CONTAINED, "{harness}: {command}");
        }
    }
}

#[test]
fn the_fetching_verbs_and_a_bare_directory_keep_their_review() {
    let ws = module("go-registry");
    for command in [
        "go get golang.org/x/text",
        "go install golang.org/x/tools/cmd/stringer@latest",
        "go mod download",
        "go mod tidy",
        "go work sync",
        "go clean -modcache",
        "go build ./... && go get golang.org/x/text",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
        }
    }
    // Outside a module the same verbs read the wider GOPATH, which the
    // workspace sandbox does not hold.
    let bare = workspace("go-bare", true);
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "go build ./...", &bare);
        assert_ne!(reason, CONTAINED, "{harness}");
    }
}
