use crate::native_command_controls::CompiledNativeCommandControls;
use crate::native_command_program::packaged_command_program;
use guard_contracts::NativeCommandControlBindingV1;
use std::path::PathBuf;

fn controls() -> CompiledNativeCommandControls {
    let program = packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest, "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest, "health": "protected",
        "revision": 1, "managed_revision": 0, "effective_digest": "", "layers": []
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    CompiledNativeCommandControls::new(&binding).unwrap()
}

fn workspace(name: &str, git: bool) -> PathBuf {
    let root = std::env::temp_dir().join(format!("guard-ws-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("package.json"), "{}").unwrap();
    if git {
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    }
    root.canonicalize().unwrap()
}

fn reason(harness: &str, command: &str, cwd: &std::path::Path, with_controls: bool) -> String {
    let controls = controls();
    crate::pretool::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
        with_controls.then_some(&controls),
        None,
        Some("/Users/nobody"),
        cwd.to_str(),
    )
    .reason_code
}

const CONTAINED: &str = "native_workspace_containment_required";

#[test]
fn unproven_local_commands_run_in_the_workspace_sandbox_on_macos() {
    let ws = workspace("convert", true);
    for command in [
        "./todo.py add x",
        "node -e 1",
        "python3 app.py",
        "mkdir -p src && touch src/a.js",
        "git add -A && git commit -m x",
        "npm run build && git diff",
    ] {
        let got = reason("omp", command, &ws, true);
        if cfg!(target_os = "macos") {
            assert_eq!(got, CONTAINED, "{command}");
        } else {
            assert_ne!(got, CONTAINED, "{command}");
        }
    }
}

#[test]
fn git_init_converts_only_in_a_fresh_workspace() {
    let fresh = workspace("init", false);
    let existing = workspace("init-existing", true);
    let expected = cfg!(target_os = "macos");
    assert_eq!(
        reason("omp", "git init", &fresh, true) == CONTAINED,
        expected
    );
    assert_eq!(
        reason("omp", "git init && git add -A", &fresh, true) == CONTAINED,
        expected
    );
    assert_ne!(reason("omp", "git init", &existing, true), CONTAINED);
    assert_ne!(reason("omp", "git init sub", &fresh, true), CONTAINED);
}

#[test]
fn commands_with_network_privilege_or_escape_stay_at_review() {
    let ws = workspace("reject", true);
    for command in [
        "git push origin main",
        "git fetch origin",
        "gh pr list",
        "curl https://example.com",
        "npm install",
        "sudo ls",
        "chmod 777 x",
        "echo $(x)",
        "echo hi > ../out",
        "git reset --hard",
        "git checkout main",
        "cat .env",
        "GIT_DIR=/x git status",
    ] {
        assert_ne!(reason("omp", command, &ws, true), CONTAINED, "{command}");
    }
}

#[test]
fn missing_evidence_keeps_the_command_at_review() {
    let ws = workspace("evidence", true);
    assert_ne!(reason("omp", "./todo.py add x", &ws, false), CONTAINED);
    assert_ne!(reason("cursor", "./todo.py add x", &ws, true), CONTAINED);
    assert_ne!(
        reason("omp", "./todo.py add x", &PathBuf::from("/"), true),
        CONTAINED
    );
    assert_ne!(
        reason(
            "omp",
            "./todo.py add x",
            &PathBuf::from("/private/tmp"),
            true
        ),
        CONTAINED
    );
}

#[test]
fn hostile_git_configuration_stays_at_review() {
    let ws = workspace("hostile", true);
    std::fs::write(
        ws.join(".git/config"),
        "[core]\n\thooksPath = /outside/hooks\n",
    )
    .unwrap();
    assert_ne!(reason("omp", "./todo.py add x", &ws, true), CONTAINED);
    std::fs::write(
        ws.join(".git/config"),
        "[core]\n\tfsmonitor = ./tools/mon\n",
    )
    .unwrap();
    let got = reason("omp", "./todo.py add x", &ws, true);
    assert_eq!(got == CONTAINED, cfg!(target_os = "macos"));
}
