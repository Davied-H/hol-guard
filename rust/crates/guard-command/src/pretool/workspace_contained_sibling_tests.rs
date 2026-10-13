//! `cd <sibling repository root> && …` runs contained in that root.
use crate::native_command_controls::CompiledNativeCommandControls;
use crate::native_command_program::packaged_command_program;
use guard_contracts::NativeCommandControlBindingV1;
use std::path::{Path, PathBuf};

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

fn host() -> bool {
    cfg!(target_os = "macos") || crate::restricted_pytest::linux_workspace_sandbox_available()
}

fn reason(harness: &str, home: &Path, cwd: &Path, command: &str) -> String {
    let controls = controls();
    crate::pretool::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
        Some(&controls),
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .reason_code
}

/// A main checkout, a linked worktree beside it, an unrelated clone and a
/// plain directory, all below a private home.
fn fixture() -> (PathBuf, PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("guard-sibling-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let projects = root.join("home/projects");
    let (main, tree) = (projects.join("app"), projects.join("app-report"));
    let admin = main.join(".git/worktrees/app-report");
    for directory in [
        &admin,
        &tree.join("scripts"),
        &projects.join("other/.git"),
        &projects.join("plain"),
    ] {
        std::fs::create_dir_all(directory).unwrap();
    }
    let home = root.join("home").canonicalize().unwrap();
    let (main, tree) = (main.canonicalize().unwrap(), tree.canonicalize().unwrap());
    let admin = admin.canonicalize().unwrap();
    for config in [main.join(".git/config"), projects.join("other/.git/config")] {
        std::fs::write(config, "[core]\n\tbare = false\n").unwrap();
    }
    std::fs::write(admin.join("commondir"), "../..\n").unwrap();
    std::fs::write(
        admin.join("gitdir"),
        format!("{}\n", tree.join(".git").display()),
    )
    .unwrap();
    std::fs::write(tree.join(".git"), format!("gitdir: {}\n", admin.display())).unwrap();
    for project in [
        &main,
        &tree,
        &projects.join("other"),
        &projects.join("plain"),
    ] {
        std::fs::write(project.join("package.json"), "{}").unwrap();
    }
    (home, main, tree)
}

fn contained(reason: &str) -> bool {
    reason.ends_with("_containment_required")
}

#[test]
fn a_list_after_cd_into_a_sibling_root_runs_contained_there() {
    let (home, main, tree) = fixture();
    let absolute = format!(
        "cd {} && node scripts/report.mjs && cat reports/weekly.md",
        tree.display()
    );
    for command in [
        "cd ../app-report && node scripts/report.mjs && cat reports/weekly.md",
        "cd ../app-report && npm run build && ls dist",
        "cd ../other && npm run build && cat package.json",
        absolute.as_str(),
    ] {
        assert_eq!(
            contained(&reason("omp", &home, &main, command)),
            host(),
            "{command}"
        );
    }
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

#[test]
fn a_sibling_cd_the_sink_would_not_rebase_keeps_its_review() {
    let (home, main, _tree) = fixture();
    for command in [
        // Not a repository root, or no repository at all.
        "cd ../app-report/scripts && node report.mjs && cat out.md",
        "cd ../plain && npm run build && ls dist",
        "cd .. && npm run build && ls dist",
        // A pipe or `;` is not the `&&` list the sink peels.
        "cd ../app-report && npm run build && ls | wc -l",
        "cd ../app-report; npm run build && ls dist",
        // The rest still faces every check it would from that root.
        "cd ../app-report && git add -A && git status",
        "cd ../app-report && npm run build && curl https://example.com",
        "cd ../app-report && npm run build && cat ../app/.git/config",
        "cd ../app-report && npm run build && rm -rf .",
        "cd ../app-report && ls && rm notes.txt",
    ] {
        assert!(
            !contained(&reason("omp", &home, &main, command)),
            "{command}"
        );
    }
    assert!(!contained(&reason(
        "cursor",
        &home,
        &main,
        "cd ../app-report && npm run build && ls dist"
    )));
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}
