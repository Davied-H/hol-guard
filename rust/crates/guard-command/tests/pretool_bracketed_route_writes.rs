#![cfg(unix)]
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::{json, Value};

struct Fixture {
    root: std::path::PathBuf,
    home: std::path::PathBuf,
    project: std::path::PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn fixture() -> Fixture {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-bracketed-route-writes")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    let project = home.join("project");
    for file in [
        "project/app/registry/[slug]/page.tsx",
        "project/app/[id]/settings.ts",
        "project/.git/hooks/pre-commit",
        ".ssh/config",
    ] {
        let path = home.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "synthetic fixture\n").unwrap();
    }
    std::fs::create_dir_all(root.join("outside")).unwrap();
    std::os::unix::fs::symlink(home.join(".ssh"), project.join("app/[link]")).unwrap();
    Fixture {
        root,
        home,
        project,
    }
}

fn run(f: &Fixture, harness: &str, tool: &str, input: Value) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": tool, "tool_input": input}),
        None,
        None,
        f.home.to_str(),
        f.project.to_str(),
    )
}

fn host_write(f: &Fixture, harness: &str, path: &str) -> guard_contracts::PreToolResultV1 {
    match harness {
        "omp" => run(f, harness, "write", json!({"path": path, "content": "x\n"})),
        _ => run(
            f,
            harness,
            "Write",
            json!({"file_path": path, "content": "x\n"}),
        ),
    }
}

#[test]
fn dynamic_route_files_are_literal_workspace_writes() {
    let f = fixture();
    let existing = f.project.join("app/registry/[slug]/page.tsx");
    let new_subtree = f
        .project
        .join("app/api/guard/extensions/[id]/promotion/local-distribution/route.ts");
    let catch_all = f.project.join("app/docs/[...slug]/page.tsx");
    let optional = f.project.join("app/shop/[[...slug]]/page.tsx");
    for harness in ["claude-code", "zcode", "omp"] {
        for path in [&existing, &new_subtree, &catch_all, &optional] {
            let path = path.to_str().unwrap();
            let result = host_write(&f, harness, path);
            assert_eq!(
                (result.minimum_action.as_str(), result.reason_code.as_str()),
                ("allow", "native_exact_safe_file_write"),
                "{harness} {path}"
            );
        }
        let result = host_write(&f, harness, "app/[id]/settings.ts");
        assert_eq!(result.minimum_action, "allow", "{harness}: {result:?}");
    }
    let existing = existing.to_str().unwrap();
    let result = run(
        &f,
        "claude-code",
        "Edit",
        json!({"file_path": existing, "old_string": "synthetic", "new_string": "updated"}),
    );
    assert_eq!(result.minimum_action, "allow", "{result:?}");
    let result = run(
        &f,
        "omp",
        "edit",
        json!({"path": "app/[id]/settings.ts", "oldText": "synthetic", "newText": "updated"}),
    );
    assert_eq!(result.minimum_action, "allow", "{result:?}");
}

#[test]
fn bracketed_writes_keep_every_other_screen() {
    let f = fixture();
    let outside = f.root.join("outside/[id]/route.ts");
    let home_dotfile = f.home.join(".zshrc");
    let git_hook = f.project.join(".git/hooks/pre-commit");
    for path in [
        // Other glob metacharacters and parent components stay rejected.
        "app/[id]/*.ts",
        "app/{a,b}/[id].ts",
        "app/[id]/../../../outside/escape.ts",
        // A bracketed directory that links elsewhere resolves to its target.
        "app/[link]/config",
        // Hidden and protected targets inside the workspace stay reviewed.
        "app/[id]/.env",
        "[id]/.git/hooks/post-checkout",
        git_hook.to_str().unwrap(),
        ".claude/settings.json",
        // Writes outside the workspace and verified home stay reviewed.
        outside.to_str().unwrap(),
        home_dotfile.to_str().unwrap(),
    ] {
        for harness in ["claude-code", "zcode", "omp"] {
            let result = host_write(&f, harness, path);
            assert_ne!(
                result.minimum_action, "allow",
                "{harness} {path}: {result:?}"
            );
        }
    }
}
