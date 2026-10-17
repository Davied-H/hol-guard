use super::*;
use std::os::unix::fs::PermissionsExt;

static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A fresh directory holding `workspace/` and `tools/`; neither `tools`
/// directory is a `bin` the toolchain rules could accept.
fn scratch() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "guard-launch-roots-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("workspace")).unwrap();
    fs::create_dir_all(root.join("tools")).unwrap();
    root.canonicalize().unwrap()
}

fn tool(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn outside(root: &Path, program: &str, search_path: &str) -> bool {
    let workspace = root.join("workspace");
    launches_outside_exec_roots([program], search_path, None, &workspace, &workspace)
}

#[test]
fn a_program_found_only_outside_the_roots_is_unreachable() {
    let root = scratch();
    tool(&root.join("tools/lanectl"), "#!/bin/sh\n");
    let search_path = format!("{}:/usr/bin:/bin", root.join("tools").display());

    assert!(outside(&root, "lanectl", &search_path));
    assert!(outside(
        &root,
        root.join("tools/lanectl").to_str().unwrap(),
        "/usr/bin:/bin"
    ));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn system_and_workspace_programs_stay_reachable() {
    let root = scratch();
    tool(&root.join("workspace/run.sh"), "#!/bin/sh\necho ok\n");

    assert!(!outside(&root, "sh", "/usr/bin:/bin"));
    assert!(!outside(&root, "./run.sh", "/usr/bin:/bin"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_name_the_shell_cannot_find_is_left_to_the_shell() {
    let root = scratch();

    assert!(!outside(&root, "cd-not-a-real-program", "/usr/bin:/bin"));
    assert!(!outside(&root, "$TOOL", "/usr/bin:/bin"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_workspace_script_whose_interpreter_is_outside_is_unreachable() {
    let root = scratch();
    let python = root.join("tools/python3");
    tool(&python, "");
    tool(
        &root.join("workspace/direct.py"),
        &format!("#!{}\nprint('x')\n", python.display()),
    );
    tool(
        &root.join("workspace/by-name.py"),
        "#!/usr/bin/env -S lanectl-python -u\n",
    );
    tool(&root.join("workspace/system.sh"), "#!/usr/bin/env sh\n");

    assert!(outside(&root, "./direct.py", "/usr/bin:/bin"));
    assert!(outside(&root, "./by-name.py", "/usr/bin:/bin"));
    assert!(!outside(&root, "./system.sh", "/usr/bin:/bin"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn shebang_parsing_reads_env_operands_and_whole_lines_only() {
    let root = scratch();
    let script = root.join("workspace/s");
    for (body, expected) in [
        ("#!/bin/sh\n", Some("/bin/sh")),
        ("#!/usr/bin/env FOO=1 -i node --flag\n", Some("node")),
        ("#! /usr/bin/python3 -I", Some("/usr/bin/python3")),
        ("echo no shebang\n", None),
    ] {
        tool(&script, body);
        assert_eq!(interpreter(&script).as_deref(), expected, "{body}");
    }
    tool(&script, &format!("#!/{}", "a".repeat(SHEBANG_BYTES)));
    assert_eq!(interpreter(&script), None);
    let _ = fs::remove_dir_all(root);
}
