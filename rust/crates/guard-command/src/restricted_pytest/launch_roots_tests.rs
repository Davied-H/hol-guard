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
    outside_from(root, program, search_path, vec![Some(workspace)])
}

/// Whether `program` is unreachable when the shell may be in any of `places`.
fn outside_from(
    root: &Path,
    program: &str,
    search_path: &str,
    places: Vec<Option<PathBuf>>,
) -> bool {
    let workspace = root.join("workspace");
    launches_outside_exec_roots([(program, places)], search_path, None, &workspace)
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
fn an_env_interpreter_outside_the_roots_is_unreachable() {
    let root = scratch();
    let env = root.join("tools/env");
    tool(&env, "");
    tool(
        &root.join("workspace/by-env.py"),
        &format!("#!{} sh\n", env.display()),
    );
    tool(
        &root.join("workspace/quoted.py"),
        "#!/usr/bin/env -S -u FOO \"sh\"\n",
    );
    tool(
        &root.join("workspace/ambiguous.py"),
        "#!/usr/bin/env -S \"sh\n",
    );

    assert!(outside(&root, "./by-env.py", "/usr/bin:/bin"));
    assert!(!outside(&root, "./quoted.py", "/usr/bin:/bin"));
    assert!(outside(&root, "./ambiguous.py", "/usr/bin:/bin"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn relative_search_path_entries_resolve_from_the_session_directory() {
    let root = scratch();
    fs::create_dir_all(root.join("workspace/bin")).unwrap();
    tool(&root.join("workspace/bin/lanectl"), "#!/bin/sh\n");
    tool(&root.join("workspace/lanectl-here"), "#!/bin/sh\n");

    // Neither directory exists below this process's own working directory,
    // and the sandbox's search path has no relative entry to find them by.
    assert!(outside(&root, "lanectl", "bin:/usr/bin:/bin"));
    assert!(outside(&root, "lanectl-here", ":/usr/bin:/bin"));
    assert!(outside(&root, "lanectl-here", "/usr/bin:.:/bin"));
    assert!(!outside(&root, "lanectl-missing", "bin:/usr/bin:/bin"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_program_is_looked_up_from_every_directory_the_shell_may_be_in() {
    let root = scratch();
    let (workspace, tools) = (root.join("workspace"), root.join("workspace/tools"));
    fs::create_dir_all(&tools).unwrap();
    let python = root.join("tools/python3");
    tool(&python, "");
    tool(&tools.join("lanectl"), &format!("#!{}\n", python.display()));
    let path = "/usr/bin:/bin";

    assert!(!outside_from(
        &root,
        "./lanectl",
        path,
        vec![Some(workspace.clone())]
    ));
    assert!(outside_from(
        &root,
        "./lanectl",
        path,
        vec![Some(tools.clone())]
    ));
    assert!(outside_from(
        &root,
        "./lanectl",
        path,
        vec![Some(workspace), Some(tools)]
    ));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_lookup_that_needs_an_unknown_directory_is_unreachable() {
    let root = scratch();
    let unknown = || vec![None];

    assert!(outside_from(&root, "./run.sh", "/usr/bin:/bin", unknown()));
    assert!(outside_from(&root, "sh", "bin:/usr/bin:/bin", unknown()));
    assert!(!outside_from(&root, "sh", "/usr/bin:/bin", unknown()));
    assert!(!outside_from(
        &root,
        "/bin/sh",
        "bin:/usr/bin:/bin",
        unknown()
    ));
    let _ = fs::remove_dir_all(root);
}
