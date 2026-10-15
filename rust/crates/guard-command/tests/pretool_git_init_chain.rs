#![cfg(unix)]

//! A scratch repository made, written and committed in one `&&` chain is
//! quiet when the new directory is fresh and below a temporary directory only
//! the user can write, and the chain only prints, stages and commits there
//! with no configured program or hook. A planted or shared location, another
//! step, a `-c` setting beyond the identity or a hidden file keeps the review.

use crate::git_helper_fixture::FixtureCleanup;
use crate::pretool_git_session_ops::{git, session, Session};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const CHAIN: &str = "native_exact_safe_git_init_chain";

fn unique(label: &str) -> String {
    format!(
        "guard-init-chain-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

/// An owned 0700 directory directly in `/tmp`.
fn owned_parent() -> (PathBuf, FixtureCleanup) {
    let parent = std::fs::canonicalize("/tmp")
        .unwrap()
        .join(unique("parent"));
    let cleanup = FixtureCleanup(parent.clone());
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    (parent, cleanup)
}

fn allowed(session: &Session, command: &str, cwd: &Path) -> Result<(), String> {
    let result = session.evaluate_at(command, cwd);
    (result.minimum_action == "allow" && result.reason_code == CHAIN)
        .then_some(())
        .ok_or(format!("{command}: {}", result.reason_code))
}

#[test]
fn a_scratch_repository_made_and_committed_in_one_chain_is_quiet() {
    let session = session("init-chain");
    let (parent, _cleanup) = owned_parent();
    let scratch = parent.join("guard-scratch");
    let s = scratch.display();
    let init = format!("git init -q {s} && cd {s}");
    let commit = format!(
        "{init} && echo hi > a.txt && git add a.txt && git -c user.name=t -c user.email=t@t commit -qm test"
    );
    for cwd in [&session.org, &session.primary] {
        allowed(&session, &commit, cwd).unwrap();
    }
    for rest in [
        "printf 'x\\n' > notes.md && git add -A && git commit -m init",
        "git add . && git commit --author='A <a@example.test>' -m x",
    ] {
        allowed(&session, &format!("{init} && {rest}"), &session.org).unwrap();
    }

    let commit_tail = "git add a.txt && git commit -qm test";
    for command in [
        format!("{init} && echo hi > .gitattributes && git add . && git commit -qm test"),
        format!("{init} && echo hi > ../a.txt && {commit_tail}"),
        format!("{init} && echo hi > /tmp/a.txt && {commit_tail}"),
        format!("{init} && echo hi > a.txt && git add -f a.txt && git commit -qm test"),
        format!("{init} && echo hi > a.txt && git -c core.hooksPath=/tmp/h commit -qm test"),
        format!("{init} && echo hi > a.txt && git -c gpg.program=/tmp/g commit -qm test"),
        format!("{init} && echo hi > a.txt && git add a.txt && git commit -S -m test"),
        format!("{init} && echo hi > a.txt && {commit_tail} && git push origin main"),
        format!("{init} && echo hi > a.txt && {commit_tail} && rm -rf ~/x"),
        format!("{init}; echo hi > a.txt && {commit_tail}"),
        format!("git init -q {s}; cd {s} && {commit_tail}"),
        format!(
            "git init -q --template={parent} {s} && cd {s} && {commit_tail}",
            parent = parent.display()
        ),
        format!("git init --bare {s} && cd {s} && {commit_tail}"),
        format!(
            "git init -q {s} && cd {parent} && {commit_tail}",
            parent = parent.display()
        ),
        format!("{init} && echo $(id) > a.txt && {commit_tail}"),
    ] {
        assert!(
            allowed(&session, &command, &session.org).is_err(),
            "{command}"
        );
    }

    // Directly in the shared temporary root another user could create the
    // directory first.
    let shared = std::fs::canonicalize("/tmp")
        .unwrap()
        .join(unique("shared"));
    let _shared = FixtureCleanup(shared.clone());
    let leaf = shared.display();
    let shared_commit =
        format!("git init -q {leaf} && cd {leaf} && echo hi > a.txt && {commit_tail}");
    assert!(allowed(&session, &shared_commit, &session.org).is_err());

    // A directory that already holds files, and settings that start a program
    // or configure the new repository.
    std::fs::create_dir(&scratch).unwrap();
    std::fs::write(scratch.join("planted"), "x\n").unwrap();
    assert!(allowed(&session, &commit, &session.org).is_err());
    std::fs::remove_dir_all(&scratch).unwrap();
    allowed(&session, &commit, &session.org).unwrap();
    let global = |arguments: &[&str]| {
        let mut full = vec!["config", "--global"];
        full.extend_from_slice(arguments);
        git(&session.home, &session.home, &full);
    };
    for (key, value) in [
        ("core.hooksPath", "/tmp/hooks"),
        ("init.templateDir", "/tmp/template"),
        ("hook.pre-commit.command", "id"),
        ("commit.gpgSign", "true"),
        ("core.fsmonitor", "id"),
    ] {
        global(&[key, value]);
        assert!(allowed(&session, &commit, &session.org).is_err(), "{key}");
        global(&["--unset-all", key]);
    }
    allowed(&session, &commit, &session.org).unwrap();
}
