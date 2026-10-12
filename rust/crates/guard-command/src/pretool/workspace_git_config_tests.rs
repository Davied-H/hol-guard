use super::{helper_write_denials, workspace_write_denials};
use std::path::{Path, PathBuf};

fn denials(config: &str, workspace: &Path) -> Option<Vec<PathBuf>> {
    helper_write_denials(config, workspace)
}

#[test]
fn workspace_includes_and_outside_hooks_keep_the_command_at_review() {
    let ws = Path::new("/w/repo");
    // Relative includes resolve against `.git/`, so both name workspace files.
    assert_eq!(denials("[include]\n\tpath = ../.gitconfig\n", ws), None);
    assert_eq!(denials("[include]\n\tpath = extra\n", ws), None);
    assert_eq!(
        denials("[includeIf \"gitdir:/w/\"]\n\tpath = /w/repo/cfg\n", ws),
        None
    );
    assert_eq!(denials("[core]\n\thooksPath = /outside/hooks\n", ws), None);
    assert_eq!(denials("[core]\n\thooksPath = ~/hooks\n", ws), None);
    // An include outside the workspace is not writable from the sandbox.
    assert_eq!(
        denials("[include]\n\tpath = /etc/gitconfig.d/team\n", ws),
        Some(vec![])
    );
}

#[test]
fn shell_punctuation_splits_helper_words() {
    let ws = Path::new("/w/repo");
    let config = "[alias]\n\tx = \"!f() { ./tools/x.sh; }; f\"\n\ty = !./tools/a&&git status\n\tz = \"!f() { ./tools/z; }\"\n";
    let got = denials(config, ws).unwrap();
    assert!(got.contains(&ws.join("tools/x.sh")), "{got:?}");
    assert!(got.contains(&ws.join("tools/a")), "{got:?}");
    assert!(got.contains(&ws.join("tools/z")), "{got:?}");
    for expansion in [
        "!$PWD/tools/x.sh",
        "!`pwd`/x.sh",
        "!sh tools\\\\x",
        "!./tools/ru?",
        "!sh tools/*.sh",
        "!./tools/[r]un",
        "!./tools/{run,x}.sh",
    ] {
        let config = format!("[alias]\n\tx = {expansion}\n");
        assert_eq!(denials(&config, ws), None, "{expansion}");
    }
}

#[test]
fn helper_paths_in_any_word_are_write_denied() {
    // Nothing here exists yet: the sandbox could create any of it.
    let ws = Path::new("/w/repo");
    let config = "[core]\n\thooksPath = .githooks\n\tfsmonitor = ./tools/mon\n\
         \tsshCommand = ssh -F sshcfg\n\
         [alias]\n\tx = !sh tools/x\n\ty = !sh x.sh\n\tst = status -s\n\
         \td = difftool --extcmd=./tools/d\n\
         [branch \"main\"]\n\tmerge = refs/heads/main\n";
    let got = denials(config, ws).unwrap();
    assert_eq!(
        got,
        vec![
            ws.join(".githooks"),
            ws.join("tools/mon"),
            ws.join("sshcfg"),
            ws.join("tools/x"),
            ws.join("x.sh"),
            ws.join("tools/d"),
        ]
    );
}

#[test]
fn remote_and_submodule_data_keys_are_not_helpers() {
    let ws = Path::new("/w/repo");
    let config = "[remote \"origin\"]\n\turl = ../origin.git\n\
         \tfetch = +refs/heads/*:refs/remotes/origin/*\n\
         \tuploadpack = ./tools/up\n\
         [submodule \"libs/x\"]\n\tpath = libs/x\n\turl = ./libs/x.git\n\
         \tupdate = !sh tools/sync\n";
    assert_eq!(
        denials(config, ws).unwrap(),
        vec![ws.join("tools/up"), ws.join("tools/sync")]
    );
}

#[test]
fn a_key_on_the_header_line_keeps_the_command_at_review() {
    let ws = Path::new("/w/repo");
    assert_eq!(denials("[core] hooksPath = tools/hooks\n", ws), None);
    assert_eq!(denials("[alias]x = !./tools/evil\n", ws), None);
    assert_eq!(denials("[core\n\thooksPath = h\n", ws), None);
    assert_eq!(
        denials("[core] # comment\n\thooksPath = h\n", ws),
        Some(vec![ws.join("h")])
    );
}

fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("guard-wgc-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("home")).unwrap();
    std::fs::create_dir_all(root.join("repo/app")).unwrap();
    root.canonicalize().unwrap()
}

#[test]
fn worktree_config_keeps_the_command_at_review() {
    let root = scratch("worktree");
    let (home, repo) = (root.join("home"), root.join("repo"));
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::write(repo.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    assert_eq!(workspace_write_denials(&repo, Some(&home)), Some(vec![]));
    std::fs::write(
        repo.join(".git/config.worktree"),
        "[core]\n\thooksPath = h\n",
    )
    .unwrap();
    assert_eq!(workspace_write_denials(&repo, Some(&home)), None);
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn an_enclosing_repository_and_global_hooks_name_workspace_paths() {
    let root = scratch("enclosing");
    let (home, repo) = (root.join("home"), root.join("repo"));
    let app = repo.join("app");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::write(
        repo.join(".git/config"),
        "[core]\n\tfsmonitor = app/tools/mon\n[alias]\n\tx = !sh other/x\n",
    )
    .unwrap();
    // Only paths inside the workspace need a denial; `other/x` is outside
    // the sandbox's writable tree.
    assert_eq!(
        workspace_write_denials(&app, Some(&home)),
        Some(vec![app.join("tools/mon")])
    );
    // A relative global hook directory resolves against the work tree.
    std::fs::write(
        home.join(".gitconfig"),
        "[core]\n\thooksPath = app/.githooks\n",
    )
    .unwrap();
    assert_eq!(
        workspace_write_denials(&app, Some(&home)),
        Some(vec![app.join("tools/mon"), app.join(".githooks")])
    );
    std::fs::write(home.join(".gitconfig"), "[core]\n\thooksPath = ../../x\n").unwrap();
    assert_eq!(workspace_write_denials(&app, Some(&home)), None);
    std::fs::write(home.join("dotfile"), "[core]\n\thooksPath = ~/.hooks\n").unwrap();
    std::fs::remove_file(home.join(".gitconfig")).unwrap();
    std::os::unix::fs::symlink(home.join("dotfile"), home.join(".gitconfig")).unwrap();
    assert_eq!(
        workspace_write_denials(&app, Some(&home)),
        Some(vec![app.join("tools/mon")])
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn global_hooks_in_any_form_and_writable_global_files_are_covered() {
    let root = scratch("global-forms");
    let (home, repo) = (root.join("home"), root.join("repo"));
    let app = repo.join("app");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::write(repo.join(".git/config"), "[core]\n").unwrap();
    let global = home.join(".gitconfig");
    // Absolute and home-relative hook directories inside the workspace.
    let absolute = format!("[core]\n\thooksPath = {}/.hooks\n", app.display());
    std::fs::write(&global, absolute).unwrap();
    assert_eq!(
        workspace_write_denials(&app, Some(&home)),
        Some(vec![app.join(".hooks")])
    );
    let in_home = home.join("proj");
    std::fs::create_dir_all(&in_home).unwrap();
    std::fs::write(&global, "[core]\n\thooksPath = ~/proj/.hooks\n").unwrap();
    assert_eq!(
        workspace_write_denials(&in_home, Some(&home)),
        Some(vec![in_home.join(".hooks")])
    );
    // Included files are followed, relative to the including file.
    std::fs::write(&global, "[includeIf \"gitdir:~/\"]\n\tpath = extra\n").unwrap();
    std::fs::write(home.join("extra"), "[core]\n\thooksPath = app/.h2\n").unwrap();
    assert_eq!(
        workspace_write_denials(&app, Some(&home)),
        Some(vec![app.join(".h2")])
    );
    // A global file the sandbox could write keeps the command at review.
    std::fs::remove_file(&global).unwrap();
    std::fs::write(app.join("gitconfig"), "[user]\n\tname = x\n").unwrap();
    std::os::unix::fs::symlink(app.join("gitconfig"), &global).unwrap();
    assert_eq!(workspace_write_denials(&app, Some(&home)), None);
    std::fs::remove_file(&global).unwrap();
    std::fs::write(&global, "[include]\n\tpath = ../repo/app/inc\n").unwrap();
    assert_eq!(workspace_write_denials(&app, Some(&home)), None);
    for value in ["~other/.hooks", "app/.hooks ; note", "app", "/"] {
        let text = format!("[core]\n\thooksPath = {value}\n");
        std::fs::write(&global, text).unwrap();
        assert_eq!(workspace_write_denials(&app, Some(&home)), None, "{value}");
    }
    std::fs::remove_file(&global).unwrap();
    // Repository hook paths with an inline comment, or naming the
    // workspace itself, cannot be denied.
    for value in [".githooks ; local hooks", ".githooks # local", "app"] {
        let text = format!("[core]\n\thooksPath = {value}\n");
        std::fs::write(repo.join(".git/config"), text).unwrap();
        assert_eq!(workspace_write_denials(&app, Some(&home)), None, "{value}");
    }
    let _ = std::fs::remove_dir_all(&root);
}
