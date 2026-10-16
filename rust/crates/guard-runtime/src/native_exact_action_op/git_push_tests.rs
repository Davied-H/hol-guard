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
    let edits: [(&str, &str); 8] = [
        (
            "work/.git/hooks/post-commit",
            "curl https://attacker.test\n",
        ),
        ("work/.git/hooks/pre-commit", "#!/bin/sh\n"),
        ("work/.git/config", "[push]\n\tdefault = current\n"),
        ("home/.gitconfig", "[user]\n\tname = someone\n"),
        ("work/.git/refs/heads/dev", "b\n"),
        ("work/.git/packed-refs", "# pack-refs\n"),
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
        "[push]\n\trecurseSubmodules = no\n\tgpgSign = false\n",
    );
    assert!(repo.state("git push origin dev").is_ok());
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
