use super::*;
use crate::pretool::PathContext;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const ORIGIN: &str = "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = https://github.com/example-org/app-portal.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n";

fn words(command: &str) -> Vec<String> {
    command.split_whitespace().map(str::to_owned).collect()
}

fn segment(arguments: &[&str]) -> CommandSegmentV1 {
    prefixed_segment(&[], arguments)
}

fn prefixed_segment(names: &[&str], arguments: &[&str]) -> CommandSegmentV1 {
    let arguments: Vec<String> = arguments.iter().map(|word| (*word).to_owned()).collect();
    let text = format!("gh {}", arguments.join(" "));
    CommandSegmentV1 {
        tokens: std::iter::once("gh".to_owned())
            .chain(arguments.iter().cloned())
            .collect(),
        executable: Some("gh".to_owned()),
        arguments,
        environment_names: names.iter().map(|name| (*name).to_owned()).collect(),
        wrapper_chain: Vec::new(),
        path_overridden: false,
        execution_context: "direct".to_owned(),
        pipeline_index: 0,
        span: crate::CommandSpanV1 {
            source: text.clone(),
            start: 0,
            end: text.len(),
        },
        text,
    }
}

struct Checkout {
    root: PathBuf,
    project: PathBuf,
}

impl Checkout {
    fn new(label: &str, config: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hg-gh-conversation-{label}-{}-{nonce}",
            std::process::id()
        ));
        let project = root.join("project");
        std::fs::create_dir_all(project.join(".git")).unwrap();
        std::fs::create_dir_all(project.join(".tmp")).unwrap();
        std::fs::write(project.join(".git/config"), config).unwrap();
        let root = root.canonicalize().unwrap();
        let project = root.join("project");
        Self { root, project }
    }

    /// A linked worktree whose shared repository holds `config`.
    fn linked(label: &str, config: &str) -> Self {
        let checkout = Self::new(label, "");
        let project = &checkout.project;
        std::fs::remove_dir_all(project.join(".git")).unwrap();
        let common = checkout.root.join("main/.git");
        let admin = common.join("worktrees/project");
        std::fs::create_dir_all(&admin).unwrap();
        std::fs::write(common.join("config"), config).unwrap();
        std::fs::write(admin.join("commondir"), "../..\n").unwrap();
        let backlink = format!("{}\n", project.join(".git").display());
        std::fs::write(admin.join("gitdir"), backlink).unwrap();
        let gitfile = format!("gitdir: {}\n", admin.display());
        std::fs::write(project.join(".git"), gitfile).unwrap();
        checkout
    }

    fn allows(&self, arguments: &[&str]) -> bool {
        self.allows_segment(&segment(arguments))
    }

    fn allows_segment(&self, segment: &CommandSegmentV1) -> bool {
        let home = self.root.to_str().unwrap();
        let cwd = self.project.to_str().unwrap();
        current_repository_write(
            segment,
            PathContext {
                home_dir: Some(home),
                cwd: Some(cwd),
                ..PathContext::default()
            },
        )
    }
}

impl Drop for Checkout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn comment_write_accepts_one_body_for_one_issue_or_pull_request() {
    for command in [
        "pr comment 12 --body text",
        "pr comment --body text",
        "issue comment 7 -b text",
        "pr comment 12 --body=text",
        "pr comment 12 -F .tmp/body.md",
        "pr comment 12 --body-file=.tmp/body.md",
        "-R example-org/app-portal pr comment 12 --body text",
        "pr comment 12 --body text --repo example-org/app-portal",
    ] {
        assert!(comment_write(&words(command)).is_some(), "{command}");
    }
    for command in [
        "pr comment 12",
        "pr comment 12 --body a --body b",
        "pr comment 12 --body a --body-file b",
        "pr comment 12 --edit-last --body text",
        "pr comment 12 --delete-last",
        "pr comment 12 --web",
        "pr comment 12 --editor",
        "pr comment 12 --create-if-none --body text",
        "pr comment https://github.com/other/repo/pull/12 --body text",
        "pr comment feature-branch --body text",
        "pr comment 0 --body text",
        "pr comment 12 13 --body text",
        "--body text pr comment 12",
        "pr --body text comment 12",
        "pr review 12 --approve --body text",
        "pr merge 12 --body text",
        "pr close 12 --comment text",
        "issue close 7 --comment text",
        "pr comment 12 --body text -R a/b -R a/b",
        "pr comment 12 --body",
    ] {
        assert!(comment_write(&words(command)).is_none(), "{command}");
    }
}

#[test]
fn api_write_accepts_only_comment_and_reply_posts() {
    for command in [
        "repos/example-org/app-portal/pulls/12/comments/345/replies -f body=text",
        "/repos/example-org/app-portal/issues/12/comments -f body=text",
        "-X POST repos/example-org/app-portal/issues/12/comments --raw-field body=text",
        "--method=post repos/example-org/app-portal/issues/12/comments -F body=text",
        "repos/example-org/app-portal/issues/12/comments -fbody=text --jq .id --silent",
        "-XPOST repos/example-org/app-portal/issues/12/comments --field=body=text",
    ] {
        let args = words(command);
        let parsed = api_write(&args);
        assert_eq!(
            parsed.map(|(owner, repository, _)| (owner, repository)),
            Some(("example-org", "app-portal")),
            "{command}"
        );
    }
    for command in [
        "repos/example-org/app-portal/issues/12/comments",
        "-X PATCH repos/example-org/app-portal/issues/comments/9 -f body=text",
        "-X DELETE repos/example-org/app-portal/pulls/comments/9",
        "-X PUT repos/example-org/app-portal/pulls/12/merge -f body=text",
        "repos/example-org/app-portal/pulls/12/reviews -f body=text -f event=APPROVE",
        "repos/example-org/app-portal/issues/12/comments -f body=a -f body=b",
        "repos/example-org/app-portal/issues/12/comments -f body=a -f title=b",
        "repos/example-org/app-portal/issues/12/comments -F body=@notes.md",
        "repos/example-org/app-portal/issues/12/comments -F=body=@notes.md",
        "repos/example-org/app-portal/issues/12/comments --input notes.json",
        "repos/example-org/app-portal/issues/12/comments -f body=text --hostname example.com",
        "repos/example-org/app-portal/issues/12/comments -f body=text -H Accept:raw",
        "repos/example-org/app-portal/issues/12/comments repos/a/b/issues/1/comments -f body=x",
        "repos/example-org/app-portal/git/refs -f body=text",
        "repos/example-org/app-portal/issues/12 -f body=text",
        "repos/example-org/app-portal/pulls/12/comments -f body=text",
        "repos/example-org/../issues/12/comments -f body=text",
        "graphql -f body=text",
    ] {
        assert!(api_write(&words(command)).is_none(), "{command}");
    }
}

#[test]
fn selectors_and_origin_urls_name_one_github_repository() {
    assert_eq!(
        repository_selector("example-org/app-portal"),
        Some(("example-org", "app-portal"))
    );
    assert_eq!(
        repository_selector("GitHub.com/example-org/app-portal"),
        Some(("example-org", "app-portal"))
    );
    for selector in [
        "app-portal",
        "example.com/example-org/app-portal",
        "example-org/app-portal/extra",
        "example-org/..",
        "https://github.com/example-org/app-portal",
    ] {
        assert_eq!(repository_selector(selector), None, "{selector}");
    }
    let expected = Some(("example-org".to_owned(), "app-portal".to_owned()));
    for url in [
        "https://github.com/example-org/app-portal.git",
        "https://github.com/Example-Org/App-Portal",
        "git@github.com:example-org/app-portal.git",
        "ssh://git@github.com/example-org/app-portal/",
    ] {
        assert_eq!(github_repository(url), expected, "{url}");
    }
    for url in [
        "https://example.com/example-org/app-portal.git",
        "https://github.com.example.com/example-org/app-portal",
        "https://github.com/example-org/app-portal/extra",
        "/srv/mirror/app-portal.git",
    ] {
        assert_eq!(github_repository(url), None, "{url}");
    }
}

#[test]
fn origin_must_be_plain_and_unambiguous() {
    let plain = Checkout::new("plain", ORIGIN);
    assert_eq!(
        origin_repository(&plain.project, true),
        Some(Some(("example-org".to_owned(), "app-portal".to_owned())))
    );
    let bare = Checkout::new("none", "[core]\n\tbare = false\n");
    assert_eq!(origin_repository(&bare.project, true), Some(None));
    for (label, config) in [
        (
            "upstream",
            "[remote \"upstream\"]\n\turl = https://github.com/example-org/app-portal.git\n",
        ),
        (
            "include",
            "[include]\n\tpath = extra\n[remote \"origin\"]\n\turl = https://github.com/example-org/app-portal.git\n",
        ),
        (
            "rewrite",
            "[url \"https://github.com/other/\"]\n\tinsteadOf = https://github.com/example-org/\n[remote \"origin\"]\n\turl = https://github.com/example-org/app-portal.git\n",
        ),
        (
            "two",
            "[remote \"origin\"]\n\turl = https://github.com/example-org/app-portal.git\n\turl = https://github.com/other-org/app-portal.git\n",
        ),
        (
            "quoted",
            "[remote \"origin\"]\n\turl = \"https://github.com/example-org/app-portal.git\"\n",
        ),
        (
            "dotted",
            "[remote.origin]\n\turl = https://github.com/example-org/app-portal.git\n",
        ),
    ] {
        let checkout = Checkout::new(label, config);
        assert_eq!(origin_repository(&checkout.project, false), None, "{label}");
    }
}

#[test]
fn literal_secret_free_comments_on_the_origin_repository_pass() {
    let checkout = Checkout::new("literal", ORIGIN);
    std::fs::write(
        checkout.project.join(".tmp/body.md"),
        "Fixed in the latest push; the parser now rejects empty input.\n",
    )
    .unwrap();
    for arguments in [
        &[
            "pr",
            "comment",
            "12",
            "--body",
            "Addressed in the latest commit.",
        ][..],
        &["issue", "comment", "7", "--body", "Thanks, merged the fix."],
        &[
            "pr",
            "comment",
            "12",
            "-R",
            "Example-Org/app-portal",
            "--body",
            "Done.",
        ],
        &["pr", "comment", "12", "--body-file", ".tmp/body.md"],
        &[
            "api",
            "repos/example-org/app-portal/pulls/12/comments/345/replies",
            "-f",
            "body=Addressed in the latest commit.",
        ],
    ] {
        assert!(checkout.allows(arguments), "{arguments:?}");
    }
}

#[test]
fn other_repositories_secrets_and_unsafe_files_stay_reviewed() {
    let checkout = Checkout::new("negative", ORIGIN);
    let tmp = checkout.project.join(".tmp");
    std::fs::write(
        tmp.join("pem-reply.md"),
        "-----BEGIN RSA PRIVATE KEY-----\n",
    )
    .unwrap();
    std::fs::write(tmp.join("large.md"), "a".repeat(70 * 1024)).unwrap();
    std::fs::write(tmp.join("empty.md"), "  \n").unwrap();
    std::fs::write(tmp.join("binary.md"), b"text\0more").unwrap();
    std::fs::write(checkout.project.join(".git/notes.md"), "Done.\n").unwrap();
    // A shared directory others can write is neither workspace nor private.
    let shared = checkout.root.join("shared");
    std::fs::create_dir(&shared).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
    }
    std::fs::write(shared.join("outside.md"), "Done.\n").unwrap();
    std::fs::write(tmp.join("linked.md"), "Done.\n").unwrap();
    std::fs::hard_link(tmp.join("linked.md"), shared.join("second.md")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(shared.join("outside.md"), tmp.join("link.md")).unwrap();
    let token = format!("ghp_{}", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
    let token_body = format!("token {token}");
    let reply_with_token = format!("body=see {token}");
    for arguments in [
        &["pr", "comment", "12", "--body", token_body.as_str()][..],
        &["pr", "comment", "12", "--body", "   "],
        &[
            "pr",
            "comment",
            "12",
            "-R",
            "other-org/app-portal",
            "--body",
            "Done.",
        ],
        &[
            "pr",
            "comment",
            "12",
            "-R",
            "example.com/example-org/app-portal",
            "--body",
            "Done.",
        ],
        &["pr", "comment", "12", "--body-file", ".tmp/pem-reply.md"],
        &["pr", "comment", "12", "--body-file", ".tmp/large.md"],
        &["pr", "comment", "12", "--body-file", ".tmp/empty.md"],
        &["pr", "comment", "12", "--body-file", ".tmp/binary.md"],
        &["pr", "comment", "12", "--body-file", ".tmp/missing.md"],
        &["pr", "comment", "12", "--body-file", ".tmp/link.md"],
        &["pr", "comment", "12", "--body-file", ".tmp/linked.md"],
        &["pr", "comment", "12", "--body-file", ".git/notes.md"],
        &["pr", "comment", "12", "--body-file", "../shared/outside.md"],
        &["pr", "comment", "12", "--body-file", "-"],
        &["pr", "comment", "12", "--body-file", "~/notes.md"],
        &[
            "api",
            "repos/other-org/app-portal/pulls/12/comments/345/replies",
            "-f",
            "body=Done.",
        ],
        &[
            "api",
            "repos/example-org/app-portal/issues/12/comments",
            "-f",
            reply_with_token.as_str(),
        ],
        &["pr", "review", "12", "--approve", "--body", "Looks good."],
        &["pr", "merge", "12", "--squash"],
    ] {
        assert!(!checkout.allows(arguments), "{arguments:?}");
    }
    let no_context = segment(&["pr", "comment", "12", "--body", "Done."]);
    assert!(!current_repository_write(
        &no_context,
        PathContext::default()
    ));
}

#[test]
fn a_comment_without_a_selector_needs_origin_as_the_base_repository() {
    let reply = ["pr", "comment", "12", "--body", "Done."];
    let selected = [
        "pr",
        "comment",
        "12",
        "-R",
        "example-org/app-portal",
        "--body",
        "Done.",
    ];
    let set_default = format!("{ORIGIN}\tgh-resolved = base\n");
    for (label, config) in [
        ("single", ORIGIN.to_owned()),
        ("set-default", set_default),
        (
            "push-default",
            format!("[remote]\n\tpushDefault = origin\n{ORIGIN}"),
        ),
    ] {
        let checkout = Checkout::new(label, &config);
        assert!(checkout.allows(&reply), "{label}");
        assert!(checkout.allows(&selected), "{label}");
    }
    // gh ranks `upstream` and `github` above `origin`, and honors any remote
    // `gh repo set-default` marked, so a selector-less comment could land on
    // a repository never compared with origin. `-R origin` still passes.
    let upstream = format!(
        "{ORIGIN}[remote \"upstream\"]\n\turl = https://github.com/other-org/app-portal.git\n"
    );
    let other_default = format!(
        "{ORIGIN}[remote \"fork\"]\n\turl = https://github.com/other-org/app-portal.git\n\tgh-resolved = base\n"
    );
    let resolved_elsewhere = format!("{ORIGIN}\tgh-resolved = other-org/app-portal\n");
    for (label, config, selected_passes) in [
        ("upstream", upstream.as_str(), true),
        ("other-default", other_default.as_str(), true),
        ("resolved-elsewhere", resolved_elsewhere.as_str(), true),
        (
            "github-origin-missing",
            "[remote \"origin\"]\n\tfetch = x\n",
            false,
        ),
    ] {
        let checkout = Checkout::new(label, config);
        assert!(!checkout.allows(&reply), "{label}");
        assert_eq!(checkout.allows(&selected), selected_passes, "{label}");
    }
    // `GH_REPO` names the base repository before any remote when no `-R` is
    // given; `-R` itself still wins over it.
    let checkout = Checkout::new("gh-repo", ORIGIN);
    assert!(!checkout.allows_segment(&prefixed_segment(&["GH_REPO"], &reply)));
    assert!(checkout.allows_segment(&prefixed_segment(&["GH_REPO"], &selected)));
}

#[test]
fn linked_worktrees_and_remote_free_checkouts_resolve_like_gh() {
    let reply = ["pr", "comment", "12", "--body", "Done."];
    let selected = [
        "pr",
        "comment",
        "12",
        "-R",
        "example-org/app-portal",
        "--body",
        "Done.",
    ];
    // A linked worktree reads its shared repository's configuration.
    let linked = Checkout::linked("linked", ORIGIN);
    assert!(linked.allows(&reply));
    assert!(linked.allows(&selected));
    let upstream = format!(
        "{ORIGIN}[remote \"upstream\"]\n\turl = https://github.com/other-org/app-portal.git\n"
    );
    let linked = Checkout::linked("linked-upstream", &upstream);
    assert!(!linked.allows(&reply));
    assert!(linked.allows(&selected));
    // With no remote at all gh resolves no base repository and posts nothing;
    // a `-R` selector still has to name origin.
    for checkout in [
        Checkout::new("remote-free", "[core]\n\tbare = false\n"),
        Checkout::linked("linked-remote-free", "[core]\n\tbare = false\n"),
    ] {
        assert!(checkout.allows(&reply));
        assert!(!checkout.allows(&selected));
        assert!(!checkout.allows_segment(&prefixed_segment(&["GH_REPO"], &reply)));
    }
}
