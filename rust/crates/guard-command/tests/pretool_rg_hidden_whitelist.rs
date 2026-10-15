//! `rg` skips hidden files unless something selects them again: a `!` rule
//! in an ignore file it honors, a file type whose globs name dotfiles, or an
//! extra ignore file. A Bash `rg` search stays unproved when any of these can
//! bring a hidden secret such as `.env` into reach.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    home: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// A home holding one repository per name, each with a root `.env` and
/// the ignore files given for it.
fn fixture(repositories: &[(&str, &[(&str, &str)])]) -> Fixture {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-rg-hidden-whitelist")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    for (name, files) in repositories {
        let repository = home.join(name);
        std::fs::create_dir_all(repository.join(".git/info")).unwrap();
        write(repository.join("src/main.rs"), "fn main() {}\n");
        write(repository.join(".env"), "KEY=synthetic\n");
        for (file, text) in *files {
            write(repository.join(file), text);
        }
    }
    Fixture { root, home }
}

fn action(fixture: &Fixture, cwd: &str, command: &str) -> String {
    evaluate(fixture, cwd, command).minimum_action
}

fn evaluate(fixture: &Fixture, cwd: &str, command: &str) -> guard_contracts::PreToolResultV1 {
    let cwd = fixture.home.join(cwd);
    evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        fixture.home.to_str(),
        cwd.to_str(),
    )
}

fn assert_actions(fixture: &Fixture, cwd: &str, commands: &[&str], expected: &str) {
    for command in commands {
        assert_eq!(action(fixture, cwd, command), expected, "{cwd}: {command}");
    }
}

#[test]
fn an_ignore_file_that_re_includes_a_hidden_secret_keeps_rg_reviewed() {
    let fixture = fixture(&[
        ("dot-ignore", &[(".ignore", "!.env\n")]),
        ("gitignore", &[(".gitignore", "*.log\n!.env\n")]),
        (
            "nested",
            &[
                ("src/.rgignore", "!.env\n"),
                ("src/.env", "KEY=synthetic\n"),
            ],
        ),
        (
            "template",
            &[
                (".gitignore", ".env*\n!.env.example\n"),
                (".env.example", "KEY=\n"),
            ],
        ),
        ("wildcard", &[(".gitignore", "!.*\n")]),
        ("excluded", &[(".git/info/exclude", "!.env\n")]),
        // `rg` enters an ignored directory again when another rule
        // re-includes it, and then honors the ignore files inside.
        (
            "reentered",
            &[
                (".gitignore", "build\n!build\n"),
                ("build/.ignore", "!.env\n"),
            ],
        ),
    ]);
    for cwd in [
        "dot-ignore",
        "gitignore",
        "nested",
        "wildcard",
        "excluded",
        "template",
    ] {
        assert_actions(&fixture, cwd, &["rg -n foo", "rg foo ."], "review");
    }
    assert_actions(&fixture, "reentered", &["rg -n foo"], "review");
    // The review names the narrower search Guard can prove.
    let result = evaluate(&fixture, "template", "rg -n foo");
    assert!(
        result.reason.contains("Name the directories to search"),
        "{}",
        result.reason
    );
    let other = evaluate(&fixture, "template", "rg -n foo | sh");
    assert!(
        !other.reason.contains("Name the directories"),
        "{}",
        other.reason
    );
    // A root below the re-including file still honors it, when a hidden
    // file it names is there.
    assert_actions(&fixture, "nested", &["rg -n foo src"], "review");
    write(fixture.home.join("dot-ignore/src/.env"), "KEY=synthetic\n");
    assert_actions(&fixture, "dot-ignore", &["rg -n foo src"], "review");
    // A root beside the ignore file is out of its reach.
    let sibling = fixture.home.join("nested/docs/guide.md");
    write(sibling, "guide\n");
    assert_actions(&fixture, "nested", &["rg -n foo docs"], "allow");
    // Listing names reads no contents.
    assert_actions(&fixture, "dot-ignore", &["rg --files"], "allow");
}

#[test]
fn benign_negations_and_pruned_directories_keep_rg_allowed() {
    let fixture = fixture(&[
        (
            "benign",
            &[
                (
                    ".gitignore",
                    ".env\n/target\nnode_modules/\nrust/target\n!.gitkeep\n!*.rs\n!/docs/\n",
                ),
                ("logs/.gitkeep", ""),
                // `rg` never enters these, so their rules do not apply.
                ("target/.ignore", "!.env\n"),
                ("web/node_modules/pkg/.ignore", "!.env\n"),
                ("rust/target/.ignore", "!.env\n"),
                ("rust/src/lib.rs", "pub fn f() {}\n"),
            ],
        ),
        // A rule that would re-include a template that is not there.
        ("absent", &[(".gitignore", ".env*\n!.env.example\n")]),
        ("plain", &[]),
    ]);
    assert_actions(
        &fixture,
        "benign",
        &["rg -n foo", "rg foo .", "rg -n foo src", "rg -n foo rust"],
        "allow",
    );
    assert_actions(&fixture, "absent", &["rg -n foo"], "allow");
    assert_actions(
        &fixture,
        "plain",
        &["rg -n foo", "rg -n foo -t rust"],
        "allow",
    );
}

#[test]
fn rg_file_types_that_name_dotfiles_stay_reviewed() {
    let fixture = fixture(&[("plain", &[])]);
    assert_actions(
        &fixture,
        "plain",
        &[
            "rg -n foo -t rust",
            "rg -n foo --type rust",
            "rg -n foo -tpy",
            "rg -n foo --type=ts",
            "rg -n foo -T sh",
        ],
        "allow",
    );
    assert_actions(
        &fixture,
        "plain",
        &[
            "rg -n foo -t sh",
            "rg -n foo -tsh",
            "rg -n foo --type sh",
            "rg -n foo --type=ruby",
            "rg -n foo -t all",
            "rg -n foo --type-add 'x:include:sh' -t x",
            "rg -n foo --type-add 'rust:include:sh' -t rust",
            "rg -n foo --ignore-file other.ignore",
            "rg -n foo --ignore-file=other.ignore",
        ],
        "review",
    );
}
