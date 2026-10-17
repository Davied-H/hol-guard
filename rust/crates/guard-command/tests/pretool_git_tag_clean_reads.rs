use crate::git_helper_fixture as fixture;
use fixture::*;
use serde_json::json;

fn decide(
    harness: &str,
    command: &str,
    home: &std::path::Path,
    repository: &std::path::Path,
) -> String {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&github_controls("enabled")),
        None,
        home.to_str(),
        repository.to_str(),
    )
    .decision
}

fn repository_fixture(name: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!("guard-git-{name}-{}", std::process::id()));
    let home = root.join("home");
    let repository = root.join("repository");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&repository).unwrap();
    assert!(std::process::Command::new("git")
        .args(["init", "--quiet"])
        .arg(&repository)
        .status()
        .unwrap()
        .success());
    (root, home, repository)
}

#[test]
fn tag_listing_is_allowed_and_tag_writes_stay_reviewed() {
    let (root, home, repository) = repository_fixture("tag");
    let _cleanup = FixtureCleanup(root);
    let config = repository.join(".git/config");
    for (settings, command, expected) in [
        ("", "git tag --list", "allow"),
        ("", "git tag -l", "allow"),
        ("", "git tag -li", "allow"),
        ("", "git tag --list v1.*", "allow"),
        ("", "git tag -l release-*", "allow"),
        ("", "git tag --list --sort=-creatordate", "allow"),
        ("", "git tag --list --points-at=HEAD", "allow"),
        ("", "git --no-pager tag --list", "allow"),
        ("", "git tag --list | cat", "allow"),
        // A bare `git tag` lists, but the same spelling with an operand
        // creates one, so only an explicit listing is proven.
        ("", "git tag", "review"),
        ("", "git tag v1.0.0", "review"),
        ("", "git tag v1.0.0 HEAD", "review"),
        ("", "git tag -a v1.0.0 -m release", "review"),
        ("", "git tag -d v1.0.0", "review"),
        ("", "git tag --delete v1.0.0", "review"),
        ("", "git tag -f v1.0.0", "review"),
        ("", "git tag -s v1.0.0", "review"),
        ("", "git tag --list --format=%(refname)", "review"),
        ("", "git tag -l -n", "review"),
        // The configured pager is a program the listing would start.
        (
            "",
            "git -c pager.tag=./synthetic-never-execute tag --list",
            "review",
        ),
        (
            "[pager]\ntag = ./synthetic-never-execute\n",
            "git tag --list",
            "review",
        ),
        (
            "[core]\npager = ./synthetic-never-execute\n",
            "git tag --list",
            "review",
        ),
        (
            "[core]\npager = ./synthetic-never-execute\n",
            "git tag --list | cat",
            "allow",
        ),
    ] {
        std::fs::write(&config, settings).unwrap();
        for harness in ["omp", "zcode"] {
            let decision = decide(harness, command, &home, &repository);
            if expected == "review" {
                assert_ne!(decision, "allow", "{harness}: {command}: {settings}");
            } else {
                assert_eq!(decision, expected, "{harness}: {command}: {settings}");
            }
        }
    }
}

#[test]
fn clean_preview_is_allowed_and_removal_stays_reviewed() {
    let (root, home, repository) = repository_fixture("clean");
    let _cleanup = FixtureCleanup(root);
    let config = repository.join(".git/config");
    for (settings, command, expected) in [
        ("", "git clean -n", "allow"),
        ("", "git clean --dry-run", "allow"),
        ("", "git clean -nd", "allow"),
        ("", "git clean -ndx", "allow"),
        ("", "git clean -n -X", "allow"),
        ("", "git clean -n -q", "allow"),
        ("", "git clean -n -e build", "allow"),
        ("", "git clean -n --exclude=build", "allow"),
        ("", "git clean -n -- src tests", "allow"),
        ("", "git clean --dry-run -d src", "allow"),
        // The preview prints names without a pager, so a configured one
        // never runs.
        (
            "[core]\npager = ./synthetic-never-execute\n",
            "git clean -n",
            "allow",
        ),
        ("", "git clean", "review"),
        ("", "git clean -d", "review"),
        ("", "git clean -f", "review"),
        ("", "git clean -fd", "review"),
        ("", "git clean --force", "review"),
        ("", "git clean -i", "review"),
        ("", "git clean --interactive", "review"),
        ("", "git clean -n -f", "review"),
        ("", "git clean -nf", "review"),
        ("", "git clean -n --no-dry-run", "review"),
    ] {
        std::fs::write(&config, settings).unwrap();
        for harness in ["omp", "zcode"] {
            let decision = decide(harness, command, &home, &repository);
            if expected == "review" {
                assert_ne!(decision, "allow", "{harness}: {command}: {settings}");
            } else {
                assert_eq!(decision, expected, "{harness}: {command}: {settings}");
            }
        }
    }
}
