#![cfg(unix)]

use crate::pretool_git_session_ops::{git, session};

#[test]
fn listing_inspections_are_proven_reads() {
    let session = session("listing-reads");
    for cwd in [&session.primary, &session.worktree] {
        for command in [
            // Git reads `-sn` as `-s -n`, so a bundle is the same read as the
            // letters spelled apart and is proven the same way.
            "git shortlog -sn",
            "git check-ignore -vz src",
            "git shortlog",
            "git shortlog --summary --numbered --email",
            "git shortlog -s -n HEAD",
            "git shortlog -w72,6,9 -s",
            "git shortlog --group=committer -s",
            "git check-ignore -v src",
            "git check-ignore build/ dist/",
            "git check-ignore -q node_modules",
            "git check-ignore --no-index -v src/index.ts",
            "git status --short && git shortlog -sn",
        ] {
            let result = session.evaluate_at(command, cwd);
            assert_eq!(
                result.minimum_action, "allow",
                "{command}: {}",
                result.reason_code
            );
        }
        for command in [
            // A pretty format expands `%G`, which runs the verification
            // program, so a shortlog that carries one keeps its review.
            "git shortlog --format=%G? -s",
            "git shortlog --pretty=%GK",
            "git shortlog --unknown-option",
            // A bundle is only a bundle when every letter is a known flag.
            "git shortlog -sx",
            "git check-ignore --unknown-option src",
            // The command needs a path or the pipe it reads them from.
            "git check-ignore",
            "git check-ignore -v",
        ] {
            let result = session.evaluate_at(command, cwd);
            assert_ne!(
                result.minimum_action, "allow",
                "{command}: {}",
                result.reason_code
            );
        }
    }
    // A configured pager runs a program, so the probe keeps the review.
    git(
        &session.home,
        &session.primary,
        &["config", "pager.shortlog", "./synthetic-never-execute"],
    );
    let result = session.evaluate_at("git shortlog -sn", &session.primary);
    assert_ne!(result.minimum_action, "allow", "{}", result.reason_code);
}
