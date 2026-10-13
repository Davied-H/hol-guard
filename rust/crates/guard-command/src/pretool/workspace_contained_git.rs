//! Git commands the workspace sandbox cannot complete.
//!
//! The sandbox write-denies the repository configuration and the `.git`
//! directories that hold hooks, submodules and linked worktrees, so a later
//! host Git never runs something a contained command planted. A command that
//! has to write there fails inside the sandbox with "Operation not permitted",
//! sometimes after a partial effect such as a new branch, and the agent keeps
//! retrying a command that cannot succeed. These commands stay at review.
//!
//! Creating a new branch is the opposite case: the Git workspace rules keep
//! switching and checkout at review because they can discard uncommitted
//! work, but a plain `git switch -c` or `git checkout -b` cannot, and the
//! sandbox completes it.

use crate::CanonicalCommandV1;
use guard_contracts::NativeCommandObservationV1;

/// Workspace rules whose matches a new branch from `git switch -c` or
/// `git checkout -b` accounts for.
const BRANCH_CREATE_RULES: &[&str] = &["command.git.checkout", "command.git.switch"];
/// Global options whose value is the next argument.
const VALUE_OPTIONS: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--config-env",
];
/// `git branch` long options that write or remove the branch's configuration
/// section. Their short forms are `BRANCH_CONFIG_LETTERS`.
const BRANCH_CONFIG_WRITES: &[&str] = &[
    "--set-upstream-to",
    "--unset-upstream",
    "--track",
    "--edit-description",
    "--move",
    "--copy",
    "--delete",
];
const BRANCH_CONFIG_LETTERS: &str = "utmMcCdD";
/// `git config` reads. Anything else that names a key and a value writes.
const CONFIG_READS: &[&str] = &[
    "--get",
    "--get-all",
    "--get-regexp",
    "--get-urlmatch",
    "-l",
    "--list",
];
const CONFIG_WRITES: &[&str] = &[
    "--add",
    "--unset",
    "--unset-all",
    "--replace-all",
    "--rename-section",
    "--remove-section",
    "-e",
    "--edit",
];

/// The subcommand after Git's global options, and the arguments after it.
fn subcommand(arguments: &[String]) -> Option<(&str, &[String])> {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if VALUE_OPTIONS.contains(&argument.as_str()) {
            index += 2;
        } else if argument.starts_with('-') {
            index += 1;
        } else {
            return Some((argument.as_str(), &arguments[index + 1..]));
        }
    }
    None
}

/// Whether creating a branch may record an upstream in `.git/config`. An
/// explicit `--track` always does. With Git's default `branch.autoSetupMerge`
/// a remote-tracking start point does too, and telling one from a local
/// branch needs the repository, so any start point counts unless the command
/// says `--no-track`.
/// Whether a short-option cluster such as `-fu` includes one of `letters`.
fn short_option(argument: &str, letters: &str) -> bool {
    argument
        .strip_prefix('-')
        .is_some_and(|flags| !flags.starts_with('-') && flags.chars().any(|c| letters.contains(c)))
}

fn tracks(arguments: &[String]) -> bool {
    if arguments.iter().any(|argument| {
        short_option(argument, "t") || argument == "--track" || argument.starts_with("--track=")
    }) {
        return true;
    }
    !arguments.iter().any(|argument| argument == "--no-track")
        && arguments
            .iter()
            .take_while(|argument| argument.as_str() != "--")
            .filter(|argument| !argument.starts_with('-'))
            .count()
            >= 2
}

fn writes_config(arguments: &[String]) -> bool {
    let positional: Vec<&str> = arguments
        .iter()
        .map(String::as_str)
        .filter(|argument| !argument.starts_with('-'))
        .collect();
    if matches!(positional.first(), Some(&("get" | "list")))
        || arguments
            .iter()
            .any(|argument| CONFIG_READS.contains(&argument.as_str()))
    {
        return false;
    }
    positional.len() >= 2
        || matches!(
            positional.first(),
            Some(&("set" | "unset" | "rename-section" | "remove-section" | "edit"))
        )
        || arguments
            .iter()
            .any(|argument| CONFIG_WRITES.contains(&argument.as_str()))
}

/// Options a new-branch `switch` or `checkout` may carry without touching
/// existing work. Anything else, such as `--force`, `--merge`, `--orphan` or
/// a pathspec, keeps the command at review.
const BRANCH_CREATE_OPTIONS: &[&str] = &[
    "-q",
    "--quiet",
    "--no-track",
    "--no-guess",
    "--progress",
    "--no-progress",
];

/// Whether a `git switch -c` or `git checkout -b` only creates a new branch.
/// Git refuses to create a branch that exists and keeps uncommitted changes
/// unless they conflict with the start point, in which case it stops. The
/// upper-case `-C` and `-B` reset an existing branch, so the comparison is
/// case-sensitive.
pub(super) fn creates_branch(arguments: &[String]) -> bool {
    let Some((name, rest)) = subcommand(arguments) else {
        return false;
    };
    let create = match name {
        "switch" => ["-c", "--create"].as_slice(),
        "checkout" => ["-b"].as_slice(),
        _ => return false,
    };
    let mut created = false;
    let mut positional = 0;
    for argument in rest {
        if create.contains(&argument.as_str()) && !created {
            created = true;
        } else if argument.starts_with('-') {
            if !BRANCH_CREATE_OPTIONS.contains(&argument.as_str()) {
                return false;
            }
        } else {
            positional += 1;
        }
    }
    // The new branch's name and at most one start point.
    created && (1..=2).contains(&positional)
}

/// Whether an observation of a Git workspace rule covers only segments that
/// create a new branch, which loses no work and so need not stay at review.
pub(super) fn only_creates_branches(
    observation: &NativeCommandObservationV1,
    model: &CanonicalCommandV1,
) -> bool {
    let mut segments = observation
        .matcher_evidence
        .iter()
        .map(|evidence| evidence.segment_index)
        .chain(observation.effective_segment_indexes.iter().copied())
        .peekable();
    BRANCH_CREATE_RULES.contains(&observation.rule_id.as_str())
        && segments.peek().is_some()
        && segments.all(|index| {
            model.segments.get(index).is_some_and(|segment| {
                segment
                    .executable
                    .as_deref()
                    .is_some_and(|value| super::super::executable_basename(value) == "git")
                    && creates_branch(&segment.arguments)
            })
        })
}

/// Whether a `git` invocation with these arguments must write a path the
/// workspace sandbox denies.
pub(super) fn writes_denied_metadata(arguments: &[String]) -> bool {
    let Some((name, rest)) = subcommand(arguments) else {
        return false;
    };
    let first = rest
        .iter()
        .map(String::as_str)
        .find(|argument| !argument.starts_with('-'));
    match name {
        "worktree" => first != Some("list"),
        "submodule" => !matches!(first, None | Some("status" | "summary")),
        "sparse-checkout" => first != Some("list"),
        "remote" => matches!(
            first,
            Some("add" | "rename" | "rm" | "remove" | "set-url" | "set-branches" | "set-head")
        ),
        "lfs" => matches!(first, Some("install" | "uninstall" | "update")),
        "branch" => {
            tracks(rest)
                || rest.iter().any(|argument| {
                    BRANCH_CONFIG_WRITES.contains(&argument.as_str())
                        || short_option(argument, BRANCH_CONFIG_LETTERS)
                        || argument.starts_with("--set-upstream-to=")
                })
        }
        "checkout" | "switch" => tracks(rest),
        "config" => writes_config(rest),
        // A clone writes a new repository's configuration; repacking updates
        // `.git/objects/info`. A push can record an upstream through `-u` or
        // `push.autoSetupRemote`, and needs the network the sandbox lacks.
        "clone" | "gc" | "repack" | "maintenance" | "push" => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{creates_branch, writes_denied_metadata};

    fn writes(command: &str) -> bool {
        let arguments: Vec<String> = command
            .split_whitespace()
            .skip(1)
            .map(str::to_owned)
            .collect();
        writes_denied_metadata(&arguments)
    }

    #[test]
    fn commands_that_write_sandbox_denied_metadata() {
        for command in [
            "git worktree add -b report ../report-wt main",
            "git -C . worktree add ../wt",
            "git worktree remove ../wt",
            "git worktree prune",
            "git config user.name Agent",
            "git config --global user.email agent@example.com",
            "git config --unset user.name",
            "git config set user.name Agent",
            "git remote add origin https://example.com/x.git",
            "git remote set-url origin https://example.com/y.git",
            "git branch -u origin/main",
            "git branch --set-upstream-to=origin/main",
            "git branch -m main trunk",
            "git switch -c feature --track origin/feature",
            "git switch -c fix origin/main",
            "git checkout -b fix origin/main",
            "git branch fix origin/main",
            "git push -u origin main",
            "git push -fu origin main",
            "git push origin main",
            "git branch -d feature",
            "git branch -D feature",
            "git branch --delete feature",
            "git branch -vu origin/main",
            "git switch -tc feature origin/feature",
            "git submodule add ../lib lib",
            "git sparse-checkout set src",
            "git lfs install",
            "git clone ../origin copy",
            "git gc",
        ] {
            assert!(writes(command), "{command}");
        }
    }

    #[test]
    fn commands_the_sandbox_completes() {
        for command in [
            "git status",
            "git add -A",
            "git commit -m worktree",
            "git worktree list",
            "git config user.name",
            "git config --get user.name",
            "git config --list",
            "git config get user.name",
            "git remote -v",
            "git remote show origin",
            "git branch feature",
            "git branch -a",
            "git branch -vv",
            "git switch -c feature",
            "git checkout -b feature",
            "git switch -c fix --no-track origin/main",
            "git branch --list feat*",
            "git submodule status",
            "git -c core.pager=cat log --oneline",
            "git log -C --oneline",
        ] {
            assert!(!writes(command), "{command}");
        }
    }

    #[test]
    fn branch_creation_is_told_apart_from_switching_and_resets() {
        let creates = |command: &str| {
            let arguments: Vec<String> = command
                .split_whitespace()
                .skip(1)
                .map(str::to_owned)
                .collect();
            creates_branch(&arguments)
        };
        for command in [
            "git switch -c feature",
            "git switch --create feature",
            "git checkout -b feature",
            "git checkout -q -b fix/login",
            "git switch -c fix --no-track origin/main",
            "git -C . checkout -b feature main",
        ] {
            assert!(creates(command), "{command}");
        }
        for command in [
            "git switch main",
            "git checkout main",
            "git checkout -b",
            "git switch -C feature",
            "git checkout -B feature",
            "git switch -c feature --discard-changes",
            "git checkout -f -b feature",
            "git checkout -b feature -- src",
            "git checkout -b feature main src",
            "git switch -m -c feature",
            "git switch --orphan feature",
            "git checkout -b feature -b other",
            "git branch feature",
        ] {
            assert!(!creates(command), "{command}");
        }
    }
}
