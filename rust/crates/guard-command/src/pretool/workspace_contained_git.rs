//! Git commands the workspace sandbox cannot complete.
//!
//! The sandbox write-denies the repository configuration and the `.git`
//! directories that hold hooks, submodules and linked worktrees, so a later
//! host Git never runs something a contained command planted. A command that
//! has to write there fails inside the sandbox with "Operation not permitted",
//! sometimes after a partial effect such as a new branch, and the agent keeps
//! retrying a command that cannot succeed. These commands stay at review.

/// Global options whose value is the next argument.
const VALUE_OPTIONS: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--config-env",
];
/// `git branch` options that write the branch's configuration section.
const BRANCH_CONFIG_WRITES: &[&str] = &[
    "-u",
    "--set-upstream-to",
    "--unset-upstream",
    "-t",
    "--track",
    "--edit-description",
    "-m",
    "-M",
    "--move",
    "-c",
    "-C",
    "--copy",
];
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

fn tracks(arguments: &[String]) -> bool {
    arguments.iter().any(|argument| {
        matches!(argument.as_str(), "-t" | "--track") || argument.starts_with("--track=")
    })
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
        "branch" => rest.iter().any(|argument| {
            BRANCH_CONFIG_WRITES.contains(&argument.as_str())
                || argument.starts_with("--set-upstream-to=")
                || argument.starts_with("--track=")
        }),
        "checkout" | "switch" => tracks(rest),
        "config" => writes_config(rest),
        // A clone writes a new repository's configuration; repacking updates
        // `.git/objects/info`.
        "clone" | "gc" | "repack" | "maintenance" => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::writes_denied_metadata;

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
            "git submodule status",
            "git -c core.pager=cat log --oneline",
            "git log -C --oneline",
        ] {
            assert!(!writes(command), "{command}");
        }
    }
}
