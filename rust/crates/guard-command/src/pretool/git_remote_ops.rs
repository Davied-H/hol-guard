//! A plain `origin` refresh and a feature-branch push. Both run only Git
//! built-ins once the effective configuration proves `origin` is a GitHub
//! HTTPS remote with no program, proxy or URL rewrite in the way, every
//! credential helper resolves to a trusted executable, and no hook Git
//! would start for the operation can run. A push must also name exactly the
//! checked-out branch, which must not be the default branch.

use super::git_remote_config as config;
use super::git_session_probe::Probe;
use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::time::Instant;

const MAX_BRANCH_BYTES: usize = 200;

enum Operation<'a> {
    Fetch,
    Push { branch: &'a str },
}

/// The allow reason for a proven refresh or push, or `None`.
pub(super) fn exact_safe_command(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<(&'static str, &'static str)> {
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || model.segments.len() != 1
    {
        return None;
    }
    let segment = &model.segments[0];
    let (leading, operation) = parse(segment, context)?;
    let proven = super::git_probe::memoized(memo_key(segment, context), || {
        Some(prove(
            segment.executable.as_deref()?,
            leading,
            &operation,
            context,
            deadline,
            execution_environment,
        ))
    });
    if proven != Some(true) {
        return None;
    }
    Some(match operation {
        Operation::Fetch => (
            "native_exact_safe_git_origin_refresh",
            "The Rust command authority proved this fetch reaches only a GitHub HTTPS origin with trusted credential helpers, plain refspecs and no hooks or transport programs.",
        ),
        Operation::Push { .. } => (
            "native_exact_safe_git_feature_push",
            "The Rust command authority proved this push sends only the checked-out feature branch to a GitHub HTTPS origin, without force, deletion, hooks or transport programs.",
        ),
    })
}

/// Whether this evaluation already proved `segment` as a safe `origin`
/// operation; the compatibility layer uses it to drop the unverified-fetch
/// review it would otherwise record.
pub(super) fn verified(segment: &CommandSegmentV1, context: super::PathContext<'_>) -> bool {
    parse(segment, context).is_some() && super::git_probe::proven(&memo_key(segment, context))
}

fn memo_key(
    segment: &CommandSegmentV1,
    context: super::PathContext<'_>,
) -> super::git_probe::MemoKey {
    (
        format!(
            "\0origin:{}",
            segment.executable.as_deref().unwrap_or_default()
        ),
        segment.arguments.clone(),
        context.home_dir.map(str::to_owned),
        context.cwd.map(str::to_owned),
        false,
    )
}

fn parse<'a>(
    segment: &'a CommandSegmentV1,
    context: super::PathContext<'_>,
) -> Option<(&'a [String], Operation<'a>)> {
    let executable = segment.executable.as_deref()?;
    if executable != "git"
        || segment.pipeline_index != 0
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
        || segment
            .text
            .contains(['>', '<', '$', '`', '|', '&', ';', '\n', '\r'])
        || !super::directory_targets::drive_targets_quoted(segment)
        || !super::directory_targets::home_targets_unquoted(segment)
    {
        return None;
    }
    let arguments = segment.arguments.as_slice();
    let remaining = crate::command_compatibility::git_routed_arguments(arguments, context)?;
    let leading = &arguments[..arguments.len() - remaining.len()];
    if !leading
        .chunks(2)
        .all(|pair| matches!(pair, [flag, _] if flag == "-C"))
    {
        return None;
    }
    let (command, rest) = remaining.split_first()?;
    let operation = match command.as_str() {
        "fetch" if crate::command_compatibility::git_fetch_origin_shaped(rest) => Operation::Fetch,
        "push" => Operation::Push {
            branch: push_branch(rest)?,
        },
        _ => return None,
    };
    Some((leading, operation))
}

/// Branch names that are a default or release branch in common workflows,
/// refused even when the remote's default branch cannot be read.
const PROTECTED_BRANCHES: [&str; 14] = [
    "HEAD",
    "dev",
    "develop",
    "development",
    "gh-pages",
    "main",
    "master",
    "prod",
    "production",
    "release",
    "staging",
    "stable",
    "trunk",
    "latest",
];

/// `[-u|--set-upstream|-q|--quiet]... origin <branch>` with one plain branch.
fn push_branch(arguments: &[String]) -> Option<&str> {
    let mut positional = Vec::new();
    for argument in arguments {
        match argument.as_str() {
            "-u" | "--set-upstream" | "-q" | "--quiet" => {}
            value if value.starts_with('-') => return None,
            value => positional.push(value),
        }
    }
    let ["origin", branch] = positional.as_slice() else {
        return None;
    };
    let mut bytes = branch.bytes();
    let plain = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && branch.len() <= MAX_BRANCH_BYTES
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte))
        && !branch.ends_with(['/', '.'])
        && !branch.contains("..")
        && !branch.contains("//")
        && !PROTECTED_BRANCHES.contains(branch);
    plain.then_some(*branch)
}

fn prove(
    executable: &str,
    leading: &[String],
    operation: &Operation<'_>,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let Some(probe) = Probe::new(
        executable,
        leading,
        context,
        deadline,
        execution_environment,
    ) else {
        return false;
    };
    let Some((effective, repository)) = probe.config() else {
        return false;
    };
    let urls = effective
        .get("remote.origin.url")
        .map_or(&[][..], Vec::as_slice);
    if urls.is_empty()
        || !urls
            .iter()
            .all(|url| config::safe_github_https_remote_url(url.trim()))
        || config::fetch_config_routes_execution(&effective)
        || !probe.credential_helpers_trusted(&config::credential_helpers(&effective))
    {
        return false;
    }
    match operation {
        // Initialized submodules are fetched on demand with their own
        // config and hooks, which this probe does not read.
        Operation::Fetch => {
            !config::config_weakens_transport(&effective)
                && !config::repository_config_routes_transport(&repository)
                && !effective.keys().any(|key| key.starts_with("submodule."))
                && probe.hooks_inert(&["pre-auto-gc", "reference-transaction", "post-fetch"])
        }
        Operation::Push { branch } => {
            urls.len() == 1
                && !config::push_config_routes_execution(&effective, branch)
                && !config::config_weakens_transport(&effective)
                && !config::repository_config_routes_transport(&repository)
                && !effective
                    .get("init.defaultbranch")
                    .is_some_and(|values| values.iter().any(|value| value.trim() == *branch))
                && feature_branch_checked_out(&probe, branch)
                && probe.hooks_inert(&["pre-push", "reference-transaction"])
        }
    }
}

/// `branch` is a valid branch name, is the checked-out branch, and is not
/// the remote's default branch, which must be known.
fn feature_branch_checked_out(probe: &Probe, branch: &str) -> bool {
    probe
        .text(&["check-ref-format", "--branch", branch])
        .is_some_and(|value| value == branch)
        && probe
            .text(&["symbolic-ref", "--quiet", "--short", "HEAD"])
            .is_some_and(|value| value == branch)
        && probe
            .optional_text(&[
                "symbolic-ref",
                "--quiet",
                "--short",
                "refs/remotes/origin/HEAD",
            ])
            .flatten()
            .is_some_and(|remote_head| remote_head != format!("origin/{branch}"))
}
