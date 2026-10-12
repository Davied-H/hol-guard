//! General workspace containment for confidently parsed local commands.
//!
//! A command no narrower profile claims runs inside the macOS workspace
//! sandbox (no network, no home, credentials denied, `.git` execution config
//! and agent/editor paths write-denied) instead of becoming a review prompt.
//! The sandbox, not this classifier, is the security boundary; this module only
//! refuses shapes whose effect the sandbox cannot bound.
use super::PathContext;
use crate::native_command_controls::CompiledNativeCommandControls;
use crate::CanonicalCommandV1;
use guard_contracts::{PreToolActionTypeV1, PreToolResultV1};
use std::path::Path;

pub(crate) const REASON: &str = "native_workspace_containment_required";
pub(crate) const PROFILE: &str = "workspace-contained-v1";

#[path = "workspace_contained_package.rs"]
mod package;

// Privilege and permission changes. This is an exclusion, not an allowlist.
const PRIVILEGE_DENY: &[&str] = &[
    "sudo",
    "doas",
    "su",
    "login",
    "chmod",
    "chown",
    "chgrp",
    "chflags",
    "xattr",
    "setfacl",
    "launchctl",
    "crontab",
    "at",
    "security",
    "osascript",
    "open",
    "defaults",
    "dscl",
    "spctl",
    "csrutil",
    "kill",
    "killall",
    "pkill",
];
// The sandbox cannot undo losing uncommitted work, so these stay at review.
const UNRECOVERABLE_RULES: &[&str] = &[
    "command.git.hard-reset",
    "command.git.force-clean",
    "command.git.clean",
    "command.git.reset",
    "command.git.local-branch-delete",
    "command.git.stash",
    "command.git.checkout",
    "command.git.restore",
    "command.git.switch",
    "command.git.unsafe-read",
];
// These change a remote. The sandbox has no network, so containing them would
// only turn a consent prompt into a silent failure.
const REMOTE_RULES: &[&str] = &["command.git.force-push", "command.git.remote-branch-delete"];
const SHELL_DESTRUCTION: &str = "command.shell-mutations.destructive-shell";
const CONTAINABLE_RISKS: &[&str] = &["local_secret_read", "destructive_shell"];
/// What the sandbox executes for one authorized command.
pub(crate) struct Shape {
    /// Arguments for a trusted `git init`, run before the sandbox starts
    /// because `git init` always rewrites the write-denied `.git/config`.
    pub bootstrap: Option<Vec<String>>,
    /// Text for `sh -c`; `None` runs the original bytes unchanged.
    pub remainder: Option<String>,
}

fn branch_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
}

fn init_arguments(arguments: &[String]) -> Option<Vec<String>> {
    let mut result = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "-q" | "--quiet" => result.push("-q".to_owned()),
            "." => {}
            "-b" => {
                index += 1;
                let name = arguments.get(index).filter(|name| branch_name(name))?;
                result.extend(["-b".to_owned(), name.clone()]);
            }
            value => {
                let name = value
                    .strip_prefix("--initial-branch=")
                    .filter(|name| branch_name(name))?;
                result.extend(["-b".to_owned(), name.to_owned()]);
            }
        }
        index += 1;
    }
    Some(result)
}

/// Shape checks shared by classification and the launch plan. `original` is
/// the exact text the caller will run; it is needed only to slice off a
/// bootstrapped `git init`.
pub(crate) fn command_shape(
    model: &CanonicalCommandV1,
    workspace: &Path,
    original: Option<&str>,
) -> Option<Shape> {
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || model.segments.is_empty()
    {
        return None;
    }
    let mut bootstrap = None;
    for (index, segment) in model.segments.iter().enumerate() {
        let executable = segment.executable.as_deref()?;
        if executable.contains('$')
            || !segment.wrapper_chain.is_empty()
            || segment.path_overridden
            // Redirecting Git's repository or configuration roots would move
            // the write-denied paths this profile relies on.
            || segment
                .environment_names
                .iter()
                .any(|name| name.to_ascii_uppercase().starts_with("GIT_"))
        {
            return None;
        }
        let name = super::executable_basename(executable);
        if PRIVILEGE_DENY.contains(&name) {
            return None;
        }
        if name == "git" && segment.arguments.iter().any(|argument| argument == "init") {
            if index != 0 || segment.arguments.first().map(String::as_str) != Some("init") {
                return None;
            }
            // An existing `.git` is never re-initialized: that is a config write.
            if std::fs::symlink_metadata(workspace.join(".git")).is_ok() {
                return None;
            }
            bootstrap = Some(init_arguments(&segment.arguments[1..])?);
        }
    }
    let Some(arguments) = bootstrap else {
        return Some(Shape {
            bootstrap: None,
            remainder: None,
        });
    };
    let text = original?;
    if text.trim() != model.normalized_text || model.normalized_text != model.normalized_text.trim()
    {
        return None;
    }
    let tail: String = model
        .normalized_text
        .chars()
        .skip(model.segments[0].span.end)
        .collect();
    let tail = tail.trim_start_matches([' ', '\t']);
    let rest = if tail.is_empty() {
        ""
    } else {
        // Only an unconditional sequence may drop the `git init` segment.
        tail.strip_prefix("&&")
            .or_else(|| tail.strip_prefix(';'))
            .or_else(|| tail.strip_prefix('\n'))?
    };
    Some(Shape {
        bootstrap: Some(arguments),
        remainder: Some(rest.trim().to_owned()),
    })
}

fn extensions_contain(
    result: &PreToolResultV1,
    controls: &CompiledNativeCommandControls,
    package: bool,
) -> bool {
    // Without the loaded extension program there is no network or risk
    // evidence, so the command stays at review.
    let Some(extensions) = result.command_extensions.as_ref() else {
        return false;
    };
    extensions.binding.uncertainty_count == 0
        && extensions.evaluation_error.is_none()
        // The Node package-firewall permission marks package-manager use, not
        // a proven risk. A disabled one already blocked before this point.
        && extensions.permission_observations.iter().all(|observation| {
            package
                && observation.mcp_tool.is_none()
                && observation.extension_id == package::NODE_PACKAGE_EXTENSION
                && observation.uncertainty_reasons.is_empty()
        })
        && extensions.observations.iter().all(|observation| {
            observation.uncertainty_reasons.is_empty()
                && !UNRECOVERABLE_RULES.contains(&observation.rule_id.as_str())
                && !REMOTE_RULES.contains(&observation.rule_id.as_str())
                && controls
                    .rule_risk_classes(&observation.rule_id)
                    .is_some_and(|classes| {
                        classes
                            .iter()
                            .all(|class| CONTAINABLE_RISKS.contains(&class.as_str()))
                    })
        })
}

/// Whether a destructive argument names the whole workspace, an ancestor of
/// it, or every entry at its root. Deleting build output stays contained;
/// wiping the workspace loses uncommitted work like `git reset --hard`.
fn broad_target(argument: &str, workspace: &Path) -> bool {
    use std::path::Component;
    if argument.starts_with('-') {
        return false;
    }
    if argument.starts_with('~') || argument.contains('$') {
        return true;
    }
    let path = Path::new(argument);
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace.join(path)
    };
    let mut normal = std::path::PathBuf::new();
    for component in joined.components() {
        match component {
            Component::ParentDir => {
                normal.pop();
            }
            Component::CurDir => {}
            other => normal.push(other),
        }
    }
    let root_glob = normal.parent() == Some(workspace)
        && normal
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.chars().all(|c| matches!(c, '*' | '.' | '?')));
    workspace.starts_with(&normal) || root_glob
}

fn destroys_workspace(
    result: &PreToolResultV1,
    model: &CanonicalCommandV1,
    workspace: &Path,
) -> bool {
    let Some(extensions) = result.command_extensions.as_ref() else {
        return true;
    };
    extensions
        .observations
        .iter()
        .filter(|observation| observation.rule_id == SHELL_DESTRUCTION)
        .flat_map(|observation| {
            observation
                .matcher_evidence
                .iter()
                .map(|evidence| evidence.segment_index)
                .chain(observation.effective_segment_indexes.iter().copied())
        })
        .any(|index| {
            model.segments.get(index).is_none_or(|segment| {
                segment
                    .arguments
                    .iter()
                    .any(|argument| broad_target(argument, workspace))
            })
        })
}

/// Convert a generic review into a workspace sandbox requirement when every
/// condition holds. `pre_floor` is the reason and action before the Git
/// execution-context floor ran.
#[allow(clippy::too_many_arguments)]
pub(super) fn convert(
    result: &mut PreToolResultV1,
    pre_floor: &(String, String),
    model: Option<&CanonicalCommandV1>,
    controls: Option<&CompiledNativeCommandControls>,
    context: PathContext<'_>,
    harness: &str,
    event: &str,
    command_text: Option<&str>,
) {
    if !cfg!(target_os = "macos")
        || event != "PreToolUse"
        || !matches!(
            harness,
            "omp" | "oh-my-pi" | "zcode" | "claude-code" | "codex"
        )
        || !matches!(
            result.action.action_type,
            PreToolActionTypeV1::Command | PreToolActionTypeV1::Package
        )
        || result.action.sensitive_target
    {
        return;
    }
    let package = result.action.action_type == PreToolActionTypeV1::Package;
    let floor_reason = if package {
        "native_package_review"
    } else {
        "native_command_review_required"
    };
    let generic = result.reason_code == floor_reason && result.minimum_action == "review";
    // The Git floor existed because unsandboxed helpers could run; inside the
    // sandbox the configuration is write-denied and helpers stay contained.
    let git_floor = result.reason_code == "native_git_execution_context_review"
        && pre_floor.1 == "review"
        && (pre_floor.0 == floor_reason || pre_floor.0 == "native_git_helper_context_review");
    if !generic && !git_floor {
        return;
    }
    let (Some(model), Some(controls), Some(cwd)) = (model, controls, context.cwd) else {
        return;
    };
    if !extensions_contain(result, controls, package)
        || (package && !package::local_package_work(model))
    {
        return;
    }
    let Some(workspace) = crate::restricted_pytest::workspace_admissible(
        Path::new(cwd),
        context.home_dir.map(Path::new),
    ) else {
        return;
    };
    // Installs, one-shot executions and lockfile syncs stay with supply-chain
    // admission even when the verb check above missed their spelling.
    if package
        && command_text.is_none_or(|text| {
            crate::package_intent_parser::parse_package_intent(
                text,
                Some(&workspace),
                context.home_dir.map(Path::new),
                None,
                None,
            )
            .is_some()
        })
    {
        return;
    }
    let Ok(config) = super::workspace_git_config::repository_config(&workspace) else {
        return;
    };
    if config.is_some_and(|text| {
        super::workspace_git_config::helper_write_denials(&text, &workspace).is_none()
    }) || command_shape(model, &workspace, command_text).is_none()
        || destroys_workspace(result, model, &workspace)
    {
        return;
    }
    result.minimum_action = "sandbox-required".into();
    result.policy_action = "sandbox-required".into();
    result.decision = "deny".into();
    result.explicitly_benign = false;
    result.reason_code = REASON.into();
    result.reason = concat!(
        "HOL Guard runs this command in a protected workspace sandbox ",
        "(no network, no home access).",
    )
    .into();
}
