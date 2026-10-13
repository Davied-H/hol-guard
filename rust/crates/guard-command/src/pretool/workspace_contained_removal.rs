//! File removal inside the workspace sandbox.
//!
//! The destructive-shell rule matches every `rm`, `dd`, `truncate` and in-place
//! edit, and marks each match uncertain because the rule alone cannot prove a
//! target is safe to lose. A plain `rm` or `rmdir` in the workspace is ordinary
//! cleanup: the sandbox keeps it off the home directory and `.git`, so this
//! module accepts that uncertainty for those two programs only. A recursive
//! removal could still take uncommitted work with it, so each of its targets
//! must be missing or ignored by Git, and it must run before any other command
//! could create or move what it names.
use super::super::git_session_probe::Probe;
use super::PathContext;
use crate::CanonicalCommandV1;
use guard_contracts::{
    GuardExecutionEnvironmentV1, NativeCommandObservationV1, NativeCommandObservationsV1,
    PreToolResultV1,
};
use std::path::Path;

pub(super) const SHELL_DESTRUCTION: &str = "command.shell-mutations.destructive-shell";

fn segment_indexes(observation: &NativeCommandObservationV1) -> impl Iterator<Item = usize> + '_ {
    observation
        .matcher_evidence
        .iter()
        .map(|evidence| evidence.segment_index)
        .chain(observation.effective_segment_indexes.iter().copied())
}

/// The operands of a plain `rm` or `rmdir` segment and whether it recurses,
/// or `None` for any other program, option or shell expansion.
fn removal(model: &CanonicalCommandV1, index: usize) -> Option<(bool, Vec<&str>)> {
    let segment = model.segments.get(index)?;
    let program = segment.executable.as_deref()?;
    if !matches!(program, "rm" | "rmdir")
        || segment.path_overridden
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
    {
        return None;
    }
    let (mut recursive, mut options, mut operands) = (false, true, Vec::new());
    for argument in &segment.arguments {
        if options && argument == "--" {
            options = false;
        } else if options && argument.starts_with("--") {
            match argument.as_str() {
                "--recursive" => recursive = true,
                "--force" | "--verbose" | "--dir" => {}
                _ => return None,
            }
        } else if options && argument.len() > 1 && argument.starts_with('-') {
            for flag in argument[1..].chars() {
                match flag {
                    'r' | 'R' => recursive = true,
                    'f' | 'i' | 'I' | 'v' | 'd' => {}
                    _ => return None,
                }
            }
        } else if argument.is_empty() || argument.contains(['$', '`', '~']) {
            return None;
        } else {
            operands.push(argument.as_str());
        }
    }
    (program == "rm" || !recursive).then_some((recursive, operands))
}

/// Whether `observation` is the destructive-shell match on plain removals.
pub(super) fn accepted(
    observation: &NativeCommandObservationV1,
    model: &CanonicalCommandV1,
) -> bool {
    let mut indexes = segment_indexes(observation).peekable();
    observation.rule_id == SHELL_DESTRUCTION
        && observation.uncertainty_reasons == ["matcher-failure"]
        && indexes.peek().is_some()
        && indexes.all(|index| removal(model, index).is_some())
}

/// The uncertainty the binding may carry: one per accepted removal match.
pub(super) fn accepted_uncertainty(
    extensions: &NativeCommandObservationsV1,
    model: &CanonicalCommandV1,
) -> usize {
    extensions
        .observations
        .iter()
        .filter(|observation| {
            !observation.uncertainty_reasons.is_empty() && accepted(observation, model)
        })
        .count()
}

/// Whether a recursive removal could take work Git does not already ignore.
pub(super) fn loses_work(
    result: &PreToolResultV1,
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    let (Some(extensions), Some(cwd)) = (result.command_extensions.as_ref(), context.cwd) else {
        return true;
    };
    let cwd = Path::new(cwd);
    let removals: Vec<(usize, Vec<&str>)> = extensions
        .observations
        .iter()
        .filter(|observation| observation.rule_id == SHELL_DESTRUCTION)
        .flat_map(segment_indexes)
        .filter_map(|index| match removal(model, index) {
            Some((true, operands)) => Some((index, operands)),
            _ => None,
        })
        .collect();
    if removals.is_empty() {
        return false;
    }
    // An earlier command could create or move what the removal names, so the
    // check below would describe the wrong tree.
    let first_other = model
        .segments
        .iter()
        .enumerate()
        .position(|(index, _)| removal(model, index).is_none())
        .unwrap_or(model.segments.len());
    if removals.iter().any(|(index, _)| *index > first_other) {
        return true;
    }
    let mut probe = None;
    removals
        .iter()
        .flat_map(|(_, operands)| operands)
        .any(|operand| {
            if operand.contains(['*', '?', '[', '{']) {
                return true;
            }
            if std::fs::symlink_metadata(cwd.join(operand)).is_err() {
                return false;
            }
            let probe = probe.get_or_insert_with(|| {
                let probe = Probe::new("git", &[], context, None, execution_environment)?;
                let (effective, repository) = probe.config()?;
                super::super::git_local_writes::inert(&effective, &repository).then_some(probe)
            });
            probe
                .as_ref()
                .and_then(|probe| probe.text(&["check-ignore", "--", operand]))
                .is_none()
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
    let root_glob = normal
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            // Brackets and braces can spell any name, so only a literal
            // stem or suffix such as `*.pyc` keeps a root glob narrow.
            name.chars().all(|c| matches!(c, '*' | '.' | '?')) || name.contains(['[', '{', '\\'])
        });
    // The volume may be case-insensitive, so `/Users/me/Proj` can name the
    // workspace `/Users/me/proj`.
    let fold = |path: &Path| std::path::PathBuf::from(path.to_string_lossy().to_ascii_lowercase());
    let (normal, workspace) = (fold(&normal), fold(workspace));
    workspace.starts_with(&normal) || (root_glob && normal.parent() == Some(workspace.as_path()))
}

pub(super) fn destroys_workspace(
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
        .flat_map(segment_indexes)
        .any(|index| {
            model.segments.get(index).is_none_or(|segment| {
                segment
                    .arguments
                    .iter()
                    .any(|argument| broad_target(argument, workspace))
            })
        })
}
