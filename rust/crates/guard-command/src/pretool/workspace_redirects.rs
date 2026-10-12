//! Redirects inside the workspace sandbox.
//!
//! The ordinary redirect projection removes a write only from a single
//! segment and only to a bounded, non-hidden target, because outside a
//! sandbox an earlier segment could retarget the write through `cd` or a
//! symlink. Inside `workspace-contained-v1` the kernel confines every write
//! and read, so compound commands whose redirects name literal paths may run
//! there too. This projection removes those redirects so the command that
//! remains can be classified exactly. It never decides by itself: the
//! projected command must still earn the workspace profile, and the raw text
//! is what runs.

use std::path::Path;
use std::time::Instant;

use guard_contracts::{GuardExecutionEnvironmentV1, PreToolResultV1};
use serde_json::Value;

use super::redirect_projection::{
    boundary, remove_quoted_heredoc, skip_heredoc_bodies, trailing_word,
};
use crate::native_command_controls::CompiledNativeCommandControls;
use crate::pretool::workspace_contained::Shape;
use crate::CommandModelRequestV1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Quote {
    None,
    Single,
    Double,
}

/// The command with every literal-path redirect, descriptor copy and quoted
/// `cat` heredoc removed. `None` when nothing was removed or any redirect has
/// another form: process substitution, a computed or home-relative target, a
/// descriptor above 2, a herestring, or a heredoc fed to anything but `cat`.
pub(crate) fn project(raw: &str) -> Option<String> {
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::with_capacity(raw.len());
    let mut heredocs: Vec<(String, bool)> = Vec::new();
    let (mut quote, mut escaped, mut removed) = (Quote::None, false, false);
    let mut index = 0usize;
    while index < chars.len() {
        let current = chars[index];
        if escaped {
            escaped = false;
            out.push(current);
            index += 1;
            continue;
        }
        match quote {
            Quote::Single => {
                quote = if current == '\'' { Quote::None } else { quote };
                out.push(current);
                index += 1;
                continue;
            }
            Quote::Double => {
                if current == '"' {
                    quote = Quote::None;
                } else if current == '\\' {
                    escaped = true;
                }
                out.push(current);
                index += 1;
                continue;
            }
            Quote::None => {}
        }
        match current {
            '\'' => quote = Quote::Single,
            '"' => quote = Quote::Double,
            '\\' => escaped = true,
            '\n' if !heredocs.is_empty() => {
                out.push('\n');
                index = skip_heredoc_bodies(&chars, index + 1, &mut heredocs)?;
                continue;
            }
            '<' if chars.get(index + 1) == Some(&'<') => {
                // A heredoc is stdin. Only `cat` is known to treat it as data.
                if current_segment(&out).trim() != "cat" {
                    return None;
                }
                index = remove_quoted_heredoc(&chars, index, &mut out, &mut heredocs)?;
                index = rejoin(&chars, index, &mut out);
                removed = true;
                continue;
            }
            '<' | '>' => {
                index = remove_redirect(&chars, index, &mut out)?;
                index = rejoin(&chars, index, &mut out);
                removed = true;
                continue;
            }
            _ => {}
        }
        out.push(current);
        index += 1;
    }
    (removed && quote == Quote::None && !escaped && heredocs.is_empty())
        .then(|| out.trim().to_owned())
}

/// The shape the projected command earns, with a bootstrapped `git init`
/// sliced from the raw bytes that will run. `None` when the init segment
/// itself carried a redirect, so the raw text cannot be split the same way.
pub(crate) fn contained_shape(raw: &str, projected: &str, workspace: &Path) -> Option<Shape> {
    let model = crate::parse_command(&CommandModelRequestV1 {
        command: projected.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "pre-tool-generic".into(),
    })
    .ok()?;
    let mut shape = crate::pretool::command_shape(&model, workspace, Some(projected))?;
    if let Some(rest) = shape.remainder.take() {
        let prefix = projected.trim().strip_suffix(rest.as_str())?;
        let raw_rest = raw.trim().strip_prefix(prefix)?.trim();
        if rest.is_empty() != raw_rest.is_empty() {
            return None;
        }
        shape.remainder = Some(raw_rest.to_owned());
    }
    Some(shape)
}

/// Leaves one space where a redirect was, so the projection keeps the
/// spacing the parser normalizes to.
fn rejoin(chars: &[char], mut index: usize, out: &mut String) -> usize {
    // An escaped space is part of a word; dropping it could join lines.
    while out.ends_with([' ', '\t']) && !out[..out.len() - 1].ends_with('\\') {
        out.pop();
    }
    while matches!(chars.get(index), Some(' ' | '\t')) {
        index += 1;
    }
    if !out.is_empty() && chars.get(index).is_some_and(|value| *value != '\n') {
        out.push(' ');
    }
    index
}

/// A compound command whose redirects all name literal paths runs in the
/// workspace sandbox when the command without them earns that profile and
/// the raw text targets nothing sensitive. The sandbox confines the files the
/// redirects open, which the single-segment projection cannot prove.
#[allow(clippy::too_many_arguments)]
pub(super) fn contained(
    harness: &str,
    event: &str,
    payload: &Value,
    command: &str,
    controls: Option<&CompiledNativeCommandControls>,
    deadline: Option<Instant>,
    context: crate::pretool::PathContext<'_>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> Option<PreToolResultV1> {
    if !crate::pretool::workspace_contained::host_eligible(harness, event) {
        return None;
    }
    let projected_text = project(command)?;
    let projected_payload =
        super::command_rewrite::payload_with_command(payload, command, &projected_text);
    let projected = super::evaluate_envelope(
        harness,
        event,
        &projected_payload,
        controls,
        deadline,
        context,
        execution_environment,
        false,
    );
    if projected.reason_code != crate::pretool::workspace_contained::REASON {
        return None;
    }
    let workspace = crate::pretool::workspace_contained::admitted_workspace(context)?;
    contained_shape(command, &projected_text, &workspace)?;
    let raw = super::evaluate_envelope(
        harness,
        event,
        payload,
        None,
        deadline,
        context,
        execution_environment,
        false,
    );
    (!raw.action.sensitive_target && raw.reason_code == "native_command_review_required")
        .then_some(projected)
}

/// The text of the simple command being written, after the last separator.
fn current_segment(out: &str) -> &str {
    let start = out
        .rfind([';', '|', '&', '\n', '(', ')', '{', '}'])
        .map_or(0, |position| position + 1);
    &out[start..]
}

fn remove_redirect(chars: &[char], start: usize, out: &mut String) -> Option<usize> {
    let input = chars[start] == '<';
    let mut index = start + 1;
    let descriptor = trailing_word(out).to_owned();
    match descriptor.as_str() {
        "" => {}
        "1" | "2" if !input => out.truncate(out.len() - 1),
        "0" if input => out.truncate(out.len() - 1),
        _ if descriptor.chars().all(|value| value.is_ascii_digit()) => return None,
        // `&>` means background-then-redirect under POSIX `sh`.
        _ if descriptor.ends_with('&') => return None,
        _ => {}
    }
    if chars.get(index) == Some(&'&') {
        // A descriptor copy between stdout and stderr moves no file data.
        if input
            || !matches!(chars.get(index + 1), Some('1' | '2'))
            || !boundary(chars.get(index + 2))
        {
            return None;
        }
        out.push(' ');
        return Some(index + 2);
    }
    if !input && matches!(chars.get(index), Some('>' | '|')) {
        index += 1;
    }
    if matches!(chars.get(index), Some('|' | '(' | '>' | '<' | '&')) {
        return None;
    }
    while matches!(chars.get(index), Some(' ' | '\t')) {
        index += 1;
    }
    let target_start = index;
    while chars.get(index).is_some_and(|value| {
        !value.is_whitespace() && !matches!(value, ';' | '|' | '&' | ')' | '(' | '<' | '>')
    }) {
        index += 1;
    }
    let target: String = chars[target_start..index].iter().collect();
    if !literal_target(&target) {
        return None;
    }
    out.push(' ');
    Some(index)
}

/// A path the shell opens exactly as written: no expansion, glob, quote or
/// home prefix. The sandbox decides whether it may be written.
fn literal_target(target: &str) -> bool {
    !target.is_empty()
        && target.len() <= 4096
        && !target.starts_with(['-', '~'])
        && target
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || "._-/+@%,=:".contains(value))
}

#[cfg(test)]
#[path = "workspace_redirects_tests.rs"]
mod tests;
