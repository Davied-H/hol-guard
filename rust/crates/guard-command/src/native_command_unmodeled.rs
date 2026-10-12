//! Keep ordinary shell structure the canonical parser cannot model reviewable.
//!
//! Loops, conditionals and heredocs defeat the exact model that extension
//! matchers need. Treating that as an evaluation failure blocked them
//! outright, so a fully permitted `gh` call inside a `for` loop, or a
//! `gh pr comment` fed by a heredoc, could not even be approved. Those two
//! shapes are now treated like an uncertain observation: they take the
//! strongest floor of every active extension whose programs the text names,
//! or that cannot be recognized by name, and never less than review.
//!
//! Everything that could hide a program or move data keeps the evaluation
//! failure: wrappers, nested executors, command substitution, redirects
//! other than one input heredoc, `PATH` overrides, interpreters and program
//! names built from expansions or globs, as do signed or managed policy and
//! global lockdown.

use std::collections::BTreeSet;
use std::time::Instant;

use guard_contracts::NativeCommandObservationBatchV1;

use super::{rank, rule_floor, CompiledNativeCommandControls};
use crate::CanonicalCommandV1;

/// Compatibility owners recognize these programs without a catalog matcher.
const COMPATIBILITY_EXECUTABLES: &[(&str, &[&str])] = &[
    ("command.git", &["git"]),
    ("command.github", &["gh"]),
    ("command.container-runtime", &["docker"]),
    ("command.kubernetes-operations", &["kubectl", "oc"]),
    ("command.kubernetes-secrets", &["kubectl", "oc"]),
];

const UNMODELED_ERRORS: [&str; 2] = [
    "native_command_compatibility_model_unsupported",
    "native_command_compatibility_context_unsupported",
];

/// Programs that run text they receive, so they can assemble any command.
const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "fish",
    "ash",
    "busybox",
    "pwsh",
    "powershell",
    "cmd",
    "eval",
    "source",
    "exec",
    "xargs",
    "env",
    "python",
    "python2",
    "python3",
    "node",
    "deno",
    "bun",
    "perl",
    "ruby",
    "php",
    "lua",
    "osascript",
    "awk",
    "gawk",
    "watch",
    "parallel",
    "su",
    "script",
    "tmux",
    "screen",
    "expect",
];

/// Words that take a command position without being the program.
const SHELL_PREFIXES: &[&str] = &[
    "do", "then", "else", "elif", "while", "until", "if", "!", "time", "command", "builtin",
    "nohup",
];

impl CompiledNativeCommandControls {
    /// Observes `command`, returning the review floor it takes when it is
    /// unmodeled but its possible owners can still be bounded.
    pub(super) fn observe_command(
        &self,
        command: &CanonicalCommandV1,
        deadline: Option<Instant>,
        context: crate::pretool::PathContext<'_>,
    ) -> Result<(NativeCommandObservationBatchV1, Option<&'static str>), &'static str> {
        match self
            .program
            .observe_with_context(command, &self.active_extensions, deadline, context)
        {
            Err(error) if UNMODELED_ERRORS.contains(&error) => self
                .unmodeled_floor(command)
                .map(|floor| (NativeCommandObservationBatchV1::default(), Some(floor)))
                .ok_or(error),
            observed => observed.map(|batch| (batch, None)),
        }
    }

    /// The strongest floor of every active extension that could own part of
    /// the command, and never less than review. `None` keeps the evaluation
    /// failure.
    fn unmodeled_floor(&self, command: &CanonicalCommandV1) -> Option<&'static str> {
        if self.global_block
            || self.binding.managed_revision != 0
            || self
                .binding
                .layers
                .iter()
                .any(|layer| layer.global_lockdown || layer.kind != "local-admin")
        {
            return None;
        }
        if !reviewable_structure(command) {
            return None;
        }
        let text = &command.normalized_text;
        let literal = unquoted_literal(text);
        let interpreted = named_words(&literal);
        if synthesizes_program(&literal)
            || INTERPRETERS.iter().any(|name| interpreted.contains(*name))
        {
            return None;
        }
        let named = named_words(text);
        let mut floor = "review";
        for (index, extension) in self.program.extensions.iter().enumerate() {
            if !self.active_extensions.contains(&extension.extension_id) {
                continue;
            }
            let compatibility = COMPATIBILITY_EXECUTABLES
                .iter()
                .find(|(id, _)| *id == extension.extension_id)
                .map(|(_, executables)| *executables);
            let owns = self
                .program
                .extension_names(index, compatibility)
                .is_none_or(|names| names.is_empty() || !names.is_disjoint(&named));
            if owns && rank(self.extension_floor(index)) > rank(floor) {
                floor = self.extension_floor(index);
            }
        }
        Some(floor)
    }

    /// The floor the extension would apply to its strongest rule, as an
    /// uncertain observation owned by it would take.
    fn extension_floor(&self, index: usize) -> &'static str {
        let extension = &self.program.extensions[index];
        if self.blocked_extensions.contains(&extension.extension_id)
            || extension
                .permissions
                .iter()
                .any(|permission| self.blocked_permissions.contains(&permission.permission_id))
        {
            return "block";
        }
        self.program
            .rules
            .iter()
            .filter(|rule| rule.extension_index == index)
            .map(|rule| {
                if self
                    .explicitly_enabled_permissions
                    .contains(&rule.permission_id)
                {
                    "review"
                } else {
                    rule_floor(rule, extension.required)
                }
            })
            .max_by_key(|floor| rank(floor))
            .unwrap_or("review")
    }
}

/// Loops and conditionals, or one heredoc that only feeds standard input,
/// with nothing in the shell text that redirects, substitutes or overrides
/// `PATH`.
fn reviewable_structure(command: &CanonicalCommandV1) -> bool {
    if command.path_overridden || command.confidence != "uncertain" {
        return false;
    }
    match command.uncertainty_reason.as_deref() {
        Some("compound_shell_not_yet_supported") => {
            !moves_data(&unquoted_literal(&command.normalized_text))
        }
        Some("command_redirect_not_yet_supported") => input_heredoc(&command.normalized_text),
        _ => false,
    }
}

/// Whether shell text redirects, substitutes or sets the environment of a
/// command, such as `PATH`, outside single quotes.
fn moves_data(literal: &str) -> bool {
    literal.contains(['<', '>', '`'])
        || literal.contains("$(")
        || command_words(literal).any(|word| {
            is_assignment(word)
                || matches!(
                    word,
                    "export" | "declare" | "typeset" | "readonly" | "local" | "unset" | "alias"
                )
        })
}

/// One heredoc on the first line, ending the text, whose body cannot run
/// commands: its delimiter is quoted, or the body expands nothing.
fn input_heredoc(text: &str) -> bool {
    let Some((line, rest)) = text.split_once('\n') else {
        return false;
    };
    let Some((before, after)) = line.split_once("<<") else {
        return false;
    };
    let after = after.strip_prefix('-').unwrap_or(after).trim();
    let quoted = after.starts_with(['\'', '"']);
    let delimiter = after.trim_matches(['\'', '"']);
    if delimiter.is_empty()
        || !delimiter
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        || moves_data(&unquoted_literal(before))
    {
        return false;
    }
    let mut lines: Vec<&str> = rest.lines().collect();
    if lines.pop().map(str::trim) != Some(delimiter)
        || lines.iter().any(|body| body.trim() == delimiter)
    {
        return false;
    }
    quoted || lines.iter().all(|body| !body.contains(['$', '`', '\\']))
}

/// Every word the shell could read as a program name or keyword token, with
/// and without quoting, as a full path, a basename and without a Windows
/// suffix, so `sh -c 'gh …'`, `g""h` and `C:\tools\GH.EXE` all name `gh`.
fn named_words(text: &str) -> BTreeSet<String> {
    let unquoted: String = text
        .chars()
        .filter(|character| !matches!(character, '\'' | '"' | '\\'))
        .collect();
    let mut named = BTreeSet::new();
    for value in [text, unquoted.as_str()] {
        let words = value.split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | '+' | '/'))
        });
        for word in words.chain(value.split_whitespace()) {
            let lowered = word.to_ascii_lowercase();
            let base = lowered
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or_default()
                .to_owned();
            for name in [lowered, base] {
                if let Some(stem) = name
                    .strip_suffix(".exe")
                    .or_else(|| name.strip_suffix(".cmd"))
                {
                    named.insert(stem.to_owned());
                }
                if !name.is_empty() {
                    named.insert(name);
                }
            }
        }
    }
    named
}

/// The text outside single quotes. Single-quoted text is literal and only
/// runs as a command through an interpreter, which is checked separately.
/// Quotes inside double quotes or after a backslash stay ordinary text. An
/// unterminated quote or a heredoc, whose body quotes are not shell syntax,
/// keeps the whole text in view.
fn unquoted_literal(text: &str) -> String {
    if text.contains("<<") {
        return text.to_owned();
    }
    let mut literal = String::with_capacity(text.len());
    let (mut single, mut double, mut escaped) = (false, false, false);
    for character in text.chars() {
        if single {
            single = character != '\'';
        } else if escaped {
            escaped = false;
            literal.push(character);
        } else if character == '\'' && !double {
            single = true;
        } else {
            escaped = character == '\\';
            double ^= character == '"';
            literal.push(character);
        }
    }
    if single {
        return text.to_owned();
    }
    literal
}

/// Whether a command position holds an expansion, glob or `.` source, which
/// can run a program whose name appears nowhere in the text.
fn synthesizes_program(literal: &str) -> bool {
    command_words(literal)
        .filter(|word| !is_assignment(word))
        .any(|word| {
            !matches!(
                word,
                "for" | "case" | "select" | "in" | "done" | "fi" | "esac" | "[" | "[["
            ) && (word == "." || word.contains(['$', '*', '?', '[']))
        })
}

/// The leading assignments and first word of each simple command, after
/// any shell keyword that takes a command position.
fn command_words(literal: &str) -> impl Iterator<Item = &str> {
    literal
        .split(|character: char| {
            matches!(
                character,
                ';' | '&' | '|' | '(' | ')' | '{' | '}' | '\n' | '`'
            )
        })
        .flat_map(|piece| {
            let words = piece
                .split_whitespace()
                .skip_while(|word| SHELL_PREFIXES.contains(word));
            let mut leading = Vec::new();
            for word in words {
                leading.push(word);
                if !is_assignment(word) {
                    break;
                }
            }
            leading
        })
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

#[cfg(test)]
#[path = "native_command_unmodeled_tests.rs"]
mod tests;
