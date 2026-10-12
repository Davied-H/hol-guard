//! Keep commands the canonical parser cannot model reviewable where safe.
//!
//! Loops, heredocs, shell wrappers and environment prefixes defeat the exact
//! model that extension matchers need. Treating that as an evaluation failure
//! blocked them outright, so a fully permitted `gh` call inside a `for` loop
//! could not even be approved. They are now treated like an uncertain
//! observation: they take the strongest floor of every active extension that
//! could own part of them, and never less than review. An extension could own
//! the command when the text names one of its programs, when it cannot be
//! recognized by name, or when the text runs an interpreter or synthesizes a
//! program name the scan cannot see. Signed or managed policy keeps the
//! evaluation failure.

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
    /// failure where signed or managed policy governs the controls.
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
        let text = &command.normalized_text;
        let named = named_words(text);
        let literal = unquoted_literal(text);
        let opaque = synthesizes_program(&literal) || {
            let interpreted = named_words(&literal);
            INTERPRETERS.iter().any(|name| interpreted.contains(*name))
        };
        let mut floor = "review";
        for (index, extension) in self.program.extensions.iter().enumerate() {
            if !self.active_extensions.contains(&extension.extension_id) {
                continue;
            }
            let compatibility = COMPATIBILITY_EXECUTABLES
                .iter()
                .find(|(id, _)| *id == extension.extension_id)
                .map(|(_, executables)| *executables);
            let owns = opaque
                || self
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
    literal
        .split(|character: char| {
            matches!(
                character,
                ';' | '&' | '|' | '(' | ')' | '{' | '}' | '\n' | '`'
            )
        })
        .any(|piece| {
            let mut words = piece
                .split_whitespace()
                .skip_while(|word| SHELL_PREFIXES.contains(word) || is_assignment(word));
            match words.next() {
                Some("for" | "case" | "select" | "in" | "done" | "fi" | "esac" | "[" | "[[")
                | None => false,
                Some(word) => word == "." || word.contains(['$', '*', '?', '[']),
            }
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
