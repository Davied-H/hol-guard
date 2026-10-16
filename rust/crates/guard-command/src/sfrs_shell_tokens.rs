//! Shell tokenization, wrapper and redirection parsing used by the request
//! classifier (`shell_tokenization.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;

use crate::env_wrapper::parse_env_wrapper;
use crate::hook_adapter_pytext::{compile_fancy, is_py_space, py_strip};
use crate::sfrs_constants::SHELL_TOOL_NAMES;
use crate::sfrs_patterns::{
    SHELL_ASSIGNMENT_PATTERN, SHELL_COMMAND_SEPARATORS, SHELL_COMMAND_WRAPPERS,
    SHELL_NEWLINE_SEPARATOR, WRAPPER_FLAGS_WITH_VALUES,
};
use crate::sfrs_shlex::split_punctuation;

const NOCLOBBER_SENTINEL: &str = "__HOL_GUARD_NOCLOBBER_REDIRECT__";

static ATTACHED_REDIRECT: LazyLock<FancyRegex> =
    LazyLock::new(|| compile_fancy(r"\A[0-2]?(?:>\||>>|>).+\z"));

const SUDO_VALUE_FLAGS: &[char] = &['C', 'D', 'R', 'T', 'g', 'h', 'p', 'r', 't', 'u'];

/// `_normalized_shell_command_name`.
pub(crate) fn normalized_shell_command_name(command_name: &str) -> String {
    let normalized = command_name.replace('\\', "/");
    let normalized = py_strip(&normalized);
    match normalized.rsplit_once('/') {
        Some((_, last)) => last.to_lowercase(),
        None => normalized.to_lowercase(),
    }
}

/// `_shell_normalized_tool_name` over already collected command candidates.
pub(crate) fn shell_normalized_tool_name(
    normalized_tool_name: Option<&str>,
    has_command_candidates: bool,
) -> Option<String> {
    if let Some(name) = normalized_tool_name {
        if SHELL_TOOL_NAMES.contains(&name) {
            return Some(name.to_owned());
        }
    }
    if has_command_candidates {
        return Some("shell".to_owned());
    }
    normalized_tool_name.map(str::to_owned)
}

/// `_stdin_redirect_target_from_token`: the redirect target and the number of
/// tokens consumed.
pub(crate) fn stdin_redirect_target_from_token(
    token: &str,
    next_token: Option<&str>,
) -> (Option<String>, usize) {
    if token_is_heredoc_operator(token) {
        return (None, 1);
    }
    if token == "<" || token == "0<" {
        return match next_token {
            None => (None, 1),
            Some(next) => (Some(next.to_owned()), 2),
        };
    }
    if token.matches('<').count() != 1 {
        return (None, 1);
    }
    let Some((fd, target)) = token.split_once('<') else {
        return (None, 1);
    };
    if (!fd.is_empty() && fd != "0") || target.is_empty() {
        return (None, 1);
    }
    (Some(target.to_owned()), 1)
}

pub(crate) fn token_is_heredoc_operator(token: &str) -> bool {
    token.contains("<<")
}

/// `_iter_shell_command_segments`.
pub(crate) fn iter_shell_command_segments(parts: &[String]) -> Vec<Vec<String>> {
    let mut segments = Vec::new();
    let mut current: Vec<String> = Vec::new();
    for part in parts {
        let token = py_strip(part);
        if token.is_empty() {
            continue;
        }
        if SHELL_COMMAND_SEPARATORS.contains(&token) {
            if !current.is_empty() {
                segments.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(token.to_owned());
    }
    if !current.is_empty() {
        segments.push(current);
    }
    segments
}

/// `_shell_segment_primary_command`: the command name and its token index.
pub(crate) fn shell_segment_primary_command(segment: &[String]) -> (Option<String>, Option<usize>) {
    let mut index = 0;
    while index < segment.len() {
        let consumed = leading_shell_redirection_tokens_consumed(segment, index);
        if consumed > 0 {
            index += consumed;
            continue;
        }
        let normalized_token = shell_command_token_without_attached_redirection(&segment[index]);
        if SHELL_ASSIGNMENT_PATTERN
            .is_match(&normalized_token)
            .unwrap_or(false)
        {
            index += 1;
            continue;
        }
        let command_name = normalized_shell_command_name(&normalized_token);
        if command_name == "env" {
            let parsed = parse_env_wrapper(&segment[index + 1..], None, None);
            let command_index = parsed.command_index;
            if parsed.complete && command_index.is_none() {
                return (Some(command_name), Some(index));
            }
            let Some(command_index) = command_index else {
                return (None, None);
            };
            if !parsed.complete || !parsed.split_expansions.is_empty() {
                return (None, None);
            }
            index += command_index + 1;
            continue;
        }
        if command_name == "timeout" {
            let Some(consumed) = timeout_clock_tokens_consumed(&segment[index + 1..]) else {
                return (None, None);
            };
            index += consumed + 1;
            continue;
        }
        if SHELL_COMMAND_WRAPPERS.contains(&command_name.as_str()) {
            index += 1;
            while index < segment.len() {
                let token = &segment[index];
                if !token.starts_with('-') {
                    break;
                }
                index += wrapper_option_tokens_consumed(&command_name, token);
            }
            continue;
        }
        return (Some(command_name), Some(index));
    }
    (None, None)
}

/// The tokens a `timeout` clock takes before the program it bounds: an
/// optional `--`, then the duration. `timeout` runs that program itself, so
/// the classifier reads the segment as the program's own, the same way the
/// command model does. Anything else after the clock — an option, a second
/// clock, nothing at all — leaves the program unreadable from the text.
fn timeout_clock_tokens_consumed(rest: &[String]) -> Option<usize> {
    let mut consumed = 0;
    if rest.first().is_some_and(|token| token == "--") {
        consumed += 1;
    }
    if !rest.get(consumed).is_some_and(|value| is_duration(value)) {
        return None;
    }
    consumed += 1;
    let program = rest.get(consumed)?;
    let readable = !program.is_empty()
        && !program.starts_with('-')
        && !SHELL_ASSIGNMENT_PATTERN.is_match(program).unwrap_or(false);
    readable.then_some(consumed)
}

/// A duration `timeout` reads: seconds, or a number carrying an `s`, `m`, `h`
/// or `d` unit, with an optional fraction.
fn is_duration(value: &str) -> bool {
    let number = value.strip_suffix(['s', 'm', 'h', 'd']).unwrap_or(value);
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    number.len() <= 10
        && !whole.is_empty()
        && whole.bytes().all(|byte| byte.is_ascii_digit())
        && fraction.bytes().all(|byte| byte.is_ascii_digit())
}

/// `_leading_shell_redirection_tokens_consumed`.
pub(crate) fn leading_shell_redirection_tokens_consumed(segment: &[String], index: usize) -> usize {
    let token = segment[index].as_str();
    let has_next = index + 1 < segment.len();
    let (target, consumed) =
        stdin_redirect_target_from_token(token, segment.get(index + 1).map(String::as_str));
    if target.is_some() {
        return consumed;
    }
    if matches!(token, "<<" | "<<-" | "<<<") {
        return if has_next { 2 } else { 1 };
    }
    if matches!(
        token,
        ">" | ">>" | ">|" | "0>" | "0>>" | "0>|" | "1>" | "1>>" | "1>|" | "2>" | "2>>" | "2>|"
    ) {
        return if has_next { 2 } else { 1 };
    }
    if ATTACHED_REDIRECT.is_match(token).unwrap_or(false) {
        return 1;
    }
    0
}

/// `_shell_command_token_without_attached_redirection`.
pub(crate) fn shell_command_token_without_attached_redirection(token: &str) -> String {
    let normalized = token.trim_start_matches('(').trim_end_matches(')');
    for (index, character) in normalized.char_indices() {
        if index == 0 || (character != '<' && character != '>') {
            continue;
        }
        return normalized[..index].to_owned();
    }
    normalized.to_owned()
}

/// `_split_shell_parts`.
pub(crate) fn split_shell_parts(command_text: &str) -> Vec<String> {
    let protected = protect_unquoted_noclobber_redirects(
        &replace_unquoted_newlines_with_separators(command_text),
    );
    let parts = match split_punctuation(&protected) {
        Ok(tokens) => tokens
            .into_iter()
            .map(|token| token.replace(NOCLOBBER_SENTINEL, ">|"))
            .collect(),
        Err(_) => command_text
            .split(is_py_space)
            .filter(|piece| !piece.is_empty())
            .map(str::to_owned)
            .collect(),
    };
    merge_shell_fd_redirect_parts(parts)
}

fn is_quote_char(c: char) -> bool {
    matches!(c, '\'' | '"' | '`')
}

/// `_protect_unquoted_noclobber_redirects`.
pub(crate) fn protect_unquoted_noclobber_redirects(command_text: &str) -> String {
    let chars: Vec<char> = command_text.chars().collect();
    let mut result = String::new();
    let mut quote: Option<char> = None;
    let mut escape_next = false;
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        if escape_next {
            result.push(character);
            escape_next = false;
            index += 1;
            continue;
        }
        if character == '\\' {
            result.push(character);
            escape_next = true;
            index += 1;
            continue;
        }
        if quote.is_none() && is_quote_char(character) {
            quote = Some(character);
        } else if quote == Some(character) {
            quote = None;
        }
        if quote.is_none() && character == '>' && chars.get(index + 1) == Some(&'|') {
            result.push_str(NOCLOBBER_SENTINEL);
            index += 2;
            continue;
        }
        result.push(character);
        index += 1;
    }
    result
}

/// `_merge_shell_fd_redirect_parts`.
pub(crate) fn merge_shell_fd_redirect_parts(parts: Vec<String>) -> Vec<String> {
    let mut merged = Vec::new();
    let mut index = 0;
    while index < parts.len() {
        let token = parts[index].as_str();
        if index + 2 < parts.len() && parts[index + 1] == "&" && is_fd_redirect(token) {
            let prefix = &token[..token.len() - 1];
            merged.push(format!("{prefix}>&{}", parts[index + 2]));
            index += 3;
            continue;
        }
        merged.push(parts[index].clone());
        index += 1;
    }
    merged
}

fn is_fd_redirect(token: &str) -> bool {
    matches!(token, ">" | "0>" | "1>" | "2>")
}

/// `_replace_unquoted_newlines_with_separators`.
pub(crate) fn replace_unquoted_newlines_with_separators(command_text: &str) -> String {
    let mut result = String::new();
    let mut quote: Option<char> = None;
    let mut escape_next = false;
    for character in command_text.chars() {
        if escape_next {
            result.push(character);
            escape_next = false;
            continue;
        }
        if character == '\\' {
            result.push(character);
            escape_next = true;
            continue;
        }
        if quote.is_none() && is_quote_char(character) {
            quote = Some(character);
            result.push(character);
            continue;
        }
        if quote == Some(character) {
            quote = None;
            result.push(character);
            continue;
        }
        if quote.is_none() && (character == '\n' || character == '\r') {
            if !result.ends_with(' ') {
                result.push(' ');
            }
            result.push('\n');
            result.push_str(SHELL_NEWLINE_SEPARATOR);
            result.push('\n');
            continue;
        }
        result.push(character);
    }
    result
}

/// `_wrapper_option_tokens_consumed`.
pub(crate) fn wrapper_option_tokens_consumed(command_name: &str, token: &str) -> usize {
    if !token.starts_with('-') {
        return 1;
    }
    if command_name == "sudo" {
        if let Some(consumed) = sudo_short_option_tokens_consumed(token) {
            return consumed;
        }
    }
    let exact = WRAPPER_FLAGS_WITH_VALUES
        .iter()
        .find(|(name, _)| *name == command_name)
        .is_some_and(|(_, flags)| flags.contains(&token));
    if exact {
        return 2;
    }
    1
}

/// `_sudo_short_option_tokens_consumed`.
pub(crate) fn sudo_short_option_tokens_consumed(token: &str) -> Option<usize> {
    let chars: Vec<char> = token.chars().collect();
    if !token.starts_with('-') || token.starts_with("--") || chars.len() <= 2 {
        return None;
    }
    for (index, flag) in chars.iter().enumerate().skip(1) {
        if !SUDO_VALUE_FLAGS.contains(flag) {
            continue;
        }
        return Some(if index < chars.len() - 1 { 1 } else { 2 });
    }
    Some(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn splits_redirects_and_newlines() {
        assert_eq!(
            split_shell_parts("a >| f\nb 2>&1"),
            ["a", ">|", "f", ";", "b", "2>&1"]
        );
        assert_eq!(split_shell_parts("echo 'x"), ["echo", "'x"]);
    }

    #[test]
    fn primary_command_skips_wrappers_and_assignments() {
        let segment = strings(&["A=1", "sudo", "-u", "root", "env", "B=2", "Git", "status"]);
        assert_eq!(
            shell_segment_primary_command(&segment),
            (Some("git".to_owned()), Some(6))
        );
        let redirected = strings(&["2>", "/dev/null", "ls"]);
        assert_eq!(
            shell_segment_primary_command(&redirected),
            (Some("ls".to_owned()), Some(2))
        );
    }

    #[test]
    fn stdin_redirects_and_segments() {
        assert_eq!(
            stdin_redirect_target_from_token("<", Some("f")),
            (Some("f".to_owned()), 2)
        );
        assert_eq!(stdin_redirect_target_from_token("<<EOF", None), (None, 1));
        assert_eq!(
            iter_shell_command_segments(&strings(&["a", "&&", " ", "b", ";"])),
            vec![strings(&["a"]), strings(&["b"])]
        );
    }

    #[test]
    fn attached_redirection_is_trimmed() {
        assert_eq!(
            shell_command_token_without_attached_redirection("(cat>out)"),
            "cat"
        );
        assert_eq!(wrapper_option_tokens_consumed("sudo", "-u"), 2);
        assert_eq!(wrapper_option_tokens_consumed("sudo", "-uroot"), 1);
    }

    #[test]
    fn a_timeout_clock_reads_through_to_its_program() {
        for (segment, name, index) in [
            (vec!["timeout", "300", "pytest", "-q"], "pytest", 2),
            (vec!["timeout", "5m", "npm", "run", "build"], "npm", 2),
            (vec!["timeout", "1.5h", "make"], "make", 2),
            (vec!["timeout", "--", "10", "git", "status"], "git", 3),
            (vec!["timeout", "10", "sudo", "-u", "root", "id"], "id", 5),
            (vec!["/usr/bin/timeout", "10", "curl", "host"], "curl", 2),
        ] {
            assert_eq!(
                shell_segment_primary_command(&strings(&segment)),
                (Some(name.to_owned()), Some(index)),
                "{segment:?}"
            );
        }
    }

    #[test]
    fn a_timeout_without_a_readable_program_stays_unreadable() {
        for segment in [
            // The clock is missing, so the next word is the program only if
            // this guesses at it.
            vec!["timeout", "pytest", "-q"],
            // Its options carry values this does not read.
            vec!["timeout", "-s", "KILL", "300", "pytest"],
            vec!["timeout", "--signal=KILL", "300", "pytest"],
            // Nothing follows the clock, or what follows is not a program.
            vec!["timeout", "300"],
            vec!["timeout"],
            vec!["timeout", "300", "--flag"],
            vec!["timeout", "300", "FOO=bar"],
            vec!["timeout", "300", ""],
        ] {
            assert_eq!(
                shell_segment_primary_command(&strings(&segment)),
                (None, None),
                "{segment:?}"
            );
        }
    }
}
