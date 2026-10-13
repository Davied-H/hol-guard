//! Text a Git search matches: `git grep` patterns and the `-S`, `-G` and
//! `--grep` values of `git log`. Git compares them against content and
//! messages and never opens them, so a pattern such as `process.env` or
//! `.ssh/` names no path. Every other token still meets the sensitive-text
//! and path screens, and a credential keyword in a pattern still reads as a
//! credential search.

use crate::{CanonicalCommandV1, CommandSegmentV1};

/// Positions in `arguments`, the tokens after `git`, that hold search text
/// or the closed `git grep` options around it.
pub(super) fn pattern_positions(arguments: &[String]) -> Vec<usize> {
    let Some(start) = subcommand_position(arguments) else {
        return Vec::new();
    };
    let rest = &arguments[start + 1..];
    let positions = match arguments[start].as_str() {
        "grep" => grep_patterns(rest),
        "log" => log_patterns(rest),
        _ => Vec::new(),
    };
    positions
        .into_iter()
        .map(|position| position + start + 1)
        .collect()
}

/// Whether `text`, the whole command or one of its segments, trips the
/// sensitive-text floor. `without_patterns` is the same text with its Git
/// search patterns left out: only a credential keyword in a pattern counts.
pub(super) fn sensitive_beyond_patterns(text: &str, without_patterns: Option<String>) -> bool {
    match without_patterns {
        Some(rest) => super::credential_keyword_text(text) || super::sensitive_command(&rest),
        None => super::sensitive_command(text),
    }
}

/// The command's text with each Git search pattern left out, or `None` when
/// no segment holds one.
pub(super) fn command_without_patterns(model: &CanonicalCommandV1) -> Option<String> {
    let mut masked = false;
    let parts = model
        .segments
        .iter()
        .map(|segment| match segment_without_patterns(segment) {
            Some(text) => {
                masked = true;
                text
            }
            None => segment.text.clone(),
        })
        .collect::<Vec<_>>();
    masked.then(|| parts.join(" ; "))
}

/// One segment's tokens with its Git search patterns left out, or `None`
/// when it is not a plain `git` search holding a pattern.
pub(super) fn segment_without_patterns(segment: &CommandSegmentV1) -> Option<String> {
    let executable = segment.executable.as_deref()?;
    if super::executable_basename(executable) != "git"
        || !segment.environment_names.is_empty()
        || !segment.wrapper_chain.is_empty()
        || segment.tokens.len() != segment.arguments.len() + 1
    {
        return None;
    }
    let positions = pattern_positions(&segment.arguments);
    if positions.is_empty() {
        return None;
    }
    let kept = segment
        .arguments
        .iter()
        .enumerate()
        .filter(|(index, _)| !positions.contains(index))
        .map(|(_, argument)| argument.as_str());
    Some(
        std::iter::once(segment.tokens[0].as_str())
            .chain(kept)
            .collect::<Vec<_>>()
            .join(" "),
    )
}

fn subcommand_position(arguments: &[String]) -> Option<usize> {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        match argument.as_str() {
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" => index += 2,
            value if value.starts_with('-') => index += 1,
            _ => return Some(index),
        }
    }
    None
}

/// Everything before the revisions and pathspecs of a `git grep` inside the
/// closed grammar: closed options, counts and patterns.
fn grep_patterns(rest: &[String]) -> Vec<usize> {
    super::git_grep::targets(rest).map_or_else(Vec::new, |targets| {
        (0..rest.len() - targets.len()).collect()
    })
}

/// The `-S`, `-G` and `--grep` values before `--`.
fn log_patterns(rest: &[String]) -> Vec<usize> {
    let mut positions = Vec::new();
    let mut index = 0;
    while let Some(argument) = rest.get(index) {
        match argument.as_str() {
            "--" => break,
            "-S" | "-G" | "--grep" => {
                if index + 1 < rest.len() {
                    positions.push(index + 1);
                }
                index += 2;
                continue;
            }
            value
                if (value.len() > 2 && (value.starts_with("-S") || value.starts_with("-G")))
                    || value.starts_with("--grep=") =>
            {
                positions.push(index);
            }
            _ => {}
        }
        index += 1;
    }
    positions
}

#[cfg(test)]
mod tests {
    use super::pattern_positions;

    fn positions(command: &str) -> Vec<usize> {
        let arguments: Vec<String> = command.split(' ').map(str::to_owned).collect();
        pattern_positions(&arguments)
    }

    #[test]
    fn grep_patterns_and_log_search_values_are_found() {
        assert_eq!(positions("grep -n process.env -- src"), vec![1, 2]);
        assert_eq!(positions("-C repo grep -ln -e .env src"), vec![3, 4, 5]);
        assert_eq!(positions("log --oneline -S process.env -- a.ts"), vec![3]);
        assert_eq!(positions("log -G.env --grep=.ssh/ HEAD"), vec![1, 2]);
        assert_eq!(positions("log --grep .env -- .env"), vec![2]);
    }

    #[test]
    fn paths_revisions_and_other_operations_keep_their_screens() {
        assert!(positions("grep -f .env -- src").is_empty());
        assert!(positions("grep --no-index .env").is_empty());
        assert!(positions("show HEAD:.env").is_empty());
        assert!(positions("log -p -- .env").is_empty());
        assert!(positions("diff -S .env").is_empty());
        assert_eq!(positions("grep foo .env -- src"), vec![1]);
    }
}
