//! A script a shell takes from its own argument, read as command text.
use super::{literal_redirects_only, moves_data, prefix, synthesizes_program, unquoted_literal};

/// A script a shell takes from its own argument, judged as the command text it
/// is.
///
/// `sh -c 'npm run build'` runs the programs `npm run build` runs, so it owns
/// what that command owns. Every `-c` form reached an evaluation failure and
/// blocked outright, with no approval left to give it, while the same words
/// without the shell in front modelled exactly. The script keeps that failure
/// when it holds a substitution, a heredoc, a word built from an expansion, a
/// file it runs, or data it moves: each of those names a program this text
/// does not.
pub(super) fn script_is_reviewable(script: &str) -> bool {
    let literal = unquoted_literal(script);
    !script.contains(['`', '$', '\n'])
        && !script.contains("<<")
        && !prefix::runs_a_program_file(script)
        && !synthesizes_program(&literal, false)
        && (!moves_data(&literal) || literal_redirects_only(script))
}

/// A shell whose script is in this same text, naming every program it runs.
pub(super) fn script_names_its_programs(shell: &str) -> bool {
    prefix::inline_shell_script(shell).is_some_and(|script| script_is_reviewable(&script))
}
