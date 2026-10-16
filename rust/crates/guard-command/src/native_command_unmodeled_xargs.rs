//! Reading the program an `xargs` runs out of the command text.
use super::{command_basename, INTERPRETERS};

/// `xargs` options whose value is the next word, so the word after one of
/// these is not the program it runs.
const XARGS_VALUE_OPTIONS: &[&str] = &[
    "-a",
    "-d",
    "-E",
    "-e",
    "-I",
    "-i",
    "-L",
    "-l",
    "-n",
    "-P",
    "-s",
    "--arg-file",
    "--delimiter",
    "--eof",
    "--max-args",
    "--max-chars",
    "--max-lines",
    "--max-procs",
    "--process-slot-var",
    "--replace",
];

/// Whether every `xargs` in the text names the program it runs.
///
/// `xargs` reads standard input as arguments for a program the command
/// already names, so `xargs rm -f < list.txt` runs the `rm` the text shows
/// and owns what `rm` owns. Reading it as an unbounded interpreter refused
/// that outright. An `xargs` with no operand runs `echo`, one whose operand
/// is itself an interpreter (`xargs sh -c ...`) runs whatever that reads, and
/// one built from an expansion names nothing, so those stay unbounded.
pub(super) fn xargs_names_its_program(shell: &str) -> bool {
    // Braces stay: `-I {}` is how a replacement is written, and a `{ ...; }`
    // group's own words are read in the same piece anyway.
    for piece in shell.split(['\n', ';', '&', '|', '(', ')', '`']) {
        let words: Vec<&str> = piece.split_whitespace().collect();
        for (index, word) in words.iter().enumerate() {
            if command_basename(word) == "xargs" && !xargs_operand(&words[index + 1..]) {
                return false;
            }
        }
    }
    true
}

/// The operand `xargs` runs, read past its own options.
///
/// `-I`/`-i`/`--replace` name a token that each input line replaces. When
/// that token is the program, the program is whatever standard input holds,
/// which this text does not name.
fn xargs_operand(rest: &[&str]) -> bool {
    let mut words = rest.iter();
    let mut replace: Option<String> = None;
    while let Some(word) = words.next() {
        if *word == "--" {
            break;
        }
        // A redirect ends the words `xargs` itself reads, and the file it
        // names is not the program: `xargs < list.txt` runs `echo`.
        if redirect(word) {
            return false;
        }
        if !word.starts_with('-') {
            return named_program(word, replace.as_deref());
        }
        if let Some(token) = attached_replacement(word) {
            replace = Some(token);
            continue;
        }
        if *word == "-i" || *word == "--replace" {
            replace = Some("{}".to_owned());
            continue;
        }
        // `--max-args=3` carries its own value.
        if word.contains('=') {
            continue;
        }
        if XARGS_VALUE_OPTIONS.contains(word) {
            let Some(value) = words.next() else {
                return false;
            };
            if *word == "-I" {
                replace = Some((*value).to_owned());
            }
            continue;
        }
        // A long option this does not know may take the next word, which
        // would then be read as the program. A short one such as `-0` or
        // `-n3` carries whatever value it has itself.
        if word.starts_with("--") {
            return false;
        }
    }
    words
        .next()
        .is_some_and(|program| !redirect(program) && named_program(program, replace.as_deref()))
}

/// A word that redirects rather than names anything: `<`, `>`, `>>`, `2>`,
/// `<<<` and the file names written against them without a space.
fn redirect(word: &str) -> bool {
    word.contains(['<', '>'])
}

/// The replacement token carried on the option itself: `-I{}`, `-iCMD`,
/// `--replace=X`. A bare `-I`, `-i` or `--replace` is not one of these.
fn attached_replacement(word: &str) -> Option<String> {
    if let Some(token) = word
        .strip_prefix("--replace=")
        .filter(|token| !token.is_empty())
    {
        return Some(token.to_owned());
    }
    for prefix in ["-I", "-i"] {
        if let Some(token) = word.strip_prefix(prefix).filter(|token| !token.is_empty()) {
            return Some(token.to_owned());
        }
    }
    None
}

fn named_program(word: &str, replace: Option<&str>) -> bool {
    plain_program(word) && !replace.is_some_and(|token| !token.is_empty() && word.contains(token))
}

/// A program named outright: not built from an expansion, a glob or a
/// substitution, and not an interpreter that runs something else.
fn plain_program(word: &str) -> bool {
    !word.contains(['$', '*', '?', '[', '`', '\'', '"', '='])
        && !INTERPRETERS.contains(&command_basename(word).as_str())
}
