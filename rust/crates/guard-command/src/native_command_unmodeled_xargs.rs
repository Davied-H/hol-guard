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
fn xargs_operand(rest: &[&str]) -> bool {
    let mut words = rest.iter();
    while let Some(word) = words.next() {
        if *word == "--" {
            break;
        }
        if !word.starts_with('-') {
            return plain_program(word);
        }
        // `--max-args=3` carries its own value.
        if word.contains('=') {
            continue;
        }
        if XARGS_VALUE_OPTIONS.contains(word) {
            if words.next().is_none() {
                return false;
            }
            continue;
        }
        // A long option this does not know may take the next word, which
        // would then be read as the program. A short one such as `-0`, `-n3`
        // or `-I{}` carries whatever value it has itself.
        if word.starts_with("--") {
            return false;
        }
    }
    words.next().is_some_and(|program| plain_program(program))
}

/// A program named outright: not built from an expansion, a glob or a
/// substitution, and not an interpreter that runs something else.
fn plain_program(word: &str) -> bool {
    !word.contains(['$', '*', '?', '[', '`', '\'', '"', '='])
        && !INTERPRETERS.contains(&command_basename(word).as_str())
}
