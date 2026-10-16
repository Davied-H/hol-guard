//! Reading the program an `xargs` runs out of the command text.
use super::{command_basename, INTERPRETERS};
use std::collections::BTreeSet;

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
    xargs_programs(shell).is_some()
}

/// Whether the text says where every `xargs` in it reads its operands: a pipe
/// into it, an input redirect, or `-a`/`--arg-file`. A bare `xargs` takes the
/// caller's standard input, which the text does not hold, so the operands it
/// hands the program it names are unknown and it stays unbounded.
pub(super) fn xargs_input_is_named(shell: &str) -> bool {
    for statement in shell.split(['\n', ';', '&', '(', ')', '`']) {
        let stages: Vec<&str> = statement.split('|').collect();
        for (stage, text) in stages.iter().enumerate() {
            // The right side of a `||` follows an empty stage, not a pipe.
            let piped = stage > 0 && !stages[stage - 1].trim().is_empty();
            let words: Vec<&str> = text.split_whitespace().collect();
            for (index, word) in words.iter().enumerate() {
                if command_basename(word) == "xargs" && !input_is_named(piped, &words[index + 1..])
                {
                    return false;
                }
            }
        }
    }
    true
}

/// The input source one `xargs` names, read from the words after it.
fn input_is_named(piped: bool, rest: &[&str]) -> bool {
    if piped || rest.iter().any(|word| word.contains('<')) {
        return true;
    }
    // Only the options `xargs` itself reads, so a program's own `-a` is not
    // mistaken for an argument file.
    rest.iter()
        .take_while(|word| word.starts_with('-'))
        .any(|word| {
            word.starts_with("--arg-file")
                || (!word.starts_with("--") && word.trim_start_matches('-').starts_with('a'))
        })
}

/// The programs every `xargs` in the text names, by basename, or `None` when
/// one of them names none.
pub(super) fn xargs_programs(shell: &str) -> Option<BTreeSet<String>> {
    let mut programs = BTreeSet::new();
    // Braces stay: `-I {}` is how a replacement is written, and a `{ ...; }`
    // group's own words are read in the same piece anyway.
    for piece in shell.split(['\n', ';', '&', '|', '(', ')', '`']) {
        let words: Vec<&str> = piece.split_whitespace().collect();
        for (index, word) in words.iter().enumerate() {
            if command_basename(word) == "xargs" {
                let program = command_basename(xargs_operand(&words[index + 1..])?);
                // A `.cmd` launcher runs the program it is named for, the way
                // `command_basename` already reads a `.exe` suffix.
                if let Some(stem) = program.strip_suffix(".cmd") {
                    programs.insert(stem.to_owned());
                }
                programs.insert(program);
            }
        }
    }
    Some(programs)
}

/// The operand `xargs` runs, read past its own options.
///
/// `-I`/`-i`/`--replace` name a token that each input line replaces. When
/// that token is the program, the program is whatever standard input holds,
/// which this text does not name.
fn xargs_operand<'a>(rest: &[&'a str]) -> Option<&'a str> {
    let mut words = rest.iter();
    let mut replace: Option<String> = None;
    while let Some(word) = words.next() {
        if *word == "--" {
            break;
        }
        // A redirect ends the words `xargs` itself reads, and the file it
        // names is not the program: `xargs < list.txt` runs `echo`.
        if redirect(word) {
            return None;
        }
        if !word.starts_with('-') {
            return named_program(word, replace.as_deref()).then_some(*word);
        }
        if let Some(token) = word
            .strip_prefix("--replace=")
            .filter(|token| !token.is_empty())
        {
            replace = Some(token.to_owned());
            continue;
        }
        // `--replace` carries its token attached. GNU reads a bare one as the
        // option with its default token, leaving the next word the program;
        // an implementation that takes a separate value reads that word as
        // the token and the one after it as the program. The text does not
        // settle which program runs.
        if *word == "--replace" {
            return None;
        }
        if word.starts_with("--") {
            // `--max-args=3` carries its own value. An unknown long option
            // may take the next word, which would then be read as the program.
            if word.contains('=') {
                continue;
            }
            if XARGS_VALUE_OPTIONS.contains(word) {
                words.next()?;
                continue;
            }
            return None;
        }
        // Short options cluster, so `-0I{}` is `-0` and `-I{}`, and an
        // unknown letter may take the next word as its value.
        if !short_option(word, &mut words, &mut replace) {
            return None;
        }
    }
    let program = words.next()?;
    (!redirect(program) && named_program(program, replace.as_deref())).then_some(*program)
}

/// A word that redirects rather than names anything: `<`, `>`, `>>`, `2>`,
/// `<<<` and the file names written against them without a space.
fn redirect(word: &str) -> bool {
    word.contains(['<', '>'])
}

/// One short-option word, clustered the way getopt reads it. `I`, `i` and
/// `J` record their replacement token. An unknown letter takes a value this
/// does not know how to skip, so the program after it is not one this text
/// has identified.
fn short_option(
    word: &str,
    words: &mut std::slice::Iter<&str>,
    replace: &mut Option<String>,
) -> bool {
    let Some(body) = word.strip_prefix('-').filter(|body| !body.is_empty()) else {
        return false;
    };
    let mut rest = body;
    while let Some(letter) = rest.chars().next() {
        rest = &rest[letter.len_utf8()..];
        if "0txrp".contains(letter) {
            continue;
        }
        let attached = rest;
        let value = if !attached.is_empty() {
            Some(attached.to_owned())
        } else if "eil".contains(letter) {
            None
        } else if "aEILnPsdJ".contains(letter) {
            match words.next() {
                Some(value) => Some((*value).to_owned()),
                None => return false,
            }
        } else {
            return false;
        };
        if matches!(letter, 'I' | 'i' | 'J') {
            *replace = Some(value.unwrap_or_else(|| "{}".to_owned()));
        }
        return true;
    }
    true
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
