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
        if let Some(token) = word
            .strip_prefix("--replace=")
            .filter(|token| !token.is_empty())
        {
            replace = Some(token.to_owned());
            continue;
        }
        if *word == "--replace" {
            replace = Some("{}".to_owned());
            continue;
        }
        if word.starts_with("--") {
            // `--max-args=3` carries its own value. An unknown long option
            // may take the next word, which would then be read as the program.
            if word.contains('=') {
                continue;
            }
            if XARGS_VALUE_OPTIONS.contains(word) {
                if words.next().is_none() {
                    return false;
                }
                continue;
            }
            return false;
        }
        // Short options cluster, so `-0I{}` is `-0` and `-I{}`, and an
        // unknown letter may take the next word as its value.
        if !short_option(word, &mut words, &mut replace) {
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
    let bytes = body.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let letter = bytes[index] as char;
        index += 1;
        if "0txrp".contains(letter) {
            continue;
        }
        let attached = &body[index..];
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
