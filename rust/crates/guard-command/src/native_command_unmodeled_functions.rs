//! The parts of a sourced file that run nothing: comments, and functions the
//! file defines but never calls.
//!
//! The virtualenv `activate` script every Python project carries ends with a
//! convenience wrapper:
//!
//! ```sh
//! # Make sure to unalias pydoc if it's already there
//! alias pydoc 2>/dev/null >/dev/null && unalias pydoc || true
//!
//! pydoc () {
//!     python -m pydoc "$@"
//! }
//! ```
//!
//! Nothing in the file calls that wrapper and neither does the command that
//! sourced the file, so sourcing it cannot run `python`. Reading its body as
//! part of the file's words handed every virtualenv an interpreter it never
//! runs, and the command lost the bounded owner set reading the file had just
//! given it. The script's prose comments read the same way: a sentence ending
//! in a full stop put `.` in a command position, which is the shell's other
//! name for `source`.

/// The text with every comment removed.
///
/// `None` leaves the text alone: a quote that never closes means this scan
/// cannot say which `#` the shell would read as a comment, and dropping the
/// wrong one would drop a command with it.
pub(super) fn without_comments(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut fresh = true;
    let mut comment = false;
    for character in text.chars() {
        if comment {
            if character != '\n' {
                continue;
            }
            comment = false;
        }
        if let Some(open) = quote {
            out.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' && open == '"' {
                escaped = true;
            } else if character == open {
                quote = None;
            }
            continue;
        }
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '\'' || character == '"' {
            quote = Some(character);
        } else if character == '#' && fresh {
            comment = true;
            continue;
        }
        // A `#` starts a comment only where a word starts. `main#2` is one
        // word, and so is the fragment in `curl https://host/p#frag`.
        fresh = character.is_whitespace() || matches!(character, ';' | '&' | '|' | '(');
        out.push(character);
    }
    (quote.is_none() && !escaped).then_some(out)
}

/// The literal with the definition of every function nothing calls removed.
///
/// `None` leaves the text exactly as it stands, either because nothing in it
/// is dead or because it is not plain enough to take apart this way. A body
/// is removed only when a line opens it with nothing after the brace and a
/// later line closes it with nothing else on it, so the span removed is the
/// definition and never a neighbour.
pub(super) fn without_uncalled_definitions(literal: &str, command: &str) -> Option<String> {
    let masked = super::mask_double_quoted_separators(literal);
    // Bash's `${ cmd; }` runs what it holds, and its braces are not a body.
    // A text still carrying one is left for the rest of the scan to judge.
    if masked.contains("${") {
        return None;
    }
    let characters: Vec<char> = literal.chars().collect();
    let masked: Vec<char> = masked.chars().collect();
    if masked.len() != characters.len() {
        return None;
    }
    let lines = line_bounds(&masked);
    let mut dead: Vec<(usize, usize)> = Vec::new();
    let mut at = 0;
    while at < lines.len() {
        let Some(name) = defines(&span(&masked, lines[at])) else {
            at += 1;
            continue;
        };
        let close = body_end(&masked, &lines, at)?;
        if !invoked(&masked, &lines, (at, close), &name) && !names(command, &name) {
            dead.push((lines[at].0, lines[close].1));
        }
        at = close + 1;
    }
    if dead.is_empty() {
        return None;
    }
    let kept = characters
        .iter()
        .enumerate()
        .filter(|(index, _)| {
            !dead
                .iter()
                .any(|(start, end)| (*start..*end).contains(index))
        })
        .map(|(_, character)| *character)
        .collect();
    Some(kept)
}

/// The function a line defines, for the two shapes a script is written in:
/// `name () {` and `function name {`. The brace has to close the line, so the
/// body is what follows it rather than something to find inside the line.
fn defines(line: &str) -> Option<String> {
    let head = line.trim().strip_suffix('{')?.trim_end().to_owned();
    let (keyword, rest) = match head.strip_prefix("function ") {
        Some(rest) => (true, rest.trim_start()),
        None => (false, head.as_str()),
    };
    let end = rest
        .find(|character: char| !name_character(character))
        .unwrap_or(rest.len());
    let (name, after) = rest.split_at(end);
    let after: String = after.chars().filter(|c| !c.is_whitespace()).collect();
    (!name.is_empty() && (after == "()" || (keyword && after.is_empty()))).then(|| name.to_owned())
}

/// The line closing the definition opened at `at`, or `None` when the body
/// holds a brace this scan cannot place. Stopping there keeps a body whose
/// shape is unclear in the text the rest of the scan reads.
fn body_end(masked: &[char], lines: &[(usize, usize)], at: usize) -> Option<usize> {
    for (index, bounds) in lines.iter().enumerate().skip(at + 1) {
        let line = span(masked, *bounds);
        let text = line.trim();
        if text == "}" {
            return Some(index);
        }
        if text.contains(['{', '}']) {
            return None;
        }
    }
    None
}

/// Whether anything outside the definition could still run `name`.
///
/// A name handed to `unset -f`, `alias` or `type` is a function those look up
/// rather than run, which is how a generated script tidies up around its own
/// wrapper. Anywhere else the body stays in the text: in a command position,
/// glued into a word such as `p=pydoc`, or handed to something like `trap`
/// that could run it later.
fn invoked(masked: &[char], lines: &[(usize, usize)], body: (usize, usize), name: &str) -> bool {
    let rest: String = lines
        .iter()
        .enumerate()
        .filter(|(index, _)| *index < body.0 || *index > body.1)
        .map(|(_, bounds)| span(masked, *bounds))
        .collect();
    rest.split(|character: char| {
        matches!(
            character,
            ';' | '&' | '|' | '(' | ')' | '{' | '}' | '\n' | '`'
        )
    })
    .any(|piece| runs(piece, name))
}

/// Whether one simple command could run `name`.
fn runs(piece: &str, name: &str) -> bool {
    let mut words = piece
        .split_whitespace()
        .skip_while(|word| super::SHELL_PREFIXES.contains(word));
    let Some(first) = words.next() else {
        return false;
    };
    if first == name {
        return true;
    }
    let looks_up = matches!(
        first,
        "unset" | "unalias" | "alias" | "type" | "declare" | "typeset"
    );
    words.any(|word| word.contains(name) && !(looks_up && word == name))
}

/// Whether the command that sourced the file spells the name at all. It runs
/// in the same shell, so a wrapper the file leaves behind is the command's to
/// call: `source .venv/bin/activate && pydoc json` runs that body.
fn names(command: &str, name: &str) -> bool {
    command
        .split(|character: char| !name_character(character))
        .any(|word| word == name)
}

fn name_character(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '_' | '-' | '.' | ':')
}

/// Each line's `(start, end)` in characters, the end past its newline.
fn line_bounds(masked: &[char]) -> Vec<(usize, usize)> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (index, character) in masked.iter().enumerate() {
        if *character == '\n' {
            lines.push((start, index + 1));
            start = index + 1;
        }
    }
    if start < masked.len() {
        lines.push((start, masked.len()));
    }
    lines
}

fn span(masked: &[char], bounds: (usize, usize)) -> String {
    masked[bounds.0..bounds.1].iter().collect()
}
