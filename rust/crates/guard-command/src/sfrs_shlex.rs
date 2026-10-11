//! `shlex.shlex(text, posix=True, punctuation_chars=";&|")` with
//! `whitespace_split` and the default `#` comment character, as the request
//! classifier drives it. The state machine follows CPython's `read_token`.

// Consumed by the later classifier slices.
#![allow(dead_code)]

#[derive(Clone, Copy, PartialEq)]
enum State {
    Blank,
    Word,
    Punct,
    Quote(char),
    Escape,
    Done,
}

const WHITESPACE: &[char] = &[' ', '\t', '\r', '\n'];
const PUNCTUATION: &[char] = &[';', '&', '|'];

fn is_punctuation(c: char) -> bool {
    PUNCTUATION.contains(&c)
}

/// cmd and PowerShell treat backslash as a path separator, so the lexer drops
/// its escape character on Windows.
fn is_escape(c: char) -> bool {
    c == '\\' && !cfg!(windows)
}

fn is_quote(c: char) -> bool {
    c == '\'' || c == '"'
}

/// Lexer error (`ValueError`) text; callers only branch on failure.
pub(crate) type LexError = &'static str;

/// Split `text` into shlex tokens, or the lexer's `ValueError`.
pub(crate) fn split_punctuation(text: &str) -> Result<Vec<String>, LexError> {
    let chars: Vec<char> = text.chars().collect();
    let mut position = 0usize;
    let mut pushback: Vec<char> = Vec::new();
    let mut tokens = Vec::new();
    let mut state = State::Blank;
    loop {
        let (token, next) = read_token(&chars, &mut position, &mut pushback, state)?;
        state = next;
        match token {
            Some(token) => tokens.push(token),
            None => return Ok(tokens),
        }
    }
}

fn read_token(
    chars: &[char],
    position: &mut usize,
    pushback: &mut Vec<char>,
    mut state: State,
) -> Result<(Option<String>, State), LexError> {
    let mut token = String::new();
    let mut quoted = false;
    let mut escaped_state = State::Blank;
    let next_char = |position: &mut usize, pushback: &mut Vec<char>| -> Option<char> {
        if let Some(c) = pushback.pop() {
            return Some(c);
        }
        let c = chars.get(*position).copied();
        if c.is_some() {
            *position += 1;
        }
        c
    };
    loop {
        let ch = next_char(position, pushback);
        match state {
            State::Done => {
                token.clear();
                break;
            }
            State::Blank => {
                let Some(c) = ch else {
                    state = State::Done;
                    break;
                };
                if WHITESPACE.contains(&c) {
                    if !token.is_empty() || quoted {
                        break;
                    }
                } else if c == '#' {
                    skip_line(chars, position);
                } else if is_escape(c) {
                    escaped_state = State::Word;
                    state = State::Escape;
                } else if is_punctuation(c) {
                    token.push(c);
                    state = State::Punct;
                } else if is_quote(c) {
                    state = State::Quote(c);
                } else {
                    token.push(c);
                    state = State::Word;
                }
            }
            State::Quote(open) => {
                quoted = true;
                let Some(c) = ch else {
                    return Err("No closing quotation");
                };
                if c == open {
                    state = State::Word;
                } else if is_escape(c) && open == '"' {
                    escaped_state = State::Quote(open);
                    state = State::Escape;
                } else {
                    token.push(c);
                }
            }
            State::Escape => {
                let Some(c) = ch else {
                    return Err("No escaped character");
                };
                if let State::Quote(open) = escaped_state {
                    if c != open && c != '\\' {
                        token.push('\\');
                    }
                }
                token.push(c);
                state = escaped_state;
            }
            State::Word | State::Punct => {
                let Some(c) = ch else {
                    state = State::Done;
                    break;
                };
                if WHITESPACE.contains(&c) {
                    state = State::Blank;
                    if !token.is_empty() || quoted {
                        break;
                    }
                } else if c == '#' {
                    skip_line(chars, position);
                    state = State::Blank;
                    if !token.is_empty() || quoted {
                        break;
                    }
                } else if state == State::Punct {
                    if is_punctuation(c) {
                        token.push(c);
                    } else {
                        pushback.push(c);
                        state = State::Blank;
                        break;
                    }
                } else if is_quote(c) {
                    state = State::Quote(c);
                } else if is_escape(c) {
                    escaped_state = State::Word;
                    state = State::Escape;
                } else if !is_punctuation(c) {
                    token.push(c);
                } else {
                    pushback.push(c);
                    state = State::Blank;
                    if !token.is_empty() || quoted {
                        break;
                    }
                }
            }
        }
    }
    if token.is_empty() && !quoted {
        Ok((None, state))
    } else {
        Ok((Some(token), state))
    }
}

fn skip_line(chars: &[char], position: &mut usize) {
    while let Some(&c) = chars.get(*position) {
        *position += 1;
        if c == '\n' {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::split_punctuation;

    fn split(text: &str) -> Vec<String> {
        split_punctuation(text).expect("valid")
    }

    #[test]
    fn separates_punctuation_runs() {
        assert_eq!(split("a&&b;c|d"), ["a", "&&", "b", ";", "c", "|", "d"]);
        assert_eq!(
            split("echo 'a b' \"c d\" e\\ f"),
            ["echo", "a b", "c d", "e f"]
        );
    }

    #[test]
    fn comments_end_the_line_and_the_word() {
        assert_eq!(split("a # note\nb"), ["a", "b"]);
        assert_eq!(split("ab#cd"), ["ab"]);
    }

    #[test]
    fn unterminated_quote_and_escape_fail() {
        assert!(split_punctuation("echo 'a").is_err());
        assert!(split_punctuation("echo a\\").is_err());
    }

    #[test]
    fn matches_cpython_on_mixed_inputs() {
        assert_eq!(split("a;;b"), ["a", ";;", "b"]);
        assert_eq!(split("a&|b c"), ["a", "&|", "b", "c"]);
        assert_eq!(split("x\"a\\\"b\"y"), ["xa\"by"]);
        assert_eq!(split("a>b&c"), ["a>b", "&", "c"]);
    }

    #[test]
    fn empty_quoted_token_is_kept() {
        assert_eq!(split("echo ''"), ["echo", ""]);
    }
}
