//! A forgiving reader of one line of source, for `code_expression`.
//!
//! It walks identifiers, calls, indexes, templates and short literals without
//! building a syntax tree, and fails closed on anything it does not know: a
//! long or encoded-looking literal, a stray symbol, an unbalanced bracket.

const MAX_EXPRESSION_BYTES: usize = 600;
const MAX_DEPTH: usize = 8;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scan {
    Fail,
    Done,
    /// The line ended before the expression closed, as in `await sign({`.
    Incomplete,
}

#[derive(Clone, Copy)]
pub(crate) struct Operand {
    pub(crate) structural: bool,
    pub(crate) dotted: bool,
}

pub(crate) struct Cursor<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) at: usize,
}

pub(crate) fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte == b'$'
}

pub(crate) fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

/// An identifier or number long enough to be encoded material.
pub(crate) fn encoded_looking(word: &[u8]) -> bool {
    word.len() >= 16 && word.iter().any(u8::is_ascii_digit)
}

/// A quoted argument that cannot be a credential: every word is short, or the
/// whole literal reads as a slug, a host or a path of at most three words.
pub(crate) fn literal_ok(literal: &[u8]) -> bool {
    literal
        .split(|byte| byte.is_ascii_whitespace())
        .all(|word| word.len() < 12)
        || word_like(literal)
}

pub(crate) fn word_like(literal: &[u8]) -> bool {
    literal.len() <= 80
        && literal
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || b"._~:/?&=%#@-".contains(&byte))
        && literal.iter().filter(|&&byte| byte == b'-').count() <= 2
        && literal
            .split(|byte| !byte.is_ascii_alphanumeric())
            .all(|run| {
                run.len() < 16
                    && !(run.len() >= 10
                        && run.iter().any(u8::is_ascii_digit)
                        && run.iter().any(u8::is_ascii_alphabetic))
            })
}

/// Literal text of a template: no run that looks like an encoded secret.
pub(crate) fn text_ok(text: &[u8]) -> bool {
    text.split(|&byte| !(byte.is_ascii_alphanumeric() || byte == b'_'))
        .all(|run| run.len() < 20 && !encoded_looking(run))
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(text: &'a str) -> Self {
        let bytes = text.as_bytes();
        Self {
            bytes: &bytes[..bytes.len().min(MAX_EXPRESSION_BYTES)],
            at: 0,
        }
    }

    pub(crate) fn done(&self) -> bool {
        self.at >= self.bytes.len()
    }

    pub(crate) fn peek(&self, ahead: usize) -> u8 {
        self.bytes.get(self.at + ahead).copied().unwrap_or(0)
    }

    pub(crate) fn starts_with(&self, token: &[u8]) -> bool {
        self.bytes
            .get(self.at..)
            .is_some_and(|rest| rest.starts_with(token))
    }

    pub(crate) fn skip_blanks(&mut self) {
        while !self.done() && matches!(self.bytes[self.at], b' ' | b'\t') {
            self.at += 1;
        }
    }

    pub(crate) fn identifier(&mut self) -> Option<&'a [u8]> {
        let bytes: &'a [u8] = self.bytes;
        let start = self.at;
        if self.done() || !is_identifier_start(bytes[start]) {
            return None;
        }
        while !self.done() && is_identifier_byte(bytes[self.at]) {
            self.at += 1;
        }
        Some(&bytes[start..self.at])
    }

    /// A keyword followed by a blank, consumed with the blanks after it.
    pub(crate) fn keyword(&mut self, word: &[u8]) -> bool {
        if self.starts_with(word) && matches!(self.peek(word.len()), b' ' | b'\t') {
            self.at += word.len();
            self.skip_blanks();
            return true;
        }
        false
    }

    /// The body of a quoted literal, with the cursor after its closing quote.
    pub(crate) fn quoted(&mut self) -> Option<&'a [u8]> {
        let bytes: &'a [u8] = self.bytes;
        let quote = bytes[self.at];
        self.at += 1;
        let start = self.at;
        while !self.done() {
            let byte = bytes[self.at];
            if byte == b'\\' {
                self.at = (self.at + 2).min(bytes.len());
                continue;
            }
            if byte == quote {
                let body = &bytes[start..self.at];
                self.at += 1;
                return Some(body);
            }
            self.at += 1;
        }
        None
    }

    /// A template literal from its opening backtick, with the number of
    /// interpolations it holds.
    pub(crate) fn template(&mut self) -> (Scan, usize) {
        self.at += 1;
        let mut interpolations = 0;
        let mut text: Vec<u8> = Vec::new();
        loop {
            if self.done() {
                let scan = if text_ok(&text) {
                    Scan::Incomplete
                } else {
                    Scan::Fail
                };
                return (scan, interpolations);
            }
            let byte = self.bytes[self.at];
            if byte == b'\\' {
                let end = (self.at + 2).min(self.bytes.len());
                text.extend_from_slice(&self.bytes[self.at..end]);
                self.at = end;
                continue;
            }
            if byte == b'`' {
                self.at += 1;
                let scan = if text_ok(&text) {
                    Scan::Done
                } else {
                    Scan::Fail
                };
                return (scan, interpolations);
            }
            if byte == b'$' && self.peek(1) == b'{' {
                if !text_ok(&text) {
                    return (Scan::Fail, interpolations);
                }
                text.clear();
                self.at += 2;
                interpolations += 1;
                let scan = self.scan(Some(b'}'), 1);
                if scan != Scan::Done {
                    return (scan, interpolations);
                }
                continue;
            }
            text.push(byte);
            self.at += 1;
        }
    }

    /// Loose scan of code up to `closer`, or up to a terminator when there is
    /// none: identifiers, numbers, operators, short literals and nested groups.
    pub(crate) fn scan(&mut self, closer: Option<u8>, depth: usize) -> Scan {
        if depth > MAX_DEPTH {
            return Scan::Fail;
        }
        loop {
            if self.done() {
                return if closer.is_some() {
                    Scan::Incomplete
                } else {
                    Scan::Done
                };
            }
            let byte = self.bytes[self.at];
            if closer == Some(byte) {
                self.at += 1;
                return Scan::Done;
            }
            if closer.is_none() && b",;)}]".contains(&byte) {
                return Scan::Done;
            }
            match byte {
                b' ' | b'\t' | b',' | b':' | b'?' | b'.' | b'=' | b'<' | b'>' | b'+' | b'-'
                | b'*' | b'!' | b'&' | b'|' | b'%' | b'~' | b'^' => self.at += 1,
                b'/' => {
                    if matches!(self.peek(1), b'/' | b'*') {
                        return if closer.is_some() {
                            Scan::Incomplete
                        } else {
                            Scan::Done
                        };
                    }
                    self.at += 1;
                }
                b';' if closer == Some(b'}') => self.at += 1,
                b'0'..=b'9' => {
                    let start = self.at;
                    while !self.done()
                        && (is_identifier_byte(self.bytes[self.at]) || self.bytes[self.at] == b'.')
                    {
                        self.at += 1;
                    }
                    if self.at - start >= 16 {
                        return Scan::Fail;
                    }
                }
                b'"' | b'\'' => match self.quoted() {
                    Some(literal) if literal_ok(literal) => {}
                    _ => return Scan::Fail,
                },
                b'`' => {
                    let (scan, _) = self.template();
                    if scan != Scan::Done {
                        return scan;
                    }
                }
                b'(' | b'[' | b'{' => {
                    let close = match byte {
                        b'(' => b')',
                        b'[' => b']',
                        _ => b'}',
                    };
                    self.at += 1;
                    let scan = self.scan(Some(close), depth + 1);
                    if scan != Scan::Done {
                        return scan;
                    }
                }
                _ if is_identifier_start(byte) => {
                    let Some(name) = self.identifier() else {
                        return Scan::Fail;
                    };
                    if encoded_looking(name) {
                        return Scan::Fail;
                    }
                }
                _ => return Scan::Fail,
            }
        }
    }

    /// A `<...>` type argument list directly before a call, as in `parse<T>(`.
    pub(crate) fn generic_before_call(&mut self) -> bool {
        let mut at = self.at + 1;
        let mut depth = 1usize;
        while at < self.bytes.len() && depth > 0 {
            match self.bytes[at] {
                b'<' => depth += 1,
                b'>' => depth -= 1,
                byte if is_identifier_byte(byte) || b" \t,[]|&.".contains(&byte) => {}
                _ => return false,
            }
            at += 1;
        }
        if depth == 0 && self.bytes.get(at) == Some(&b'(') {
            self.at = at;
            return true;
        }
        false
    }

    /// An identifier path with calls, indexes, casts and non-null marks.
    pub(crate) fn operand(&mut self, numbers: bool) -> Option<Operand> {
        let mut structural = false;
        self.skip_blanks();
        loop {
            if self.keyword(b"await") || self.keyword(b"new") {
                structural = true;
            } else if self.keyword(b"typeof") || self.keyword(b"void") {
                continue;
            } else if self.peek(0) == b'!' && self.peek(1) != b'=' {
                self.at += 1;
            } else {
                break;
            }
        }
        if self.done() {
            return None;
        }
        let first = self.bytes[self.at];
        if first.is_ascii_digit() {
            if !numbers {
                return None;
            }
            let start = self.at;
            while !self.done()
                && (is_identifier_byte(self.bytes[self.at]) || self.bytes[self.at] == b'.')
            {
                self.at += 1;
            }
            return (self.at - start < 16).then_some(Operand {
                structural,
                dotted: false,
            });
        }
        if first == b'(' {
            self.at += 1;
            return (self.scan(Some(b')'), 1) != Scan::Fail).then_some(Operand {
                structural,
                dotted: false,
            });
        }
        if !is_identifier_start(first) || first == b'$' {
            return None;
        }
        if encoded_looking(self.identifier()?) {
            return None;
        }
        let mut dotted = false;
        while !self.done() {
            let byte = self.bytes[self.at];
            if byte == b'.' && is_identifier_start(self.peek(1)) {
                self.at += 1;
                dotted = true;
                if encoded_looking(self.identifier()?) {
                    return None;
                }
            } else if byte == b'?' && self.peek(1) == b'.' {
                self.at += 2;
                if !self.done() && is_identifier_start(self.bytes[self.at]) {
                    dotted = true;
                    if encoded_looking(self.identifier()?) {
                        return None;
                    }
                }
            } else if byte == b'?'
                && (self.at + 1 >= self.bytes.len() || b";),".contains(&self.peek(1)))
            {
                self.at += 1;
                structural = true;
            } else if byte == b':' && self.peek(1) == b':' && is_identifier_start(self.peek(2)) {
                self.at += 2;
                self.identifier()?;
            } else if byte == b'(' || byte == b'[' {
                self.at += 1;
                let close = if byte == b'(' { b')' } else { b']' };
                let scan = self.scan(Some(close), 1);
                if scan == Scan::Fail {
                    return None;
                }
                structural = true;
                if scan == Scan::Incomplete {
                    self.at = self.bytes.len();
                    break;
                }
            } else if byte == b'!' && self.peek(1) != b'=' {
                self.at += 1;
                structural = true;
            } else if byte == b'<' && self.generic_before_call() {
                continue;
            } else {
                break;
            }
        }
        Some(Operand { structural, dotted })
    }
}
