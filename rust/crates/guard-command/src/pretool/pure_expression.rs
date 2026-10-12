//! Constant numeric expressions have no file, network, import or process effects.

struct Expression<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Expression<'_> {
    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.position)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.position += 1;
        }
    }

    fn expression(&mut self, depth: usize) -> bool {
        if !self.term(depth) {
            return false;
        }
        loop {
            self.whitespace();
            if !matches!(self.bytes.get(self.position), Some(b'+' | b'-')) {
                return true;
            }
            self.position += 1;
            if !self.term(depth) {
                return false;
            }
        }
    }

    fn term(&mut self, depth: usize) -> bool {
        if !self.atom(depth) {
            return false;
        }
        loop {
            self.whitespace();
            if !matches!(self.bytes.get(self.position), Some(b'*' | b'/' | b'%')) {
                return true;
            }
            self.position += 1;
            if !self.atom(depth) {
                return false;
            }
        }
    }

    fn atom(&mut self, depth: usize) -> bool {
        self.whitespace();
        if depth >= 8 {
            return false;
        }
        if matches!(self.bytes.get(self.position), Some(b'+' | b'-')) {
            self.position += 1;
            return self.atom(depth + 1);
        }
        if self.bytes.get(self.position) == Some(&b'(') {
            self.position += 1;
            if !self.expression(depth + 1) {
                return false;
            }
            self.whitespace();
            if self.bytes.get(self.position) != Some(&b')') {
                return false;
            }
            self.position += 1;
            return true;
        }
        let start = self.position;
        while self
            .bytes
            .get(self.position)
            .is_some_and(u8::is_ascii_digit)
        {
            self.position += 1;
        }
        (1..=9).contains(&(self.position - start))
    }
}

pub(super) fn safe_inline_expression(executable: &str, arguments: &[String]) -> bool {
    let [flag, script] = arguments else {
        return false;
    };
    let (flag_expected, prefix) = if matches!(executable, "python" | "python3") {
        ("-c", "print(")
    } else {
        ("-e", "console.log(")
    };
    if flag != flag_expected || script.len() > 256 {
        return false;
    }
    let Some(source) = script
        .trim()
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(')'))
    else {
        return false;
    };
    let mut parser = Expression {
        bytes: source.as_bytes(),
        position: 0,
    };
    if !parser.expression(0) {
        return false;
    }
    parser.whitespace();
    parser.position == parser.bytes.len()
}

fn numeric_source(source: &str) -> bool {
    let mut parser = Expression {
        bytes: source.as_bytes(),
        position: 0,
    };
    if !parser.expression(0) {
        return false;
    }
    parser.whitespace();
    parser.position == parser.bytes.len()
}

/// A quoted literal with no escapes, interpolation prefix, or line breaks.
fn plain_string_literal(source: &str) -> bool {
    let source = source.trim();
    let Some(quote) = source.chars().next().filter(|c| matches!(c, '"' | '\'')) else {
        return false;
    };
    source.len() >= 2
        && source.len() <= 202
        && source.ends_with(quote)
        && source[1..source.len() - 1]
            .chars()
            .all(|c| (c.is_ascii_graphic() || c == ' ') && c != '"' && c != '\'' && c != '\\')
}

fn call_argument<'a>(statement: &'a str, callee: &str) -> Option<&'a str> {
    statement
        .trim()
        .strip_prefix(callee)?
        .strip_prefix('(')?
        .strip_suffix(')')
}

/// Python `print(<number expression | plain string>)` lines and comments only.
pub(super) fn python_print_program(code: &str) -> bool {
    // Python treats a lone CR as a line break that `lines()` does not split on.
    if code.contains('\r') {
        return false;
    }
    let lines: Vec<&str> = code
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    code.len() <= 1024
        && !lines.is_empty()
        && lines.len() <= 16
        && lines.iter().all(|line| {
            call_argument(line, "print")
                .is_some_and(|arg| numeric_source(arg) || plain_string_literal(arg))
        })
}

/// Built-in runtime identity properties. Reading one runs no user code, and
/// anything that could redefine it (a preload or loader) already runs for a
/// constant program too, so the existing runtime-context checks still apply.
const JAVASCRIPT_RUNTIME_IDENTITY: [&str; 9] = [
    "Bun.version",
    "Bun.revision",
    "process.version",
    "process.platform",
    "process.arch",
    "process.versions.node",
    "process.versions.bun",
    "process.versions.v8",
    "process.release.name",
];

/// Split `console.log` arguments at top-level commas. Plain strings carry no
/// quote characters, so a quote always opens or closes one.
fn console_arguments(source: &str) -> Option<Vec<&str>> {
    let mut arguments = Vec::new();
    let (mut start, mut depth, mut quote) = (0usize, 0usize, None);
    for (index, character) in source.char_indices() {
        match (quote, character) {
            (Some(open), _) if character == open => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(character),
            (None, '(') => depth += 1,
            (None, ')') => depth = depth.checked_sub(1)?,
            (None, ',') if depth == 0 => {
                arguments.push(&source[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if quote.is_some() || depth != 0 {
        return None;
    }
    arguments.push(&source[start..]);
    (arguments.len() <= 8).then_some(arguments)
}

fn javascript_value(source: &str) -> bool {
    numeric_source(source)
        || plain_string_literal(source)
        || JAVASCRIPT_RUNTIME_IDENTITY.contains(&source.trim())
}

/// One JavaScript expression statement: a number expression, a plain string,
/// or `console.log` of up to eight of those or built-in runtime identity
/// properties such as `Bun.version`.
pub(super) fn javascript_pure_program(code: &str) -> bool {
    let code = code.trim().trim_end_matches(';').trim();
    code.len() <= 256
        && (numeric_source(code)
            || plain_string_literal(code)
            || call_argument(code, "console.log")
                .and_then(console_arguments)
                .is_some_and(|arguments| arguments.into_iter().all(javascript_value)))
}

#[cfg(test)]
mod tests {
    use super::javascript_pure_program;

    #[test]
    fn console_log_accepts_literals_arithmetic_and_runtime_identity() {
        for code in [
            "console.log('bun-ok')",
            "console.log('bun-eval-ok', 1+1)",
            "console.log('bun-ok', Bun.version)",
            "console.log(process.version, process.platform, process.arch);",
            "console.log('a, b', (2 * 3) % 4)",
        ] {
            assert!(javascript_pure_program(code), "{code}");
        }
    }

    #[test]
    fn console_log_rejects_anything_that_can_run_code() {
        for code in [
            "console.log(Bun.version())",
            "console.log(Bun.env)",
            "console.log(process.env.HOME)",
            "console.log(require('fs'))",
            "console.log('x'), require('child_process')",
            "console.log('x', `${1}`)",
            "console.log(Bun.version.constructor)",
            "console.log(globalThis.Bun.version)",
            "console.log('a', 1, 2, 3, 4, 5, 6, 7, 8)",
            "console.log('unterminated)",
            "console.log(1))",
        ] {
            assert!(!javascript_pure_program(code), "{code}");
        }
    }
}
