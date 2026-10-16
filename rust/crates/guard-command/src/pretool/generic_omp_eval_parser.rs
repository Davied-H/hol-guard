//! Grammar for the OMP eval bridge: the literal-only JavaScript program and
//! the Python `read` lines, each parsed into ordered tool calls.

use super::tokens::{tokenize, Token};
use serde_json::{json, Value};
use std::collections::HashSet;

const MAX_CODE_BYTES: usize = 16 * 1024;
const MAX_CALLS: usize = 24;
const MAX_DEPTH: usize = 12;

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Lit {
    Str(String),
    Scalar(Value),
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct Call {
    pub(super) tool: String,
    pub(super) args: Vec<(String, Lit)>,
    pub(super) sdk_read_helper: bool,
    /// A `browser.*` call: `Null`, or the literal options of `browser.open`.
    pub(super) browser: Option<Value>,
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    declared: HashSet<String>,
    calls: Vec<Call>,
}

const RESERVED: &[&str] = &[
    "read",
    "tool",
    "display",
    "log",
    "console",
    "Promise",
    "JSON",
    "await",
    "async",
    "const",
    "let",
    "var",
    "function",
    "class",
    "new",
    "this",
    "import",
    "require",
    "process",
    "eval",
    "Function",
    "globalThis",
    "window",
    "global",
    "fetch",
    "return",
    "if",
    "else",
    "for",
    "while",
    "do",
    "try",
    "catch",
    "throw",
    "delete",
    "typeof",
    "void",
    "yield",
    "with",
    "in",
    "instanceof",
    "of",
    "true",
    "false",
    "null",
    "undefined",
    "constructor",
    "prototype",
    "__proto__",
];

/// Page-driving methods of an Oh My Pi browser tab. Navigation, file
/// uploads and downloads are absent; each opens a path the proof cannot bound.
const TAB_METHODS: &[&str] = &[
    "observe",
    "fill",
    "click",
    "check",
    "uncheck",
    "isChecked",
    "text",
    "count",
    "waitFor",
    "waitForText",
    "screenshot",
    "close",
    "evaluate",
    "type",
    "press",
    "hover",
    "select",
];

/// Option names a tab method may carry. A destination such as `path` is not
/// among them.
const TAB_OPTION_KEYS: &[&str] = &[
    "fullPage", "timeout", "name", "delay", "force", "exact", "visible", "state", "text",
    "selector",
];

/// Page script that talks to another host or builds code at run time.
fn page_script_reaches_out(script: &str) -> bool {
    let lower = script.to_ascii_lowercase().replace("location.reload()", "");
    [
        "fetch",
        "xmlhttprequest",
        "websocket",
        "sendbeacon",
        "eventsource",
        "import",
        "eval",
        "function",
        "http:",
        "https:",
        "ftp:",
        "window.open",
        "location",
        "cookie",
        "worker",
        "script",
        "iframe",
        "navigator",
        "indexeddb",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        token
    }

    fn eat(&mut self, punct: char) -> Option<()> {
        (self.next()? == Token::Punct(punct)).then_some(())
    }

    fn eat_ident(&mut self, name: &str) -> Option<()> {
        matches!(self.next()?, Token::Ident(ref ident) if ident == name).then_some(())
    }

    fn at(&self, punct: char) -> bool {
        self.peek() == Some(&Token::Punct(punct))
    }

    fn ident(&mut self) -> Option<String> {
        match self.next()? {
            Token::Ident(ident) => Some(ident),
            _ => None,
        }
    }

    fn program(&mut self) -> Option<()> {
        while self.peek().is_some() {
            if self.at(';') {
                self.pos += 1;
                continue;
            }
            self.statement()?;
            // A `(`, `[`, `.`, operator or (template) string after an
            // expression continues it even across a newline, so the host would
            // run a different program. Only `;`, the end, or a statement that
            // starts with a word (where JavaScript inserts the semicolon) may
            // follow.
            match self.peek() {
                None | Some(Token::Punct(';')) | Some(Token::Ident(_)) => {}
                Some(_) => return None,
            }
        }
        Some(())
    }

    fn binding_name(&mut self) -> Option<String> {
        let name = self.ident()?;
        (!RESERVED.contains(&name.as_str())).then_some(name)
    }

    fn statement(&mut self) -> Option<()> {
        match self.peek()? {
            Token::Ident(word) if word == "const" || word == "let" => {
                self.pos += 1;
                let mut names = Vec::new();
                if self.at('[') {
                    self.pos += 1;
                    while !self.at(']') {
                        names.push(self.binding_name()?);
                        if self.at(',') {
                            self.pos += 1;
                        } else {
                            break;
                        }
                    }
                    self.eat(']')?;
                } else {
                    names.push(self.binding_name()?);
                }
                self.eat('=')?;
                self.value(0)?;
                self.declared.extend(names);
                Some(())
            }
            Token::Ident(word) if word == "display" || word == "log" => {
                self.pos += 1;
                self.paren_value()
            }
            Token::Ident(word) if word == "console" => {
                self.pos += 1;
                self.eat('.')?;
                self.eat_ident("log")?;
                self.paren_value()
            }
            _ => self.value(0),
        }
    }

    /// Output calls take one or more values, as `console.log(a, b)` does.
    fn paren_value(&mut self) -> Option<()> {
        self.eat('(')?;
        self.value(0)?;
        while self.at(',') {
            self.pos += 1;
            self.value(0)?;
        }
        self.eat(')')
    }

    fn value(&mut self, depth: usize) -> Option<()> {
        if depth > MAX_DEPTH {
            return None;
        }
        match self.next()? {
            Token::Ident(word) => match word.as_str() {
                "await" => self.awaited(depth)?,
                "tool" => self.tool_call(depth)?,
                "browser" => self.browser_call()?,
                // An un-awaited `read(...)`, as inside `Promise.all([...])`.
                "read" => self.read_helper()?,
                "Promise" => self.promise_all(depth)?,
                "JSON" => {
                    self.eat('.')?;
                    self.eat_ident("stringify")?;
                    self.eat('(')?;
                    self.value(depth + 1)?;
                    self.eat(')')?;
                }
                "true" | "false" | "null" => {}
                name if self.declared.contains(name) => self.tab_method()?,
                _ => return None,
            },
            Token::Str(_) | Token::Num(_) => {}
            Token::Punct('(') => {
                self.value(depth + 1)?;
                self.eat(')')?;
            }
            Token::Punct('[') => {
                while !self.at(']') {
                    self.value(depth + 1)?;
                    if self.at(',') {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                self.eat(']')?;
            }
            Token::Punct('{') => self.display_object(depth)?,
            _ => return None,
        }
        // Only the `.text` and `.length` accessors may follow a value.
        while self.at('.') {
            self.pos += 1;
            match self.ident()?.as_str() {
                "text" | "length" => {}
                _ => return None,
            }
        }
        Some(())
    }

    fn display_object(&mut self, depth: usize) -> Option<()> {
        while !self.at('}') {
            match self.next()? {
                Token::Ident(name) if self.at(',') || self.at('}') => {
                    if !self.declared.contains(&name) {
                        return None;
                    }
                }
                Token::Ident(_) | Token::Str(_) => {
                    self.eat(':')?;
                    self.value(depth + 1)?;
                }
                _ => return None,
            }
            if self.at(',') {
                self.pos += 1;
            } else {
                break;
            }
        }
        self.eat('}')
    }

    fn awaited(&mut self, depth: usize) -> Option<()> {
        match self.next()? {
            Token::Ident(word) if word == "tool" => self.tool_call(depth),
            Token::Ident(word) if word == "browser" => self.browser_call(),
            Token::Ident(word) if self.declared.contains(&word) => self.tab_method(),
            Token::Ident(word) if word == "read" => self.read_helper(),
            Token::Ident(word) if word == "Promise" => self.promise_all(depth),
            Token::Punct('(') => {
                self.value(depth + 1)?;
                self.eat(')')
            }
            _ => None,
        }
    }

    fn read_helper(&mut self) -> Option<()> {
        self.eat('(')?;
        let Token::Str(path) = self.next()? else {
            return None;
        };
        if self.calls.len() >= MAX_CALLS {
            return None;
        }
        let call = read_helper_call(path)?;
        self.eat(')')?;
        self.calls.push(call);
        Some(())
    }

    /// `browser.open({..})`, `browser.tab("name")` and `browser.close({..})`.
    /// The options are literals; the caller judges what `open` may start.
    fn browser_call(&mut self) -> Option<()> {
        self.eat('.')?;
        let method = self.ident()?;
        self.eat('(')?;
        let options = match method.as_str() {
            "open" | "close" => self.literal(0)?,
            "tab" => match self.next()? {
                Token::Str(name) => Value::String(name),
                _ => return None,
            },
            _ => return None,
        };
        self.eat(')')?;
        if self.calls.len() >= MAX_CALLS {
            return None;
        }
        let browser = if method == "open" {
            options
        } else {
            Value::Null
        };
        self.calls.push(Call {
            tool: "browser".to_owned(),
            args: Vec::new(),
            sdk_read_helper: false,
            browser: Some(browser),
        });
        Some(())
    }

    /// A method call on a bound name, when it is one of the page-driving
    /// methods of a browser tab. Other `.name` accessors are left to the
    /// caller, which accepts only `.text` and `.length`.
    fn tab_method(&mut self) -> Option<()> {
        let (Some(Token::Punct('.')), Some(Token::Ident(method)), Some(Token::Punct('('))) = (
            self.tokens.get(self.pos),
            self.tokens.get(self.pos + 1),
            self.tokens.get(self.pos + 2),
        ) else {
            return Some(());
        };
        if !TAB_METHODS.contains(&method.as_str()) {
            return None;
        }
        let method = method.clone();
        self.pos += 3;
        let mut args = 0;
        while !self.at(')') {
            let value = self.literal(0)?;
            match &value {
                Value::String(text)
                    if matches!(method.as_str(), "evaluate" | "waitForFunction") =>
                {
                    if page_script_reaches_out(text) {
                        return None;
                    }
                }
                Value::Object(map) => {
                    if !map
                        .keys()
                        .all(|key| TAB_OPTION_KEYS.contains(&key.as_str()))
                    {
                        return None;
                    }
                }
                Value::Array(_) => return None,
                _ => {}
            }
            args += 1;
            if args > 4 {
                return None;
            }
            if self.at(',') {
                self.pos += 1;
            } else {
                break;
            }
        }
        self.eat(')')
    }

    /// A JSON-shaped literal: string, number, boolean, `null`, array or
    /// object with plain keys.
    fn literal(&mut self, depth: usize) -> Option<Value> {
        if depth > 4 {
            return None;
        }
        match self.next()? {
            Token::Str(text) => Some(Value::String(text)),
            Token::Num(number) => Some(number),
            Token::Ident(word) => match word.as_str() {
                "true" => Some(json!(true)),
                "false" => Some(json!(false)),
                "null" => Some(Value::Null),
                _ => None,
            },
            Token::Punct('[') => {
                let mut items = Vec::new();
                while !self.at(']') {
                    items.push(self.literal(depth + 1)?);
                    if self.at(',') {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                self.eat(']')?;
                Some(Value::Array(items))
            }
            Token::Punct('{') => {
                let mut map = serde_json::Map::new();
                while !self.at('}') {
                    let key = match self.next()? {
                        Token::Ident(key) | Token::Str(key) => key,
                        _ => return None,
                    };
                    self.eat(':')?;
                    let value = self.literal(depth + 1)?;
                    if map.insert(key, value).is_some() {
                        return None;
                    }
                    if self.at(',') {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                self.eat('}')?;
                Some(Value::Object(map))
            }
            _ => None,
        }
    }

    fn promise_all(&mut self, depth: usize) -> Option<()> {
        self.eat('.')?;
        self.eat_ident("all")?;
        self.eat('(')?;
        self.value(depth + 1)?;
        self.eat(')')
    }

    fn tool_call(&mut self, _depth: usize) -> Option<()> {
        self.eat('.')?;
        let tool = self.ident()?;
        if !matches!(tool.as_str(), "read" | "grep" | "glob" | "bash") {
            return None;
        }
        self.eat('(')?;
        self.eat('{')?;
        let mut args: Vec<(String, Lit)> = Vec::new();
        while !self.at('}') {
            let key = match self.next()? {
                Token::Ident(key) | Token::Str(key) => key,
                _ => return None,
            };
            if args.iter().any(|(seen, _)| *seen == key) {
                return None;
            }
            self.eat(':')?;
            let lit = match self.next()? {
                Token::Str(text) => Lit::Str(text),
                Token::Num(number) => Lit::Scalar(number),
                Token::Ident(word) if word == "true" => Lit::Scalar(json!(true)),
                Token::Ident(word) if word == "false" => Lit::Scalar(json!(false)),
                _ => return None,
            };
            args.push((key, lit));
            if self.at(',') {
                self.pos += 1;
            } else {
                break;
            }
        }
        self.eat('}')?;
        self.eat(')')?;
        if self.calls.len() >= MAX_CALLS {
            return None;
        }
        self.calls.push(Call {
            tool,
            args,
            sdk_read_helper: false,
            browser: None,
        });
        Some(())
    }
}

/// Parse a complete program into its ordered tool calls, or `None` when any
/// byte falls outside the grammar. At least one call is required.
pub(super) fn parse_program(code: &str) -> Option<Vec<Call>> {
    if code.len() > MAX_CODE_BYTES {
        return None;
    }
    let mut parser = Parser {
        tokens: tokenize(code)?,
        pos: 0,
        declared: HashSet::new(),
        calls: Vec::new(),
    };
    parser.program()?;
    (!parser.calls.is_empty()).then_some(parser.calls)
}

/// The SDK `read(path)` helper in both kernels resolves a raw filesystem path
/// against cwd. It does not expand ~, parse line selectors, or normalize
/// Windows separators, so spellings the standalone tool would interpret
/// differently are rejected.
fn read_helper_call(path: String) -> Option<Call> {
    if path.starts_with('~')
        || path.contains("://")
        || path.contains(['\\', '$'])
        || path.trim() != path
        || path.chars().any(char::is_control)
    {
        return None;
    }
    Some(Call {
        tool: "read".to_owned(),
        args: vec![("path".to_owned(), Lit::Str(path))],
        sdk_read_helper: true,
        browser: None,
    })
}

/// Parse a Python kernel program made only of whole lines of `read(LIT)`,
/// `print(read(LIT))` or `display(read(LIT))`. The Python prelude's `read`
/// is `Path(path).read_text()` for a plain path, the same contract as the JS
/// helper. Indented lines, continuations, string prefixes, comments and every
/// other statement are rejected.
pub(super) fn parse_python(code: &str) -> Option<Vec<Call>> {
    if code.len() > MAX_CODE_BYTES {
        return None;
    }
    let mut calls = Vec::new();
    for line in code.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with(char::is_whitespace) || calls.len() >= MAX_CALLS {
            return None;
        }
        // The shared lexer decodes JS escapes and backtick strings. Python
        // keeps the backslash, and a backtick string never reaches read().
        // Reject both so the proven path is the literal text.
        if line.contains(['\\', '`']) {
            return None;
        }
        let tokens = tokenize(line)?;
        let inner = match tokens.as_slice() {
            [Token::Ident(word), Token::Punct('('), inner @ .., Token::Punct(')')]
                if word == "print" || word == "display" =>
            {
                inner
            }
            all => all,
        };
        let [Token::Ident(word), Token::Punct('('), Token::Str(path), Token::Punct(')')] = inner
        else {
            return None;
        };
        if word != "read" {
            return None;
        }
        calls.push(read_helper_call(path.clone())?);
    }
    (!calls.is_empty()).then_some(calls)
}

#[test]
fn python_read_lines_are_parsed_as_reads() {
    let calls =
        parse_python("print(read('calc.py'))\ndisplay(read(\"a.ts\"))\nread('b')\n").unwrap();
    assert_eq!(calls.len(), 3);
    for code in [
        "import os",
        "print(read('a'));import os",
        "  print(read('a'))",
        "print(read(r'a'))",
        "print(read('a', 1, 5))",
        "print(read('~/.ssh/id_rsa'))",
        "print(read('a'))  # note",
        "print(read('a'))\rimport os",
        "print(read(\n'a'))",
        "x = read('a')",
        "",
        "print(read('a\\b'))",
        "print(read('a`b'))",
        "read(`a`)",
    ] {
        assert!(parse_python(code).is_none(), "{code:?}");
    }
}

#[test]
fn literal_read_helper_is_parsed_as_one_read() {
    let calls = parse_program("display(await read('README.md'))").unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].tool, "read");
}
