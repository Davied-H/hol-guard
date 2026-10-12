//! Text analysis for Hermes skill documents: frontmatter, fenced code, plain
//! markdown, environment-variable mentions and secret-looking values.

use std::collections::BTreeSet;
use std::path::{Component, Path};
use std::sync::OnceLock;

use regex::Regex;

use super::context_digest::python_strip;
use super::hermes_inspect::parse_yaml_mapping;
use super::pyjson::{float_repr, PyVal};

pub(crate) const ERR_REPR: &str = "native_runner_authority_hermes_value_unrepresentable";

const SCANNABLE_EXTENSIONS: [&str; 14] = [
    ".md", ".txt", ".py", ".sh", ".bash", ".js", ".ts", ".yaml", ".yml", ".json", ".toml", ".cfg",
    ".ini", ".env",
];
const SCANNABLE_NAMES: [&str; 4] = [".env", "Makefile", "Dockerfile", "Procfile"];
const SECRET_PREFIXES: [&str; 11] = [
    "ghp_", "gho_", "ghu_", "ghs_", "sk-", "sk_", "xai-", "key-", "key_", "tok_", "token_",
];

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static pattern compiles"))
}

/// `Path.suffix` for a file name.
fn suffix(name: &str) -> &str {
    match name.rfind('.') {
        Some(index) if index > 0 && index < name.len() - 1 => &name[index..],
        _ => "",
    }
}

/// `_is_scannable`.
pub(crate) fn is_scannable(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = suffix(&name);
    if SCANNABLE_EXTENSIONS.contains(&ext.to_lowercase().as_str()) {
        return true;
    }
    if !ext.is_empty() {
        return false;
    }
    if SCANNABLE_NAMES.contains(&name.as_str()) {
        return true;
    }
    path.components().any(|part| match part {
        Component::Normal(text) => text == "scripts",
        _ => false,
    })
}

/// `_extract_code_blocks`.
pub(crate) fn code_blocks(content: &str) -> Vec<String> {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(&CELL, r"(?s)```[^\n]*\n(.*?)\n?```")
        .captures_iter(content)
        .filter_map(|captures| {
            let code = python_strip(captures.get(1)?.as_str());
            (!code.is_empty()).then(|| code.to_owned())
        })
        .collect()
}

/// `_extract_plain_markdown`.
pub(crate) fn plain_markdown(content: &str, max_len: usize) -> String {
    static CELL: OnceLock<Regex> = OnceLock::new();
    let removed = regex(&CELL, r"(?s)```[^\n]*\n.*?\n?```").replace_all(content, "");
    let mut stripped: &str = &removed;
    if let Some(rest) = stripped.strip_prefix("---") {
        if let Some((_, after)) = rest.split_once("---") {
            stripped = after;
        }
    }
    python_strip(stripped).chars().take(max_len).collect()
}

/// `_extract_env_mentions`.
pub(crate) fn env_mentions(content: &str) -> BTreeSet<String> {
    static BRACE: OnceLock<Regex> = OnceLock::new();
    static CALL: OnceLock<Regex> = OnceLock::new();
    static INDEX_SINGLE: OnceLock<Regex> = OnceLock::new();
    static INDEX_DOUBLE: OnceLock<Regex> = OnceLock::new();
    static PROCESS: OnceLock<Regex> = OnceLock::new();
    let patterns = [
        regex(&BRACE, r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}"),
        regex(
            &CALL,
            r#"os\.(?:environ(?:\.get)?|getenv)\(['"]([A-Za-z_][A-Za-z0-9_]*)['"]\)"#,
        ),
        regex(&INDEX_SINGLE, r"os\.environ\['([A-Za-z_][A-Za-z0-9_]*)'\]"),
        regex(
            &INDEX_DOUBLE,
            r#"os\.environ\["([A-Za-z_][A-Za-z0-9_]*)"\]"#,
        ),
        regex(&PROCESS, r"process\.env\.([A-Za-z_][A-Za-z0-9_]*)"),
    ];
    let mut found = BTreeSet::new();
    for pattern in patterns {
        for captures in pattern.captures_iter(content) {
            if let Some(name) = captures.get(1) {
                found.insert(name.as_str().to_owned());
            }
        }
    }
    found
}

/// `_looks_like_secret`.
pub(crate) fn looks_like_secret(value: &str) -> bool {
    static CELL: OnceLock<Regex> = OnceLock::new();
    if value.chars().count() < 8 {
        return false;
    }
    let lower = value.to_lowercase();
    SECRET_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
        || lower.starts_with("bearer ")
        || regex(&CELL, r"^[A-Za-z0-9+/=_-]{20,}$").is_match(value)
}

/// `repr(str)` for ASCII text. Text beyond ASCII needs CPython's printable
/// table and is refused instead of guessed.
fn repr_str(text: &str) -> Result<String, &'static str> {
    if !text.is_ascii() {
        return Err(ERR_REPR);
    }
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch == quote => {
                out.push('\\');
                out.push(ch);
            }
            ch if (ch as u32) < 0x20 || ch as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", ch as u32));
            }
            ch => out.push(ch),
        }
    }
    out.push(quote);
    Ok(out)
}

/// `repr(value)` for a parsed YAML value.
fn repr(value: &PyVal) -> Result<String, &'static str> {
    Ok(match value {
        PyVal::Null => "None".to_owned(),
        PyVal::Bool(true) => "True".to_owned(),
        PyVal::Bool(false) => "False".to_owned(),
        PyVal::Int(digits) => digits.clone(),
        PyVal::Float(number) => float_repr(*number),
        PyVal::Str(text) => repr_str(text)?,
        PyVal::List(items) => {
            let parts: Result<Vec<String>, _> = items.iter().map(repr).collect();
            format!("[{}]", parts?.join(", "))
        }
        PyVal::Dict(entries) => {
            let mut parts = Vec::with_capacity(entries.len());
            for (key, item) in entries {
                parts.push(format!("{}: {}", repr_str(key)?, repr(item)?));
            }
            format!("{{{}}}", parts.join(", "))
        }
    })
}

/// `str(value)`.
fn text_of(value: &PyVal) -> Result<String, &'static str> {
    match value {
        PyVal::Str(text) => Ok(text.clone()),
        other => repr(other),
    }
}

/// `_flatten_yaml_value`.
fn flatten(value: &PyVal) -> Result<String, &'static str> {
    match value {
        PyVal::List(items) => {
            let parts: Result<Vec<String>, _> = items.iter().map(text_of).collect();
            Ok(parts?.join(", "))
        }
        other => text_of(other),
    }
}

/// The parsed frontmatter of a skill preview; keys flatten on demand.
pub(crate) struct Frontmatter(Vec<(String, PyVal)>);

impl Frontmatter {
    /// `frontmatter.get(key)` after `_flatten_yaml_value`.
    pub(crate) fn flat(&self, key: &str) -> Result<Option<String>, &'static str> {
        self.0
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| flatten(value))
            .transpose()
    }
}

/// `_parse_frontmatter`.
pub(crate) fn frontmatter(content: &str) -> Result<Frontmatter, &'static str> {
    let empty = Frontmatter(Vec::new());
    let Some(rest) = content.strip_prefix("---") else {
        return Ok(empty);
    };
    let Some((raw, _)) = rest.split_once("---") else {
        return Ok(empty);
    };
    Ok(parse_yaml_mapping(python_strip(raw))?.map_or(empty, Frontmatter))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_follows_pathlib() {
        assert_eq!(suffix("a.md"), ".md");
        assert_eq!(suffix(".env"), "");
        assert_eq!(suffix("a."), "");
        assert_eq!(suffix("a.tar.gz"), ".gz");
    }

    #[test]
    fn repr_matches_cpython_for_ascii() {
        let nested = PyVal::Dict(vec![(
            "k".to_owned(),
            PyVal::List(vec![PyVal::Str("it's".to_owned()), PyVal::Null]),
        )]);
        assert_eq!(repr(&nested).unwrap(), "{'k': [\"it's\", None]}");
        assert!(repr(&PyVal::Str("é".to_owned())).is_err());
    }

    #[test]
    fn env_mentions_cover_each_reference_form() {
        let found = env_mentions(
            "${API_KEY} os.environ['A1'] os.environ.get('A2') os.getenv(\"A3\") \
             os.environ[\"A4\"] process.env.A5 ${1BAD}",
        );
        let names: Vec<&str> = found.iter().map(String::as_str).collect();
        assert_eq!(names, ["A1", "A2", "A3", "A4", "A5", "API_KEY"]);
    }

    #[test]
    fn secret_heuristic_matches_the_prefix_and_length_rules() {
        for secret in [
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
            "sk-proj-abc123longstring12345",
            "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature12345",
            "YXdzX2FjY2Vzc19rZXk=",
        ] {
            assert!(looks_like_secret(secret), "{secret}");
        }
        for plain in ["hello", "just a regular config value", "sk-"] {
            assert!(!looks_like_secret(plain), "{plain}");
        }
    }
}
