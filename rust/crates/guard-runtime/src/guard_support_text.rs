//! Text helpers shared by the `GuardSupport` subops. They reproduce the Python
//! `str` behavior the replaced helpers relied on.

use serde_json::{Map, Value};

/// Python `str.strip()`: Unicode whitespace plus the ASCII separators U+001C..U+001F.
pub(crate) fn py_strip(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// A string-typed field, or `None` for absent and non-string values.
pub(crate) fn str_field<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

/// `text.ensure_terminal_punctuation`.
pub(crate) fn terminal_punctuation(message: &str) -> String {
    let trimmed = py_strip(message);
    if trimmed.is_empty() || trimmed.ends_with(['.', '!', '?']) {
        trimmed.to_owned()
    } else {
        format!("{trimmed}.")
    }
}
