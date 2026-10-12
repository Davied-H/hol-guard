//! TOML text for `config.toml` writes. Mirrors the former Python writer: keys
//! sorted, scalars before nested tables, nested tables under `[a.b]` headers,
//! inline tables inside arrays. Strings are JSON-escaped and ASCII-only so the
//! output is stable across locales; characters outside the BMP use `\U` escapes
//! because the old surrogate-pair form is not valid TOML.

use serde_json::{Map, Number, Value};

use crate::guard_support_text::py_strip;

pub(crate) fn render_config(payload: &Value) -> Result<String, String> {
    let table = payload.as_object().ok_or("config_payload_not_a_table")?;
    let lines = table_lines(table, &[]);
    Ok(format!("{}\n", py_strip(&lines.join("\n"))))
}

fn table_lines(table: &Map<String, Value>, path: &[&str]) -> Vec<String> {
    let mut entries: Vec<(&String, &Value)> = table.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let mut lines = Vec::new();
    if !path.is_empty() {
        let header: Vec<String> = path.iter().map(|part| key(part)).collect();
        lines.push(format!("[{}]", header.join(".")));
    }
    for (name, value) in entries.iter().filter(|(_, value)| !value.is_object()) {
        lines.push(format!("{} = {}", key(name), literal(value)));
    }
    for (name, value) in entries.iter().filter(|(_, value)| value.is_object()) {
        let mut nested_path = path.to_vec();
        nested_path.push(name.as_str());
        let nested = table_lines(value.as_object().expect("object"), &nested_path);
        if !lines.is_empty() && !nested.is_empty() {
            lines.push(String::new());
        }
        lines.extend(nested);
    }
    lines
}

fn key(name: &str) -> String {
    let bare = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if bare {
        name.to_owned()
    } else {
        string(name)
    }
}

fn literal(value: &Value) -> String {
    match value {
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number_text(number),
        Value::String(text) => string(text),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(literal).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(table) => inline_table(table),
        Value::Null => string("None"),
    }
}

fn inline_table(table: &Map<String, Value>) -> String {
    let mut entries: Vec<(&String, &Value)> = table.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let items: Vec<String> = entries
        .iter()
        .map(|(name, value)| format!("{} = {}", key(name), literal(value)))
        .collect();
    format!("{{ {} }}", items.join(", "))
}

fn string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    for ch in serde_json::to_string(text).expect("string encodes").chars() {
        if ch.is_ascii() {
            out.push(ch);
        } else if (ch as u32) <= 0xffff {
            out.push_str(&format!("\\u{:04x}", ch as u32));
        } else {
            out.push_str(&format!("\\U{:08x}", ch as u32));
        }
    }
    out
}

fn number_text(number: &Number) -> String {
    match number.as_f64().filter(|_| number.is_f64()) {
        Some(float) => python_float(float),
        None => number.to_string(),
    }
}

/// Python `repr(float)`: shortest round-trip digits, positional between 1e-4 and
/// 1e16, otherwise `d.ddde+XX`.
fn python_float(value: f64) -> String {
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific.split_once('e').expect("exponent");
    let exponent: i32 = exponent.parse().expect("exponent digits");
    let (sign, mantissa) = mantissa
        .strip_prefix('-')
        .map_or(("", mantissa), |rest| ("-", rest));
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    if !(-4..16).contains(&exponent) {
        let tail = &digits[1..];
        let head = if tail.is_empty() {
            digits[..1].to_owned()
        } else {
            format!("{}.{tail}", &digits[..1])
        };
        let marker = if exponent < 0 { '-' } else { '+' };
        return format!("{sign}{head}e{marker}{:02}", exponent.abs());
    }
    if exponent < 0 {
        return format!("{sign}0.{}{digits}", "0".repeat((-exponent - 1) as usize));
    }
    let whole = exponent as usize + 1;
    if digits.len() <= whole {
        format!("{sign}{digits}{}.0", "0".repeat(whole - digits.len()))
    } else {
        format!("{sign}{}.{}", &digits[..whole], &digits[whole..])
    }
}
