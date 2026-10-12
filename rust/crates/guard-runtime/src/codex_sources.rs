//! Reading the Codex `config.toml` and `hooks.json` sources the way
//! `_read_toml` and `_json_object` do: a missing, unreadable or malformed
//! source is an empty table, and text CPython would raise on is a refusal.

use std::fs;
use std::path::Path;

use serde_json::{Map, Value};

use super::aibom_paths::is_file;
use super::codex_value::HookVal;
use super::pyjson::{parse, JsonFailure};
use super::runner_authority_op::ERR_INVALID;

pub(super) const ERR_TEXT: &str = "native_runner_authority_codex_text_undecodable";
pub(super) const ERR_VALUE: &str = "native_runner_authority_codex_value_unrepresentable";

/// A source file: whether it counts as found, and its bytes when readable.
pub(super) struct Raw {
    pub(super) present: bool,
    pub(super) bytes: Option<Vec<u8>>,
}

pub(super) fn read_source(
    path: &str,
    contents: Option<&Map<String, Value>>,
) -> Result<Raw, &'static str> {
    match contents {
        None => {
            let location = Path::new(path);
            let present = is_file(location);
            Ok(Raw {
                present,
                bytes: if present {
                    fs::read(location).ok()
                } else {
                    None
                },
            })
        }
        Some(captured) => match captured.get(path) {
            Some(Value::Null) => Ok(Raw {
                present: false,
                bytes: None,
            }),
            Some(Value::String(text)) => Ok(Raw {
                present: true,
                bytes: Some(hex::decode(text).map_err(|_| ERR_INVALID)?),
            }),
            _ => Err(ERR_INVALID),
        },
    }
}

/// Whether a failing TOML line carries a number `tomllib` reads but the
/// parser here cannot hold: an integer past 64 bits or an overflowing float.
fn has_unrepresentable_number(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut digits = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if byte.is_ascii_digit() || (*byte == b'_' && digits > 0) {
            digits += 1;
            if digits >= 19 {
                return true;
            }
        } else {
            digits = 0;
        }
        if matches!(byte, b'e' | b'E') {
            let rest = &bytes[index + 1..];
            let rest = rest
                .strip_prefix(b"+")
                .or(rest.strip_prefix(b"-"))
                .unwrap_or(rest);
            if rest.iter().take_while(|next| next.is_ascii_digit()).count() >= 3 {
                return true;
            }
        }
    }
    let lowered = line.to_ascii_lowercase();
    ["0x", "0o", "0b"].iter().any(|prefix| {
        lowered.match_indices(prefix).any(|(start, _)| {
            lowered[start + 2..]
                .bytes()
                .take_while(|next| next.is_ascii_hexdigit() || *next == b'_')
                .count()
                >= 16
        })
    })
}

/// `_read_toml`: missing, unreadable or malformed text is an empty table.
pub(super) fn toml_payload(bytes: Option<&[u8]>) -> Result<HookVal, &'static str> {
    let empty = HookVal::Dict(Vec::new());
    let Some(bytes) = bytes else {
        return Ok(empty);
    };
    let text = std::str::from_utf8(bytes).map_err(|_| ERR_TEXT)?;
    // `tomllib` rejects a byte-order mark where this parser skips it.
    if text.starts_with('\u{feff}') {
        return Ok(empty);
    }
    match text.parse::<toml_edit::DocumentMut>() {
        Ok(document) => Ok(HookVal::from_document(document.as_table())),
        Err(error) => {
            let span = error.span().map_or(0, |span| span.start.min(text.len()));
            let start = text[..span].rfind('\n').map_or(0, |index| index + 1);
            let end = text[span..]
                .find('\n')
                .map_or(text.len(), |index| span + index);
            if has_unrepresentable_number(&text[start..end]) {
                Err(ERR_VALUE)
            } else {
                Ok(empty)
            }
        }
    }
}

/// `_json_object`: missing, unreadable, not JSON or not an object is `{}`.
pub(super) fn json_payload(bytes: Option<&[u8]>) -> Result<HookVal, &'static str> {
    let empty = HookVal::Dict(Vec::new());
    let Some(bytes) = bytes else {
        return Ok(empty);
    };
    let text = std::str::from_utf8(bytes).map_err(|_| ERR_TEXT)?;
    match parse(text) {
        Ok(value @ super::pyjson::PyVal::Dict(_)) => Ok(HookVal::from_py(&value)),
        Ok(_) | Err(JsonFailure::Syntax) => Ok(empty),
        Err(JsonFailure::Unrepresentable | JsonFailure::IntegerLimit | JsonFailure::Duplicate)
            if text.trim_start().starts_with('[') =>
        {
            Ok(empty)
        }
        Err(JsonFailure::Unrepresentable | JsonFailure::IntegerLimit | JsonFailure::Duplicate) => {
            Err(ERR_VALUE)
        }
    }
}

pub(super) fn is_empty(payload: &HookVal) -> bool {
    payload.as_dict().is_none_or(<[_]>::is_empty)
}

/// `_payload_has_hooks_feature_enabled`.
pub(super) fn hooks_feature_enabled(config: &HookVal) -> bool {
    match config.get("features") {
        Some(features @ HookVal::Dict(_)) => features.get("hooks") != Some(&HookVal::Bool(false)),
        _ => true,
    }
}
