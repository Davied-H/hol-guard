//! Read a package-shim manifest the way Python `json.loads` accepts an object.
//!
//! `serde_json` rejects `NaN` and `Infinity`. Those tokens stay in the file,
//! and the audit stamp is inserted beside them. Any other parse failure is
//! returned to the caller so the existing bytes are left untouched.

use serde_json::{Map, Value};

use super::values::py_json_dumps;

#[derive(Debug)]
pub(super) enum ManifestBody {
    Object(Map<String, Value>),
    /// Original object text that contains an unquoted non-finite token.
    NonFinite(String),
}

pub(super) fn read_manifest(text: &str) -> Result<ManifestBody, String> {
    if text.trim().is_empty() {
        return Ok(ManifestBody::Object(Map::new()));
    }
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(map)) => Ok(ManifestBody::Object(map)),
        Ok(_) => Ok(ManifestBody::Object(Map::new())),
        Err(_) if is_nonfinite_object(text) => Ok(ManifestBody::NonFinite(text.to_owned())),
        Err(_) => Err("package shim manifest is not strict JSON".to_owned()),
    }
}

pub(super) fn with_stamp(body: ManifestBody, stamp: &str) -> String {
    match body {
        ManifestBody::Object(mut map) => {
            map.insert("last_audit_at".to_owned(), Value::String(stamp.to_owned()));
            py_json_dumps(&Value::Object(map), true)
        }
        ManifestBody::NonFinite(text) => splice_stamp(&text, stamp),
    }
}

fn is_nonfinite_object(text: &str) -> bool {
    let Some(substituted) = substitute_nonfinite(text) else {
        return false;
    };
    if substituted == text {
        return false;
    }
    matches!(
        serde_json::from_str::<Value>(&substituted),
        Ok(Value::Object(_))
    )
}

fn delimiter(byte: u8) -> bool {
    matches!(
        byte,
        b' ' | b'\t' | b'\n' | b'\r' | b':' | b',' | b'[' | b']' | b'{' | b'}'
    )
}

fn substitute_nonfinite(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    let mut in_string = false;
    let mut escape = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            out.push(byte);
            if escape {
                escape = false;
            } else if byte == b'\\' {
                escape = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            out.push(byte);
            index += 1;
            continue;
        }
        if let Some(literal) = nonfinite_literal(bytes, index) {
            out.push(b'0');
            index += literal.len();
            continue;
        }
        out.push(byte);
        index += 1;
    }
    String::from_utf8(out).ok()
}

fn nonfinite_literal(bytes: &[u8], index: usize) -> Option<&[u8]> {
    let before_ok = index == 0 || delimiter(bytes[index - 1]);
    if !before_ok {
        return None;
    }
    for literal in [
        b"-Infinity".as_slice(),
        b"Infinity".as_slice(),
        b"NaN".as_slice(),
    ] {
        if bytes[index..].starts_with(literal) {
            let after = index + literal.len();
            if after == bytes.len() || delimiter(bytes[after]) {
                return Some(literal);
            }
        }
    }
    None
}

fn splice_stamp(text: &str, stamp: &str) -> String {
    let trimmed = text.trim();
    let body = &trimmed[..trimmed.len() - 1];
    let rendered = serde_json::to_string(stamp).expect("stamp is a string");
    let comma = if body.trim_end().ends_with('{') {
        ""
    } else {
        ", "
    };
    format!("{body}{comma}\"last_audit_at\": {rendered}}}")
}

#[cfg(test)]
mod tests {
    use super::read_manifest;

    #[test]
    fn a_truncated_nonfinite_object_is_not_treated_as_empty() {
        let error = read_manifest("{\"enabled\": true, \"score\": NaN").expect_err("truncated");
        assert!(error.contains("not strict JSON"), "{error}");
    }
}
