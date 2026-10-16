//! Network host references, with Python `re.IGNORECASE` and `\b` semantics.
//!
//! Hosts come from `http(s)://` URLs (through the `urlsplit` hostname rule)
//! and from host-shaped words. Host-shaped words inside a media type, before
//! `(`, or ending in a file suffix are not network hosts.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use super::python_text::is_word;
use super::url_host::url_hostname;

/// `https?://[^\s'"\x60]+` under `re.IGNORECASE`: `s` also matches U+017F.
static URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"[hH][tT][tT][pP][sS\x{17F}]?://[^\s\x1C-\x1F'"\x60]+"#)
        .expect("artifact risk URL pattern compiles")
});

const MEDIA_TYPES: [&str; 9] = [
    "application",
    "audio",
    "font",
    "image",
    "message",
    "model",
    "multipart",
    "text",
    "video",
];
const NON_NETWORK_SUFFIXES: [&str; 22] = [
    "md", "json", "toml", "yaml", "yml", "txt", "py", "js", "jsx", "cjs", "cts", "mjs", "mts",
    "ts", "tsx", "sh", "cfg", "conf", "log", "tmp", "bak", "bin",
];
const NON_NETWORK_EXACT_FILENAMES: [&str; 1] = ["next.config"];

/// Non-ASCII characters Python `re.IGNORECASE` folds onto an ASCII letter.
fn folded_ascii(value: char) -> Option<char> {
    match value {
        '\u{130}' | '\u{131}' => Some('i'),
        '\u{17F}' => Some('s'),
        '\u{212A}' => Some('k'),
        _ if value.is_ascii() => Some(value.to_ascii_lowercase()),
        _ => None,
    }
}

/// `[a-z]` under `re.IGNORECASE`.
fn is_letter(value: char) -> bool {
    folded_ascii(value).is_some_and(|folded| folded.is_ascii_lowercase())
}

/// `[a-z0-9-]` under `re.IGNORECASE`.
fn is_label(value: char) -> bool {
    is_letter(value) || value.is_ascii_digit() || value == '-'
}

/// `[a-z0-9!#$&^_.+-]` under `re.IGNORECASE`.
fn is_media_subtype(value: char) -> bool {
    is_label(value) || "!#$&^_.+".contains(value)
}

/// Python `\b` before position `at`.
fn boundary(chars: &[char], at: usize) -> bool {
    let before = at > 0 && is_word(chars[at - 1]);
    let after = chars.get(at).copied().is_some_and(is_word);
    before != after
}

fn run(chars: &[char], from: usize, accept: fn(char) -> bool) -> usize {
    chars[from..]
        .iter()
        .take_while(|value| accept(**value))
        .count()
}

/// Every host reference in `text`, lowercased.
pub(super) fn extract_network_hosts(text: &str) -> BTreeSet<String> {
    let mut hosts = BTreeSet::new();
    for found in URL.find_iter(text) {
        if let Some(hostname) = url_hostname(found.as_str()) {
            hosts.insert(hostname.to_lowercase());
        }
    }
    let chars = text.chars().collect::<Vec<char>>();
    let media_spans = matches(&chars, media_type_match);
    for (start, end) in matches(&chars, host_match) {
        if media_spans
            .iter()
            .any(|(span_start, span_end)| *span_start <= start && end <= *span_end)
            || chars.get(end) == Some(&'(')
        {
            continue;
        }
        let lowered = chars[start..end].iter().collect::<String>().to_lowercase();
        let suffix = lowered.rsplit('.').next().unwrap_or_default();
        if NON_NETWORK_EXACT_FILENAMES.contains(&lowered.as_str())
            || NON_NETWORK_SUFFIXES.contains(&suffix)
        {
            continue;
        }
        hosts.insert(lowered);
    }
    hosts
}

/// Python `finditer` spans for a matcher that answers the end of the match
/// starting at a position.
fn matches(chars: &[char], matcher: fn(&[char], usize) -> Option<usize>) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0;
    while start < chars.len() {
        match matcher(chars, start) {
            Some(end) => {
                spans.push((start, end));
                start = end;
            }
            None => start += 1,
        }
    }
    spans
}

/// `\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b` at `start`, with Python backtracking:
/// the most label groups first, and a final label that ends at a boundary.
fn host_match(chars: &[char], start: usize) -> Option<usize> {
    if !is_label(chars[start]) || !boundary(chars, start) {
        return None;
    }
    let mut final_label_starts = Vec::new();
    let mut position = start;
    loop {
        let label_end = position + run(chars, position, is_label);
        if label_end == position || chars.get(label_end) != Some(&'.') {
            break;
        }
        position = label_end + 1;
        final_label_starts.push(position);
    }
    final_label_starts.into_iter().rev().find_map(|label| {
        let end = label + run(chars, label, is_letter);
        (end - label >= 2 && boundary(chars, end)).then_some(end)
    })
}

/// `\b(?:application|...|video)/[a-z0-9!#$&^_.+-]+` at `start`.
fn media_type_match(chars: &[char], start: usize) -> Option<usize> {
    if !boundary(chars, start) {
        return None;
    }
    MEDIA_TYPES.iter().find_map(|media_type| {
        let slash = start + media_type.len();
        let prefix = chars.get(start..slash)?;
        let same = prefix
            .iter()
            .zip(media_type.chars())
            .all(|(value, expected)| folded_ascii(*value) == Some(expected));
        if !same || chars.get(slash) != Some(&'/') {
            return None;
        }
        let subtype = run(chars, slash + 1, is_media_subtype);
        (subtype > 0).then_some(slash + 1 + subtype)
    })
}
