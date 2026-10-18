//! Guard's own approval link carries no leaked credential.
//!
//! When Guard holds a tool call, the reason it gives the agent ends with a
//! loopback approval link whose `#guard-token=` fragment signs the browser in
//! to the local inbox (`native_review_link` in `guard-runtime`). Some hosts
//! hand that reason back as the tool's output, as Oh My Pi does for an MCP
//! call made through `write` to `xd://` (#5191). The fragment has the
//! assignment shape the credential rule looks for, so the output review
//! blocked Guard's own reason and the user never saw the link.

/// `{"aud":"guard-local-daemon","version":"guard-local-daemon-session.v1","surface":"`
/// in unpadded base64url. Those 81 bytes are whole base64 groups, so every
/// dashboard session payload Guard signs starts with exactly this text.
const SESSION_PAYLOAD_PREFIX: &str = "eyJhdWQiOiJndWFyZC1sb2NhbC1kYWVtb24iLCJ2ZXJzaW9uIjoiZ3VhcmQtbG9jYWwtZGFlbW9uLXNlc3Npb24udjEiLCJzdXJmYWNlIjoi";
/// An HMAC-SHA256 signature in unpadded base64url.
const SIGNATURE_CHARS: usize = 43;
const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "[::1]", "localhost"];

/// Whether `matched`, which `preceding` leads up to, is the `guard-token`
/// fragment of a loopback approval link that holds a Guard dashboard
/// session. The same token anywhere else still counts.
pub(crate) fn is_guard_link(matched: &str, preceding: &str) -> bool {
    let Some(value) = matched.strip_prefix("guard-token=") else {
        return false;
    };
    // Guard ends the reason with a period right after the link.
    let value = value.strip_suffix('.').unwrap_or(value);
    is_session_token(value)
        && preceding
            .strip_suffix('#')
            .is_some_and(ends_with_loopback_url)
}

fn is_session_token(value: &str) -> bool {
    let mut parts = value.split('.');
    let (Some("gld1"), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    payload.starts_with(SESSION_PAYLOAD_PREFIX)
        && is_base64url(payload)
        && signature.len() == SIGNATURE_CHARS
        && is_base64url(signature)
}

fn is_base64url(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Whether `text` ends with `http(s)://host[:port]/path` on a loopback host,
/// with no credentials, query or escapes.
fn ends_with_loopback_url(text: &str) -> bool {
    let Some(separator) = text.rfind("://") else {
        return false;
    };
    let scheme_start = text[..separator]
        .rfind(|character: char| !character.is_ascii_alphabetic())
        .map_or(0, |index| index + 1);
    let scheme = &text[scheme_start..separator];
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let rest = &text[separator + 3..];
    let (netloc, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let (host, port) = match netloc.strip_prefix("[::1]") {
        Some(port) => ("[::1]", port),
        None => netloc.split_at(netloc.find(':').unwrap_or(netloc.len())),
    };
    let port_safe = port.is_empty()
        || port.strip_prefix(':').is_some_and(|digits| {
            !digits.is_empty()
                && digits.len() <= 5
                && digits.bytes().all(|byte| byte.is_ascii_digit())
        });
    let path_safe = path.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~')
    });
    LOOPBACK_HOSTS
        .iter()
        .any(|loopback| host.eq_ignore_ascii_case(loopback))
        && port_safe
        && path_safe
}

#[cfg(test)]
#[path = "guard_link_tests.rs"]
mod tests;
