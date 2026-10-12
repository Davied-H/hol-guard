//! Byte-level questions the daemon front door asks of a connection's buffered
//! request head. Both answers are computed from a non-consuming peek, never
//! from a read, so the request reaches its handler untouched.

use guard_contracts::{DAEMON_PEEK_HEADER_BYTES, DAEMON_PEEK_LINE_BYTES};

/// The path of the request line in `buffered`, or `None` while the line is
/// incomplete or malformed. A query string is dropped. `buffered` is what a
/// single non-blocking peek returned.
pub(crate) fn peek_request_path(buffered: &[u8]) -> Option<String> {
    let window = &buffered[..buffered.len().min(DAEMON_PEEK_LINE_BYTES)];
    if !window.contains(&b'\n') {
        return None;
    }
    let line_end = window
        .iter()
        .position(|byte| matches!(byte, b'\n' | b'\r'))
        .unwrap_or(window.len());
    let mut parts = window[..line_end]
        .split(|byte| matches!(byte, b' ' | b'\t' | 0x0b | 0x0c))
        .filter(|part| !part.is_empty());
    let (_method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || !version.starts_with(b"HTTP/") {
        return None;
    }
    if !target.is_ascii() {
        return None;
    }
    let target = std::str::from_utf8(target).ok()?;
    Some(target.split('?').next().unwrap_or(target).to_owned())
}

/// Whether the peeked bytes contain the blank line that ends a request head.
pub(crate) fn request_headers_complete(buffered: &[u8]) -> bool {
    let window = &buffered[..buffered.len().min(DAEMON_PEEK_HEADER_BYTES)];
    window.windows(4).any(|chunk| chunk == b"\r\n\r\n")
        || window.windows(2).any(|chunk| chunk == b"\n\n")
}
