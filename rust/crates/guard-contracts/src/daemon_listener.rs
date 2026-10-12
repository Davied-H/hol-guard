//! Wire contract for the Rust-hosted daemon listener: the feature flag that
//! gates it, the request kinds the front door classifies from the first
//! request line, and the admission limits and deadlines the retired Python
//! daemon server enforced (`_MAX_CONCURRENT_DAEMON_*`, `_DAEMON_*_SECONDS`).
//!
//! The values are shared by the listener and by the Python launcher so that a
//! limit has exactly one definition.

/// Advertised by `capabilities` when the runtime can host the daemon listener.
pub const DAEMON_LISTENER_FEATURE: &str = "native-daemon-listener-v1";

/// Request kinds that bypass the normal (general) admission pool. A control
/// path is a health probe that may wait briefly for capacity.
pub const DAEMON_CONTROL_PATHS: &[&str] = &["/v1/healthz/details", "/v1/healthz/verify"];
/// Critical paths are the liveness and discovery probes. They share the
/// control bypass but own a separate capacity pool.
pub const DAEMON_CRITICAL_PATHS: &[&str] = &[
    "/healthz",
    "/v1/daemon/identity-challenge",
    "/v1/desktop/bootstrap",
];

pub const DAEMON_MAX_GENERAL_REQUESTS: usize = 32;
pub const DAEMON_MAX_CONTROL_REQUESTS: usize = 8;
pub const DAEMON_MAX_CRITICAL_REQUESTS: usize = 8;
pub const DAEMON_MAX_CONNECTIONS: usize = 128;
/// `HOL_GUARD_DAEMON_MAX_ACTIVE_REQUESTS` default (`bounded_http`).
pub const DAEMON_MAX_ACTIVE_SLOTS: usize = 64;
/// Upper bound the environment override is clamped to.
pub const DAEMON_MAX_ACTIVE_SLOTS_CEILING: usize = 256;

/// Time a connection may spend before its request headers are complete.
pub const DAEMON_REQUEST_READ_TIMEOUT_MS: u64 = 400;
/// Accept-thread wait for a connection permit.
pub const DAEMON_CONNECTION_ADMISSION_WAIT_MS: u64 = 50;
/// Wait a control or critical request has for its capacity pool.
pub const DAEMON_CONTROL_ADMISSION_WAIT_MS: u64 = 1_000;
/// How long an unread saturation probe may wait for its request line.
pub const DAEMON_SATURATION_PROBE_WINDOW_MS: u64 = 150;
/// Watchdog tick that classifies unread and partially read connections.
pub const DAEMON_WATCHDOG_POLL_MS: u64 = 25;
/// Bytes peeked to classify a request line.
pub const DAEMON_PEEK_LINE_BYTES: usize = 4_096;
/// Bytes peeked to decide that request headers are complete.
pub const DAEMON_PEEK_HEADER_BYTES: usize = 65_536;
/// Largest request head drained before an overload reply is written.
pub const DAEMON_OVERLOAD_DRAIN_BYTES: usize = 16 * 1024;
pub const DAEMON_OVERLOAD_DRAIN_TIMEOUT_MS: u64 = 50;
pub const DAEMON_OVERLOAD_WRITE_TIMEOUT_MS: u64 = 250;

/// Capacity pool a request is charged to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DaemonRequestKind {
    Critical,
    Control,
    General,
}

impl DaemonRequestKind {
    /// Classify a request path; a query string never changes the kind.
    pub fn of_path(path: &str) -> Self {
        let path = path.split('?').next().unwrap_or(path);
        if DAEMON_CRITICAL_PATHS.contains(&path) {
            Self::Critical
        } else if DAEMON_CONTROL_PATHS.contains(&path) {
            Self::Control
        } else {
            Self::General
        }
    }

    pub fn is_priority(self) -> bool {
        self != Self::General
    }
}

/// Body of the 503 written to a request the front door refuses.
pub const DAEMON_OVERLOAD_BODY: &str = r#"{"error":"daemon_overloaded","message":"HOL Guard is busy. Retry the unchanged request shortly.","retryable":true}"#;

/// The complete overload response (`bounded_http._overload_response`).
pub fn daemon_overload_response() -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(
        b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nRetry-After: 1\r\n",
    );
    response.extend_from_slice(
        format!("Content-Length: {}\r\n\r\n", DAEMON_OVERLOAD_BODY.len()).as_bytes(),
    );
    response.extend_from_slice(DAEMON_OVERLOAD_BODY.as_bytes());
    response
}
