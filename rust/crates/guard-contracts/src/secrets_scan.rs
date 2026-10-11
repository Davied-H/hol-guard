//! `SecretsScan` — wire contract for the resident op that owns the
//! `hol-guard-secrets` command surface: the repository, history and staged
//! secret scans, the pre-commit hook install/uninstall and the public detector
//! rule catalog.
//!
//! Python parses the command line, absolutizes the target and renders text;
//! it never detects, reads repository content or edits hooks itself. A
//! resident that cannot answer fails the command closed.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const SECRETS_SCAN_REQUEST_SCHEMA: &str = "guard-secrets-scan-request.v1";
/// Schema discriminator for the result.
pub const SECRETS_SCAN_RESULT_SCHEMA: &str = "guard-secrets-scan-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const SECRETS_SCAN_FEATURE: &str = "secrets-scan-v1";

/// Largest canonical request serialization the op will accept.
pub const SECRETS_SCAN_MAX_BYTES: usize = 64 * 1024;

/// `Option` field that must be present (possibly `null`) on the wire.
fn required<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Bounds for a scan. Every field is required so the canonical request digest
/// Python binds results to is exactly the request Rust parsed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretsScanBoundsV1 {
    pub include_history: bool,
    pub max_commits: u64,
    pub max_files: u64,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_findings: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretsScanRequestV1 {
    pub schema: String,
    /// Caller correlation id; echoed back in the result.
    pub request_id: String,
    /// Resolved guard home the request is scoped to.
    pub guard_home: String,
    /// `scan`, `staged`, `install_hook`, `uninstall_hook` or `rules`.
    pub action: String,
    /// Absolute scan or hook target; empty for `rules`.
    pub target: String,
    /// `scan` and `staged` only; `null` for every other action.
    #[serde(deserialize_with = "required")]
    pub bounds: Option<SecretsScanBoundsV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SecretsScanResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, `secrets_scan_refused` (a user-facing refusal carried in
    /// `message`) or one of the `native_secrets_scan_*` failure codes.
    pub code: String,
    /// `scan`/`staged`: the public scan result. `install_hook`/
    /// `uninstall_hook`: the public hook result. `rules`: `{json, text}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    /// The refusal text for `secrets_scan_refused`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
