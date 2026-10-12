//! Request/result contract for the `GuardSupport` resident op: pure, deterministic
//! helpers that used to live in Python (`guard/config.py` settings writes and
//! `cli/commands_support_prompts.py` hook copy).
//!
//! One subop-multiplexed op keeps the resident surface small. Every subop takes
//! only the data it needs in `payload` and returns a JSON `result`.
//!
//!   * `toml_render`              - render a config table as TOML text
//!   * `coerce_setting`           - validate one editable setting
//!   * `coerce_loaded`            - coerce loaded values with fallbacks
//!   * `native_reason`            - hook reason for a runtime artifact
//!   * `claude_additional_context`, `claude_system_message`,
//!     `codex_block_message`      - harness-specific hook copy
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const GUARD_SUPPORT_FEATURE: &str = "guard-support-v1";
pub const GUARD_SUPPORT_REQUEST_SCHEMA: &str = "guard-support-request.v1";
pub const GUARD_SUPPORT_RESULT_SCHEMA: &str = "guard-support-result.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardSupportRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub subop: String,
    pub payload: Value,
    pub guard_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardSupportResultV1 {
    pub schema: String,
    pub result: Option<Value>,
}
