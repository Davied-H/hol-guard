//! The client modes of the Python Codex bridge, served natively.
//!
//! - Codex Desktop (`HOL_GUARD_DESKTOP=1`) forwards hooks exactly as the
//!   terminal client does; only its daemon-start environment differs, and
//!   `hook_bridge_daemon_start` keeps the signed proxy selectors for it. The
//!   one Desktop hook left to Python is a transition probe, which Python
//!   answers by running the signed Desktop proxy's `guard hook` rather than
//!   asking the daemon.
//! - An opt-in binding capture records the hook's raw and forwarded
//!   fingerprints as `record_bridge_ingress` does, in process: capture is
//!   diagnostics only and never changes how the hook is settled.
//! - A query the request line cannot carry never reaches the daemon, so the
//!   hook fails closed, as every hook without a daemon answer does.

use super::Prepared;
use crate::codex_hook_response::PRE_TOOL_USE;
use crate::pyjson::{self, PyVal};

#[cfg(unix)]
const CAPTURE_MARKER: [&str; 2] = ["diagnostics", "codex-binding-capture.v2.json"];
const PROBE_FIELD: &str = "guard_transition_probe";

/// The query goes into the request line verbatim; `http.client` refuses
/// controls, spaces and non-ASCII, so Python never reaches the daemon.
pub(super) fn query_is_sendable(query: &str) -> bool {
    query.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

/// The hooks `_desktop_transition_probe_command` may answer through the
/// signed Desktop proxy instead of the daemon. Python runs the probe only
/// from a frozen macOS bundle, applies its remaining checks (frozen bundle,
/// valid probe) itself and asks the daemon when they fail.
pub(super) fn desktop_transition_probe(data: &str) -> bool {
    cfg!(target_os = "macos")
        && std::env::var_os("HOL_GUARD_DESKTOP").is_some_and(|value| value == "1")
        && carries_transition_probe(data)
}

/// A `PreToolUse` hook, by its literal `hook_event_name`, that names a
/// transition probe: the hooks Python checks for one.
pub(super) fn carries_transition_probe(data: &str) -> bool {
    pyjson::parse_mapping_lone_surrogates(data).is_ok_and(|parsed| {
        matches!(parsed.value.get("hook_event_name"), Some(PyVal::Str(name)) if name == PRE_TOOL_USE)
            && parsed.value.get(PROBE_FIELD).is_some()
    })
}

/// `record_bridge_ingress` for the hook as it is forwarded, when the private
/// capture marker exists. Best effort: a capture that fails is not recorded
/// and the hook is settled the same way.
#[cfg(unix)]
pub(super) fn record_ingress(state_path: &str, raw_data: &str, prepared: &Prepared) {
    let Some(home) = super::guard_home(state_path) else {
        return;
    };
    let marker = home.join(CAPTURE_MARKER[0]).join(CAPTURE_MARKER[1]);
    if std::fs::symlink_metadata(marker).is_err() {
        return;
    }
    let _ = crate::binding_capture_capture::record_bridge_ingress(
        &home,
        raw_data,
        Some(&prepared.data),
        &prepared.event_name,
        "codex",
        crate::binding_capture_op::now_seconds(),
    );
}

/// Python never captures on Windows.
#[cfg(not(unix))]
pub(super) fn record_ingress(_state_path: &str, _raw_data: &str, _prepared: &Prepared) {}
