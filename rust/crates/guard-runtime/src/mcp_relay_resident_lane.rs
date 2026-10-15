//! The relay's direct-lane probe and the one retry a deferred call gets.
//!
//! The probe asks the resident's `mcp_relay_ready` whether the lane is bound
//! for the session's workspace and harness. A call the lane deferred for a
//! reason the daemon can clear asks the daemon to prepare the workspace once,
//! within the retry budget, and is decided once more; a deferral that remains
//! is refused as before. A deferred decision queues nothing, so the retry
//! never records a call twice.
//!
//! A session that started before its lane was ready stays native, and its
//! first call waits for the lane before it is decided: the probe repeats
//! until the lane is ready, the lane names a reason no wait clears, or the
//! warm-up budget is spent, asking the daemon again whenever the kick
//! interval allows. The call is then decided once, as any other.
//!
//! The resident knows a server only from a report of its whole catalog
//! (`mcp_relay_servers.rs`), so the relay reports the catalog it relays, as
//! the proxy does. The server's later sessions then start on the lane, or
//! under the proxy when the catalog offers a tool the proxy decides. Only
//! the session's own listing can report an unknown server, so its first call
//! never waits for one.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{defer, RelayFacts, ResidentRelayAuthority};
use crate::claude_hook_bridge_http::remaining;
use crate::mcp_relay_lane::{kickable, unported, Kick, LaneKick, RETRY_BUDGET, WARM_UP_BUDGET};
use crate::mcp_relay_ready::MCP_RELAY_READY_SCHEMA;
use crate::mcp_relay_servers::SERVER_UNKNOWN;

/// The pause between probes while the first call waits for the lane.
const WARM_UP_POLL: Duration = Duration::from_millis(100);
/// How long the relay waits for the resident to take a catalog report.
const REPORT_TIMEOUT: Duration = Duration::from_millis(500);

impl ResidentRelayAuthority {
    /// Ask the daemon to prepare the lane for a deferred call.
    pub(crate) fn with_kick(mut self, kick: Box<dyn LaneKick>) -> Self {
        self.kick = Some(kick);
        self
    }

    /// Whether the first call waits for a lane that was not ready at startup.
    pub(crate) fn warming(mut self, warming: bool) -> Self {
        self.warming = warming;
        self
    }

    /// Before the session's first call only: wait for the lane the startup
    /// gate found not ready.
    pub(super) fn warm_up(&mut self) {
        self.warm_up_within(WARM_UP_BUDGET);
    }

    fn warm_up_within(&mut self, budget: Duration) {
        if !std::mem::take(&mut self.warming) {
            return;
        }
        let deadline = Instant::now() + budget;
        loop {
            let probe = (Instant::now() + RETRY_BUDGET).min(deadline);
            match self.lane_ready(probe) {
                Ok(()) => return,
                Err(code) if unported(&code) || code == SERVER_UNKNOWN => return,
                Err(_) => {}
            }
            if let Some(kick) = self.kick.as_mut() {
                // The kick rate-limits itself, so this asks the daemon at
                // most once per kick interval.
                let _ = kick.kick((Instant::now() + RETRY_BUDGET).min(deadline));
            }
            let left = remaining(deadline);
            if left.is_zero() {
                return;
            }
            std::thread::sleep(left.min(WARM_UP_POLL));
        }
    }

    /// The workspace the session's decisions are admitted under.
    pub(crate) fn lane_workspace(&self) -> Option<&str> {
        let facts = self.facts.as_ref()?;
        Some(facts.workspace.as_deref().unwrap_or(&facts.hash_workspace))
    }

    /// `Ok` when the resident's lane is ready for this session, else the
    /// lane's defer code or the reason the resident did not answer.
    pub(crate) fn lane_ready(&mut self, deadline: Instant) -> Result<(), String> {
        let Some(facts) = self.facts.as_ref() else {
            return Err(defer::FACTS_UNAVAILABLE.to_owned());
        };
        let payload = json!({
            "operation": "mcp_relay_ready",
            "request": {
                "guard_home": facts.guard_home,
                "workspace": facts.workspace.as_deref().unwrap_or(&facts.hash_workspace),
                "harness": facts.harness,
                "server": server(facts),
            },
        });
        let guard_home = PathBuf::from(&facts.guard_home);
        let payload =
            serde_json::to_vec(&payload).map_err(|_| defer::REQUEST_UNSENDABLE.to_owned())?;
        let output = self
            .exchange_until(&guard_home, &payload, deadline)
            .ok_or_else(|| defer::RESIDENT_UNREACHABLE.to_owned())?;
        ready_answer(&output)
    }

    /// `_report_relay_server`: report the session server's whole catalog.
    /// Best effort: a report the resident never took leaves the server
    /// unknown, and its later sessions start native again.
    pub(super) fn report_server(&mut self, tools: &[Value]) {
        let Some(facts) = self.facts.as_ref() else {
            return;
        };
        let payload = json!({
            "operation": "mcp_relay_server_report",
            "request": {
                "guard_home": facts.guard_home,
                "server": server(facts),
                "tools": tools,
            },
        });
        let guard_home = PathBuf::from(&facts.guard_home);
        let Ok(payload) = serde_json::to_vec(&payload) else {
            return;
        };
        let _ = self.exchange_until(&guard_home, &payload, Instant::now() + REPORT_TIMEOUT);
    }

    /// Whether a call deferred with `output` gets its one retry: the lane
    /// deferred it for a reason the daemon can clear, and the daemon took
    /// the request to prepare the workspace.
    pub(super) fn rekick(&mut self, output: Option<&[u8]>) -> bool {
        let Some(code) = output.and_then(defer::defer_code) else {
            return false;
        };
        let Some(kick) = self.kick.as_mut() else {
            return false;
        };
        kickable(&code) && kick.kick(Instant::now() + RETRY_BUDGET) == Kick::Requested
    }
}

/// The session's server, as the resident's registry names it.
fn server(facts: &RelayFacts) -> Value {
    json!({
        "harness": facts.harness,
        "server_name": facts.server_name,
        "source_scope": facts.source_scope,
        "config_path": facts.config_path,
        "server_id": facts.server_id,
        "identity_hash": facts.server_identity.get("identity_hash"),
    })
}

/// The resident's readiness answer.
pub(super) fn ready_answer(output: &[u8]) -> Result<(), String> {
    let invalid = || defer::REPLY_INVALID.to_owned();
    let answer: Value = serde_json::from_slice(output).map_err(|_| invalid())?;
    if answer.get("schema").and_then(Value::as_str) != Some(MCP_RELAY_READY_SCHEMA) {
        return Err(invalid());
    }
    match answer.get("ready").and_then(Value::as_bool) {
        Some(true) => Ok(()),
        Some(false) => Err(answer
            .get("reason")
            .and_then(Value::as_str)
            .filter(|reason| defer::is_code(reason))
            .map_or_else(invalid, str::to_owned)),
        None => Err(invalid()),
    }
}

#[cfg(test)]
#[path = "mcp_relay_resident_lane_tests.rs"]
mod tests;
