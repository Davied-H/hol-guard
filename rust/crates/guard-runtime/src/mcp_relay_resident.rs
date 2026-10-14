//! The native MCP relay's `tools/call` authority: one resident round trip.
//!
//! Each call is sent to the live resident that runs this executable as one
//! `mcp_relay_decide` request, which builds the identity, evaluates the tool
//! policy, routes the call and queues the evidence the proxy would record.
//! A forward's evidence is held under a ticket, and the relay commits it with
//! `mcp_relay_commit` once the child answered, as the proxy records a forward
//! only after the child's response. A forward the relay drops at the catalog
//! boundary, and one whose decision answer never arrived, is never committed.
//! The facts the proxy fixes for a session (the launch fingerprint, the
//! server identity, the workspace the approval hash binds and the launcher
//! paths) are computed once, so no call hashes the executable again.
//!
//! The relay answers only what the resident decided. A call it cannot send
//! as the proxy would see it (a shell or package request, a Composio action,
//! arguments whose key order or numbers the decoded map lost), a resident
//! that cannot be reached, and every deferred decision get the proxy's
//! fail-closed "no native decision" response.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::claude_hook_bridge_http::remaining;
use crate::mcp_relay_args::RelayArgs;
use crate::mcp_relay_authority::{
    blocked_response, no_decision_response, tool_name, ForwardTicket, RelayAuthority,
    ToolCallVerdict,
};
use crate::mcp_relay_catalog::RelayCatalog;
use crate::mcp_relay_launch::Launch;
use crate::resident_state::ResidentState;

const STATE_DIRECTORY: &str = "native-runtime";
const RESULT_SCHEMA: &str = "guard-mcp-relay-decide-result.v1";
const DECIDE_TIMEOUT: Duration = Duration::from_millis(1_000);
const COMMIT_TIMEOUT: Duration = Duration::from_millis(250);
const MINIMUM_TIMEOUT: Duration = Duration::from_millis(50);
/// The session facts every decision request carries.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RelayFacts {
    guard_home: String,
    workspace: Option<String>,
    hash_workspace: String,
    harness: String,
    server_name: String,
    source_scope: String,
    config_path: String,
    transport: String,
    server_id: Option<String>,
    fingerprint: Map<String, Value>,
    server_identity: Value,
    launcher_path: Option<String>,
    launcher_home: String,
}

/// The process facts the proxy reads from its own environment.
pub(crate) struct ProcessFacts {
    pub(crate) path: Option<OsString>,
    pub(crate) home: Option<OsString>,
    pub(crate) cwd: Option<PathBuf>,
}

impl ProcessFacts {
    pub(crate) fn current() -> Self {
        Self {
            path: std::env::var_os("PATH"),
            home: std::env::var_os("HOME"),
            cwd: std::env::current_dir().ok(),
        }
    }
}

/// A resident this relay reached, kept for the next call.
struct Resident {
    state: ResidentState,
    token: Vec<u8>,
}

/// The decision authority the relay ships with.
pub(crate) struct ResidentRelayAuthority {
    facts: Option<RelayFacts>,
    resident: Option<Resident>,
    /// The ticket of the forward in flight, committed once the child answers.
    uncommitted: Option<String>,
}

impl ResidentRelayAuthority {
    /// Without session facts every call is answered "no native decision".
    pub(crate) fn new(args: &RelayArgs, launch: &Launch, process: &ProcessFacts) -> Self {
        Self {
            facts: relay_facts(args, launch, process),
            resident: None,
            uncommitted: None,
        }
    }

    /// Queue a completed forward's evidence; a lost commit records nothing.
    fn commit(&self, ticket: &str) {
        let (Some(facts), Some(resident)) = (self.facts.as_ref(), self.resident.as_ref()) else {
            return;
        };
        let payload = json!({
            "operation": "mcp_relay_commit",
            "request": {"guard_home": facts.guard_home, "ticket": ticket},
        });
        if let Ok(payload) = serde_json::to_vec(&payload) {
            // Only the resident that issued the ticket holds its record.
            let _ = send(resident, &payload, Instant::now() + COMMIT_TIMEOUT);
        }
    }

    fn exchange(&mut self, guard_home: &Path, payload: &[u8]) -> Option<Vec<u8>> {
        let deadline = Instant::now() + DECIDE_TIMEOUT;
        let state_base = guard_home.join(STATE_DIRECTORY);
        let previous = match self.resident.take() {
            Some(resident) => match send(&resident, payload, deadline) {
                Ok(output) => {
                    self.resident = Some(resident);
                    return Some(output);
                }
                Err(retryable) => Some((resident.state, retryable)),
            },
            None => None,
        };
        let fresh = discover(&state_base)?;
        // A resident that may have seen the request is never asked again: a
        // retry goes only to a restarted resident or follows a teardown
        // before authentication.
        if let Some((state, retryable)) = previous {
            let same = state.process_id == fresh.state.process_id
                && state.process_start_marker == fresh.state.process_start_marker;
            if same && !retryable {
                self.resident = Some(fresh);
                return None;
            }
        }
        let output = send(&fresh, payload, deadline).ok()?;
        self.resident = Some(fresh);
        Some(output)
    }
}

impl RelayAuthority for ResidentRelayAuthority {
    fn decide(
        &mut self,
        message: &Value,
        params: &Map<String, Value>,
        order: Option<&[String]>,
        catalog: &RelayCatalog,
    ) -> ToolCallVerdict {
        self.uncommitted = None;
        let id = message.get("id");
        let no_decision = || ToolCallVerdict::Respond(no_decision_response(id, params));
        let Some(facts) = self.facts.as_ref() else {
            return no_decision();
        };
        let Some((payload, expected)) = decide_request(facts, params, order, catalog) else {
            return no_decision();
        };
        let guard_home = PathBuf::from(&facts.guard_home);
        match self
            .exchange(&guard_home, &payload)
            .as_deref()
            .and_then(reply)
        {
            Some(Reply::Forward { ticket }) => {
                self.uncommitted = Some(ticket);
                ToolCallVerdict::Forward(ForwardTicket {
                    message: message.clone(),
                    expected,
                })
            }
            Some(Reply::Block { message, data }) => ToolCallVerdict::Respond(blocked_response(
                id,
                &tool_name(params),
                Some(&message),
                Some(data),
            )),
            None => no_decision(),
        }
    }

    fn boundary_changed(&mut self, ticket: ForwardTicket) -> Value {
        // The call was never written, so its evidence is never committed.
        self.uncommitted = None;
        let params = ticket
            .message
            .get("params")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        no_decision_response(ticket.message.get("id"), &params)
    }

    fn complete(&mut self, _ticket: ForwardTicket, response: Value) -> Value {
        if let Some(ticket) = self.uncommitted.take() {
            self.commit(&ticket);
        }
        response
    }
}

/// What the resident decided.
#[derive(Debug, Clone, PartialEq)]
enum Reply {
    Forward { ticket: String },
    Block { message: String, data: Value },
}

fn reply(output: &[u8]) -> Option<Reply> {
    let result: Value = serde_json::from_slice(output).ok()?;
    if result.get("schema")?.as_str()? != RESULT_SCHEMA {
        return None;
    }
    match result.get("outcome")?.as_str()? {
        "forward" => Some(Reply::Forward {
            ticket: result
                .get("ticket")?
                .as_str()
                .filter(|ticket| !ticket.is_empty())?
                .to_owned(),
        }),
        "block" => Some(Reply::Block {
            message: result.get("message")?.as_str()?.to_owned(),
            data: result.get("data").filter(|data| data.is_object())?.clone(),
        }),
        _ => None,
    }
}

/// The first live resident of this executable, with its token.
fn discover(state_base: &Path) -> Option<Resident> {
    // Discovery checks the directory's privacy; it must already exist.
    if !std::fs::symlink_metadata(state_base).is_ok_and(|metadata| metadata.is_dir()) {
        return None;
    }
    let states = crate::resident_state::discover_same_executable_states(state_base).ok()?;
    states.into_iter().find_map(|(_scope, _digest, state)| {
        crate::resident_state::validate_same_executable_process_identity(
            state.process_id,
            &state.process_start_marker,
        )
        .ok()?;
        let token = crate::resident_state::token_from_state(&state).ok()?;
        Some(Resident { state, token })
    })
}

/// Send once; `Err(true)` when the connection was torn down before the
/// resident could read the request.
fn send(resident: &Resident, payload: &[u8], deadline: Instant) -> Result<Vec<u8>, bool> {
    let timeout = remaining(deadline);
    if timeout < MINIMUM_TIMEOUT {
        return Err(false);
    }
    let identity = crate::resident_client::ExpectedProcessIdentity {
        process_id: resident.state.process_id,
        start_marker: &resident.state.process_start_marker,
        digest: None,
    };
    crate::resident_client::send_request_for_digest_detailed(
        &resident.state.transport,
        &resident.state.endpoint,
        &resident.token,
        payload,
        timeout,
        &identity,
    )
    .map_err(|error| error.retryable_teardown)
}

#[path = "mcp_relay_resident_request.rs"]
mod request;
use request::{decide_request, relay_facts};

#[cfg(test)]
#[path = "mcp_relay_resident_tests.rs"]
mod tests;
