//! Forward evidence the resident holds until the relay completes the forward.
//!
//! The Python proxy records a forwarded `tools/call` only after the child
//! answered it. A call it decided to forward but then did not (the catalog
//! changed before the write) leaves no allow receipt. The resident therefore
//! holds a forward's evidence under a ticket, and the relay commits that
//! ticket once the child responded. Only a committed record reaches the
//! daemon's drain; a ticket the relay never commits (a boundary change, a
//! decision answer that never arrived, a relay that exited) expires here.
//!
//! A ticket names this resident's epoch, so a commit sent to a restarted
//! resident releases nothing, and each ticket releases its record once.
//!
//! Two gaps remain against the proxy. At a catalog boundary change the proxy
//! re-resolves the call and records a fresh block or approval receipt, while
//! the relay records nothing for it. A resident restart between the decision
//! and the commit drops the held record.

use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::hook_direct_evidence::{DirectEvidenceQueue, MAX_RECORD_BYTES};

const COMMIT_RESULT_SCHEMA: &str = "guard-mcp-relay-commit-result.v1";
/// Forwards awaiting their commit; a decision without a free slot defers.
const MAX_HELD_RECORDS: usize = 256;
/// A forwarded tool may run long; its evidence waits this long for the commit.
const HOLD_TTL: Duration = Duration::from_secs(3_600);

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct McpRelayCommitRequestV1 {
    pub(crate) guard_home: String,
    pub(crate) ticket: String,
}

struct Held {
    seq: u64,
    held_at: Instant,
    record: Value,
}

struct HeldState {
    next_seq: u64,
    records: VecDeque<Held>,
}

pub(crate) struct PendingRelayEvidence {
    epoch: String,
    state: Mutex<HeldState>,
}

impl Default for PendingRelayEvidence {
    fn default() -> Self {
        static HOLDS: AtomicU64 = AtomicU64::new(0);
        let started = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        Self {
            epoch: format!(
                "{:x}-{started:x}-{:x}",
                std::process::id(),
                HOLDS.fetch_add(1, Ordering::Relaxed)
            ),
            state: Mutex::new(HeldState {
                next_seq: 1,
                records: VecDeque::new(),
            }),
        }
    }
}

impl PendingRelayEvidence {
    /// Hold one forward's record; `None` when it cannot be held.
    pub(crate) fn hold(&self, record: Value, now: Instant) -> Option<String> {
        let bytes = serde_json::to_vec(&record).ok()?.len();
        if bytes > MAX_RECORD_BYTES {
            return None;
        }
        let mut state = self.state.lock().ok()?;
        state
            .records
            .retain(|held| now.saturating_duration_since(held.held_at) < HOLD_TTL);
        if state.records.len() >= MAX_HELD_RECORDS {
            return None;
        }
        let seq = state.next_seq;
        state.next_seq = state.next_seq.saturating_add(1);
        state.records.push_back(Held {
            seq,
            held_at: now,
            record,
        });
        Some(format!("{}:{seq}", self.epoch))
    }

    /// The record a ticket of this epoch holds, released once.
    pub(crate) fn release(&self, ticket: &str) -> Option<Value> {
        let seq = ticket
            .strip_prefix(self.epoch.as_str())?
            .strip_prefix(':')?
            .parse::<u64>()
            .ok()?;
        let mut state = self.state.lock().ok()?;
        let index = state.records.iter().position(|held| held.seq == seq)?;
        state.records.remove(index).map(|held| held.record)
    }
}

/// Queue a completed forward's evidence for the daemon's drain.
pub(crate) fn commit(
    request: &McpRelayCommitRequestV1,
    pending: &PendingRelayEvidence,
    queue: &DirectEvidenceQueue,
) -> Result<Vec<u8>, String> {
    let committed = pending
        .release(&request.ticket)
        .is_some_and(|record| queue.offer(record));
    serde_json::to_vec(&json!({"schema": COMMIT_RESULT_SCHEMA, "committed": committed}))
        .map_err(|_| "mcp_relay_commit_result_encoding_failed".to_owned())
}

#[cfg(test)]
#[path = "mcp_relay_pending_tests.rs"]
mod tests;
