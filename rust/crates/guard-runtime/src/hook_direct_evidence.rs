//! Evidence for hooks the resident answers directly.
//!
//! After a `PreToolUse` allow the daemon records the decision receipt and the
//! command activity, and observes the command line. A direct answer skips the
//! daemon, so the resident keeps those inputs here until the daemon drains
//! them over the resident channel and records them through its own writer.
//!
//! The queue lives in memory only, so raw tool input never reaches disk
//! outside the daemon's evidence writer. A record that does not fit makes the
//! hook take the daemon path rather than answer without its evidence.

use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::Mutex;

pub(crate) const HOOK_DIRECT_EVIDENCE_FEATURE: &str = "hook-direct-evidence-v1";
const DRAIN_RESULT_SCHEMA: &str = "guard-hook-direct-evidence.v1";
const MAX_QUEUED_RECORDS: usize = 1_024;
const MAX_QUEUED_BYTES: usize = 8 * 1024 * 1024;
/// One drain page stays well under the resident response cap.
const MAX_DRAIN_BYTES: usize = 1536 * 1024;
const MAX_RECORD_BYTES: usize = 1024 * 1024;
const DEFAULT_DRAIN_RECORDS: usize = 256;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookDirectEvidenceDrainRequestV1 {
    pub(crate) guard_home: String,
    #[serde(default)]
    pub(crate) max_records: Option<usize>,
}

struct QueuedRecord {
    bytes: usize,
    record: Value,
}

#[derive(Default)]
struct QueueState {
    records: VecDeque<QueuedRecord>,
    bytes: usize,
}

#[derive(Default)]
pub(crate) struct DirectEvidenceQueue {
    state: Mutex<QueueState>,
}

impl DirectEvidenceQueue {
    /// Queue one record, or refuse it when the queue cannot hold it.
    pub(crate) fn offer(&self, record: Value) -> bool {
        let Ok(encoded) = serde_json::to_vec(&record) else {
            return false;
        };
        let bytes = encoded.len();
        if bytes > MAX_RECORD_BYTES {
            return false;
        }
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.records.len() >= MAX_QUEUED_RECORDS || state.bytes + bytes > MAX_QUEUED_BYTES {
            return false;
        }
        state.bytes += bytes;
        state.records.push_back(QueuedRecord { bytes, record });
        true
    }

    /// Remove and return the oldest records that fit one response.
    fn take(&self, max_records: usize) -> (Vec<Value>, usize) {
        let Ok(mut state) = self.state.lock() else {
            return (Vec::new(), 0);
        };
        let mut taken = Vec::new();
        let mut page_bytes = 0;
        while taken.len() < max_records {
            let Some(next) = state.records.front() else {
                break;
            };
            if !taken.is_empty() && page_bytes + next.bytes > MAX_DRAIN_BYTES {
                break;
            }
            let Some(next) = state.records.pop_front() else {
                break;
            };
            state.bytes -= next.bytes;
            page_bytes += next.bytes;
            taken.push(next.record);
        }
        (taken, state.records.len())
    }
}

pub(crate) fn drain(
    request: &HookDirectEvidenceDrainRequestV1,
    queue: &DirectEvidenceQueue,
) -> Result<Vec<u8>, String> {
    let max_records = request
        .max_records
        .unwrap_or(DEFAULT_DRAIN_RECORDS)
        .clamp(1, DEFAULT_DRAIN_RECORDS);
    let (records, remaining) = queue.take(max_records);
    serde_json::to_vec(&json!({
        "schema": DRAIN_RESULT_SCHEMA,
        "records": records,
        "remaining": remaining,
    }))
    .map_err(|_| "direct_hook_evidence_encoding_failed".to_owned())
}

#[cfg(test)]
#[path = "hook_direct_evidence_tests.rs"]
mod tests;
