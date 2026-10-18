//! The resident operation that runs the hook evidence writer.
//!
//! `daemon.runtime_hook_evidence_writer.RuntimeHookEvidenceWriter` keeps one
//! long-lived writer per Guard home: a queue, a journal and a background
//! thread that drains both into the store. Python callers only ever push a
//! record onto it and occasionally read its counters, so the whole object can
//! live here and be reached over the resident protocol.
//!
//! The writer is built from the all-native seams rather than the Python ones:
//! [`NativeEvidenceStore`] for the store, [`NativeCorrelation`] for the
//! installation key, [`NativeReceiptValidation`] for receipt shape,
//! [`NativeComposio`] for provider discovery and [`NativeEvidenceJournal`] for
//! the on-disk journal. Nothing in the path recalculates a verdict; the writer
//! records what the decision path already decided.
//!
//! One writer per Guard home is a process-wide resource, so it is held in a
//! registry instead of being rebuilt per request. The registry keeps the
//! first request's `source` for that home, matching the single `GuardStore`
//! the daemon builds at startup and hands to the writer.
//!
//! The request carries the Guard home and no store path. The resident
//! validates the home like every other operation, and the store seam
//! derives its database from that home the same way the daemon does, so a
//! caller cannot point a writer at a database outside the home it named.
//!
//! `store_review_event_outbox` closes the native policy barrier after a
//! Composio discovery write. In Python that wakes the in-process snapshot
//! publishers through `notify_native_policy_mutation`, which walks a registry
//! of Python publisher objects this process cannot see. The barrier here
//! counts those mutations instead, and `stats` hands the count back so the
//! caller can wake its own publishers. Rust still owns the write; Python only
//! refreshes what it pushes.
//!
//! A fatal store failure is reported the same way. `_native_store_call`
//! quarantines and rebuilds a store a probe has proven unusable, which the
//! `GuardStore` object owns and this process has no handle on. The store seam
//! records the failure instead, `stats` and `stop` hand the code back, and the
//! caller runs `GuardStore._recover_fatal_sqlite_store` for it. Both reads
//! clear the slot, so one failure is recovered once.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use guard_command::hook_evidence_writer::{
    ComposioApi, EvidenceWriterDeps, NativeEvidenceJournal, NativeReceiptValidation,
    ReceiptValidationApi, RuntimeHookEvidenceWriter,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::hook_evidence_activity::NativeCorrelation;
use crate::hook_evidence_composio::NativeComposio;
use crate::hook_evidence_store::{NativeEvidenceStore, PolicyBarrierApi, StoreFatalSignal};
use crate::hook_evidence_store_timeout::NativeSqliteTimeout;

pub(crate) const HOOK_EVIDENCE_WRITER_REQUEST_SCHEMA: &str =
    "guard-hook-evidence-writer-request.v1";
pub(crate) const HOOK_EVIDENCE_WRITER_RESULT_SCHEMA: &str = "guard-hook-evidence-writer-result.v1";
/// The feature advertised to callers that route evidence here.
pub(crate) const HOOK_EVIDENCE_WRITER_FEATURE: &str = "hook-evidence-writer-v1";

/// `RuntimeHookEvidenceWriter.__init__` defaults (:88-92).
const MAX_RECORDS: usize = 2_000;
const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_BATCH: usize = 50;
const BATCH_WAIT_SECONDS: f64 = 0.025;
/// `submit_command_activity(approval_reuse_status=)` default (:153).
const APPROVAL_REUSE_NOT_APPLICABLE: &str = "not-applicable";

#[derive(Debug, Deserialize)]
pub(crate) struct HookEvidenceWriterRequestV1 {
    pub(crate) schema: String,
    pub(crate) request_id: String,
    pub(crate) guard_home: String,
    /// `GuardStore.guard_source` of the store the Python writer was built on.
    pub(crate) source: String,
    #[serde(flatten)]
    pub(crate) action: HookEvidenceWriterActionV1,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub(crate) enum HookEvidenceWriterActionV1 {
    /// `submit_command_activity` (:143-154).
    SubmitCommandActivity {
        harness: String,
        event: String,
        payload: Map<String, Value>,
        succeeded: bool,
        #[serde(default)]
        policy_action: Option<String>,
        #[serde(default)]
        receipt_id: Option<String>,
        #[serde(default)]
        prompted: bool,
        #[serde(default = "approval_reuse_default")]
        approval_reuse_status: String,
    },
    /// `submit_composio_discovery` (:197-203). The Python entry point reads
    /// the tool name out of the payload and refuses an unsuccessful call, so
    /// the same narrowing happens here rather than at each caller.
    SubmitComposioDiscovery {
        harness: String,
        payload: Map<String, Value>,
        succeeded: bool,
    },
    /// `submit_native_decision_receipt` (:243).
    SubmitNativeDecisionReceipt { receipt: Map<String, Value> },
    /// `stats` (:396), plus the policy mutations observed since the last read.
    Stats,
    /// `stop` (:432). The writer is dropped from the registry either way, so
    /// a later submit builds a fresh one rather than queueing onto a drained
    /// writer.
    Stop {
        #[serde(default = "stop_timeout_default")]
        timeout_seconds: f64,
    },
}

fn approval_reuse_default() -> String {
    APPROVAL_REUSE_NOT_APPLICABLE.to_owned()
}

fn stop_timeout_default() -> f64 {
    2.0
}

#[derive(Debug, Serialize)]
struct HookEvidenceWriterResultV1 {
    schema: String,
    request_id: String,
    status: String,
    code: String,
    payload: Value,
}

/// The policy barrier the store seam closes after a discovery write. It
/// records the mutation for the caller instead of reaching into the Python
/// publisher registry this process has no handle on.
struct MutationCounter(Arc<AtomicU64>);

impl PolicyBarrierApi for MutationCounter {
    fn notify_policy_mutation(&self, _guard_home: &Path) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// One Guard home's writer, the mutations its store seam has recorded, and
/// the fatal store failure it is waiting to report.
#[derive(Clone)]
struct ResidentWriter {
    writer: Arc<RuntimeHookEvidenceWriter>,
    mutations: Arc<AtomicU64>,
    fatal: StoreFatalSignal,
}

fn registry() -> &'static Mutex<HashMap<PathBuf, ResidentWriter>> {
    static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, ResidentWriter>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn build(guard_home: &Path, source: &str) -> Result<ResidentWriter, io::Error> {
    let mutations = Arc::new(AtomicU64::new(0));
    let store = NativeEvidenceStore::new(
        guard_home.to_path_buf(),
        source,
        Box::new(MutationCounter(Arc::clone(&mutations))),
    );
    let fatal = store.fatal();
    // The journal validates the records it rewrites with the same pair the
    // writer validates submissions with, so both share one instance each.
    let receipts: Arc<dyn ReceiptValidationApi + Send + Sync> = Arc::new(NativeReceiptValidation);
    let composio: Arc<dyn ComposioApi + Send + Sync> = Arc::new(NativeComposio);
    let deps = EvidenceWriterDeps {
        correlation: Box::new(NativeCorrelation::new(guard_home.to_path_buf())),
        journal: Box::new(NativeEvidenceJournal::new(
            Arc::clone(&receipts),
            Arc::clone(&composio),
        )),
        receipts,
        composio,
        sqlite_timeout: Box::new(NativeSqliteTimeout),
    };
    let writer = RuntimeHookEvidenceWriter::new(
        Arc::new(store),
        deps,
        MAX_RECORDS,
        MAX_BYTES,
        MAX_BATCH,
        BATCH_WAIT_SECONDS,
        None,
    )?;
    Ok(ResidentWriter {
        writer: Arc::new(writer),
        mutations,
        fatal,
    })
}

/// The writer for this Guard home, started on first use.
fn writer(guard_home: &Path, source: &str) -> Result<ResidentWriter, io::Error> {
    let mut registry = registry().lock().unwrap_or_else(|e| e.into_inner());
    if !registry.contains_key(guard_home) {
        registry.insert(guard_home.to_path_buf(), build(guard_home, source)?);
    }
    Ok(registry[guard_home].clone())
}

/// The writer for this Guard home only if one is already running. `stats` and
/// `stop` must not start a writer that no submission has asked for.
fn running(guard_home: &Path) -> Option<ResidentWriter> {
    let registry = registry().lock().unwrap_or_else(|e| e.into_inner());
    registry.get(guard_home).cloned()
}

fn forget(guard_home: &Path) {
    registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(guard_home);
}

fn stats_payload(resident: &ResidentWriter) -> Value {
    let stats = resident.writer.stats();
    json!({
        "queued": stats.queued,
        "queued_bytes": stats.queued_bytes,
        "accepted": stats.accepted,
        "processed": stats.processed,
        "dropped": stats.dropped,
        "failures": stats.failures,
        "recovered": stats.recovered,
        "durable_pending": stats.durable_pending,
        "degraded": stats.degraded,
        "running": stats.running,
        "receipt_accepted": stats.receipt_accepted,
        "receipt_processed": stats.receipt_processed,
        "receipt_deduped": stats.receipt_deduped,
        "receipt_dropped": stats.receipt_dropped,
        "receipt_failures": stats.receipt_failures,
        "receipt_durable_pending": stats.receipt_durable_pending,
        // Read-and-clear: the caller that reads a mutation owns waking its
        // own publishers for it, and a second reader must not repeat the wake.
        "policy_mutations": resident.mutations.swap(0, Ordering::SeqCst),
        // Read-and-clear for the same reason: the caller that reads a fatal
        // store failure owns recovering from it, and recovery runs once.
        "store_fatal": resident.fatal.take(),
    })
}

/// A writer that was never started has nothing queued and is not running.
fn idle_stats() -> Value {
    json!({
        "queued": 0,
        "queued_bytes": 0,
        "accepted": 0,
        "processed": 0,
        "dropped": 0,
        "failures": 0,
        "recovered": 0,
        "durable_pending": 0,
        "degraded": false,
        "running": false,
        "receipt_accepted": 0,
        "receipt_processed": 0,
        "receipt_deduped": 0,
        "receipt_dropped": 0,
        "receipt_failures": 0,
        "receipt_durable_pending": 0,
        "policy_mutations": 0,
        "store_fatal": Value::Null,
    })
}

pub(crate) fn evaluate_hook_evidence_writer_request(
    request: &HookEvidenceWriterRequestV1,
) -> Result<Vec<u8>, String> {
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), payload),
        Err(error) => (
            "error".to_owned(),
            error.0.to_owned(),
            json!({ "message": error.1 }),
        ),
    };
    crate::encode_response(&HookEvidenceWriterResultV1 {
        schema: HOOK_EVIDENCE_WRITER_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        status,
        code,
        payload,
    })
}

/// `(code, message)` — the shape the result carries for a refused request.
struct WriterError(&'static str, String);

fn evaluate(request: &HookEvidenceWriterRequestV1) -> Result<Value, WriterError> {
    if request.schema != HOOK_EVIDENCE_WRITER_REQUEST_SCHEMA {
        return Err(WriterError(
            "invalid_schema",
            format!("unsupported schema: {}", request.schema),
        ));
    }
    if request.guard_home.is_empty() {
        return Err(WriterError(
            "invalid_guard_home",
            "guard home is required".to_owned(),
        ));
    }
    let guard_home = PathBuf::from(&request.guard_home);
    let started = |error: io::Error| WriterError("writer_unavailable", error.to_string());
    match &request.action {
        HookEvidenceWriterActionV1::SubmitCommandActivity {
            harness,
            event,
            payload,
            succeeded,
            policy_action,
            receipt_id,
            prompted,
            approval_reuse_status,
        } => {
            let writer = writer(&guard_home, &request.source)
                .map_err(started)?
                .writer;
            let queued = writer.submit_command_activity(
                harness,
                event,
                payload,
                *succeeded,
                policy_action.as_deref(),
                receipt_id.as_deref(),
                *prompted,
                approval_reuse_status,
            );
            Ok(json!({ "queued": queued }))
        }
        HookEvidenceWriterActionV1::SubmitComposioDiscovery {
            harness,
            payload,
            succeeded,
        } => {
            let Some(tool_name) = payload.get("tool_name").and_then(Value::as_str) else {
                return Ok(json!({ "queued": false }));
            };
            if !succeeded {
                return Ok(json!({ "queued": false }));
            }
            let writer = writer(&guard_home, &request.source)
                .map_err(started)?
                .writer;
            let queued = writer.submit_composio_discovery(harness, tool_name, payload);
            Ok(json!({ "queued": queued }))
        }
        HookEvidenceWriterActionV1::SubmitNativeDecisionReceipt { receipt } => {
            let writer = writer(&guard_home, &request.source)
                .map_err(started)?
                .writer;
            Ok(json!({ "queued": writer.submit_native_decision_receipt(receipt) }))
        }
        HookEvidenceWriterActionV1::Stats => Ok(match running(&guard_home) {
            Some(resident) => stats_payload(&resident),
            None => idle_stats(),
        }),
        HookEvidenceWriterActionV1::Stop { timeout_seconds } => {
            let Some(resident) = running(&guard_home) else {
                return Ok(json!({
                    "drained": true,
                    "policy_mutations": 0,
                    "store_fatal": Value::Null,
                }));
            };
            // Drop the registry entry first: a submission racing this stop
            // then builds its own writer rather than queueing onto one that
            // is draining and will never run its thread again.
            forget(&guard_home);
            let drained = resident.writer.stop(*timeout_seconds);
            Ok(json!({
                "drained": drained,
                "policy_mutations": resident.mutations.swap(0, Ordering::SeqCst),
                "store_fatal": resident.fatal.take(),
            }))
        }
    }
}

#[cfg(test)]
#[path = "hook_evidence_writer_op_tests.rs"]
mod tests;
