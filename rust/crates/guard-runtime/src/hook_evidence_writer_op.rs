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
struct ResidentWriter {
    writer: Arc<RuntimeHookEvidenceWriter>,
    mutations: Arc<AtomicU64>,
    fatal: StoreFatalSignal,
}

/// One Guard home's writer slot. Holding the slot's lock serializes every
/// request for that home: a submission cannot queue onto a writer a stop has
/// already begun draining, and a stop cannot drop a writer a later submission
/// built. Both matter because the writers for one home share one journal file.
struct HomeSlot {
    writer: Mutex<Option<ResidentWriter>>,
}

fn registry() -> &'static Mutex<HashMap<PathBuf, Arc<HomeSlot>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, Arc<HomeSlot>>>> = OnceLock::new();
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

/// The path the registry keys a home's writer by. Two spellings of one home
/// must not receive two writers: they share one `runtime-hook-evidence.jsonl`,
/// and each would recover and replay the records the other still has pending.
/// Authorization compares canonical homes without rewriting the request, so
/// the canonical form is taken here. A home that cannot be resolved keeps the
/// path it was given, which is the path the writer would have used anyway.
fn canonical_home(given: &str) -> PathBuf {
    let path = PathBuf::from(given);
    std::fs::canonicalize(&path).unwrap_or(path)
}

/// This Guard home's slot. Slots are never removed: an empty slot costs a
/// pointer, and keeping it is what lets a stop and a racing submission agree
/// on which writer they are talking about.
fn slot(guard_home: &Path) -> Arc<HomeSlot> {
    let mut registry = registry().lock().unwrap_or_else(|e| e.into_inner());
    Arc::clone(registry.entry(guard_home.to_path_buf()).or_insert_with(|| {
        Arc::new(HomeSlot {
            writer: Mutex::new(None),
        })
    }))
}

/// Run `act` against this Guard home's writer, started on first use.
fn with_writer<T>(
    guard_home: &Path,
    source: &str,
    act: impl FnOnce(&ResidentWriter) -> T,
) -> Result<T, io::Error> {
    let slot = slot(guard_home);
    let mut held = slot.writer.lock().unwrap_or_else(|e| e.into_inner());
    // A stop that ran out of drain budget leaves its writer here: its worker
    // still owned the journal, so only once that worker is gone may a fresh
    // writer take the ownership over and replay what it left pending.
    if held
        .as_ref()
        .is_some_and(|resident| resident.writer.has_exited())
    {
        *held = None;
    }
    if held.is_none() {
        *held = Some(build(guard_home, source)?);
    }
    Ok(act(held.as_ref().expect("the writer was just built")))
}

/// Run `act` against this Guard home's writer only if one is already running.
/// `stats` must not start a writer that no submission has asked for.
fn with_running<T>(guard_home: &Path, act: impl FnOnce(&ResidentWriter) -> T) -> Option<T> {
    let slot = slot(guard_home);
    let held = slot.writer.lock().unwrap_or_else(|e| e.into_inner());
    held.as_ref().map(act)
}

/// The widest drain a caller may ask for. `timeout_seconds` arrives as an
/// unvalidated JSON number, and the duration a drain deadline is built from
/// panics on a value a `Duration` cannot hold.
const MAX_STOP_TIMEOUT_SECONDS: f64 = 60.0;

fn stop_timeout(value: f64) -> f64 {
    if value.is_nan() {
        return stop_timeout_default();
    }
    value.clamp(0.0, MAX_STOP_TIMEOUT_SECONDS)
}

/// The two signals the resident hands back with every reply, read and cleared
/// together. The caller that reads a mutation owns waking its own publishers
/// for it and the caller that reads a fatal store failure owns recovering from
/// it, so neither may be reported to a second reader. They ride every reply
/// rather than only the counters: a one-shot hook submits and exits without
/// ever reading stats, and a signal only a dashboard collects is a snapshot
/// left stale and a store left unrepaired.
fn signals(resident: &ResidentWriter) -> (u64, Value) {
    (
        resident.mutations.swap(0, Ordering::SeqCst),
        resident.fatal.take(),
    )
}

/// The writer's counters, without the signals. A stop reports these too: the
/// drain it runs is where a store failure shows up, and after it the writer is
/// gone, so counters read later would describe a writer that never ran.
fn counters(resident: &ResidentWriter) -> Value {
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
        "started": true,
    })
}

fn stats_payload(resident: &ResidentWriter) -> Value {
    let mut payload = counters(resident);
    let (mutations, fatal) = signals(resident);
    if let Some(object) = payload.as_object_mut() {
        let _ = object.insert("policy_mutations".to_owned(), json!(mutations));
        let _ = object.insert("store_fatal".to_owned(), fatal);
    }
    payload
}

/// A writer that was never started has nothing queued and is not running.
/// `started` separates that from a writer that stopped: a daemon which has
/// admitted no hook yet is healthy, and a reader that saw only `running` would
/// read the two the same way and call for repair.
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
        "started": false,
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

/// A submission's reply: whether the record was queued, and the signals the
/// writer reported while queueing it.
fn queued_payload((queued, (mutations, fatal)): (bool, (u64, Value))) -> Value {
    json!({
        "queued": queued,
        "policy_mutations": mutations,
        "store_fatal": fatal,
    })
}

/// A submission the resident declined before reaching a writer. No writer ran,
/// so there is nothing to report.
fn refused_payload() -> Value {
    json!({
        "queued": false,
        "policy_mutations": 0,
        "store_fatal": Value::Null,
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
    let guard_home = canonical_home(&request.guard_home);
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
            let queued = with_writer(&guard_home, &request.source, |resident| {
                let queued = resident.writer.submit_command_activity(
                    harness,
                    event,
                    payload,
                    *succeeded,
                    policy_action.as_deref(),
                    receipt_id.as_deref(),
                    *prompted,
                    approval_reuse_status,
                );
                (queued, signals(resident))
            })
            .map_err(started)?;
            Ok(queued_payload(queued))
        }
        HookEvidenceWriterActionV1::SubmitComposioDiscovery {
            harness,
            payload,
            succeeded,
        } => {
            let Some(tool_name) = payload.get("tool_name").and_then(Value::as_str) else {
                return Ok(refused_payload());
            };
            if !succeeded {
                return Ok(refused_payload());
            }
            let queued = with_writer(&guard_home, &request.source, |resident| {
                let queued = resident
                    .writer
                    .submit_composio_discovery(harness, tool_name, payload);
                (queued, signals(resident))
            })
            .map_err(started)?;
            Ok(queued_payload(queued))
        }
        HookEvidenceWriterActionV1::SubmitNativeDecisionReceipt { receipt } => {
            let queued = with_writer(&guard_home, &request.source, |resident| {
                let queued = resident.writer.submit_native_decision_receipt(receipt);
                (queued, signals(resident))
            })
            .map_err(started)?;
            Ok(queued_payload(queued))
        }
        HookEvidenceWriterActionV1::Stats => {
            Ok(with_running(&guard_home, stats_payload).unwrap_or_else(idle_stats))
        }
        HookEvidenceWriterActionV1::Stop { timeout_seconds } => {
            let slot = slot(&guard_home);
            let mut held = slot.writer.lock().unwrap_or_else(|e| e.into_inner());
            let (drained, payload) = {
                let Some(resident) = held.as_ref() else {
                    return Ok(json!({
                        "drained": true,
                        "policy_mutations": 0,
                        "store_fatal": Value::Null,
                    }));
                };
                // The slot stays locked across the drain, which the writer
                // bounds by the budget asked for here. A submission racing this
                // stop waits that long and no longer, rather than queueing onto
                // a writer that will never run its thread again or appending to
                // the journal the draining writer still owns.
                let drained = resident.writer.stop(stop_timeout(*timeout_seconds));
                let (mutations, fatal) = signals(resident);
                (
                    drained,
                    json!({
                        "drained": drained,
                        "final_stats": counters(resident),
                        "policy_mutations": mutations,
                        "store_fatal": fatal,
                    }),
                )
            };
            if drained {
                *held = None;
            }
            // A worker still inside a write owns the journal until it leaves,
            // so its writer stays in the slot. The next submission replaces it
            // once that worker is gone.
            Ok(payload)
        }
    }
}

#[cfg(test)]
#[path = "hook_evidence_writer_op_tests.rs"]
mod tests;
