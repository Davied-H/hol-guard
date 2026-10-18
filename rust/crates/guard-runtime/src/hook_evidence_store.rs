//! The evidence writer's [`EvidenceStoreApi`] and [`SqliteTimeoutApi`] seams,
//! answered by the resident's own store ops instead of a Python `GuardStore`.
//!
//! `store_review_event_outbox._native_store_call` is what this replaces: it
//! held the shared storage gate, ran one `GuardStoreRequestV1` through the
//! resident, repaired the store file modes and woke the outbox. None of the
//! evidence methods write the review-event outbox, so the wake has nothing to
//! carry here; the gate hold and the permission repair do, and they follow
//! `mcp_relay_decide_ask`, which already calls store ops in process.
//!
//! Two Python behaviours are ported rather than called. The storage gate
//! Python takes is blocking and creates its own lock file
//! (`store_storage_gate.hold_storage_gate`), where the daemon's hook path
//! takes a try-once hold on a gate that must already exist, so the blocking
//! hold lives here. And `sqlite_tuning._sqlite_wait_limit_seconds` reads a
//! `ContextVar` the writer installs for the duration of one batch; a
//! thread-local is the same thing for the writer's single worker thread, so
//! the override seam no longer needs Python either.
//!
//! TODO(deps): the native policy barrier stays a seam. Moving provider
//! authority has to be bracketed by `notify_native_policy_mutation`, which
//! walks a registry of in-process Python publisher objects; there is no Rust
//! counterpart to wake, so [`PolicyBarrierApi`] carries it until the snapshot
//! publisher itself is ported.

use std::cell::Cell;
use std::fs::File;
use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

use fs2::FileExt;
use guard_command::hook_evidence_writer::{
    ComposioActionSchema, ComposioWorkflowProposal, CorrelationHandle, EvidenceStoreApi,
    ObservedMcpTool, SqliteTimeoutApi,
};
use guard_command::local_supply_chain::utc_now_iso;
use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use serde_json::{json, Map, Value};

use crate::guard_store_db::StoreError;
use crate::hook_direct::saved_decision::consume::repair_store_permissions;
use crate::local_store_read::STORE_FILE_NAME;

/// `store_storage_gate._GATE_FILE_NAME`.
const STORAGE_GATE_FILE_NAME: &str = "storage-access.lock";
/// `hold_storage_gate` retries a contended gate on this interval
/// (`time.sleep(0.01)`).
const GATE_POLL: Duration = Duration::from_millis(10);
/// `sqlite_tuning._DEFAULT_SQLITE_CONNECT_TIMEOUT_SECONDS` in milliseconds.
const DEFAULT_SQLITE_TIMEOUT_MS: u32 = 30_000;
/// `sqlite_tuning._MAX_INTERNAL_HOOK_SQLITE_TIMEOUT_MS`.
const MAX_INTERNAL_HOOK_SQLITE_TIMEOUT_MS: u32 = 250;
/// `sqlite_tuning._INTERNAL_HOOK_SQLITE_TIMEOUT_ENV`.
const INTERNAL_HOOK_SQLITE_TIMEOUT_ENV: &str = "HOL_GUARD_INTERNAL_HOOK_SQLITE_TIMEOUT_MS";
/// `command_activity_display.INVOCATION_PREVIEW_MAX_CHARS`.
const INVOCATION_PREVIEW_MAX_CHARS: usize = 4_096;
/// The largest `busy_timeout_ms` `guard_store_op::evaluate` accepts.
const MAX_BUSY_TIMEOUT_MS: u64 = 600_000;

thread_local! {
    /// `sqlite_tuning._sqlite_connect_timeout_override` — the per-batch
    /// override the writer installs around its store calls.
    static SQLITE_TIMEOUT_MS: Cell<Option<NonZeroU32>> = const { Cell::new(None) };
}

/// `notify_native_policy_mutation(guard_home)` — the native policy barrier.
///
/// A store op that would move policy authority writes nothing and answers
/// `{"need_barrier": true}`; the caller notifies the publishers, repeats the
/// call with `barrier_closed`, and notifies them again.
pub(crate) trait PolicyBarrierApi {
    fn notify_policy_mutation(&self, guard_home: &Path);
}

/// `_notify_legacy_mcp_denial` — notifies on the way in and on the way out,
/// including when the bracketed call fails.
struct PolicyBarrier<'a> {
    barrier: &'a (dyn PolicyBarrierApi + Send + Sync),
    guard_home: &'a Path,
}

impl<'a> PolicyBarrier<'a> {
    fn close(barrier: &'a (dyn PolicyBarrierApi + Send + Sync), guard_home: &'a Path) -> Self {
        barrier.notify_policy_mutation(guard_home);
        Self {
            barrier,
            guard_home,
        }
    }
}

impl Drop for PolicyBarrier<'_> {
    fn drop(&mut self) {
        self.barrier.notify_policy_mutation(self.guard_home);
    }
}

/// The writer's store seam, bound to one installation's Guard home.
pub(crate) struct NativeEvidenceStore {
    guard_home: PathBuf,
    /// `GuardStore.guard_source`, echoed into every request.
    source: String,
    barrier: Box<dyn PolicyBarrierApi + Send + Sync>,
}

impl NativeEvidenceStore {
    pub(crate) fn new(
        guard_home: PathBuf,
        source: &str,
        barrier: Box<dyn PolicyBarrierApi + Send + Sync>,
    ) -> Self {
        Self {
            guard_home,
            source: crate::guard_store_approval_write::oauth_source(source),
            barrier,
        }
    }

    /// One store call under the shared storage gate, with the store files put
    /// back into private mode afterwards.
    fn call(
        &self,
        request_id: &str,
        method: &str,
        args: Map<String, Value>,
    ) -> Result<Value, io::Error> {
        let timeout_ms = sqlite_timeout_ms();
        let _gate = hold_storage_gate(&self.guard_home, Duration::from_millis(timeout_ms.into()))?;
        // `GuardStoreRequestV1.busy_timeout_ms` is bounded by the resident; a
        // wait longer than that bound still waits here for the gate, and the
        // store's own busy timeout takes the largest value it accepts.
        let busy_timeout_ms = u64::from(timeout_ms).min(MAX_BUSY_TIMEOUT_MS);
        let payload = crate::guard_store_op::evaluate(&GuardStoreRequestV1 {
            schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
            request_id: request_id.to_owned(),
            store_path: self
                .guard_home
                .join(STORE_FILE_NAME)
                .to_string_lossy()
                .into_owned(),
            guard_home: self.guard_home.to_string_lossy().into_owned(),
            method: method.to_owned(),
            source: self.source.clone(),
            busy_timeout_ms,
            args,
        })
        .map(|(payload, _)| payload)
        .map_err(|error| store_failure(method, &error));
        repair_store_permissions(&self.guard_home);
        payload
    }

    /// A call whose answer the Python wrapper narrows with `bool()`. These
    /// ops answer null for "nothing matched", which is false there too.
    fn call_flag(
        &self,
        request_id: &str,
        method: &str,
        args: Map<String, Value>,
    ) -> Result<bool, io::Error> {
        Ok(python_truthy(&self.call(request_id, method, args)?))
    }
}

impl EvidenceStoreApi for NativeEvidenceStore {
    fn guard_home(&self) -> PathBuf {
        self.guard_home.clone()
    }

    fn is_exact_command_activity_pre_replay(
        &self,
        evidence: &Map<String, Value>,
    ) -> Result<bool, io::Error> {
        // `store_command_activity_lifecycle` answers False for evidence that
        // carries no request correlation, without opening the store.
        if request_correlation(evidence).is_none() {
            return Ok(false);
        }
        self.call_flag(
            "hook-evidence-pre-replay",
            "is_exact_command_activity_pre_replay",
            evidence_args(evidence),
        )
    }

    fn record_command_activity(
        &self,
        evidence: &Map<String, Value>,
        invocation_preview: Option<&str>,
    ) -> Result<bool, io::Error> {
        let mut args = evidence_args(evidence);
        args.insert(
            "invocation_preview".to_owned(),
            match validated_invocation_preview(invocation_preview)? {
                Some(preview) => Value::String(preview),
                None => Value::Null,
            },
        );
        // The writer records the decided command, never a shadow evaluation,
        // so both shadow arguments carry their Python defaults.
        args.insert("shadow".to_owned(), Value::Null);
        args.insert("shadow_evaluation_succeeded".to_owned(), Value::Bool(false));
        self.call_flag(
            "hook-evidence-command-activity",
            "record_command_activity",
            args,
        )
    }

    fn record_composio_discovery(
        &self,
        source: &ObservedMcpTool,
        actions: &[ComposioActionSchema],
        seen_at: &str,
        proposals: &[ComposioWorkflowProposal],
    ) -> Result<(), io::Error> {
        let cli_id = self.ensure_local_mcp_observation(source, seen_at)?;
        let mut args = Map::new();
        args.insert("cli_id".to_owned(), Value::String(cli_id));
        args.insert(
            "identity_hash".to_owned(),
            Value::String(source.server.identity_hash.clone()),
        );
        args.insert(
            "server_command".to_owned(),
            match &source.server.command {
                Some(command) => Value::String(command.clone()),
                None => Value::Null,
            },
        );
        args.insert(
            "source_tool".to_owned(),
            Value::String(source.qualified_name.clone()),
        );
        args.insert("seen_at".to_owned(), Value::String(seen_at.to_owned()));
        args.insert(
            "actions".to_owned(),
            Value::Array(
                actions
                    .iter()
                    .map(|action| {
                        json!({
                            "toolkit": action.toolkit,
                            "tool_slug": action.tool_slug,
                            "description": action.description,
                            "input_schema": Value::Object(action.input_schema.clone()),
                            "full_schema": action.full_schema,
                        })
                    })
                    .collect(),
            ),
        );
        args.insert(
            "proposals".to_owned(),
            Value::Array(
                proposals
                    .iter()
                    .map(|proposal| {
                        json!({
                            "primary": proposal.primary,
                            "supporting": proposal.supporting,
                            "guidance_present": proposal.guidance_present,
                        })
                    })
                    .collect(),
            ),
        );
        let answer = self.call(
            "hook-evidence-composio-discovery",
            "record_composio_discovery",
            args.clone(),
        )?;
        if needs_barrier(&answer) {
            // This batch moves the provider authority, so it has to run inside
            // the barrier the resident cannot close for itself.
            let _barrier = PolicyBarrier::close(self.barrier.as_ref(), &self.guard_home);
            args.insert("barrier_closed".to_owned(), Value::Bool(true));
            self.call(
                "hook-evidence-composio-discovery-barrier",
                "record_composio_discovery",
                args,
            )?;
        }
        Ok(())
    }

    fn record_native_decision_receipt(
        &self,
        receipt: &Map<String, Value>,
    ) -> Result<bool, io::Error> {
        // `_receipt_wire` — the op parses the text itself, so a receipt that
        // cannot be serialized never reaches the store.
        let wire = serde_json::to_string(&Value::Object(receipt.clone())).map_err(|error| {
            io::Error::other(format!("invalid native decision receipt: {error}"))
        })?;
        let mut args = Map::new();
        args.insert("receipt".to_owned(), Value::String(wire));
        // Python stamps `datetime.now(timezone.utc).isoformat()`, which keeps
        // microseconds; the stored column only orders receipts, and the
        // resident already carries its own second-precision clock helper.
        args.insert("now".to_owned(), Value::String(utc_now_iso()));
        self.call(
            "hook-evidence-receipt",
            "record_native_decision_receipt",
            args,
        )?;
        // `store_native_decision_receipts.record_native_decision_receipt`
        // always answers True: an insert the store ignored as a duplicate is
        // still a receipt the writer has nothing left to do about.
        Ok(true)
    }

    fn command_activity_by_request_correlation(
        &self,
        correlation: &CorrelationHandle,
    ) -> Result<Option<Map<String, Value>>, io::Error> {
        let mut args = Map::new();
        args.insert("correlation".to_owned(), handle_wire(correlation));
        match self.call(
            "hook-evidence-activity-by-correlation",
            "command_activity_by_request_correlation",
            args,
        )? {
            Value::Null => Ok(None),
            Value::Object(row) => Ok(Some(row)),
            other => Err(io::Error::other(format!(
                "command_activity_by_request_correlation: expected a row, got {other}"
            ))),
        }
    }

    fn transition_command_activity(&self, current: &Map<String, Value>) -> Result<bool, io::Error> {
        let mut args = Map::new();
        args.insert("current".to_owned(), Value::Object(current.clone()));
        self.call_flag(
            "hook-evidence-activity-transition",
            "transition_command_activity",
            args,
        )
    }

    fn record_command_activity_observation_conflict(
        &self,
        occurred_at: &str,
    ) -> Result<(), io::Error> {
        let mut args = Map::new();
        args.insert(
            "occurred_at".to_owned(),
            Value::String(occurred_at.to_owned()),
        );
        self.call(
            "hook-evidence-observation-conflict",
            "record_command_activity_observation_conflict",
            args,
        )?;
        Ok(())
    }
}

impl NativeEvidenceStore {
    /// `store_local_mcp.ensure_local_mcp_observation` — the connection grant
    /// the catalog write is held against, bound before any metadata is
    /// written. It carries its own barrier retry: adopting a legacy denial
    /// moves policy authority too.
    fn ensure_local_mcp_observation(
        &self,
        source: &ObservedMcpTool,
        seen_at: &str,
    ) -> Result<String, io::Error> {
        let identity = &source.identity;
        let mut args = Map::new();
        args.insert("cli_id".to_owned(), Value::String(identity.cli_id.clone()));
        args.insert(
            "identity_hash".to_owned(),
            Value::String(identity.identity_hash.clone()),
        );
        args.insert("kind".to_owned(), Value::String(identity.kind.clone()));
        args.insert("name".to_owned(), Value::String(identity.name.clone()));
        args.insert(
            "interpreter_name".to_owned(),
            match &identity.interpreter_name {
                Some(name) => Value::String(name.clone()),
                None => Value::Null,
            },
        );
        args.insert(
            "example_label".to_owned(),
            Value::String(identity.example_label.clone()),
        );
        args.insert("seen_at".to_owned(), Value::String(seen_at.to_owned()));
        args.insert(
            "server_identity_hash".to_owned(),
            Value::String(source.server.identity_hash.clone()),
        );
        args.insert(
            "server_command".to_owned(),
            match &source.server.command {
                Some(command) => Value::String(command.clone()),
                None => Value::Null,
            },
        );
        args.insert(
            "server_args_hash".to_owned(),
            Value::String(source.server.args_hash.clone()),
        );
        args.insert(
            "source_label".to_owned(),
            Value::String(format!(
                "{} · observed provider metadata",
                python_title(&source.harness)
            )),
        );
        args.insert("connection_identity_hash".to_owned(), Value::Null);
        args.insert("replayed".to_owned(), Value::Bool(false));
        args.insert("replay_now".to_owned(), Value::Null);
        args.insert("clock".to_owned(), Value::String(utc_now_iso()));
        let mut answer = self.call(
            "hook-evidence-mcp-observation",
            "ensure_local_mcp_observation",
            args.clone(),
        )?;
        if needs_barrier(&answer) {
            let _barrier = PolicyBarrier::close(self.barrier.as_ref(), &self.guard_home);
            args.insert("barrier_closed".to_owned(), Value::Bool(true));
            answer = self.call(
                "hook-evidence-mcp-observation-barrier",
                "ensure_local_mcp_observation",
                args,
            )?;
        }
        match answer.get("cli_id") {
            Some(Value::String(cli_id)) => Ok(cli_id.clone()),
            // `LocalCliReplaySkippedError` cannot happen here — this call
            // never replays — so every other answer is the store returning a
            // shape its own contract rules out.
            _ => Err(io::Error::other(
                "ensure_local_mcp_observation: native_local_mcp_observation_invalid",
            )),
        }
    }
}

/// The writer's sqlite-timeout seam, installed around one batch of calls.
pub(crate) struct NativeSqliteTimeout;

impl SqliteTimeoutApi for NativeSqliteTimeout {
    fn sqlite_timeout_override(&self, timeout_ms: NonZeroU32) -> Box<dyn std::any::Any + Send> {
        let previous = SQLITE_TIMEOUT_MS.with(|cell| cell.replace(Some(timeout_ms)));
        Box::new(SqliteTimeoutReset {
            previous,
            owner: std::thread::current().id(),
        })
    }
}

/// `ContextVar.reset(token)` — restores whatever the override replaced.
struct SqliteTimeoutReset {
    previous: Option<NonZeroU32>,
    owner: ThreadId,
}

impl Drop for SqliteTimeoutReset {
    fn drop(&mut self) {
        // A `ContextVar` token belongs to the context that set it. The seam
        // hands back a `Send` box, so a drop on another thread would reset a
        // override that thread never installed; leave it alone.
        if std::thread::current().id() == self.owner {
            SQLITE_TIMEOUT_MS.with(|cell| cell.set(self.previous));
        }
    }
}

/// `sqlite_tuning._sqlite_wait_limit_seconds`, in milliseconds: the installed
/// override first, then the internal-hook environment bound, then the default
/// connect timeout.
fn sqlite_timeout_ms() -> u32 {
    if let Some(timeout) = SQLITE_TIMEOUT_MS.with(Cell::get) {
        return timeout.get();
    }
    std::env::var(INTERNAL_HOOK_SQLITE_TIMEOUT_ENV)
        .ok()
        .and_then(|raw| internal_hook_timeout_ms(&raw))
        .unwrap_or(DEFAULT_SQLITE_TIMEOUT_MS)
}

/// The internal-hook bound as Python reads it: integers only, a non-positive
/// value ignored, the rest capped. A float or trailing text leaves the
/// default in place.
fn internal_hook_timeout_ms(raw: &str) -> Option<u32> {
    match raw.trim().parse::<i64>().ok()? {
        milliseconds if milliseconds > 0 => Some(
            u64::try_from(milliseconds)
                .unwrap_or(u64::MAX)
                .min(u64::from(MAX_INTERNAL_HOOK_SQLITE_TIMEOUT_MS)) as u32,
        ),
        _ => None,
    }
}

/// `hold_storage_gate(guard_home)` — a shared hold that waits for an
/// exclusive maintenance hold to end, creating the gate file when the home has
/// never taken one.
///
/// The daemon's hook path takes this gate try-once on a file that must already
/// exist, because a hook that cannot have it immediately defers to the daemon.
/// The writer has nothing to defer to, so it waits like Python does.
fn hold_storage_gate(guard_home: &Path, wait: Duration) -> Result<File, io::Error> {
    let gate = open_gate(&guard_home.join(STORAGE_GATE_FILE_NAME))?;
    let deadline = Instant::now() + wait;
    loop {
        match FileExt::try_lock_shared(&gate) {
            Ok(()) => return Ok(gate),
            Err(error) if Instant::now() >= deadline => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("timed out waiting for the Guard storage gate: {error}"),
                ))
            }
            Err(_) => std::thread::sleep(GATE_POLL),
        }
    }
}

/// The gate opened without following a link at the leaf, created private when
/// it is not there yet.
#[cfg(unix)]
fn open_gate(path: &Path) -> Result<File, io::Error> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// Python takes the gate with `msvcrt.locking` on its first byte, which has no
/// shared mode; the shared whole-file `LockFileEx` here still excludes that
/// hold and any exclusive one.
#[cfg(windows)]
fn open_gate(path: &Path) -> Result<File, io::Error> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the Guard storage gate is not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn open_gate(_path: &Path) -> Result<File, io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the Guard storage gate needs file locking",
    ))
}

fn store_failure(method: &str, error: &StoreError) -> io::Error {
    io::Error::other(format!("{method}: {} ({})", error.code(), error.message()))
}

fn evidence_args(evidence: &Map<String, Value>) -> Map<String, Value> {
    let mut args = Map::new();
    args.insert("evidence".to_owned(), Value::Object(evidence.clone()));
    args
}

/// `handle_wire(correlation)` (`store_command_activity_wire.py`).
/// `bool(payload)` on what the resident answered: these ops return null when
/// nothing matched, which Python narrows to False.
fn python_truthy(payload: &Value) -> bool {
    match payload {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|value| value != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
    }
}

fn request_correlation(evidence: &Map<String, Value>) -> Option<&Map<String, Value>> {
    evidence
        .get("activity")?
        .as_object()?
        .get("request_correlation")?
        .as_object()
}

fn handle_wire(correlation: &CorrelationHandle) -> Value {
    json!({
        "kind": correlation.kind,
        "harness": correlation.harness,
        "key_id": correlation.key_id,
        "digest": correlation.digest,
    })
}

fn needs_barrier(answer: &Value) -> bool {
    answer.get("need_barrier") == Some(&Value::Bool(true))
}

/// `_validated_invocation_preview` — the store refuses a preview it cannot
/// store rather than truncating one.
fn validated_invocation_preview(preview: Option<&str>) -> Result<Option<String>, io::Error> {
    let Some(preview) = preview else {
        return Ok(None);
    };
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid_invocation_preview");
    if preview.contains('\0') {
        return Err(invalid());
    }
    let trimmed = preview.trim();
    if trimmed.is_empty() || trimmed.chars().count() > INVOCATION_PREVIEW_MAX_CHARS {
        return Err(invalid());
    }
    Ok(Some(trimmed.to_owned()))
}

/// Python `str.title()`: every run of letters is capitalized at its first
/// character and lowercased after it, so `claude-code` becomes `Claude-Code`.
fn python_title(value: &str) -> String {
    let mut titled = String::with_capacity(value.len());
    let mut in_word = false;
    for character in value.chars() {
        if character.is_alphabetic() {
            if in_word {
                titled.extend(character.to_lowercase());
            } else {
                titled.extend(character.to_uppercase());
            }
            in_word = true;
        } else {
            titled.push(character);
            in_word = false;
        }
    }
    titled
}

#[cfg(test)]
#[path = "hook_evidence_store_tests.rs"]
mod tests;
