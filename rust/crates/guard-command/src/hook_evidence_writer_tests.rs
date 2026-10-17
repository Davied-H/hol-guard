//! Persistence parity for `RuntimeHookEvidenceWriter`.
//!
//! A Pre event carries the verdict Rust already reached, so the writer builds
//! the evidence and the store only stores it. A post event carries no verdict,
//! so it may only promote a stored pre-hook row or be written as explicitly
//! unpaired. These cover the branch the Python drain loop takes at
//! `runtime_hook_evidence_writer.py:410-455` and the pairing rules in
//! `cli/commands_support_command_activity.py:208-246`.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value};

use crate::hook_evidence_writer::{
    ComposioActionSchema, ComposioWorkflowProposal, CorrelationApi, CorrelationHandle,
    EvidenceJournalApi, EvidenceRecord, EvidenceStoreApi, EvidenceWriterDeps,
    InstallationCorrelationKey, ObservedMcpTool, ReceiptValidationApi, RuntimeHookEvidenceWriter,
    SqliteTimeoutApi,
};

/// The correlation digest every fixture starts from, before a prevented
/// attempt rewrites it.
const BASE_DIGEST: &str = "9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f";

/// What the store was asked to do, in call order.
#[derive(Debug, Clone, PartialEq)]
enum StoreCall {
    PreReplayProbe(Map<String, Value>),
    RecordCommandActivity {
        evidence: Map<String, Value>,
        invocation_preview: Option<String>,
    },
    ActivityLookup(String),
    Transition(Map<String, Value>),
    ObservationConflict(String),
}

#[derive(Default)]
struct StubStoreState {
    calls: Vec<StoreCall>,
    pre_replay: bool,
    /// The row the lookup finds, if a pre-hook event already stored one.
    previous: Option<Map<String, Value>>,
}

struct StubStore {
    guard_home: PathBuf,
    state: Mutex<StubStoreState>,
}

impl StubStore {
    fn new(guard_home: PathBuf, pre_replay: bool) -> Arc<Self> {
        Arc::new(Self {
            guard_home,
            state: Mutex::new(StubStoreState {
                calls: Vec::new(),
                pre_replay,
                previous: None,
            }),
        })
    }

    fn calls(&self) -> Vec<StoreCall> {
        self.state.lock().expect("state").calls.clone()
    }

    fn push(&self, call: StoreCall) {
        self.state.lock().expect("state").calls.push(call);
    }

    fn set_previous(&self, previous: Map<String, Value>) {
        self.state.lock().expect("state").previous = Some(previous);
    }
}

impl EvidenceStoreApi for StubStore {
    fn guard_home(&self) -> PathBuf {
        self.guard_home.clone()
    }

    fn is_exact_command_activity_pre_replay(
        &self,
        evidence: &Map<String, Value>,
    ) -> Result<bool, io::Error> {
        self.push(StoreCall::PreReplayProbe(evidence.clone()));
        Ok(self.state.lock().expect("state").pre_replay)
    }

    fn record_command_activity(
        &self,
        evidence: &Map<String, Value>,
        invocation_preview: Option<&str>,
    ) -> Result<bool, io::Error> {
        self.push(StoreCall::RecordCommandActivity {
            evidence: evidence.clone(),
            invocation_preview: invocation_preview.map(str::to_owned),
        });
        Ok(true)
    }

    fn record_composio_discovery(
        &self,
        _source: &ObservedMcpTool,
        _actions: &[ComposioActionSchema],
        _seen_at: &str,
        _proposals: &[ComposioWorkflowProposal],
    ) -> Result<(), io::Error> {
        Ok(())
    }

    fn record_native_decision_receipt(
        &self,
        _receipt: &Map<String, Value>,
    ) -> Result<bool, io::Error> {
        Ok(true)
    }

    fn command_activity_by_request_correlation(
        &self,
        correlation: &CorrelationHandle,
    ) -> Result<Option<Map<String, Value>>, io::Error> {
        self.push(StoreCall::ActivityLookup(correlation.digest.clone()));
        Ok(self.state.lock().expect("state").previous.clone())
    }

    fn transition_command_activity(&self, current: &Map<String, Value>) -> Result<bool, io::Error> {
        self.push(StoreCall::Transition(current.clone()));
        Ok(true)
    }

    fn record_command_activity_observation_conflict(
        &self,
        occurred_at: &str,
    ) -> Result<(), io::Error> {
        self.push(StoreCall::ObservationConflict(occurred_at.to_owned()));
        Ok(())
    }
}

/// Echoes the arguments it was handed so a test can read the evidence the
/// writer decided on, rather than the shape the lifecycle module would build.
struct StubCorrelation;

impl CorrelationApi for StubCorrelation {
    fn load_or_create_installation_correlation_key(
        &self,
    ) -> Result<Option<InstallationCorrelationKey>, io::Error> {
        Ok(Some(InstallationCorrelationKey::new("key-1", &[7u8; 32])?))
    }

    fn derive_proven_request_correlation(
        &self,
        harness: &str,
        _event: &str,
        _payload: &Map<String, Value>,
        key: &InstallationCorrelationKey,
    ) -> Result<Option<CorrelationHandle>, io::Error> {
        Ok(Some(CorrelationHandle {
            kind: "command_execution".to_owned(),
            harness: harness.to_owned(),
            key_id: key.key_id.clone(),
            digest: BASE_DIGEST.to_owned(),
        }))
    }

    fn build_invocation_preview_from_payload(
        &self,
        _payload: &Map<String, Value>,
    ) -> Result<Option<String>, io::Error> {
        Ok(Some("rm -rf …".to_owned()))
    }

    fn build_policy_only_pre_hook_evidence(
        &self,
        activity_id: &str,
        occurred_at: &str,
        harness: &str,
        policy_action: &str,
        request_correlation: Option<&CorrelationHandle>,
        receipt_id: Option<&str>,
        prompted: bool,
        approval_reuse_status: &str,
    ) -> Result<Map<String, Value>, io::Error> {
        let Value::Object(evidence) = json!({
            "activity_id": activity_id,
            "occurred_at": occurred_at,
            "harness": harness,
            "policy_action": policy_action,
            "correlation_digest": request_correlation.map(|handle| handle.digest.clone()),
            "receipt_id": receipt_id,
            "interaction_observed": prompted,
            "approval_reuse_status": approval_reuse_status,
        }) else {
            unreachable!("object literal");
        };
        Ok(evidence)
    }

    fn build_unpaired_post_evidence(
        &self,
        activity_id: &str,
        occurred_at: &str,
        harness: &str,
        succeeded: bool,
    ) -> Result<Map<String, Value>, io::Error> {
        let Value::Object(evidence) = json!({
            "activity_id": activity_id,
            "occurred_at": occurred_at,
            "harness": harness,
            "execution_status": "unpaired_post",
            "succeeded": succeeded,
        }) else {
            unreachable!("object literal");
        };
        Ok(evidence)
    }

    fn build_correlated_post_activity(
        &self,
        previous: &Map<String, Value>,
        request_correlation: &CorrelationHandle,
        succeeded: bool,
    ) -> Result<Map<String, Value>, io::Error> {
        let mut current = previous.clone();
        current.insert(
            "execution_status".to_owned(),
            Value::from(if succeeded {
                "confirmed_success"
            } else {
                "confirmed_failure"
            }),
        );
        current.insert(
            "correlation_digest".to_owned(),
            Value::from(request_correlation.digest.as_str()),
        );
        Ok(current)
    }
}

struct StubReceipts;

impl ReceiptValidationApi for StubReceipts {
    fn validate_native_decision_receipt(
        &self,
        value: &Map<String, Value>,
    ) -> Option<Map<String, Value>> {
        Some(value.clone())
    }
}

struct StubComposio;

impl crate::hook_evidence_writer::ComposioApi for StubComposio {
    fn observed_mcp_tool(&self, _harness: &str, _tool_name: &str) -> Option<ObservedMcpTool> {
        None
    }

    fn composio_discovered_actions(
        &self,
        _tool_name: &str,
        _response: &Value,
    ) -> Option<Vec<ComposioActionSchema>> {
        None
    }

    fn composio_workflow_proposals(
        &self,
        _tool_name: &str,
        _response: &Value,
    ) -> Option<Vec<ComposioWorkflowProposal>> {
        None
    }
}

/// Accepts every append without touching the filesystem; journal durability
/// has its own coverage and would only add I/O here.
struct StubJournal;

impl EvidenceJournalApi for StubJournal {
    fn append_journal(&self, _path: &Path, _record: &EvidenceRecord) -> Result<(), io::Error> {
        Ok(())
    }

    fn rewrite_journal(
        &self,
        _path: &Path,
        _remove_record_id: &str,
        _max_bytes: usize,
    ) -> Result<u64, io::Error> {
        Ok(0)
    }

    fn recover_journal_records(
        &self,
        _path: &Path,
        _max_bytes: usize,
    ) -> Result<(Vec<Map<String, Value>>, u64), io::Error> {
        Ok((Vec::new(), 0))
    }

    fn now_utc_iso(&self) -> String {
        "2026-10-17T00:00:00+00:00".to_owned()
    }
}

struct StubSqliteTimeout;

impl SqliteTimeoutApi for StubSqliteTimeout {
    fn sqlite_timeout_override(
        &self,
        _timeout_ms: std::num::NonZeroU32,
    ) -> Box<dyn std::any::Any + Send> {
        Box::new(())
    }
}

fn deps() -> EvidenceWriterDeps {
    EvidenceWriterDeps {
        correlation: Box::new(StubCorrelation),
        receipts: Arc::new(StubReceipts),
        composio: Arc::new(StubComposio),
        journal: Box::new(StubJournal),
        sqlite_timeout: Box::new(StubSqliteTimeout),
    }
}

fn writer(store: Arc<StubStore>, journal_path: PathBuf) -> RuntimeHookEvidenceWriter {
    RuntimeHookEvidenceWriter::new(store, deps(), 64, 1 << 20, 8, 0.01, Some(journal_path))
        .expect("writer")
}

fn command_payload() -> Map<String, Value> {
    let Value::Object(payload) = json!({
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /tmp/scratch"},
    }) else {
        unreachable!("object literal");
    };
    payload
}

/// A fresh store plus the writer wired to it. The journal seam is stubbed, so
/// the home below is only ever a path, never a directory anything writes to.
fn fixture(pre_replay: bool) -> (Arc<StubStore>, RuntimeHookEvidenceWriter) {
    let home = PathBuf::from("/hol-guard-evidence-writer-tests");
    let store = StubStore::new(home.clone(), pre_replay);
    let writer = writer(Arc::clone(&store), home.join("runtime-hook-evidence.jsonl"));
    (store, writer)
}

#[test]
fn an_allowed_pre_event_records_the_evidence_under_its_own_correlation() {
    let (store, writer) = fixture(false);
    assert!(writer.submit_command_activity(
        "claude-code",
        "PreToolUse",
        &command_payload(),
        true,
        Some("allow"),
        None,
        false,
        "none",
    ));
    assert!(writer.stop(5.0), "writer drained");

    let calls = store.calls();
    assert!(
        matches!(calls.first(), Some(StoreCall::PreReplayProbe(_))),
        "{calls:?}"
    );
    let Some(StoreCall::RecordCommandActivity {
        evidence,
        invocation_preview,
    }) = calls.get(1)
    else {
        panic!("expected a command-activity write, got {calls:?}");
    };
    assert_eq!(
        evidence.get("correlation_digest").and_then(Value::as_str),
        Some(BASE_DIGEST),
        "an allowed call keeps the correlation its post event will carry"
    );
    assert_eq!(
        evidence.get("policy_action").and_then(Value::as_str),
        Some("allow")
    );
    assert_eq!(invocation_preview.as_deref(), Some("rm -rf …"));
}

#[test]
fn a_prevented_pre_event_rewrites_the_correlation_digest() {
    let (store, writer) = fixture(false);
    assert!(writer.submit_command_activity(
        "claude-code",
        "PreToolUse",
        &command_payload(),
        false,
        Some("block"),
        Some("receipt-1"),
        true,
        "accepted",
    ));
    assert!(writer.stop(5.0), "writer drained");

    let calls = store.calls();
    let Some(StoreCall::RecordCommandActivity { evidence, .. }) = calls.get(1) else {
        panic!("expected a command-activity write, got {calls:?}");
    };
    // The vector is `hashlib.sha256(json.dumps([...]))` over the same tuple:
    // the digest is a join key, so both runtimes must land on these bytes.
    assert_eq!(
        evidence.get("correlation_digest").and_then(Value::as_str),
        Some("d5b3406976b245e21cb4b99a6f44865fb54da626c9acfecf354bc3be3917a324"),
        "a prevented attempt cannot pair with a post event, so it gets its own key"
    );
}

#[test]
fn a_review_pre_event_without_a_receipt_still_matches_the_python_digest() {
    let (store, writer) = fixture(false);
    assert!(writer.submit_command_activity(
        "claude-code",
        "PreToolUse",
        &command_payload(),
        false,
        Some("review"),
        None,
        false,
        "not-applicable",
    ));
    assert!(writer.stop(5.0), "writer drained");

    let calls = store.calls();
    let Some(StoreCall::RecordCommandActivity { evidence, .. }) = calls.get(1) else {
        panic!("expected a command-activity write, got {calls:?}");
    };
    assert_eq!(
        evidence.get("correlation_digest").and_then(Value::as_str),
        Some("ef7096bc78457c3d3815d685e38f3bc4d9cb14cd13c9c9e556d70901efa9fcfc"),
        "a missing receipt id hashes as JSON null, not as an empty string"
    );
}

#[test]
fn an_exact_pre_replay_is_probed_and_then_dropped() {
    let (store, writer) = fixture(true);
    assert!(writer.submit_command_activity(
        "claude-code",
        "PreToolUse",
        &command_payload(),
        true,
        Some("allow"),
        None,
        false,
        "none",
    ));
    assert!(writer.stop(5.0), "writer drained");

    let calls = store.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(matches!(calls[0], StoreCall::PreReplayProbe(_)));
}

/// A stored pre-hook row in the state the lookup would return it.
fn stored_row(execution_status: &str) -> Map<String, Value> {
    let Value::Object(row) = json!({
        "activity_id": "activity:stored",
        "harness": "claude-code",
        "execution_status": execution_status,
    }) else {
        unreachable!("object literal");
    };
    row
}

/// Submit one post event and return the calls it produced.
fn post_event_calls(store: &Arc<StubStore>, writer: RuntimeHookEvidenceWriter) -> Vec<StoreCall> {
    assert!(writer.submit_command_activity(
        "claude-code",
        "PostToolUse",
        &command_payload(),
        true,
        None,
        None,
        false,
        "none",
    ));
    assert!(writer.stop(5.0), "writer drained");
    store.calls()
}

#[test]
fn an_unpaired_post_event_is_recorded_as_claiming_no_decision() {
    let (store, writer) = fixture(false);

    let calls = post_event_calls(&store, writer);
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert_eq!(calls[0], StoreCall::ActivityLookup(BASE_DIGEST.to_owned()));
    let Some(StoreCall::RecordCommandActivity {
        evidence,
        invocation_preview,
    }) = calls.get(1)
    else {
        panic!("{calls:?}");
    };
    assert_eq!(evidence["execution_status"], json!("unpaired_post"));
    assert_eq!(evidence["harness"], json!("claude-code"));
    assert_eq!(evidence["succeeded"], json!(true));
    let activity_id = evidence["activity_id"].as_str().expect("activity id");
    assert!(activity_id.starts_with("activity:"), "{activity_id}");
    assert_eq!(activity_id.len(), "activity:".len() + 32, "{activity_id}");
    assert_eq!(invocation_preview.as_deref(), Some("rm -rf …"));
}

#[test]
fn a_post_event_promotes_the_pre_hook_row_it_pairs_with() {
    let (store, writer) = fixture(false);
    store.set_previous(stored_row("allowed_unconfirmed"));

    let calls = post_event_calls(&store, writer);
    assert_eq!(calls.len(), 2, "{calls:?}");
    let Some(StoreCall::Transition(current)) = calls.get(1) else {
        panic!("{calls:?}");
    };
    assert_eq!(current["activity_id"], json!("activity:stored"));
    assert_eq!(current["execution_status"], json!("confirmed_success"));
}

#[test]
fn a_post_event_never_overwrites_a_prevented_row() {
    let (store, writer) = fixture(false);
    store.set_previous(stored_row("prevented"));

    assert_eq!(
        post_event_calls(&store, writer),
        vec![StoreCall::ActivityLookup(BASE_DIGEST.to_owned())]
    );
}

#[test]
fn a_repeated_post_event_leaves_the_confirmed_row_alone() {
    let (store, writer) = fixture(false);
    store.set_previous(stored_row("confirmed_success"));

    assert_eq!(
        post_event_calls(&store, writer),
        vec![StoreCall::ActivityLookup(BASE_DIGEST.to_owned())]
    );
}

#[test]
fn a_post_event_against_an_unexpected_status_records_a_conflict() {
    let (store, writer) = fixture(false);
    store.set_previous(stored_row("attempted"));

    let calls = post_event_calls(&store, writer);
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert_eq!(
        calls[1],
        StoreCall::ObservationConflict("2026-10-17T00:00:00+00:00".to_owned())
    );
}

#[test]
fn a_pre_event_without_a_command_never_reaches_the_store() {
    let (store, writer) = fixture(false);
    let Value::Object(payload) =
        json!({"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}})
    else {
        unreachable!("object literal");
    };
    assert!(writer.submit_command_activity(
        "claude-code",
        "PreToolUse",
        &payload,
        true,
        Some("allow"),
        None,
        false,
        "none",
    ));
    assert!(writer.stop(5.0), "writer drained");

    assert!(store.calls().is_empty(), "{:?}", store.calls());
}
