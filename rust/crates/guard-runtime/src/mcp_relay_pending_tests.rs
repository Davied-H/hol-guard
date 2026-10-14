use super::*;
use crate::hook_direct_evidence::{drain, HookDirectEvidenceDrainRequestV1};

fn drained(queue: &DirectEvidenceQueue) -> Vec<Value> {
    let request: HookDirectEvidenceDrainRequestV1 =
        serde_json::from_value(json!({"guard_home": "/home"})).unwrap();
    let page: Value = serde_json::from_slice(&drain(&request, queue).unwrap()).unwrap();
    page["records"].as_array().unwrap().clone()
}

fn commit_ticket(
    ticket: &str,
    pending: &PendingRelayEvidence,
    queue: &DirectEvidenceQueue,
) -> bool {
    let request = McpRelayCommitRequestV1 {
        guard_home: "/home".to_owned(),
        ticket: ticket.to_owned(),
    };
    let result: Value = serde_json::from_slice(&commit(&request, pending, queue).unwrap()).unwrap();
    assert_eq!(result["schema"], json!(COMMIT_RESULT_SCHEMA));
    result["committed"].as_bool().unwrap()
}

#[test]
fn only_a_committed_forward_reaches_the_drain_and_only_once() {
    let pending = PendingRelayEvidence::default();
    let queue = DirectEvidenceQueue::default();
    let now = Instant::now();
    let committed = pending.hold(json!({"call": 1}), now).unwrap();
    let abandoned = pending.hold(json!({"call": 2}), now).unwrap();
    assert_ne!(committed, abandoned);
    assert!(drained(&queue).is_empty());

    assert!(commit_ticket(&committed, &pending, &queue));
    assert!(!commit_ticket(&committed, &pending, &queue));
    assert_eq!(drained(&queue), vec![json!({"call": 1})]);
    assert!(pending.release(&abandoned).is_some());
}

#[test]
fn a_ticket_from_another_resident_releases_nothing() {
    let pending = PendingRelayEvidence::default();
    let other = PendingRelayEvidence::default();
    let queue = DirectEvidenceQueue::default();
    let ticket = other.hold(json!({"call": 1}), Instant::now()).unwrap();
    pending.hold(json!({"call": 2}), Instant::now()).unwrap();

    assert!(!commit_ticket(&ticket, &pending, &queue));
    let no_sequence = format!("{}:", pending.epoch);
    for forged in ["", "1", ":1", "x:1", no_sequence.as_str()] {
        assert!(!commit_ticket(forged, &pending, &queue), "{forged}");
    }
    assert!(drained(&queue).is_empty());
}

#[test]
fn a_full_hold_refuses_until_uncommitted_tickets_expire() {
    let pending = PendingRelayEvidence::default();
    let start = Instant::now();
    for call in 0..MAX_HELD_RECORDS {
        assert!(pending.hold(json!({"call": call}), start).is_some());
    }
    assert!(pending.hold(json!({"call": "late"}), start).is_none());
    let later = start + HOLD_TTL;
    let ticket = pending.hold(json!({"call": "fresh"}), later).unwrap();
    assert_eq!(pending.release(&ticket), Some(json!({"call": "fresh"})));
}

#[test]
fn an_oversized_record_is_not_held() {
    let pending = PendingRelayEvidence::default();
    let large = "x".repeat(MAX_RECORD_BYTES);
    assert!(pending
        .hold(json!({"blob": large}), Instant::now())
        .is_none());
}
