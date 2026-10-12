use super::{
    drain, DirectEvidenceQueue, HookDirectEvidenceDrainRequestV1, MAX_QUEUED_RECORDS,
    MAX_RECORD_BYTES,
};
use serde_json::{json, Value};

fn request(max_records: Option<usize>) -> HookDirectEvidenceDrainRequestV1 {
    HookDirectEvidenceDrainRequestV1 {
        guard_home: "/home/guard/.hol-guard".to_owned(),
        max_records,
    }
}

fn drained(queue: &DirectEvidenceQueue, max_records: Option<usize>) -> Value {
    serde_json::from_slice(&drain(&request(max_records), queue).unwrap()).unwrap()
}

#[test]
fn records_drain_once_in_order() {
    let queue = DirectEvidenceQueue::default();
    for index in 0..3 {
        assert!(queue.offer(json!({ "index": index })));
    }
    let page = drained(&queue, Some(2));
    assert_eq!(page["schema"], "guard-hook-direct-evidence.v1");
    assert_eq!(page["records"], json!([{ "index": 0 }, { "index": 1 }]));
    assert_eq!(page["remaining"], 1);
    let page = drained(&queue, None);
    assert_eq!(page["records"], json!([{ "index": 2 }]));
    assert_eq!(page["remaining"], 0);
    assert_eq!(drained(&queue, None)["records"], json!([]));
}

#[test]
fn a_full_queue_refuses_new_records() {
    let queue = DirectEvidenceQueue::default();
    for index in 0..MAX_QUEUED_RECORDS {
        assert!(queue.offer(json!(index)));
    }
    assert!(!queue.offer(json!("overflow")));
    drained(&queue, Some(1));
    assert!(queue.offer(json!("fits again")));
}

#[test]
fn an_oversized_record_is_refused() {
    let queue = DirectEvidenceQueue::default();
    let large = "x".repeat(MAX_RECORD_BYTES);
    assert!(!queue.offer(json!({ "payload": large })));
    assert_eq!(drained(&queue, None)["remaining"], 0);
}

#[test]
fn a_page_stops_before_the_response_cap() {
    let queue = DirectEvidenceQueue::default();
    let large = "x".repeat(MAX_RECORD_BYTES - 64);
    assert!(queue.offer(json!({ "payload": large.clone() })));
    assert!(queue.offer(json!({ "payload": large })));
    let page = drained(&queue, None);
    assert_eq!(page["records"].as_array().unwrap().len(), 1);
    assert_eq!(page["remaining"], 1);
}
