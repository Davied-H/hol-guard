use super::{fence_wait, poll_through_fence, POLICY_SOURCE_FENCE_ERROR, POLL_INTERVAL};
use crate::hook_direct::HookDirectDefer;
use std::time::{Duration, Instant};

fn busy() -> Result<Vec<u8>, String> {
    Err(POLICY_SOURCE_FENCE_ERROR.to_owned())
}

#[test]
fn wait_is_capped_by_the_rebuild_bound_and_the_budget() {
    assert_eq!(
        fence_wait(Duration::from_millis(1_000)),
        Duration::from_millis(750)
    );
    assert_eq!(
        fence_wait(Duration::from_millis(9_000)),
        Duration::from_millis(8_000)
    );
    assert_eq!(fence_wait(Duration::from_millis(200)), Duration::ZERO);
    assert_eq!(fence_wait(Duration::ZERO), Duration::ZERO);
}

#[test]
fn fence_that_clears_within_the_budget_is_admitted() {
    let mut calls = 0;
    let mut slept = Vec::new();
    let edge = poll_through_fence(
        Duration::from_millis(750),
        || {
            calls += 1;
            if calls < 3 {
                busy()
            } else {
                Ok(b"edge".to_vec())
            }
        },
        |interval| slept.push(interval),
    );
    assert_eq!(edge.unwrap(), b"edge");
    assert_eq!(calls, 3);
    assert_eq!(slept, vec![POLL_INTERVAL, POLL_INTERVAL]);
}

#[test]
fn spent_wait_defers_without_an_answer() {
    let started = Instant::now();
    let mut calls = 0;
    let result = poll_through_fence(
        Duration::from_millis(350),
        || {
            calls += 1;
            busy()
        },
        std::thread::sleep,
    );
    assert_eq!(result, Err(HookDirectDefer::EdgeFailed));
    assert!(calls <= 4, "polled {calls} times");
    assert!(started.elapsed() < Duration::from_millis(600));
}

#[test]
fn no_budget_never_waits_and_other_errors_never_retry() {
    let mut calls = 0;
    let result = poll_through_fence(
        Duration::ZERO,
        || {
            calls += 1;
            busy()
        },
        |_| panic!("no wait without budget"),
    );
    assert_eq!(result, Err(HookDirectDefer::EdgeFailed));
    assert_eq!(calls, 1);
    let mut calls = 0;
    let result = poll_through_fence(
        Duration::from_millis(750),
        || {
            calls += 1;
            Err("native_business_source_authority_invalid".to_owned())
        },
        |_| panic!("other errors never wait"),
    );
    assert_eq!(result, Err(HookDirectDefer::EdgeFailed));
    assert_eq!(calls, 1);
}
