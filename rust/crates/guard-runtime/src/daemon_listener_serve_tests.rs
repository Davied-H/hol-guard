//! Live listener tests against a mock upstream on loopback.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::daemon_listener_serve::{start, Running};
use crate::daemon_listener_state::Limits;

const LOCAL: &str = "127.0.0.1:0";
const HOOK: &str = "GET /v1/hook HTTP/1.1\r\nHost: x\r\n\r\n";
const HEALTH: &str = "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n";

fn small_limits() -> Limits {
    Limits {
        request: 3,
        control: 1,
        critical: 1,
        connection: 4,
        guard: 4,
    }
}

/// Upstream that answers `/healthz` at once and holds every other request
/// until `release` is set.
fn mock_upstream(release: Arc<AtomicBool>) -> SocketAddr {
    let listener = TcpListener::bind(LOCAL).unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let release = Arc::clone(&release);
            thread::spawn(move || answer(stream, &release));
        }
    });
    address
}

fn answer(mut stream: TcpStream, release: &AtomicBool) {
    let mut head = Vec::new();
    let mut chunk = [0u8; 512];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(read) => head.extend_from_slice(&chunk[..read]),
        }
    }
    if !head.starts_with(b"GET /healthz") {
        while !release.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(5));
        }
    }
    let _ = stream.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
}

fn listener(upstream: SocketAddr, limits: Limits) -> Running {
    start(LOCAL.parse().unwrap(), upstream, limits).unwrap()
}

fn client(running: &Running, request: &str) -> TcpStream {
    let mut stream = TcpStream::connect(running.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    stream
}

fn read_all(stream: &mut TcpStream) -> String {
    let mut body = Vec::new();
    let _ = stream.read_to_end(&mut body);
    String::from_utf8_lossy(&body).into_owned()
}

fn wait_for(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn assert_idle(running: &Running, limits: Limits) {
    wait_for("capacity to return", || {
        let counters = running.front.counters();
        counters.active_requests == 0
            && counters.connection_free == limits.connection
            && counters.guard_free == limits.guard
            && counters.request_free == limits.request
            && counters.normal == 0
    });
}

#[test]
fn request_is_spliced_and_capacity_returns() {
    let release = Arc::new(AtomicBool::new(true));
    let running = listener(mock_upstream(release), small_limits());
    let mut stream = client(&running, HOOK);
    assert!(read_all(&mut stream).ends_with("\r\n\r\nok"));
    assert_idle(&running, small_limits());
    running.stop();
}

#[test]
fn saturated_normal_pool_refuses_hooks_but_serves_health() {
    let release = Arc::new(AtomicBool::new(false));
    let running = listener(mock_upstream(Arc::clone(&release)), small_limits());
    let held: Vec<TcpStream> = (0..3).map(|_| client(&running, HOOK)).collect();
    wait_for("three admitted hooks", || {
        running.front.counters().active_requests == 3
    });
    let mut refused = client(&running, HOOK);
    let reply = read_all(&mut refused);
    assert!(reply.starts_with("HTTP/1.1 503"), "{reply}");
    assert!(reply.contains("daemon_overloaded") && reply.contains("Retry-After: 1"));
    let mut health = client(&running, HEALTH);
    assert!(read_all(&mut health).ends_with("\r\n\r\nok"));
    release.store(true, Ordering::Release);
    for mut stream in held {
        assert!(read_all(&mut stream).ends_with("\r\n\r\nok"));
    }
    let counters = running.front.counters();
    assert!(counters.rejected_requests >= 1 && counters.metric_rejected >= 1);
    assert_idle(&running, small_limits());
    running.stop();
}

#[test]
fn general_request_over_its_pool_is_refused_per_request() {
    let release = Arc::new(AtomicBool::new(false));
    let limits = Limits {
        request: 1,
        control: 1,
        critical: 1,
        connection: 8,
        guard: 8,
    };
    let running = listener(mock_upstream(Arc::clone(&release)), limits);
    let held = client(&running, HOOK);
    wait_for("first hook claimed", || {
        running.front.counters().request_free == 0
    });
    let mut refused = client(&running, HOOK);
    assert!(read_all(&mut refused).starts_with("HTTP/1.1 503"));
    release.store(true, Ordering::Release);
    drop(held);
    assert_idle(&running, limits);
    running.stop();
}

#[test]
fn unreachable_upstream_closes_without_a_reply() {
    let dead = TcpListener::bind(LOCAL).unwrap().local_addr().unwrap();
    let running = listener(dead, small_limits());
    let mut stream = client(&running, HOOK);
    assert_eq!(read_all(&mut stream), "");
    assert_idle(&running, small_limits());
    running.stop();
}

#[test]
fn incomplete_request_head_is_closed_at_the_read_deadline() {
    let release = Arc::new(AtomicBool::new(true));
    let running = listener(mock_upstream(release), small_limits());
    let started = Instant::now();
    let mut stream = client(&running, "GET /v1/hook HT");
    assert_eq!(read_all(&mut stream), "");
    assert!(
        started.elapsed() >= Duration::from_millis(350),
        "closed before the read deadline"
    );
    assert_idle(&running, small_limits());
    running.stop();
}
