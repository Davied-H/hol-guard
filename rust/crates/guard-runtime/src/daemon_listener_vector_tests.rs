//! Replays admission scenarios recorded from the retired Python daemon server.
//!
//! The recorder drove the old `_GuardDaemonHTTPServer` over real socket pairs
//! with virtual time and zero admission waits. Here the same steps drive the
//! Rust state machine through the shared driver, and every counter, permit
//! count and per-connection outcome must match after every step.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io::Read;

use flate2::read::GzDecoder;
use guard_contracts::{DaemonRequestKind, DAEMON_CRITICAL_PATHS};
use serde_json::{json, Value};

use crate::daemon_listener_driver::{self as driver, Host};
use crate::daemon_listener_request_line::{peek_request_path, request_headers_complete};
use crate::daemon_listener_state::{Accept, ConnId, Effect, Limits, Probe, State};

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/daemon_admission_vectors.json.gz");

fn load() -> Value {
    let mut text = String::new();
    GzDecoder::new(VECTORS).read_to_string(&mut text).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn latin1(text: &str) -> Vec<u8> {
    text.chars().map(|ch| ch as u32 as u8).collect()
}

#[derive(Default)]
struct Conn {
    buffer: Vec<u8>,
    peer_closed: bool,
    closed: bool,
    overload: bool,
    submitted: Option<&'static str>,
}

struct Replay {
    state: RefCell<State>,
    now: Cell<f64>,
    conns: RefCell<HashMap<ConnId, Conn>>,
    names: RefCell<Vec<String>>,
}

impl Replay {
    fn new(limits: Limits) -> Self {
        Self {
            state: RefCell::new(State::new(limits, 1_000.0).with_connection_wait(0.0)),
            now: Cell::new(1_000.0),
            conns: RefCell::new(HashMap::new()),
            names: RefCell::new(Vec::new()),
        }
    }

    fn id(&self, name: &str) -> ConnId {
        self.names
            .borrow()
            .iter()
            .position(|known| known == name)
            .unwrap() as ConnId
    }

    fn add(&self, name: &str, data: &str) -> ConnId {
        self.names.borrow_mut().push(name.to_owned());
        let id = self.id(name);
        let conn = Conn {
            buffer: latin1(data),
            ..Conn::default()
        };
        self.conns.borrow_mut().insert(id, conn);
        id
    }

    fn observe(&self) -> Value {
        let counters = self.state.borrow().counters();
        let mut conns = serde_json::Map::new();
        for (index, name) in self.names.borrow().iter().enumerate() {
            let conn = &self.conns.borrow()[&(index as ConnId)];
            let mut entry = json!({"closed": conn.closed, "overload": conn.overload});
            if let Some(kind) = conn.submitted {
                entry["submitted"] = json!(kind);
            }
            conns.insert(name.clone(), entry);
        }
        json!({
            "active_requests": counters.active_requests,
            "rejected_requests": counters.rejected_requests,
            "normal": counters.normal,
            "connection_free": counters.connection_free,
            "guard_free": counters.guard_free,
            "request_free": counters.request_free,
            "control_free": counters.control_free,
            "critical_free": counters.critical_free,
            "unclassified": counters.unclassified,
            "pending": counters.pending,
            "probes": counters.probes,
            "metric_rejected": counters.metric_rejected,
            "metric_accepted": counters.metric_accepted,
            "conns": conns,
        })
    }
}

impl Probe for Replay {
    fn peek_path(&self, conn: ConnId) -> Option<String> {
        let conns = self.conns.borrow();
        let conn = &conns[&conn];
        if conn.closed {
            return None;
        }
        peek_request_path(&conn.buffer)
    }

    fn headers_complete(&self, conn: ConnId) -> bool {
        let conns = self.conns.borrow();
        let conn = &conns[&conn];
        !conn.closed && request_headers_complete(&conn.buffer)
    }

    fn peer_closed(&self, conn: ConnId) -> bool {
        let conns = self.conns.borrow();
        let conn = &conns[&conn];
        conn.closed || (conn.peer_closed && conn.buffer.is_empty())
    }
}

impl Host for Replay {
    fn with_state<T>(&self, f: impl FnOnce(&mut State, f64, &dyn Probe) -> T) -> T {
        f(&mut self.state.borrow_mut(), self.now.get(), self)
    }

    fn apply(&self, effect: &Effect) -> bool {
        let mut conns = self.conns.borrow_mut();
        match effect {
            Effect::Close(conn) => conns.get_mut(conn).unwrap().closed = true,
            Effect::Overload(conn) => {
                let conn = conns.get_mut(conn).unwrap();
                conn.closed = true;
                conn.overload = true;
            }
            Effect::Submit { conn, control } => {
                conns.get_mut(conn).unwrap().submitted =
                    Some(if *control { "control" } else { "general" });
            }
            Effect::WaitPermit(_) => unreachable!("the driver resolves waits"),
        }
        true
    }

    fn wait_connection_permit(&self, _accept: &Accept) {}

    fn wait_claim_permit(&self, _kind: DaemonRequestKind) {}
}

fn limits_of(value: &Value) -> Limits {
    let get = |key: &str| value[key].as_u64().unwrap() as usize;
    Limits {
        request: get("request"),
        control: get("control"),
        critical: get("critical"),
        connection: get("connection"),
        guard: get("guard"),
    }
}

fn apply(replay: &Replay, step: &Value) -> Option<bool> {
    let name = step["name"].as_str().unwrap_or_default();
    match step["op"].as_str().unwrap() {
        "connect" => {
            let id = replay.add(name, step["data"].as_str().unwrap());
            driver::process_request(replay, id);
            None
        }
        "send" => {
            let mut conns = replay.conns.borrow_mut();
            let conn = conns.get_mut(&replay.id(name)).unwrap();
            // The recorded client socket is closed after `peer_close`, so later sends fail.
            if !conn.closed && !conn.peer_closed {
                conn.buffer.extend(latin1(step["data"].as_str().unwrap()));
            }
            None
        }
        "peer_close" => {
            replay
                .conns
                .borrow_mut()
                .get_mut(&replay.id(name))
                .unwrap()
                .peer_closed = true;
            None
        }
        "tick" => {
            replay
                .now
                .set(replay.now.get() + step["dt"].as_f64().unwrap());
            driver::tick(replay);
            None
        }
        "claim" => Some(driver::claim(
            replay,
            replay.id(name),
            step["path"].as_str().unwrap(),
        )),
        "finish" => {
            let id = replay.id(name);
            replay.apply(&Effect::Close(id));
            driver::release(replay, id);
            None
        }
        "closing" => {
            replay.state.borrow_mut().closing = true;
            None
        }
        other => panic!("unknown step {other}"),
    }
}

#[test]
fn recorded_scenarios_replay_identically() {
    let vectors = load();
    let scenarios = vectors["scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 200, "fixture lost scenarios");
    for scenario in scenarios {
        let replay = Replay::new(limits_of(&scenario["limits"]));
        for (index, entry) in scenario["trace"].as_array().unwrap().iter().enumerate() {
            let result = apply(&replay, &entry["step"]);
            let expected = entry["result"].as_bool();
            assert_eq!(result, expected, "{} step {index} result", scenario["name"]);
            assert_eq!(
                replay.observe(),
                entry["observed"],
                "{} step {index}: {}",
                scenario["name"],
                entry["step"]
            );
        }
    }
}

#[test]
fn request_line_classification_matches_python() {
    let vectors = load();
    for case in vectors["pure"]["peek"].as_array().unwrap() {
        let input = latin1(case["input"].as_str().unwrap());
        let expected = case["path"].as_str().map(str::to_owned);
        assert_eq!(
            peek_request_path(&input),
            expected,
            "peek {}",
            case["input"]
        );
    }
    for case in vectors["pure"]["headers"].as_array().unwrap() {
        let input = latin1(case["input"].as_str().unwrap());
        let expected = case["complete"].as_bool().unwrap();
        assert_eq!(
            request_headers_complete(&input),
            expected,
            "headers {:?}",
            case["input"]
        );
    }
}

#[test]
fn request_kind_and_normal_limit_match_python() {
    let vectors = load();
    for case in vectors["pure"]["kind"].as_array().unwrap() {
        let kind = match DaemonRequestKind::of_path(case["input"].as_str().unwrap()) {
            DaemonRequestKind::Critical => "critical",
            DaemonRequestKind::Control => "control",
            DaemonRequestKind::General => "general",
        };
        assert_eq!(kind, case["kind"], "kind {}", case["input"]);
    }
    for case in vectors["pure"]["limit"].as_array().unwrap() {
        let limits = limits_of(&case["input"]);
        assert_eq!(
            limits.normal_admission_limit() as u64,
            case["normal_limit"],
            "{}",
            case["input"]
        );
    }
    assert!(DAEMON_CRITICAL_PATHS.contains(&"/healthz"));
}
