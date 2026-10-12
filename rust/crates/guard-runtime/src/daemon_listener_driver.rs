//! Orchestration shared by the live listener and the recorded-vector replay.
//!
//! A [`Host`] owns the lock around [`State`], the sockets the effects act on,
//! and the two bounded waits (the connection permit and the priority capacity
//! claim). Everything else, including the order of watchdog transitions, is
//! written once here.

use std::collections::VecDeque;

use guard_contracts::DaemonRequestKind;

use crate::daemon_listener_state::{Accept, ConnId, Effect, Probe, State};

pub(crate) trait Host {
    /// Run `f` under the state lock with the current monotonic time.
    fn with_state<T>(&self, f: impl FnOnce(&mut State, f64, &dyn Probe) -> T) -> T;
    /// Act on a socket effect. Returns `false` only when a submit is refused.
    fn apply(&self, effect: &Effect) -> bool;
    /// Block until the connection permit may be free, or the admission wait ends.
    fn wait_connection_permit(&self, accept: &Accept);
    /// Block until a priority capacity pool may have room, or the wait ends.
    fn wait_claim_permit(&self, kind: DaemonRequestKind);
}

/// Apply effects in order, resolving permit waits and refused submits in place.
fn settle<H: Host>(host: &H, effects: Vec<Effect>) {
    let mut queue: VecDeque<Effect> = effects.into();
    while let Some(effect) = queue.pop_front() {
        let follow_up = match effect {
            Effect::WaitPermit(accept) => {
                host.wait_connection_permit(&accept);
                host.with_state(|state, now, probe| state.resume_accept(accept, now, probe))
            }
            Effect::Submit { conn, .. } => {
                if host.apply(&effect) {
                    Vec::new()
                } else {
                    host.with_state(|state, now, _| state.submit_failed(conn, now))
                }
            }
            other => {
                host.apply(&other);
                Vec::new()
            }
        };
        for (index, next) in follow_up.into_iter().enumerate() {
            queue.insert(index, next);
        }
    }
}

pub(crate) fn run<H, F>(host: &H, transition: F)
where
    H: Host,
    F: FnOnce(&mut State, f64, &dyn Probe) -> Vec<Effect>,
{
    let effects = host.with_state(transition);
    settle(host, effects);
}

pub(crate) fn process_request<H: Host>(host: &H, conn: ConnId) {
    run(host, |state, now, probe| {
        state.process_request(conn, now, probe)
    });
}

/// One watchdog iteration: pending heads, saturation probes, then expiry.
pub(crate) fn tick<H: Host>(host: &H) {
    for conn in host.with_state(|state, _, _| state.pending_snapshot()) {
        run(host, |state, now, probe| {
            state.advance_pending_one(conn, now, probe)
        });
    }
    for conn in host.with_state(|state, _, _| state.probe_snapshot()) {
        run(host, |state, now, probe| {
            state.advance_probe_one(conn, now, probe)
        });
    }
    for conn in host.with_state(|state, now, _| state.expired_snapshot(now)) {
        run(host, |state, now, probe| state.expire_one(conn, now, probe));
    }
}

/// Charge one request to its capacity pool; `false` means refuse it.
pub(crate) fn claim<H: Host>(host: &H, conn: ConnId, path: &str) -> bool {
    let (kind, immediate) = host.with_state(|state, now, _| state.claim_start(conn, path, now));
    let granted = immediate
        || (kind.is_priority() && {
            host.wait_claim_permit(kind);
            host.with_state(|state, _, _| state.claim_retry(kind))
        });
    host.with_state(|state, _, _| state.claim_complete(conn, kind, granted))
}

/// Return a finished connection's capacity.
pub(crate) fn release<H: Host>(host: &H, conn: ConnId) {
    host.with_state(|state, now, _| state.release(conn, now));
}
