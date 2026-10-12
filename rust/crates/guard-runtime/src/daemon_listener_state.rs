//! Admission state machine of the daemon front door.
//!
//! This is the retired Python `_GuardDaemonHTTPServer` admission logic as a
//! pure state machine: counters, semaphores and the unclassified, pending and
//! saturation-probe tables are plain data, every transition takes the current
//! time and a [`Probe`], and every socket action is returned as an [`Effect`].
//! A [`crate::daemon_listener_driver::Host`] owns the lock and the sockets, so
//! the same code runs against recorded vectors and against live connections.

use std::collections::{HashMap, HashSet};

use guard_contracts::{
    DaemonRequestKind, DAEMON_CONNECTION_ADMISSION_WAIT_MS, DAEMON_REQUEST_READ_TIMEOUT_MS,
    DAEMON_SATURATION_PROBE_WINDOW_MS,
};

pub(crate) type ConnId = u64;

pub(crate) const READ_TIMEOUT_SECONDS: f64 = DAEMON_REQUEST_READ_TIMEOUT_MS as f64 / 1000.0;
pub(crate) const CONNECTION_WAIT_SECONDS: f64 = DAEMON_CONNECTION_ADMISSION_WAIT_MS as f64 / 1000.0;
const PROBE_WINDOW_SECONDS: f64 = DAEMON_SATURATION_PROBE_WINDOW_MS as f64 / 1000.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    pub(crate) request: usize,
    pub(crate) control: usize,
    pub(crate) critical: usize,
    pub(crate) connection: usize,
    pub(crate) guard: usize,
}

impl Limits {
    pub(crate) fn normal_admission_limit(&self) -> usize {
        let capacity = self.connection.min(self.guard);
        let reserved = (self.control + self.critical).min(capacity / 4);
        capacity - reserved
    }
}

/// Socket questions the state machine asks. Answers come from non-consuming
/// peeks of the connection's buffered bytes.
pub(crate) trait Probe {
    fn peek_path(&self, conn: ConnId) -> Option<String>;
    fn headers_complete(&self, conn: ConnId) -> bool;
    fn peer_closed(&self, conn: ConnId) -> bool;
}

/// What the host must do after a transition.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Effect {
    /// Shut the socket down and close it.
    Close(ConnId),
    /// Write the 503 overload response, then close.
    Overload(ConnId),
    /// Hand the connection to the request executor of this kind.
    Submit { conn: ConnId, control: bool },
    /// Wait for a connection permit, then call [`State::resume_accept`].
    WaitPermit(Accept),
}

/// An admission that is parked on the connection permit.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Accept {
    pub(crate) conn: ConnId,
    pub(crate) control: bool,
    pub(crate) pending: bool,
    pub(crate) accepted_at: f64,
    pub(crate) admission_deadline: f64,
}

#[derive(Debug, Clone)]
pub(crate) struct Permits {
    free: usize,
    limit: usize,
}

impl Permits {
    fn new(limit: usize) -> Self {
        Self { free: limit, limit }
    }

    pub(crate) fn try_acquire(&mut self) -> bool {
        if self.free == 0 {
            return false;
        }
        self.free -= 1;
        true
    }

    pub(crate) fn release(&mut self) {
        self.free = (self.free + 1).min(self.limit);
    }

    pub(crate) fn free(&self) -> usize {
        self.free
    }
}

/// Insertion-ordered table; Python dict order decides who is "oldest".
#[derive(Debug, Clone)]
pub(crate) struct Ordered<V> {
    items: Vec<(ConnId, V)>,
}

impl<V: Copy> Ordered<V> {
    fn new() -> Self {
        Self { items: Vec::new() }
    }

    pub(crate) fn insert(&mut self, conn: ConnId, value: V) {
        match self.items.iter_mut().find(|(key, _)| *key == conn) {
            Some(slot) => slot.1 = value,
            None => self.items.push((conn, value)),
        }
    }

    pub(crate) fn remove(&mut self, conn: ConnId) -> Option<V> {
        let index = self.items.iter().position(|(key, _)| *key == conn)?;
        Some(self.items.remove(index).1)
    }

    pub(crate) fn get(&self, conn: ConnId) -> Option<V> {
        self.items
            .iter()
            .find(|(key, _)| *key == conn)
            .map(|item| item.1)
    }

    pub(crate) fn first(&self) -> Option<(ConnId, V)> {
        self.items.first().copied()
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn snapshot(&self) -> Vec<(ConnId, V)> {
        self.items.clone()
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Counters {
    pub(crate) active_requests: usize,
    pub(crate) rejected_requests: u64,
    pub(crate) normal: usize,
    pub(crate) connection_free: usize,
    pub(crate) guard_free: usize,
    pub(crate) request_free: usize,
    pub(crate) control_free: usize,
    pub(crate) critical_free: usize,
    pub(crate) unclassified: usize,
    pub(crate) pending: usize,
    pub(crate) probes: usize,
    pub(crate) metric_rejected: u64,
    pub(crate) metric_accepted: u64,
}

#[derive(Debug)]
pub(crate) struct State {
    pub(crate) limits: Limits,
    pub(crate) connection: Permits,
    pub(crate) guard: Permits,
    request: Permits,
    control: Permits,
    critical: Permits,
    pub(crate) active_requests: usize,
    pub(crate) rejected_requests: u64,
    pub(crate) normal: HashSet<ConnId>,
    kinds: HashMap<ConnId, DaemonRequestKind>,
    pub(crate) accepted_at: HashMap<ConnId, f64>,
    pub(crate) unclassified: Ordered<f64>,
    pub(crate) pending: Ordered<f64>,
    pub(crate) probes: Ordered<f64>,
    pub(crate) closing: bool,
    pub(crate) connection_wait: f64,
    pub(crate) last_activity: f64,
    pub(crate) metric_accepted: u64,
    pub(crate) metric_rejected: u64,
}

impl State {
    /// A state whose connection-permit wait differs from the production 50 ms
    /// (the recorded oracle runs with no wait).
    #[cfg(test)]
    pub(crate) fn with_connection_wait(mut self, seconds: f64) -> Self {
        self.connection_wait = seconds;
        self
    }

    pub(crate) fn new(limits: Limits, now: f64) -> Self {
        Self {
            limits,
            connection: Permits::new(limits.connection),
            guard: Permits::new(limits.guard),
            request: Permits::new(limits.request),
            control: Permits::new(limits.control),
            critical: Permits::new(limits.critical),
            active_requests: 0,
            rejected_requests: 0,
            normal: HashSet::new(),
            kinds: HashMap::new(),
            accepted_at: HashMap::new(),
            unclassified: Ordered::new(),
            pending: Ordered::new(),
            probes: Ordered::new(),
            closing: false,
            connection_wait: CONNECTION_WAIT_SECONDS,
            last_activity: now,
            metric_accepted: 0,
            metric_rejected: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn counters(&self) -> Counters {
        Counters {
            active_requests: self.active_requests,
            rejected_requests: self.rejected_requests,
            normal: self.normal.len(),
            connection_free: self.connection.free(),
            guard_free: self.guard.free(),
            request_free: self.request.free(),
            control_free: self.control.free(),
            critical_free: self.critical.free(),
            unclassified: self.unclassified.len(),
            pending: self.pending.len(),
            probes: self.probes.len(),
            metric_rejected: self.metric_rejected,
            metric_accepted: self.metric_accepted,
        }
    }

    fn permits_for(&mut self, kind: DaemonRequestKind) -> &mut Permits {
        match kind {
            DaemonRequestKind::Critical => &mut self.critical,
            DaemonRequestKind::Control => &mut self.control,
            DaemonRequestKind::General => &mut self.request,
        }
    }

    pub(crate) fn normal_full(&self) -> bool {
        self.normal.len() >= self.limits.normal_admission_limit()
    }

    pub(crate) fn reserve_normal(&mut self, conn: ConnId) -> bool {
        if self.normal.len() >= self.limits.normal_admission_limit() {
            return false;
        }
        self.normal.insert(conn);
        true
    }

    /// An overload the front door refuses before any lease exists.
    pub(crate) fn overload(&mut self, conn: ConnId) -> Effect {
        self.metric_rejected += 1;
        Effect::Overload(conn)
    }

    /// Entry point for a freshly accepted connection.
    pub(crate) fn process_request(
        &mut self,
        conn: ConnId,
        now: f64,
        probe: &dyn Probe,
    ) -> Vec<Effect> {
        let path = probe.peek_path(conn);
        let control = path
            .as_deref()
            .is_some_and(|path| DaemonRequestKind::of_path(path).is_priority());
        if path.is_some() && !control && self.normal_full() {
            self.rejected_requests += 1;
            return vec![self.overload(conn)];
        }
        let mut reserved = false;
        if !control {
            reserved = self.reserve_normal(conn);
            if path.is_none() && !reserved && self.normal_full() && self.connection.free() > 0 {
                return self.park_saturation_probe(conn, now);
            }
        }
        let accept = Accept {
            conn,
            control,
            pending: !control && !reserved,
            accepted_at: now,
            admission_deadline: now + self.connection_wait,
        };
        self.accept_classified(accept, now, probe)
    }

    fn park_saturation_probe(&mut self, conn: ConnId, now: f64) -> Vec<Effect> {
        let limit = self.limits.connection.max(1);
        let mut effects = Vec::new();
        if self.probes.len() >= limit {
            if let Some((displaced, _)) = self.probes.first() {
                self.probes.remove(displaced);
                self.rejected_requests += 1;
                effects.push(Effect::Close(displaced));
            }
        }
        self.probes.insert(conn, now + PROBE_WINDOW_SECONDS);
        effects
    }

    pub(crate) fn accept_classified(
        &mut self,
        accept: Accept,
        now: f64,
        probe: &dyn Probe,
    ) -> Vec<Effect> {
        if !self.guard.try_acquire() {
            self.normal.remove(&accept.conn);
            self.rejected_requests += 1;
            return vec![self.overload(accept.conn)];
        }
        self.metric_accepted += 1;
        if self.connection.try_acquire() {
            return self.admitted(accept, now, probe);
        }
        let mut effects = self.evict_oldest_unclassified(now);
        effects.push(Effect::WaitPermit(accept));
        effects
    }

    /// Continue a parked admission once the host finished waiting.
    pub(crate) fn resume_accept(
        &mut self,
        accept: Accept,
        now: f64,
        probe: &dyn Probe,
    ) -> Vec<Effect> {
        if self.connection.try_acquire() {
            return self.admitted(accept, now, probe);
        }
        self.rejected_requests += 1;
        self.guard.release();
        self.normal.remove(&accept.conn);
        vec![Effect::Close(accept.conn)]
    }

    fn admitted(&mut self, accept: Accept, now: f64, probe: &dyn Probe) -> Vec<Effect> {
        let conn = accept.conn;
        if self.closing {
            self.rejected_requests += 1;
            self.connection.release();
            self.guard.release();
            self.normal.remove(&conn);
            return vec![Effect::Close(conn)];
        }
        self.active_requests += 1;
        self.last_activity = now;
        self.accepted_at.insert(conn, accept.accepted_at);
        self.unclassified
            .insert(conn, accept.accepted_at + READ_TIMEOUT_SECONDS);
        if accept.pending {
            if self.unclassified.get(conn).is_some() {
                let deadline = accept
                    .admission_deadline
                    .min(accept.accepted_at + READ_TIMEOUT_SECONDS);
                self.pending.insert(conn, deadline);
            }
            return Vec::new();
        }
        self.submit_transport(conn, accept.control, probe)
    }

    pub(crate) fn submit_transport(
        &mut self,
        conn: ConnId,
        control: bool,
        probe: &dyn Probe,
    ) -> Vec<Effect> {
        if !probe.headers_complete(conn) {
            if let Some(deadline) = self.unclassified.get(conn) {
                self.pending.insert(conn, deadline);
                return Vec::new();
            }
        }
        let control = control
            || probe
                .peek_path(conn)
                .is_some_and(|path| DaemonRequestKind::of_path(&path).is_priority());
        vec![Effect::Submit { conn, control }]
    }

    /// The executor refused the connection.
    pub(crate) fn submit_failed(&mut self, conn: ConnId, now: f64) -> Vec<Effect> {
        self.rejected_requests += 1;
        self.discard(conn, now)
    }

    fn evict_oldest_unclassified(&mut self, now: f64) -> Vec<Effect> {
        let Some((oldest, _)) = self.unclassified.first() else {
            return Vec::new();
        };
        let effects = self.discard(oldest, now);
        self.rejected_requests += 1;
        effects
    }

    /// Close a connection and give back everything it holds.
    pub(crate) fn discard(&mut self, conn: ConnId, now: f64) -> Vec<Effect> {
        self.release(conn, now);
        vec![Effect::Close(conn)]
    }

    /// Return a connection's capacity. Safe to call more than once.
    pub(crate) fn release(&mut self, conn: ConnId, now: f64) {
        self.classify(conn);
        let was_active = self.accepted_at.remove(&conn).is_some();
        self.normal.remove(&conn);
        if was_active {
            self.active_requests -= 1;
            self.last_activity = now;
        }
        if let Some(kind) = self.kinds.remove(&conn) {
            self.permits_for(kind).release();
        }
        if was_active {
            self.connection.release();
            self.guard.release();
        }
    }

    /// The request head was read: the connection is no longer evictable.
    pub(crate) fn classify(&mut self, conn: ConnId) {
        self.unclassified.remove(conn);
        self.pending.remove(conn);
        self.probes.remove(conn);
    }

    /// Per-request capacity claim; returns the kind and whether it was granted
    /// without waiting. A priority request that was not granted may wait.
    pub(crate) fn claim_start(
        &mut self,
        conn: ConnId,
        path: &str,
        now: f64,
    ) -> (DaemonRequestKind, bool) {
        let kind = DaemonRequestKind::of_path(path);
        let previous = self.kinds.remove(&conn);
        if previous.is_some() && self.accepted_at.contains_key(&conn) {
            self.accepted_at.insert(conn, now);
        }
        if let Some(previous) = previous {
            self.permits_for(previous).release();
        }
        let granted = self.permits_for(kind).try_acquire();
        (kind, granted)
    }

    pub(crate) fn kind_available(&mut self, kind: DaemonRequestKind) -> bool {
        self.permits_for(kind).free() > 0
    }

    /// Retry the acquire after a priority wait.
    pub(crate) fn claim_retry(&mut self, kind: DaemonRequestKind) -> bool {
        self.permits_for(kind).try_acquire()
    }

    pub(crate) fn claim_complete(
        &mut self,
        conn: ConnId,
        kind: DaemonRequestKind,
        granted: bool,
    ) -> bool {
        if granted {
            self.kinds.insert(conn, kind);
        } else {
            self.rejected_requests += 1;
        }
        granted
    }
}
