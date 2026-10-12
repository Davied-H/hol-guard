//! Watchdog transitions of the daemon front door: they advance connections
//! whose request head was incomplete at accept time, classify parked
//! saturation probes, and expire connections that never finished a head.
//!
//! Each transition handles one connection so that a host can resolve a
//! [`crate::daemon_listener_state::Effect::WaitPermit`] before it moves on,
//! which is the order the retired Python watchdog loop observed.

use guard_contracts::DaemonRequestKind;

use crate::daemon_listener_state::{Accept, ConnId, Effect, Probe, State};

fn is_priority(path: Option<&str>) -> bool {
    path.is_some_and(|path| DaemonRequestKind::of_path(path).is_priority())
}

impl State {
    /// Connections parked for a complete request head, oldest first.
    pub(crate) fn pending_snapshot(&self) -> Vec<ConnId> {
        self.pending
            .snapshot()
            .into_iter()
            .filter(|(conn, _)| self.unclassified.get(*conn).is_some())
            .map(|(conn, _)| conn)
            .collect()
    }

    pub(crate) fn probe_snapshot(&self) -> Vec<ConnId> {
        self.probes
            .snapshot()
            .into_iter()
            .map(|(conn, _)| conn)
            .collect()
    }

    /// Unclassified connections whose read deadline has passed.
    pub(crate) fn expired_snapshot(&self, now: f64) -> Vec<ConnId> {
        self.unclassified
            .snapshot()
            .into_iter()
            .filter(|(_, deadline)| *deadline <= now)
            .map(|(conn, _)| conn)
            .collect()
    }

    pub(crate) fn advance_pending_one(
        &mut self,
        conn: ConnId,
        now: f64,
        probe: &dyn Probe,
    ) -> Vec<Effect> {
        let Some(deadline) = self.pending.get(conn) else {
            return Vec::new();
        };
        if now >= deadline || probe.peer_closed(conn) {
            return self.discard(conn, now);
        }
        if !probe.headers_complete(conn) {
            return Vec::new();
        }
        let control = is_priority(probe.peek_path(conn).as_deref());
        if self.pending.remove(conn).is_none() {
            return Vec::new();
        }
        self.unclassified.remove(conn);
        // The socket may have reserved its seat before its head was ready; a
        // full pool then fails a second reserve although it already counts.
        if !control && !self.reserve_normal(conn) && !self.normal.contains(&conn) {
            self.rejected_requests += 1;
            return self.discard(conn, now);
        }
        self.submit_transport(conn, control, probe)
    }

    pub(crate) fn advance_probe_one(
        &mut self,
        conn: ConnId,
        now: f64,
        probe: &dyn Probe,
    ) -> Vec<Effect> {
        let Some(deadline) = self.probes.get(conn) else {
            return Vec::new();
        };
        let path = probe.peek_path(conn);
        if path.is_none() && now < deadline {
            return Vec::new();
        }
        if self.probes.remove(conn).is_none() {
            return Vec::new();
        }
        if !is_priority(path.as_deref()) {
            self.rejected_requests += 1;
            return if path.is_none() {
                vec![Effect::Close(conn)]
            } else {
                vec![self.overload(conn)]
            };
        }
        let accept = Accept {
            conn,
            control: true,
            pending: false,
            accepted_at: now,
            admission_deadline: now + self.connection_wait,
        };
        self.accept_classified(accept, now, probe)
    }

    pub(crate) fn expire_one(&mut self, conn: ConnId, now: f64, probe: &dyn Probe) -> Vec<Effect> {
        let headers_complete = probe.headers_complete(conn);
        match self.unclassified.get(conn) {
            Some(deadline) if deadline <= now => {}
            _ => return Vec::new(),
        }
        if self.pending.get(conn).is_some() {
            return self.discard(conn, now);
        }
        self.unclassified.remove(conn);
        if headers_complete {
            Vec::new()
        } else {
            vec![Effect::Close(conn)]
        }
    }
}
