//! Live host for the daemon front door: a loopback TCP listener that admits
//! connections with the [`State`] machine and splices admitted ones to a
//! private upstream. The admission waits, the watchdog cadence and every limit
//! come from the contract the retired Python server enforced.

use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::thread;
use std::time::{Duration, Instant};

use guard_contracts::{
    DaemonRequestKind, DAEMON_CONTROL_ADMISSION_WAIT_MS, DAEMON_MAX_ACTIVE_SLOTS,
    DAEMON_MAX_ACTIVE_SLOTS_CEILING, DAEMON_MAX_CONNECTIONS, DAEMON_MAX_CONTROL_REQUESTS,
    DAEMON_MAX_CRITICAL_REQUESTS, DAEMON_MAX_GENERAL_REQUESTS, DAEMON_OVERLOAD_DRAIN_BYTES,
    DAEMON_OVERLOAD_DRAIN_TIMEOUT_MS, DAEMON_PEEK_HEADER_BYTES, DAEMON_PEEK_LINE_BYTES,
    DAEMON_WATCHDOG_POLL_MS,
};
use nix::sys::socket::{recv, MsgFlags};

use crate::daemon_listener_driver::{self as driver, Host};
use crate::daemon_listener_proxy::{splice, write_overload};
use crate::daemon_listener_request_line::{peek_request_path, request_headers_complete};
#[cfg(test)]
use crate::daemon_listener_state::Counters;
use crate::daemon_listener_state::{Accept, ConnId, Effect, Limits, Probe, State};

const ACTIVE_SLOTS_ENV: &str = "HOL_GUARD_DAEMON_MAX_ACTIVE_REQUESTS";

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Admission limits; the active-slot count honors the same override and
/// clamp the Python server applied.
pub(crate) fn limits_from_env() -> Limits {
    let guard = std::env::var(ACTIVE_SLOTS_ENV)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .map_or(DAEMON_MAX_ACTIVE_SLOTS, |value| {
            value.clamp(1, DAEMON_MAX_ACTIVE_SLOTS_CEILING as i64) as usize
        });
    Limits {
        request: DAEMON_MAX_GENERAL_REQUESTS,
        control: DAEMON_MAX_CONTROL_REQUESTS,
        critical: DAEMON_MAX_CRITICAL_REQUESTS,
        connection: DAEMON_MAX_CONNECTIONS,
        guard,
    }
}

pub(crate) struct Front {
    state: Mutex<State>,
    wake: Condvar,
    conns: Mutex<HashMap<ConnId, TcpStream>>,
    epoch: Instant,
    upstream: SocketAddr,
    next_id: AtomicU64,
    stopped: AtomicBool,
    me: Weak<Front>,
}

/// Non-consuming, non-blocking look at the connection's buffered bytes. An
/// empty buffer on an open idle peer is `EAGAIN`; an empty `Ok` is a close.
fn peek(stream: &TcpStream, capacity: usize) -> Result<Vec<u8>, nix::errno::Errno> {
    let mut buffer = vec![0u8; capacity];
    let read = recv(
        stream.as_raw_fd(),
        &mut buffer,
        MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT,
    )?;
    buffer.truncate(read);
    Ok(buffer)
}

impl Front {
    fn now(&self) -> f64 {
        self.epoch.elapsed().as_secs_f64()
    }

    fn with_stream<T>(&self, conn: ConnId, f: impl FnOnce(&TcpStream) -> T) -> Option<T> {
        lock(&self.conns).get(&conn).map(f)
    }

    fn wait_until(&self, deadline: f64, mut ready: impl FnMut(&mut State) -> bool) {
        let mut guard = lock(&self.state);
        loop {
            let remaining = deadline - self.now();
            if ready(&mut guard) || remaining <= 0.0 {
                return;
            }
            let wait = Duration::from_secs_f64(remaining);
            guard = self
                .wake
                .wait_timeout(guard, wait)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    fn close(&self, conn: ConnId) {
        if let Some(stream) = lock(&self.conns).remove(&conn) {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    fn overload(&self, conn: ConnId) {
        let Some(mut stream) = lock(&self.conns).remove(&conn) else {
            return;
        };
        drain_request_head(&mut stream);
        write_overload(&mut stream);
    }

    fn submit(&self, conn: ConnId) -> bool {
        let Some(me) = self.me.upgrade() else {
            return false;
        };
        let Some(Ok(stream)) = self.with_stream(conn, TcpStream::try_clone) else {
            return false;
        };
        thread::Builder::new()
            .name("guard-daemon-listener-worker".to_owned())
            .spawn(move || me.serve_connection(conn, stream))
            .is_ok()
    }

    /// Worker for one admitted connection: charge its first request, splice it
    /// to the upstream, then give its capacity back.
    fn serve_connection(&self, conn: ConnId, mut client: TcpStream) {
        self.with_state(|state, _, _| state.classify(conn));
        let granted = self
            .peek_path(conn)
            .is_some_and(|path| driver::claim(self, conn, &path));
        if granted {
            let _ = splice(&client, self.upstream);
        } else {
            write_overload(&mut client);
        }
        self.close(conn);
        driver::release(self, conn);
    }

    #[cfg(test)]
    pub(crate) fn counters(&self) -> Counters {
        lock(&self.state).counters()
    }
}

/// Read and discard the request head so the refusal is delivered, not reset.
fn drain_request_head(stream: &mut TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(
        DAEMON_OVERLOAD_DRAIN_TIMEOUT_MS,
    )));
    let mut remaining = DAEMON_OVERLOAD_DRAIN_BYTES;
    let mut trailing: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    while remaining > 0 {
        let Ok(read) = stream.read(&mut chunk[..remaining.min(4096)]) else {
            return;
        };
        if read == 0 {
            return;
        }
        remaining -= read;
        trailing.extend_from_slice(&chunk[..read]);
        if trailing.windows(4).any(|w| w == b"\r\n\r\n")
            || trailing.windows(2).any(|w| w == b"\n\n")
        {
            return;
        }
        let keep = trailing.len().saturating_sub(3);
        trailing.drain(..keep);
    }
}

impl Probe for Front {
    fn peek_path(&self, conn: ConnId) -> Option<String> {
        let buffered = self
            .with_stream(conn, |stream| peek(stream, DAEMON_PEEK_LINE_BYTES))?
            .ok()?;
        peek_request_path(&buffered)
    }

    fn headers_complete(&self, conn: ConnId) -> bool {
        self.with_stream(conn, |stream| peek(stream, DAEMON_PEEK_HEADER_BYTES))
            .and_then(Result::ok)
            .is_some_and(|buffered| request_headers_complete(&buffered))
    }

    fn peer_closed(&self, conn: ConnId) -> bool {
        match self.with_stream(conn, |stream| peek(stream, 1)) {
            Some(Ok(buffered)) => buffered.is_empty(),
            Some(Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR)) => false,
            Some(Err(_)) | None => true,
        }
    }
}

impl Host for Front {
    fn with_state<T>(&self, f: impl FnOnce(&mut State, f64, &dyn Probe) -> T) -> T {
        let now = self.now();
        let value = f(&mut lock(&self.state), now, self);
        self.wake.notify_all();
        value
    }

    fn apply(&self, effect: &Effect) -> bool {
        match effect {
            Effect::Close(conn) => self.close(*conn),
            Effect::Overload(conn) => self.overload(*conn),
            Effect::Submit { conn, .. } => return self.submit(*conn),
            Effect::WaitPermit(_) => {}
        }
        true
    }

    fn wait_connection_permit(&self, accept: &Accept) {
        self.wait_until(accept.admission_deadline, |state| {
            state.connection.free() > 0
        });
    }

    fn wait_claim_permit(&self, kind: DaemonRequestKind) {
        let deadline = self.now() + DAEMON_CONTROL_ADMISSION_WAIT_MS as f64 / 1000.0;
        self.wait_until(deadline, |state| state.kind_available(kind));
    }
}

pub(crate) struct Running {
    pub(crate) front: Arc<Front>,
    pub(crate) address: SocketAddr,
    threads: Vec<thread::JoinHandle<()>>,
}

impl Running {
    pub(crate) fn stop(mut self) {
        self.front.stopped.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(250));
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
        let conns: Vec<ConnId> = lock(&self.front.conns).keys().copied().collect();
        for conn in conns {
            self.front.close(conn);
        }
    }
}

fn loopback(address: SocketAddr) -> Result<SocketAddr, String> {
    match address.ip() {
        IpAddr::V4(ip) if ip.is_loopback() => Ok(address),
        IpAddr::V6(ip) if ip.is_loopback() => Ok(address),
        _ => Err("native_daemon_listener_address_not_loopback".to_owned()),
    }
}

pub(crate) fn start(
    listen: SocketAddr,
    upstream: SocketAddr,
    limits: Limits,
) -> Result<Running, String> {
    let listener = TcpListener::bind(loopback(listen)?)
        .map_err(|_| "native_daemon_listener_bind_failed".to_owned())?;
    let address = listener
        .local_addr()
        .map_err(|_| "native_daemon_listener_bind_failed".to_owned())?;
    let upstream = loopback(upstream)?;
    let epoch = Instant::now();
    let front = Arc::new_cyclic(|me| Front {
        state: Mutex::new(State::new(limits, 0.0)),
        wake: Condvar::new(),
        conns: Mutex::new(HashMap::new()),
        epoch,
        upstream,
        next_id: AtomicU64::new(0),
        stopped: AtomicBool::new(false),
        me: me.clone(),
    });
    let acceptor = Arc::clone(&front);
    let watchdog = Arc::clone(&front);
    let threads = vec![
        thread::Builder::new()
            .name("guard-daemon-listener-accept".to_owned())
            .spawn(move || accept_loop(&acceptor, &listener))
            .map_err(|_| "native_daemon_listener_thread_failed".to_owned())?,
        thread::Builder::new()
            .name("guard-daemon-listener-watchdog".to_owned())
            .spawn(move || watchdog_loop(&watchdog))
            .map_err(|_| "native_daemon_listener_thread_failed".to_owned())?,
    ];
    Ok(Running {
        front,
        address,
        threads,
    })
}

fn accept_loop(front: &Arc<Front>, listener: &TcpListener) {
    for incoming in listener.incoming() {
        if front.stopped.load(Ordering::Acquire) {
            return;
        }
        let Ok(stream) = incoming else {
            continue;
        };
        let loopback_peer = stream.peer_addr().is_ok_and(|peer| peer.ip().is_loopback());
        if !loopback_peer
            || stream.set_nonblocking(false).is_err()
            || stream.set_nodelay(true).is_err()
        {
            continue;
        }
        let conn = front.next_id.fetch_add(1, Ordering::Relaxed);
        lock(&front.conns).insert(conn, stream);
        driver::process_request(&**front, conn);
    }
}

fn watchdog_loop(front: &Arc<Front>) {
    while !front.stopped.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(DAEMON_WATCHDOG_POLL_MS));
        driver::tick(&**front);
    }
}

/// `daemon-listen --address ADDR --upstream ADDR`: serve until the supervisor
/// that started this process goes away.
pub(crate) fn run(listen: &str, upstream: &str) -> Result<(), String> {
    let listen: SocketAddr = listen
        .parse()
        .map_err(|_| "native_daemon_listener_address_invalid".to_owned())?;
    let upstream: SocketAddr = upstream
        .parse()
        .map_err(|_| "native_daemon_listener_upstream_invalid".to_owned())?;
    let alive = crate::resident_transport_service::resident_parent_liveness()?;
    let running = start(listen, upstream, limits_from_env())?;
    println!("listening {}", running.address);
    while alive.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(250));
    }
    running.stop();
    Ok(())
}
