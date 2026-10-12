//! Byte splice between an admitted client connection and the private upstream.
//!
//! One client connection maps to exactly one upstream connection, so the
//! upstream's per-connection state (the identity-challenge nonce binds to the
//! connection) behaves as it did when clients reached it directly.

use std::io::{self, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::thread;
use std::time::Duration;

use guard_contracts::daemon_overload_response;

const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const OVERLOAD_WRITE_TIMEOUT: Duration = Duration::from_millis(250);

/// Copy both directions until either side ends the connection.
pub(crate) fn splice(client: &TcpStream, upstream_address: SocketAddr) -> io::Result<()> {
    let upstream = TcpStream::connect_timeout(&upstream_address, UPSTREAM_CONNECT_TIMEOUT)?;
    upstream.set_nodelay(true)?;
    client.set_read_timeout(None)?;
    let result = thread::scope(|scope| -> io::Result<()> {
        let mut client_reader = client.try_clone()?;
        let mut upstream_writer = upstream.try_clone()?;
        let forward = scope.spawn(move || {
            let copied = io::copy(&mut client_reader, &mut upstream_writer);
            let _ = upstream_writer.shutdown(Shutdown::Write);
            copied
        });
        let mut upstream_reader = upstream.try_clone()?;
        let mut client_writer = client.try_clone()?;
        let backward = io::copy(&mut upstream_reader, &mut client_writer);
        // The upstream ended the exchange; closing the client unblocks the
        // forward copy so the scope can finish.
        let _ = client.shutdown(Shutdown::Both);
        let _ = upstream.shutdown(Shutdown::Both);
        let forward = forward
            .join()
            .map_err(|_| io::Error::other("forward copy panicked"))?;
        backward.and(forward).map(|_| ())
    });
    let _ = upstream.shutdown(Shutdown::Both);
    result
}

/// Write the overload reply, bounded, then close the connection.
pub(crate) fn write_overload(client: &mut TcpStream) {
    let _ = client.set_write_timeout(Some(OVERLOAD_WRITE_TIMEOUT));
    let _ = client.write_all(&daemon_overload_response());
    let _ = client.shutdown(Shutdown::Both);
}
