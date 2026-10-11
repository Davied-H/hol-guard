//! Minimal Codex app-server WebSocket client over the local control socket.
//!
//! One exchange opens the socket, upgrades it, sends JSON-RPC messages and
//! reads until the reply whose `id` is 3. Failures carry the name the Python
//! client reported for the same condition, so continuation results keep their
//! established `reason` values.

use std::path::Path;
use std::time::Instant;

use serde_json::{Map, Value};
#[cfg(unix)]
use {
    base64ct::{Base64, Encoding},
    sha1::{Digest, Sha1},
    std::io::{ErrorKind, Read, Write},
};

#[cfg(unix)]
const MAX_HEADER_BYTES: usize = 16_384;
#[cfg(unix)]
const MAX_FRAME_BYTES: u64 = 1_000_000;
#[cfg(unix)]
const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
#[cfg(unix)]
const RESPONSE_ID: i64 = 3;
#[cfg(unix)]
const READ_CHUNK: usize = 4096;

/// Why an exchange produced no reply.
#[derive(Debug, PartialEq)]
pub(crate) enum Failure {
    /// The caller's deadline passed.
    Timeout,
    /// Any other failure, by the Python exception name for it.
    Error(&'static str),
}

/// Send `messages` and wait for the reply with id 3.
///
/// `Ok(None)` means the server sent a close frame first.
#[cfg(unix)]
pub(crate) fn exchange(
    socket: &Path,
    trusted: impl Fn(&Path) -> bool,
    messages: &[Value],
    deadline: Instant,
) -> Result<Option<Map<String, Value>>, Failure> {
    if !trusted(socket) {
        return Err(Failure::Error("ValueError"));
    }
    let stream = connect(socket)?;
    let mut connection = Connection {
        stream,
        pending: Vec::new(),
        deadline,
    };
    connection.handshake()?;
    for message in messages {
        let text = serde_json::to_string(message).map_err(|_| Failure::Error("ValueError"))?;
        connection.send_frame(0x1, text.as_bytes())?;
    }
    loop {
        let (opcode, payload) = connection.read_frame()?;
        match opcode {
            0x8 => return Ok(None),
            0x9 => {
                connection.send_frame(0xA, &payload)?;
                continue;
            }
            0x1 => {}
            _ => continue,
        }
        let text = String::from_utf8(payload).map_err(|_| Failure::Error("UnicodeDecodeError"))?;
        if let Ok(Value::Object(message)) = serde_json::from_str::<Value>(&text) {
            if is_response_id(message.get("id")) {
                return Ok(Some(message));
            }
        }
    }
}

#[cfg(not(unix))]
pub(crate) fn exchange(
    _socket: &Path,
    _trusted: impl Fn(&Path) -> bool,
    _messages: &[Value],
    _deadline: Instant,
) -> Result<Option<Map<String, Value>>, Failure> {
    Err(Failure::Error("ValueError"))
}

#[cfg(unix)]
/// Python `message.get("id") == 3`: an integer or float equal to 3.
fn is_response_id(id: Option<&Value>) -> bool {
    let Some(Value::Number(number)) = id else {
        return false;
    };
    number.as_i64() == Some(RESPONSE_ID) || number.as_f64() == Some(RESPONSE_ID as f64)
}

/// Connect without waiting on a full listen backlog, as a socket with a
/// timeout does.
#[cfg(unix)]
fn connect(socket: &Path) -> Result<std::os::unix::net::UnixStream, Failure> {
    use nix::sys::socket::{self, AddressFamily, SockFlag, SockType, UnixAddr};
    use std::os::fd::AsRawFd;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    let flags = SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let flags = SockFlag::empty();
    let address = UnixAddr::new(socket).map_err(errno_failure)?;
    let descriptor = socket::socket(AddressFamily::Unix, SockType::Stream, flags, None)
        .map_err(errno_failure)?;
    socket::connect(descriptor.as_raw_fd(), &address).map_err(errno_failure)?;
    let stream = std::os::unix::net::UnixStream::from(descriptor);
    stream.set_nonblocking(false).map_err(io_failure)?;
    Ok(stream)
}

#[cfg(unix)]
struct Connection {
    stream: std::os::unix::net::UnixStream,
    pending: Vec<u8>,
    deadline: Instant,
}

#[cfg(unix)]
impl Connection {
    fn remaining(&self) -> Result<std::time::Duration, Failure> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Failure::Timeout);
        }
        Ok(remaining)
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Failure> {
        let remaining = self.remaining()?;
        self.stream
            .set_write_timeout(Some(remaining))
            .map_err(io_failure)?;
        self.stream
            .write_all(bytes)
            .map_err(|error| self.failure(error))
    }

    /// One `recv` of at most `limit` bytes; an empty read is a closed socket.
    fn read_some(&mut self, limit: usize) -> Result<Vec<u8>, Failure> {
        loop {
            let remaining = self.remaining()?;
            self.stream
                .set_read_timeout(Some(remaining))
                .map_err(io_failure)?;
            let mut buffer = vec![0_u8; limit];
            match self.stream.read(&mut buffer) {
                Ok(0) => return Err(Failure::Error("_WebSocketClosedError")),
                Ok(count) => {
                    buffer.truncate(count);
                    return Ok(buffer);
                }
                Err(error) if is_wait(&error) || error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(self.failure(error)),
            }
        }
    }

    fn failure(&self, error: std::io::Error) -> Failure {
        if is_wait(&error) && self.remaining().is_err() {
            return Failure::Timeout;
        }
        io_failure(error)
    }

    /// `_recv_exact`, consuming bytes left over from the handshake first.
    fn read_exact(&mut self, length: usize) -> Result<Vec<u8>, Failure> {
        let take = length.min(self.pending.len());
        let mut data: Vec<u8> = self.pending.drain(..take).collect();
        while data.len() < length {
            let chunk = self.read_some(length - data.len())?;
            data.extend_from_slice(&chunk);
        }
        Ok(data)
    }

    /// `_send_websocket_handshake`.
    fn handshake(&mut self) -> Result<(), Failure> {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| Failure::Error("OSError"))?;
        let key = Base64::encode_string(&nonce);
        let request = format!(
            "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        self.write_all(request.as_bytes())?;
        let mut data: Vec<u8> = Vec::new();
        let boundary = loop {
            if let Some(index) = find(&data, b"\r\n\r\n") {
                break index + 4;
            }
            let chunk = self.read_some(READ_CHUNK)?;
            if data.len() + chunk.len() > MAX_HEADER_BYTES {
                return Err(Failure::Error("ValueError"));
            }
            data.extend_from_slice(&chunk);
        };
        self.pending = data.split_off(boundary);
        // ISO-8859-1: every byte is the code point of the same value.
        let header: String = data.iter().map(|byte| char::from(*byte)).collect();
        if !header.starts_with("HTTP/1.1 101") {
            return Err(Failure::Error("ValueError"));
        }
        let mut digest = Sha1::new();
        digest.update(key.as_bytes());
        digest.update(WEBSOCKET_GUID.as_bytes());
        let expected = Base64::encode_string(&digest.finalize());
        if accept_header(&header).as_deref() != Some(expected.as_str()) {
            return Err(Failure::Error("ValueError"));
        }
        Ok(())
    }

    /// `_send_websocket_frame`: one masked client frame.
    fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), Failure> {
        let mut mask = [0_u8; 4];
        getrandom::fill(&mut mask).map_err(|_| Failure::Error("OSError"))?;
        let mut frame = vec![0x80 | opcode];
        match payload.len() {
            length @ 0..=125 => frame.push(0x80 | length as u8),
            length @ 126..=65_535 => {
                frame.push(0x80 | 126);
                frame.extend_from_slice(&(length as u16).to_be_bytes());
            }
            length => {
                frame.push(0x80 | 127);
                frame.extend_from_slice(&(length as u64).to_be_bytes());
            }
        }
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % 4]),
        );
        self.write_all(&frame)
    }

    /// `_read_websocket_frame`.
    fn read_frame(&mut self) -> Result<(u8, Vec<u8>), Failure> {
        let header = self.read_exact(2)?;
        let opcode = header[0] & 0x0F;
        let mut length = u64::from(header[1] & 0x7F);
        if length == 126 {
            let bytes = self.read_exact(2)?;
            length = u64::from(u16::from_be_bytes([bytes[0], bytes[1]]));
        } else if length == 127 {
            let bytes = self.read_exact(8)?;
            let mut array = [0_u8; 8];
            array.copy_from_slice(&bytes);
            length = u64::from_be_bytes(array);
        }
        if length > MAX_FRAME_BYTES {
            return Err(Failure::Error("ValueError"));
        }
        let mask = if header[1] & 0x80 != 0 {
            Some(self.read_exact(4)?)
        } else {
            None
        };
        let mut payload = self.read_exact(length as usize)?;
        if let Some(mask) = mask {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
        }
        Ok((opcode, payload))
    }
}

#[cfg(unix)]
/// `_parse_http_headers(...)["sec-websocket-accept"]`: the last such header.
fn accept_header(header: &str) -> Option<String> {
    header
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| {
            crate::cloud_request_text::py_strip(name).to_lowercase() == "sec-websocket-accept"
        })
        .last()
        .map(|(_, value)| crate::cloud_request_text::py_strip(value).to_owned())
}

#[cfg(unix)]
fn find(data: &[u8], marker: &[u8]) -> Option<usize> {
    data.windows(marker.len())
        .position(|window| window == marker)
}

#[cfg(unix)]
fn is_wait(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

#[cfg(unix)]
fn io_failure(error: std::io::Error) -> Failure {
    match error.raw_os_error() {
        Some(code) => errno_name(code),
        None => Failure::Error("OSError"),
    }
}

#[cfg(unix)]
fn errno_failure(error: nix::errno::Errno) -> Failure {
    errno_name(error as i32)
}

#[cfg(unix)]
/// The `OSError` subclass Python raises for an errno (PEP 3151).
fn errno_name(code: i32) -> Failure {
    use nix::errno::Errno;
    let name = match Errno::from_raw(code) {
        Errno::EAGAIN | Errno::EALREADY | Errno::EINPROGRESS => "BlockingIOError",
        Errno::ECHILD => "ChildProcessError",
        Errno::EPIPE | Errno::ESHUTDOWN => "BrokenPipeError",
        Errno::ECONNABORTED => "ConnectionAbortedError",
        Errno::ECONNREFUSED => "ConnectionRefusedError",
        Errno::ECONNRESET => "ConnectionResetError",
        Errno::EEXIST => "FileExistsError",
        Errno::ENOENT => "FileNotFoundError",
        Errno::EINTR => "InterruptedError",
        Errno::EISDIR => "IsADirectoryError",
        Errno::ENOTDIR => "NotADirectoryError",
        Errno::EACCES | Errno::EPERM => "PermissionError",
        Errno::ESRCH => "ProcessLookupError",
        Errno::ETIMEDOUT => "TimeoutError",
        _ => "OSError",
    };
    Failure::Error(name)
}
