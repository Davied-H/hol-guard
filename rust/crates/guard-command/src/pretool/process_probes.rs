//! Process and service probes that only report local state.
//!
//! * `lsof -i`: lists open network sockets and the processes that hold them,
//!   the view `ps aux` already gives for command lines. Only socket listings
//!   are admitted: an `-i` selector, `-s` state filters, `-p` process ids and
//!   the display flags `-n`, `-P`, `-t`, `-a`, `-l` and `-V`. lsof joins
//!   selectors with OR, so `-p` needs `-a` to stay a socket listing.
//! * `pg_isready`: asks a local PostgreSQL server whether it accepts
//!   connections and prints the answer. It sends no query and no password.
//!   The server is named by a loopback host or by an absolute Unix-socket
//!   directory such as `/tmp` or a Homebrew `var/postgresql@16`.
//!
//! Still reviewed:
//! - `lsof` with file or directory operands, `+` options, repeat mode (`-r`),
//!   output fields (`-F`), a host selector (`@host`) or any other option.
//! - `pg_isready` against any host other than `127.0.0.1`, `localhost`, `::1`
//!   or a socket directory, a connection string in `--dbname`, and any other
//!   option.

const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "localhost", "::1"];

/// A PostgreSQL host that never leaves the machine: a loopback name or address,
/// or an absolute Unix-socket directory (libpq reads a leading `/` that way).
/// A `,` would add a second host, `=` or `:` would start a connection string.
pub(in crate::pretool) fn local_postgres_host(value: &str) -> bool {
    LOOPBACK_HOSTS.contains(&value)
        || (value.starts_with('/')
            && value.len() <= 255
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/._-@+".contains(&byte)))
}

/// A Unix-socket directory where no other local user can stand in for the
/// server: libpq connects to `<dir>/.s.PGSQL.<port>`, and whoever owns that
/// socket answers the probe or query and can ask for a password. The directory
/// must not be writable by other users unless it is sticky, as `/tmp` is, and
/// each socket psql may reach (the named port's, or every one without a port,
/// since `PGPORT` may pick any) must belong to this user or root. A loopback
/// host and a missing directory pass: neither reaches a planted socket.
pub(in crate::pretool) fn trusted_postgres_socket(host: &str, port: Option<&str>) -> bool {
    if !host.starts_with('/') {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let directory = match std::fs::metadata(host) {
            Ok(metadata) => metadata,
            Err(error) => return error.kind() == std::io::ErrorKind::NotFound,
        };
        if !directory.is_dir() || (directory.mode() & 0o002 != 0 && directory.mode() & 0o1000 == 0)
        {
            return false;
        }
        let uid = nix::unistd::getuid().as_raw();
        let owned = |path: &std::path::Path| match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata.uid() == uid || metadata.uid() == 0,
            Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        };
        let directory = std::path::Path::new(host);
        match port {
            Some(port) => owned(&directory.join(format!(".s.PGSQL.{port}"))),
            None => std::fs::read_dir(directory).is_ok_and(|entries| {
                entries.into_iter().all(|entry| {
                    entry.is_ok_and(|entry| {
                        !entry.file_name().to_string_lossy().starts_with(".s.PGSQL.")
                            || owned(&entry.path())
                    })
                })
            }),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = port;
        true
    }
}

pub(in crate::pretool) fn safe_lsof_arguments(arguments: &[String]) -> bool {
    let mut network = false;
    let mut pid = false;
    let mut and = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        index += 1;
        let Some(cluster) = argument.strip_prefix('-') else {
            return false;
        };
        if cluster.is_empty() || cluster.starts_with('-') || !cluster.is_ascii() {
            return false;
        }
        for (offset, flag) in cluster.char_indices() {
            let rest = &cluster[offset + flag.len_utf8()..];
            match flag {
                'a' => {
                    and = true;
                    continue;
                }
                'n' | 'P' | 't' | 'l' | 'V' => continue,
                'i' => {
                    network = true;
                    if !rest.is_empty() {
                        if !socket_selector(rest) {
                            return false;
                        }
                    } else if let Some(next) = arguments.get(index) {
                        if socket_selector_start(next) {
                            if !socket_selector(next) {
                                return false;
                            }
                            index += 1;
                        }
                    }
                }
                's' => {
                    if !rest.is_empty() {
                        if !state_filter(rest) {
                            return false;
                        }
                    } else if arguments.get(index).is_some_and(|next| state_filter(next)) {
                        index += 1;
                    }
                }
                'p' => {
                    pid = true;
                    let value = if rest.is_empty() {
                        let Some(value) = arguments.get(index) else {
                            return false;
                        };
                        index += 1;
                        value.as_str()
                    } else {
                        rest
                    };
                    if !process_ids(value) {
                        return false;
                    }
                }
                _ => return false,
            }
            break;
        }
    }
    // Without `-a`, `-p` also lists every open file of that process.
    network && (!pid || and)
}

/// `[46][protocol][:port]`, for example `:5432`, `TCP:3000`, `4tcp` or
/// `:3000-3010`. A host part (`@host`) is not admitted.
fn socket_selector(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b',' | b'-'))
}

fn socket_selector_start(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    ["4", "6", ":", "tcp", "udp"]
        .iter()
        .any(|prefix| lowered.starts_with(prefix))
}

/// `TCP:LISTEN` or `UDP:Idle,^Unbound`.
fn state_filter(value: &str) -> bool {
    let Some((protocol, states)) = value.split_once(':') else {
        return false;
    };
    matches!(protocol.to_ascii_uppercase().as_str(), "TCP" | "UDP")
        && !states.is_empty()
        && states.len() <= 64
        && states
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b',' | b'^'))
}

fn process_ids(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b',' | b'^'))
}

pub(in crate::pretool) fn safe_pg_isready_arguments(arguments: &[String]) -> bool {
    // The command text must name a local host: an omitted -h would take
    // the target from PGHOST or a service file. This bounds what the agent
    // wrote, not the inherited libpq environment (PGHOSTADDR or a service
    // `hostaddr` still overrides -h); that environment is the user's own
    // configuration, and the probe sends only a startup packet.
    let mut explicit_local = false;
    let (mut host, mut port_value) = (None, None);
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        index += 1;
        if !argument.is_ascii() {
            return false;
        }
        if matches!(argument, "-q" | "--quiet") {
            continue;
        }
        let (option, attached) = match argument.split_once('=') {
            Some((option, value)) if option.starts_with("--") => (option, Some(value)),
            _ if argument.len() > 2 && argument.starts_with('-') && !argument.starts_with("--") => {
                (&argument[..2], Some(&argument[2..]))
            }
            _ => (argument, None),
        };
        let value = match attached {
            Some(value) => value,
            None => {
                let Some(value) = arguments.get(index) else {
                    return false;
                };
                index += 1;
                value.as_str()
            }
        };
        let valid = match option {
            "-h" | "--host" => {
                host = Some(value);
                explicit_local = local_postgres_host(value);
                explicit_local
            }
            "-p" | "--port" => {
                port_value = Some(value);
                port(value)
            }
            "-t" | "--timeout" => {
                (1..=3).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit())
            }
            "-d" | "--dbname" | "-U" | "--username" => plain_name(value),
            _ => false,
        };
        if !valid {
            return false;
        }
    }
    explicit_local && host.is_some_and(|host| trusted_postgres_socket(host, port_value))
}

pub(in crate::pretool) fn port(value: &str) -> bool {
    (1..=5).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u16>().is_ok_and(|port| port > 0)
}

/// A database or role name, never a connection string (`host=…`, a URI).
pub(in crate::pretool) fn plain_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::{safe_lsof_arguments, safe_pg_isready_arguments};

    fn arguments(command: &str) -> Vec<String> {
        command.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn socket_listings_and_local_readiness_checks_are_admitted() {
        for command in [
            "-i",
            "-i :5432",
            "-i:3000",
            "-ti:3000",
            "-ti :3000",
            "-nP -iTCP:5432 -sTCP:LISTEN",
            "-nP -iTCP -sTCP:LISTEN",
            "-i4 -a -p 123,456",
            "-ai -p 123",
            "-i tcp:8000-8010",
        ] {
            assert!(safe_lsof_arguments(&arguments(command)), "lsof {command}");
        }
        for command in [
            "-h localhost -q",
            "-h localhost -p 5432",
            "--host=127.0.0.1 --port=5432 -t 3",
            "-h ::1 -d app_dev -U app_user",
            "-h /private/tmp -p 55434",
            "--host=/opt/homebrew/var/postgresql@16 -q",
        ] {
            assert!(
                safe_pg_isready_arguments(&arguments(command)),
                "pg_isready {command}"
            );
        }
    }

    #[test]
    fn file_operands_hosts_and_connection_strings_are_refused() {
        for command in [
            "",
            "-n",
            "/usr/local",
            "-i :5432 /usr/local",
            "+D /usr/local",
            "-i @example.com",
            "-i TCP@example.com:443",
            "-r 1 -i",
            "-F n -i",
            "-p",
            "-p self -i",
            "-i -p 123",
            "-ip 123",
            "--help",
        ] {
            assert!(!safe_lsof_arguments(&arguments(command)), "lsof {command}");
        }
        for command in [
            "",
            "-q",
            "-d app_dev -U app_user",
            "-h db.example.com",
            "--host=10.0.0.5",
            "-h tmp",
            "-h /tmp,db.example.com",
            "-h @abstract",
            "-h /tmp/$(id)",
            "-d host=db.example.com",
            "-d postgresql://db.example.com/app",
            "-p 0",
            "-p",
            "-x",
            "app",
        ] {
            assert!(
                !safe_pg_isready_arguments(&arguments(command)),
                "pg_isready {command}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_socket_directory_any_user_can_write_is_not_a_trusted_server() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/pg-isready-sockets")
            .join(std::process::id().to_string());
        let (open, own) = (root.join("open"), root.join("own"));
        for (directory, mode) in [(&open, 0o777), (&own, 0o700)] {
            std::fs::create_dir_all(directory).unwrap();
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        std::fs::write(own.join(".s.PGSQL.5432"), "").unwrap();
        let probe = |directory: &std::path::Path, port: &str| {
            safe_pg_isready_arguments(&arguments(&format!("-h {} {port}", directory.display())))
        };
        assert!(!probe(&open, "-q"));
        assert!(!probe(&open, "-p 5432"));
        assert!(probe(&own, "-q"));
        assert!(probe(&own, "-p 5432"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
