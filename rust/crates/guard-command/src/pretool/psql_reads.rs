//! Read-only `psql` against a local server: `-l`/`--list`, or one `-c`
//! statement that `psql_statement` proves is a plain `SELECT` or `SHOW`.
//!
//! The host must be loopback or an absolute Unix-socket directory, the port a
//! number, and the database and role plain names, never a connection string
//! or URI. Without `-h`, psql uses its default local socket unless the user's
//! own `PGHOST`, `PGSERVICE` or service file names another server; that
//! inherited configuration is the user's, as it is for `pg_isready`. Inline
//! environment assignments never reach this proof.
//!
//! Still reviewed: script files (`-f`), output and log files (`-o`, `-L`),
//! variables other than `ON_ERROR_STOP`, print settings other than the pager
//! and footer, a second `-c`, an interactive session (neither `-c` nor `-l`,
//! so psql would read standard input), a remote host, and any other option.

#[path = "psql_statement.rs"]
mod psql_statement;

use crate::pretool::safe_scalar::{local_postgres_host, postgres_name, postgres_port};
use psql_statement::read_only_statement;

/// Output-shaping flags: list databases, unaligned, tuples only, quiet,
/// skip `~/.psqlrc`, never prompt for a password, expanded rows.
const FLAGS: &str = "lAtqXwx";
/// Short options that take a value, attached or as the next argument.
const VALUED: &str = "cdFhPpUv";

#[derive(Default)]
struct Invocation {
    list: bool,
    command: bool,
    positionals: usize,
}

impl Invocation {
    fn flag(&mut self, flag: char) {
        self.list |= flag == 'l';
    }

    fn valued(&mut self, option: char, value: &str) -> bool {
        match option {
            'c' if !self.command => {
                self.command = true;
                read_only_statement(value)
            }
            'h' => local_postgres_host(value),
            'p' => postgres_port(value),
            'd' | 'U' => postgres_name(value),
            'P' => matches!(value, "pager=off" | "pager=0" | "footer=off"),
            'v' => value.split_once('=').is_some_and(|(name, setting)| {
                name == "ON_ERROR_STOP"
                    && matches!(
                        setting.to_ascii_lowercase().as_str(),
                        "0" | "1" | "on" | "off" | "true" | "false"
                    )
            }),
            'F' => (1..=4).contains(&value.len()) && !value.contains(['\\', '\0']),
            _ => false,
        }
    }
}

fn long_option(name: &str) -> Option<char> {
    Some(match name {
        "list" => 'l',
        "no-align" => 'A',
        "tuples-only" => 't',
        "quiet" => 'q',
        "no-psqlrc" => 'X',
        "no-password" => 'w',
        "expanded" => 'x',
        "command" => 'c',
        "dbname" => 'd',
        "field-separator" => 'F',
        "host" => 'h',
        "pset" => 'P',
        "port" => 'p',
        "username" => 'U',
        "set" | "variable" => 'v',
        _ => return None,
    })
}

pub(in crate::pretool) fn safe_psql_arguments(arguments: &[String]) -> bool {
    let mut invocation = Invocation::default();
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        index += 1;
        if let Some(long) = argument.strip_prefix("--") {
            if long == "csv" {
                continue;
            }
            let (name, attached) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            let Some(option) = long_option(name) else {
                return false;
            };
            if FLAGS.contains(option) {
                if attached.is_some() {
                    return false;
                }
                invocation.flag(option);
                continue;
            }
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
            if !invocation.valued(option, value) {
                return false;
            }
        } else if let Some(cluster) = argument.strip_prefix('-').filter(|rest| !rest.is_empty()) {
            if !cluster.is_ascii() {
                return false;
            }
            for (offset, option) in cluster.char_indices() {
                if FLAGS.contains(option) {
                    invocation.flag(option);
                    continue;
                }
                if !VALUED.contains(option) {
                    return false;
                }
                let rest = &cluster[offset + 1..];
                let value = if rest.is_empty() {
                    let Some(value) = arguments.get(index) else {
                        return false;
                    };
                    index += 1;
                    value.as_str()
                } else {
                    rest
                };
                if !invocation.valued(option, value) {
                    return false;
                }
                break;
            }
        } else {
            // `psql [DBNAME [USERNAME]]`.
            invocation.positionals += 1;
            if invocation.positionals > 2 || !postgres_name(argument) {
                return false;
            }
        }
    }
    invocation.list || invocation.command
}

#[cfg(test)]
mod tests {
    use super::safe_psql_arguments;

    fn safe(arguments: &[&str]) -> bool {
        let arguments: Vec<String> = arguments.iter().map(|value| (*value).to_owned()).collect();
        safe_psql_arguments(&arguments)
    }

    #[test]
    fn local_lists_and_single_reads_are_admitted() {
        for arguments in [
            &[
                "-h",
                "/private/tmp",
                "-p",
                "55434",
                "-U",
                "hol",
                "-d",
                "hol",
                "-c",
                "select current_user",
            ][..],
            &[
                "-h",
                "/opt/homebrew/var/postgresql@16",
                "-U",
                "postgres",
                "-l",
            ],
            &[
                "-h",
                "localhost",
                "-U",
                "app_user",
                "app_dev",
                "-c",
                "SELECT count(*) FROM items;",
            ],
            &["--host=127.0.0.1", "--port=5432", "--list"],
            &["-tAc", "select version()"],
            &["-XtA", "-d", "app_dev", "--command=show server_version"],
            &[
                "-h",
                "::1",
                "-v",
                "ON_ERROR_STOP=1",
                "-P",
                "pager=off",
                "-c",
                "select 1",
            ],
            &["-At", "-F", ",", "--csv", "-cselect id from items"],
            &["app_dev", "app_user", "-l"],
        ] {
            assert!(safe(arguments), "psql {arguments:?}");
        }
    }

    #[test]
    fn writes_files_remote_hosts_and_sessions_stay_reviewed() {
        assert!(!safe(&[]));
        for arguments in [
            &["-h", "localhost"][..],
            &["-d", "app_dev"],
            &["-c", "drop table x"],
            &["-c", "copy items to program 'id'"],
            &["-c", "select 1; drop table x"],
            &["-c", "\\! id"],
            &["-c", "select 1", "-c", "select 2"],
            &["-h", "db.example.com", "-c", "select 1"],
            &["-h", "/tmp,db.example.com", "-l"],
            &["--host=10.0.0.5", "-l"],
            &["-d", "postgresql://db.example.com/app", "-l"],
            &["-d", "host=db.example.com", "-l"],
            &["postgresql://db.example.com/app", "-l"],
            &["-f", "script.sql"],
            &["-l", "-o", "/tmp/out"],
            &["-l", "-L", "/tmp/log"],
            &["-v", "AUTOCOMMIT=off", "-l"],
            &["--set=PROMPT1=x", "-l"],
            &["-P", "pager=always", "-l"],
            &["-l", "-s"],
            &["-l", "-W"],
            &["-l", "--"],
            &["--list=yes"],
            &["-c"],
            &["-h"],
            &["a", "b", "c", "-l"],
        ] {
            assert!(!safe(arguments), "psql {arguments:?}");
        }
    }
}
