//! What a script launched by an interpreter does, read from its source.
//!
//! The sandbox, not this scan, bounds what a contained script can do. The
//! scan predicts fit: a script that needs the network keeps its review instead
//! of failing inside a sandbox that withholds the network, and a script that
//! pairs a credential store with the network is blocked. It can only raise a
//! decision. An absent, unreadable, oversized or unrecognized script changes
//! nothing.

use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

use super::{read_paths, PathContext};
use crate::CanonicalCommandV1;
use guard_contracts::PreToolResultV1;

const MAX_FILE_BYTES: usize = 256 * 1024;
const MAX_TOTAL_BYTES: usize = 1024 * 1024;
const MAX_FILES: usize = 32;

const NODE_EXTENSIONS: &[&str] = &["js", "mjs", "cjs", "jsx", "ts", "mts", "cts", "tsx"];

/// Node and Python options that take their value as the next argument.
const NODE_VALUE_OPTIONS: &[&str] = &[
    "-r",
    "--require",
    "--import",
    "--loader",
    "--experimental-loader",
    "-C",
    "--conditions",
    "--env-file",
    "--input-type",
    "--title",
    "--inspect-port",
];
const PYTHON_VALUE_OPTIONS: &[&str] = &["-W", "-X", "--check-hash-based-pycs"];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Language {
    Python,
    Node,
}

/// Network clients a script imports or calls.
static PYTHON_NETWORK: LazyLock<Regex> = LazyLock::new(|| {
    let clients = "socket|ssl|http|urllib|urllib3|requests|httpx|aiohttp|websocket|websockets|smtplib|ftplib|poplib|imaplib|telnetlib|xmlrpc|paramiko|asyncssh|pycurl|httplib2|boto3|botocore|googleapiclient|google\\.cloud|google\\.analytics|google\\.auth\\.transport|openai|anthropic|grpc|kubernetes|psycopg|psycopg2|pymysql|MySQLdb|redis|pymongo|slack_sdk|github|gql|stripe";
    // `from client import x`, or `client` anywhere in an `import a, b` list.
    Regex::new(&format!(
        r"(?m)^[ \t]*(?:from[ \t]+(?:{clients})\b|import[ \t]+(?:[\w.]+(?:[ \t]+as[ \t]+\w+)?[ \t]*,[ \t]*)*(?:{clients})\b)"
    ))
    .unwrap()
});
static NODE_NETWORK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)["'](?:node:)?(?:https?|http2|net|tls|dgram|dns|undici|axios|node-fetch|got|ky|ws|superagent|request|socket\.io-client|ssh2|nodemailer|ftp|basic-ftp|pg|mysql2?|mongodb|ioredis|redis|openai|googleapis|google-auth-library|aws-sdk|octokit|stripe|@google-cloud/[^"']*|@google-analytics/[^"']*|@aws-sdk/[^"']*|@anthropic-ai/[^"']*|@octokit/[^"']*|@slack/[^"']*)(?:["']|/[^"']*["'])|\bfetch\s*\(|\bXMLHttpRequest\b|\bnew\s+WebSocket\b|\bEventSource\b|\bsendBeacon\b|\bBun\s*\.\s*connect\b|\bDeno\s*\.\s*connect\b"#,
    )
    .unwrap()
});

/// Credential stores that ordinary scripts reach through a client library,
/// never by naming the file: private keys, cloud credential files, browser
/// password and cookie databases, keychains and wallets. Configuration files
/// that legitimately carry a token (`.netrc`, `.npmrc`, kube config) are not
/// listed, so a script that authenticates with one is not blocked.
static CREDENTIAL_STORE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)id_(?:rsa|dsa|ecdsa|ed25519)(?:[^.\w]|$)|\.aws/credentials|\.aws["']\s*[,/]\s*["']credentials|\.gnupg\b|private-keys-v1\.d|(?:default|profile [0-9]+)/(?:cookies|login data|web data)\b|cookies\.sqlite|logins\.json|key4\.db|keychains/|\.keychain(?:-db)?\b|wallet\.dat|\.ethereum/keystore|solana/id\.json|/etc/shadow\b"#,
    )
    .unwrap()
});

static NODE_RELATIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)["'](\.{1,2}/[^"'\n]+)["']"#)
        .unwrap()
});
static PYTHON_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*(?:from[ \t]+(\.*)([\w.]*)[ \t]+import[ \t]+([\w, \t()]+)|import[ \t]+([\w., \t]+))")
        .unwrap()
});

#[derive(Default)]
pub(super) struct Findings {
    /// Imports or calls a network client.
    pub(super) network: bool,
    /// Names a credential store by path.
    pub(super) credential_store: bool,
}

/// What the scripts this command launches do, or `None` when it launches
/// none whose source could be read.
pub(super) fn assess(model: &CanonicalCommandV1, context: PathContext<'_>) -> Option<Findings> {
    if model.confidence != "exact"
        || !read_paths::verified_path_context(context.home_dir, context.cwd)
    {
        return None;
    }
    let mut findings: Option<Findings> = None;
    for (index, segment) in model.segments.iter().enumerate() {
        let Some((language, script)) = launched_script(segment) else {
            continue;
        };
        // An earlier directory change moves a relative script out of reach.
        let moved = model.segments[..index].iter().any(|prior| {
            prior.executable.as_deref().is_some_and(|value| {
                matches!(super::executable_basename(value), "cd" | "pushd" | "popd")
            })
        });
        if moved && !Path::new(script).is_absolute() {
            continue;
        }
        let Some(path) = resolve(script, context) else {
            continue;
        };
        let Some(sources) = read_graph(language, path) else {
            continue;
        };
        let found = findings.get_or_insert_with(Findings::default);
        for source in sources {
            found.network |= match language {
                Language::Python => PYTHON_NETWORK.is_match(&source),
                Language::Node => NODE_NETWORK.is_match(&source),
            };
            found.credential_store |= CREDENTIAL_STORE.is_match(&source);
        }
    }
    findings
}

/// Whether a launched script reads a credential store and uses the network.
pub(super) fn exfiltrates(model: &CanonicalCommandV1, context: PathContext<'_>) -> bool {
    assess(model, context).is_some_and(|found| found.network && found.credential_store)
}

/// Keeps the review of a command whose script uses the network: the sandbox
/// withholds it, so the script would only fail there.
pub(super) fn keeps_network_review(
    result: &mut PreToolResultV1,
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
) -> bool {
    if !assess(model, context).is_some_and(|found| found.network) {
        return false;
    }
    result.reason = concat!(
        "HOL Guard needs your review because this script uses the network, ",
        "which Guard's sandbox withholds."
    )
    .into();
    true
}

fn launched_script(segment: &crate::CommandSegmentV1) -> Option<(Language, &str)> {
    let name = super::executable_basename(segment.executable.as_deref()?);
    let name = name.strip_suffix(".exe").unwrap_or(name);
    let arguments = segment.arguments.as_slice();
    let python = name.strip_prefix("python").is_some_and(|version| {
        version
            .split('.')
            .all(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
    });
    if python {
        return first_operand(arguments, PYTHON_VALUE_OPTIONS, &["-c", "-m", "-"])
            .map(|script| (Language::Python, script));
    }
    let arguments = match (name, arguments) {
        ("bun" | "deno", [run, rest @ ..]) if run == "run" => rest,
        ("node" | "nodejs" | "bun" | "tsx" | "deno", rest) => rest,
        _ => return None,
    };
    let script = first_operand(
        arguments,
        NODE_VALUE_OPTIONS,
        &["-e", "--eval", "-p", "--print", "-"],
    )?;
    NODE_EXTENSIONS
        .contains(&extension(Path::new(script)).as_str())
        .then_some((Language::Node, script))
}

/// The first argument that is not an option, unless an option that runs
/// other code (inline source, a module, standard input) comes first.
fn first_operand<'a>(
    arguments: &'a [String],
    value_options: &[&str],
    stops: &[&str],
) -> Option<&'a str> {
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        if stops.contains(&argument.as_str()) {
            return None;
        }
        if argument == "--" {
            return rest.next().map(String::as_str);
        }
        if value_options.contains(&argument.as_str()) {
            rest.next()?;
            continue;
        }
        if !argument.starts_with('-') {
            return Some(argument);
        }
    }
    None
}

fn resolve(script: &str, context: PathContext<'_>) -> Option<PathBuf> {
    if !read_paths::bounded_file_read_target(script, context.home_dir, context.cwd) {
        return None;
    }
    let path = guard_secure_fs::resolve_candidate(
        script,
        context.cwd.map(Path::new),
        Path::new(context.home_dir.unwrap_or_default()),
    )
    .ok()?;
    std::fs::canonicalize(path)
        .ok()
        .filter(|path| path.is_file())
}

/// The script's source and that of the local modules it imports, breadth
/// first, within the file and byte bounds. Packages and the standard library
/// are not read.
fn read_graph(language: Language, entry: PathBuf) -> Option<Vec<String>> {
    let mut seen = BTreeSet::from([entry.clone()]);
    let mut queue = VecDeque::from([entry]);
    let mut sources = Vec::new();
    let mut total = 0usize;
    while let Some(path) = queue.pop_front() {
        let read = guard_secure_fs::read_bounded(&path, MAX_FILE_BYTES).ok()?;
        total += read.bytes.len();
        if total > MAX_TOTAL_BYTES {
            return None;
        }
        let source = String::from_utf8(read.bytes).ok()?;
        let directory = path.parent()?.to_path_buf();
        let imports = match language {
            Language::Node => node_imports(&source, &directory),
            Language::Python => python_imports(&source, &directory),
        };
        for import in imports {
            if seen.len() >= MAX_FILES {
                break;
            }
            if seen.insert(import.clone()) {
                queue.push_back(import);
            }
        }
        sources.push(source);
    }
    Some(sources)
}

fn node_imports(source: &str, directory: &Path) -> Vec<PathBuf> {
    NODE_RELATIVE
        .captures_iter(source)
        .filter_map(|capture| {
            let base = directory.join(&capture[1]);
            let index = NODE_EXTENSIONS
                .iter()
                .map(|extension| base.join(format!("index.{extension}")));
            std::iter::once(base.clone())
                .chain(
                    NODE_EXTENSIONS
                        .iter()
                        .map(|extension| PathBuf::from(format!("{}.{extension}", base.display()))),
                )
                .chain(index)
                .find(|candidate| {
                    candidate.is_file() && NODE_EXTENSIONS.contains(&extension(candidate).as_str())
                })
        })
        .filter_map(|path| std::fs::canonicalize(path).ok())
        .collect()
}

fn python_imports(source: &str, directory: &Path) -> Vec<PathBuf> {
    let mut modules: Vec<String> = Vec::new();
    for capture in PYTHON_IMPORT.captures_iter(source) {
        if let Some(names) = capture.get(4) {
            modules.extend(
                names
                    .as_str()
                    .split(',')
                    .filter_map(|name| name.split_whitespace().next())
                    .map(str::to_owned),
            );
            continue;
        }
        let module = capture.get(2).map_or("", |value| value.as_str());
        if module.is_empty() {
            // `from . import a, b` imports sibling modules by name.
            let names = capture.get(3).map_or("", |value| value.as_str());
            modules.extend(
                names
                    .split(',')
                    .filter_map(|name| {
                        name.trim_matches(['(', ')', ' ', '\t'])
                            .split_whitespace()
                            .next()
                    })
                    .map(str::to_owned),
            );
        } else {
            modules.push(module.to_owned());
        }
    }
    modules
        .iter()
        .filter(|module| {
            !module.is_empty()
                && module.split('.').all(|part| {
                    !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                })
        })
        .filter_map(|module| {
            let relative = module.replace('.', "/");
            [
                directory.join(format!("{relative}.py")),
                directory.join(&relative).join("__init__.py"),
            ]
            .into_iter()
            .find(|candidate| candidate.is_file())
        })
        .filter_map(|path| std::fs::canonicalize(path).ok())
        .collect()
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}
