//! The state a one-time approval of `git push` is bound to.
//!
//! git runs code from files an agent can edit: hooks, config-selected helpers
//! and the transport program with its own config. A review shows only the
//! command, so a retry may reuse a one-time approval only while every one of
//! those files, and the refs being pushed, is what it was when the review was
//! queued. Anything this cannot pin fails closed and the push stays unbound.

use std::collections::{BTreeMap, BTreeSet};

use guard_contracts::write_canonical_json;
use serde_json::{json, Value};

use super::context::Ctx;
use super::fs_path;
use super::git_config::git_push_config;
use super::git_identity::repository;
use super::reasons::{
    Proof, COMPOUND_COMMAND, GIT_HELPER_CONFIG, MUTABLE_LAUNCHER, UNPROVEN_LAUNCH,
};
use super::reuse_shape;
use crate::mcp_proxy_shlex::split_with;

const SHELL_PUNCTUATION: &str = ";&|<>";
const EXPANSIONS: [&str; 6] = ["`", "$(", "${", "\n", "\r", "#"];
/// Flags that change neither which refs are pushed nor which program runs.
const PUSH_FLAGS: [&str; 13] = [
    "-u",
    "--set-upstream",
    "-v",
    "--verbose",
    "-q",
    "--quiet",
    "-n",
    "--dry-run",
    "--porcelain",
    "--progress",
    "--no-progress",
    "--atomic",
    "--no-verify",
];
/// Variables that name a program git or ssh runs, redirect the repository,
/// or change what the dynamic loader injects into either.
const PUSH_ENVIRONMENT: [&str; 15] = [
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GIT_PROXY_COMMAND",
    "GIT_EXEC_PATH",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
];
/// ssh keywords that run or load a local program.
const SSH_PROGRAM_KEYWORDS: [&str; 6] = [
    "proxycommand",
    "localcommand",
    "knownhostscommand",
    "pkcs11provider",
    "securitykeyprovider",
    "xauthlocation",
];
/// The include line distributions ship in the system config; every file in
/// that folder is read and checked whichever glob names it.
const SYSTEM_INCLUDES: [&str; 2] = [
    "include /etc/ssh/ssh_config.d/*.conf",
    "include /etc/ssh/ssh_config.d/*",
];
/// The hooks a push runs on this machine; the receiving side runs the others.
const PUSH_HOOKS: [&str; 2] = ["pre-push", "reference-transaction"];
const MAX_CONFIG_BYTES: u64 = 1_048_576;
const MAX_SSH_FILES: usize = 24;
const MAX_REF_NAME: usize = 200;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Transport {
    Ssh,
    Http,
}

/// The digest a one-time approval of `command` is bound to, or why it cannot be.
pub(super) fn push_state(command: &str, cwd: &str, ctx: &Ctx) -> Proof<String> {
    if cfg!(windows) || EXPANSIONS.iter().any(|marker| command.contains(marker)) {
        return Err(MUTABLE_LAUNCHER);
    }
    let words = split_with(command, SHELL_PUNCTUATION, "#").ok_or(MUTABLE_LAUNCHER)?;
    if !reuse_shape::is_simple(&words) {
        return Err(COMPOUND_COMMAND);
    }
    let [git, push, rest @ ..] = words.as_slice() else {
        return Err(MUTABLE_LAUNCHER);
    };
    if git != "git" || push != "push" {
        return Err(MUTABLE_LAUNCHER);
    }
    let (remote, sources) = push_operands(rest)?;
    if ctx
        .env
        .keys()
        .any(|name| PUSH_ENVIRONMENT.contains(&name.as_str()))
    {
        return Err(GIT_HELPER_CONFIG);
    }
    ctx.check()?;
    let git_identity = reusable_launch(ctx, "git", &words[1..], cwd)?;
    let (root, git_dir, common_dir) = repository(cwd)?;
    let system = [ctx.engines.system_git_config()];
    let (config_digest, facts) = git_push_config(&root, &git_dir, &common_dir, &system, ctx)?;
    if facts.helper.is_some() {
        return Err(GIT_HELPER_CONFIG);
    }
    // A digest pins a hook's text, not the programs it runs (a `pre-push`
    // that runs the test suite runs files the agent can edit), so a hook the
    // push would run leaves it unbound, as the native push check requires.
    let skips_pre_push = rest.iter().any(|word| word == "--no-verify");
    let runs_hook = facts.hook_dirs.iter().any(|dir| {
        PUSH_HOOKS
            .iter()
            .filter(|hook| !(skips_pre_push && **hook == "pre-push"))
            .any(|hook| fs_path::is_file(&fs_path::join(dir, hook)))
    });
    if runs_hook {
        return Err(MUTABLE_LAUNCHER);
    }
    let urls = facts
        .push_urls
        .get(remote)
        .or_else(|| facts.urls.get(remote))
        .filter(|urls| !urls.is_empty())
        .ok_or(MUTABLE_LAUNCHER)?;
    let transports = urls
        .iter()
        .map(|url| transport(url).ok_or(MUTABLE_LAUNCHER))
        .collect::<Proof<BTreeSet<Transport>>>()?;
    let ssh = if transports.contains(&Transport::Ssh) {
        Some(ssh_state(cwd, ctx)?)
    } else {
        None
    };
    let refs = ref_state(&git_dir, &common_dir, &sources)?;
    let state = json!({
        "kind": "git-push.v1",
        "argv": words,
        "cwd": cwd,
        "repository": root,
        "git_dir": git_dir,
        "common_dir": common_dir,
        "git": git_identity,
        "config_digest": config_digest,
        "urls": urls,
        "ssh": ssh,
        "refs": refs,
    });
    let mut encoded = Vec::new();
    write_canonical_json(&state, &mut encoded).map_err(|_| UNPROVEN_LAUNCH)?;
    Ok(fs_path::sha256_hex(&encoded))
}

/// The named remote and the local source of each refspec. A push must name
/// both, so the current branch and `push.default` never decide what it sends.
fn push_operands(rest: &[String]) -> Proof<(&str, Vec<&str>)> {
    let mut positionals = Vec::new();
    for word in rest {
        if word.starts_with('-') {
            if !PUSH_FLAGS.contains(&word.as_str()) {
                return Err(MUTABLE_LAUNCHER);
            }
        } else {
            positionals.push(word.as_str());
        }
    }
    let [remote, refspecs @ ..] = positionals.as_slice() else {
        return Err(MUTABLE_LAUNCHER);
    };
    if refspecs.is_empty() || !is_remote_name(remote) {
        return Err(MUTABLE_LAUNCHER);
    }
    let sources = refspecs
        .iter()
        .map(|spec| refspec_source(spec))
        .collect::<Proof<Vec<&str>>>()?;
    Ok((remote, sources))
}

/// A configured remote's name; a URL or path would push to a repository whose
/// own hooks run here.
fn is_remote_name(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
        && characters
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

/// `src` or `src:dst`. A forced (`+`), deleting (`:dst`) or glob refspec is
/// another action than the one reviewed.
fn refspec_source(spec: &str) -> Proof<&str> {
    let (source, destination) = match spec.split_once(':') {
        Some((source, destination)) => (source, Some(destination)),
        None => (spec, None),
    };
    let plain_source = source == "HEAD" || is_plain_ref(source);
    if !plain_source || destination.is_some_and(|name| !is_plain_ref(name)) {
        return Err(MUTABLE_LAUNCHER);
    }
    Ok(source)
}

fn is_plain_ref(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_REF_NAME
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._/-".contains(character))
        && name.split('/').all(|part| {
            !part.is_empty()
                && !part.starts_with('.')
                && !part.ends_with('.')
                && !part.ends_with(".lock")
        })
        && !name.contains("..")
}

/// The transport a push URL selects, or `None` for one this cannot pin: a
/// local path or `file://` (that repository's hooks run here), `git://`, or a
/// `<helper>::` remote helper.
fn transport(url: &str) -> Option<Transport> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") {
        return Some(Transport::Http);
    }
    if ["ssh://", "git+ssh://", "ssh+git://"]
        .iter()
        .any(|scheme| lower.starts_with(scheme))
    {
        return Some(Transport::Ssh);
    }
    if url.contains("://") || url.contains("::") || url.starts_with(['/', '.', '~']) {
        return None;
    }
    // scp-like `[user@]host:path`: no slash before the first colon.
    let (host, path) = url.split_once(':')?;
    (!host.is_empty() && !host.contains('/') && !path.is_empty()).then_some(Transport::Ssh)
}

fn reusable_launch(ctx: &Ctx, executable: &str, args: &[String], cwd: &str) -> Proof<Value> {
    let identity = ctx
        .engines
        .launch_identity(executable, args, cwd, ctx.home, ctx.env);
    if ctx.engines.launch_reusable(&identity) {
        Ok(identity)
    } else {
        Err(UNPROVEN_LAUNCH)
    }
}

/// The `ssh` git launches and every config file it reads; a keyword that runs
/// another program fails closed.
fn ssh_state(cwd: &str, ctx: &Ctx) -> Proof<Value> {
    let identity = reusable_launch(ctx, "ssh", &[], cwd)?;
    let home = ctx.home.ok_or(UNPROVEN_LAUNCH)?;
    let system = ctx.engines.system_ssh_config();
    let mut files = vec![
        (fs_path::join(home, ".ssh/config"), false),
        (system.clone(), true),
    ];
    let included = fs_path::join(&fs_path::parent(&system), "ssh_config.d");
    files.extend(
        directory_files(&included)?
            .into_iter()
            .map(|path| (path, false)),
    );
    let mut digests = BTreeMap::new();
    for (path, allows_system_include) in files {
        ctx.check()?;
        if !fs_path::is_file(&path) {
            digests.insert(path, "absent".to_owned());
            continue;
        }
        let size = std::fs::metadata(&path).map_err(|_| UNPROVEN_LAUNCH)?.len();
        if size > MAX_CONFIG_BYTES {
            return Err(UNPROVEN_LAUNCH);
        }
        let data = fs_path::read_bounded(&path, MAX_CONFIG_BYTES).ok_or(UNPROVEN_LAUNCH)?;
        check_ssh_config(&String::from_utf8_lossy(&data), allows_system_include)?;
        digests.insert(path, fs_path::sha256_hex(&data));
    }
    Ok(json!({"identity": identity, "config": digests}))
}

fn directory_files(directory: &str) -> Proof<Vec<String>> {
    if !fs_path::is_dir(directory) {
        return Ok(Vec::new());
    }
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .map_err(|_| UNPROVEN_LAUNCH)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<Result<_, _>>()
        .map_err(|_| UNPROVEN_LAUNCH)?;
    if names.len() > MAX_SSH_FILES {
        return Err(UNPROVEN_LAUNCH);
    }
    names.sort();
    Ok(names
        .into_iter()
        .map(|name| fs_path::join(directory, &name))
        .filter(|path| fs_path::is_file(path))
        .collect())
}

fn check_ssh_config(text: &str, allows_system_include: bool) -> Proof<()> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let words: Vec<String> = line
            .split(|character: char| character.is_whitespace() || character == '=')
            .filter(|word| !word.is_empty())
            .map(str::to_ascii_lowercase)
            .collect();
        let keyword = words.first().map_or("", String::as_str);
        if keyword == "include" {
            if allows_system_include && SYSTEM_INCLUDES.contains(&words.join(" ").as_str()) {
                continue;
            }
            return Err(GIT_HELPER_CONFIG);
        }
        let runs_program = SSH_PROGRAM_KEYWORDS.contains(&keyword)
            || (keyword == "match"
                && words
                    .iter()
                    .any(|word| word.trim_start_matches('!') == "exec"));
        if runs_program {
            return Err(GIT_HELPER_CONFIG);
        }
    }
    Ok(())
}

/// Every file that decides which commits the refspecs send: `HEAD`,
/// `packed-refs` and each loose ref a source can resolve to. A name may be
/// per-worktree (`refs/worktree/`, `refs/bisect/`, `$GIT_DIR/<name>`) or
/// shared, so a linked worktree pins it under both its git dir and the common
/// dir. A symbolic loose ref names a file this does not follow, so it fails
/// closed, and so does a pseudoref (`ORIG_HEAD`, `FETCH_HEAD`, ...), which
/// everyday commands rewrite.
fn ref_state(git_dir: &str, common_dir: &str, sources: &[&str]) -> Proof<BTreeMap<String, String>> {
    if fs_path::is_dir(&fs_path::join(common_dir, "reftable")) {
        return Err(UNPROVEN_LAUNCH);
    }
    let head = fs_path::join(git_dir, "HEAD");
    let mut names = Vec::new();
    for source in sources {
        if *source == "HEAD" {
            let text = fs_path::read_bounded(&head, MAX_CONFIG_BYTES).ok_or(UNPROVEN_LAUNCH)?;
            if let Some(target) = symbolic_target(&text)? {
                names.push(target);
            }
        } else if is_pseudoref(source) {
            return Err(MUTABLE_LAUNCHER);
        } else if source.starts_with("refs/") {
            names.push((*source).to_owned());
        } else {
            names.extend([
                (*source).to_owned(),
                format!("refs/{source}"),
                format!("refs/tags/{source}"),
                format!("refs/heads/{source}"),
                format!("refs/remotes/{source}"),
                format!("refs/remotes/{source}/HEAD"),
            ]);
        }
    }
    let mut digests = BTreeMap::new();
    digests.insert(head.clone(), file_digest(&head)?);
    let packed = fs_path::join(common_dir, "packed-refs");
    digests.insert(packed.clone(), file_digest(&packed)?);
    for name in names {
        for dir in [git_dir, common_dir] {
            let path = fs_path::join(dir, &name);
            if fs_path::is_file(&path) {
                let text = fs_path::read_bounded(&path, MAX_CONFIG_BYTES).ok_or(UNPROVEN_LAUNCH)?;
                if symbolic_target(&text)?.is_some() {
                    return Err(UNPROVEN_LAUNCH);
                }
            }
            digests.insert(path.clone(), file_digest(&path)?);
        }
    }
    Ok(digests)
}

/// `ORIG_HEAD`, `FETCH_HEAD`, `MERGE_HEAD` and the like: git resolves an
/// all-caps name from `$GIT_DIR` before any `refs/` path.
fn is_pseudoref(name: &str) -> bool {
    !name.contains('/')
        && name.chars().any(|character| character.is_ascii_uppercase())
        && name.chars().all(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
        })
}

/// The target of a `ref: <name>` file, or `None` for a direct object id.
fn symbolic_target(data: &[u8]) -> Proof<Option<String>> {
    let text = String::from_utf8_lossy(data);
    let Some(target) = text.trim().strip_prefix("ref:") else {
        return Ok(None);
    };
    let target = target.trim();
    if !target.starts_with("refs/") || !is_plain_ref(target) {
        return Err(UNPROVEN_LAUNCH);
    }
    Ok(Some(target.to_owned()))
}

fn file_digest(path: &str) -> Proof<String> {
    if !fs_path::is_file(path) {
        return Ok("absent".to_owned());
    }
    let data = fs_path::read_bounded(path, MAX_CONFIG_BYTES).ok_or(UNPROVEN_LAUNCH)?;
    Ok(fs_path::sha256_hex(&data))
}

/// What a `git push` reads from config beyond the read-only helpers: the
/// remote it pushes to and the keys that make it run another program.
#[derive(Default)]
#[cfg_attr(windows, allow(dead_code))]
pub(super) struct PushFacts {
    /// `remote.<name>.url` values, by remote name, in file order.
    pub(super) urls: BTreeMap<String, Vec<String>>,
    /// `remote.<name>.pushurl` values; when present git pushes to these instead.
    pub(super) push_urls: BTreeMap<String, Vec<String>>,
    /// The first key that selects a program a push would run, if any.
    pub(super) helper: Option<String>,
    /// Every hooks folder the digest read: the repository's and `core.hooksPath`.
    pub(super) hook_dirs: Vec<String>,
}

impl PushFacts {
    pub(super) fn record(&mut self, section: &str, subsection: &str, name: &str, value: &str) {
        let selects_program = match section {
            "core" => matches!(name, "sshcommand" | "askpass" | "gitproxy"),
            "credential" => name == "helper" && !is_builtin_credential_helper(value),
            "remote" => {
                let urls = match name {
                    "url" => Some(&mut self.urls),
                    "pushurl" => Some(&mut self.push_urls),
                    _ => None,
                };
                if let Some(urls) = urls {
                    urls.entry(subsection.to_owned())
                        .or_default()
                        .push(value.to_owned());
                }
                matches!(name, "vcs" | "receivepack" | "uploadpack")
            }
            // A rewritten URL could name another transport than the one checked.
            "url" => matches!(name, "insteadof" | "pushinsteadof"),
            // Submodule pushes run hooks this digest never reads; signing runs
            // gpg; followed tags add refs beyond the named refspecs, which
            // `ref_state` never pins; push options reach the remote's hooks.
            "push" => {
                (matches!(name, "recursesubmodules" | "gpgsign" | "followtags") && !is_false(value))
                    || name == "pushoption"
            }
            "submodule" => name == "recurse" && subsection.is_empty() && !is_false(value),
            _ => false,
        };
        if selects_program && self.helper.is_none() {
            self.helper = Some(format!("{section}.{name}"));
        }
    }
}

/// `store` and `cache` are programs in git's own install; an empty value
/// clears the helper list.
fn is_builtin_credential_helper(value: &str) -> bool {
    let mut words = value.split_whitespace();
    match words.next() {
        None => true,
        Some("store" | "cache") => words.all(|word| word.starts_with("--")),
        Some(_) => false,
    }
}

fn is_false(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "false" | "no" | "off" | "0"
    )
}

#[cfg(all(test, not(windows)))]
#[path = "git_push_tests.rs"]
mod tests;
