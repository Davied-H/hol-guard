//! A one-time approval of a command that starts with environment settings.
//!
//! `FOO=1 ./release.sh` and `env FOO=1 ./release.sh` are reviewed because the
//! setting may change how the program runs. The launch proofs refuse an
//! environment prefix, so nothing else bound the approved retry and the same
//! command was held again. This binds the retry to the settings as spelled,
//! the agent's execution environment, and the launch identity of the command
//! the settings prefix. A different value, program, argument or script
//! content binds somewhere else, so the approval never reaches them.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use guard_contracts::{write_canonical_json, GuardExecutionEnvironmentV1};
use serde_json::{json, Value};

use super::context::{Ctx, Engines};
use super::fs_path;
use super::launch::launch_identity;
use super::reasons::{Proof, COMPOUND_COMMAND, MUTABLE_LAUNCHER, UNPROVEN_LAUNCH};
use super::reuse_shape;
use crate::mcp_proxy_shlex::{join, split_with};

const SHELL_PUNCTUATION: &str = ";&|<>";
/// Text the shell expands or the parser reads differently from a word list.
const EXPANSIONS: [&str; 7] = ["`", "$", "\n", "\r", "#", "~", "\\"];
const GLOBS: [char; 4] = ['*', '?', '[', '{'];
const MAX_SETTINGS: usize = 8;
const PROOF_BUDGET: Duration = Duration::from_secs(5);
const BINDING_KIND: &str = "env-launch";

/// The digest a one-time approval of `command` is bound to, or why it cannot be.
pub(super) fn env_state(
    command: &str,
    cwd: &str,
    execution_environment: Option<&Value>,
    engines: &dyn Engines,
) -> Proof<String> {
    if cfg!(windows)
        || EXPANSIONS.iter().any(|marker| command.contains(marker))
        || command.contains(&GLOBS[..])
    {
        return Err(MUTABLE_LAUNCHER);
    }
    let words = split_with(command, SHELL_PUNCTUATION, "#").ok_or(MUTABLE_LAUNCHER)?;
    if !reuse_shape::is_simple(&words) {
        return Err(COMPOUND_COMMAND);
    }
    let (settings, program) = settings_and_program(&words)?;
    let environment: GuardExecutionEnvironmentV1 =
        serde_json::from_value(execution_environment.ok_or(UNPROVEN_LAUNCH)?.clone())
            .map_err(|_| UNPROVEN_LAUNCH)?;
    if !environment.has_valid_shape() {
        return Err(UNPROVEN_LAUNCH);
    }
    let home = environment.home.clone().ok_or(UNPROVEN_LAUNCH)?;
    // The launch proofs resolve the program from the agent's own lookup path.
    let lookup = BTreeMap::from([
        ("PATH".to_owned(), environment.path.clone()),
        ("HOME".to_owned(), home.clone()),
    ]);
    let ctx = Ctx {
        home: Some(&home),
        env: &lookup,
        deadline: Instant::now() + PROOF_BUDGET,
        engines,
    };
    let launch = launch_identity(&join(program), cwd, &ctx)?;
    let bound = json!({
        "kind": BINDING_KIND,
        "argv": words,
        "settings": settings,
        "cwd": cwd,
        "path": environment.path,
        "home": home,
        "environment_digest": environment.environment_digest,
        "launch": launch,
    });
    let mut encoded = Vec::new();
    write_canonical_json(&bound, &mut encoded).map_err(|_| UNPROVEN_LAUNCH)?;
    Ok(fs_path::sha256_hex(&encoded))
}

/// The leading `NAME=value` settings, with an optional bare `env` before
/// them, and the command they prefix. `env` options (`-i`, `-u`, `-S`, `-C`)
/// change what runs, so only the assignment form is bindable.
fn settings_and_program(words: &[String]) -> Proof<(Vec<(&str, &str)>, &[String])> {
    let rest = match words.split_first() {
        Some((first, tail)) if first == "env" => tail,
        _ => words,
    };
    let mut settings: Vec<(&str, &str)> = Vec::new();
    let mut index = 0;
    while let Some((name, value)) = rest.get(index).and_then(|word| word.split_once('=')) {
        if !name
            .chars()
            .next()
            .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        {
            break;
        }
        if !guard_command::pretool::bindable_setting(name, value)
            || settings
                .iter()
                .any(|(known, _)| known.eq_ignore_ascii_case(name))
        {
            return Err(MUTABLE_LAUNCHER);
        }
        settings.push((name, value));
        index += 1;
    }
    let program = &rest[index..];
    let spelled_program = program.first().ok_or(MUTABLE_LAUNCHER)?;
    if settings.is_empty()
        || settings.len() > MAX_SETTINGS
        || spelled_program.starts_with('-')
        || spelled_program.contains('=')
        || spelled_program == "env"
    {
        return Err(MUTABLE_LAUNCHER);
    }
    Ok((settings, program))
}

#[cfg(all(test, unix))]
#[path = "env_launch_tests.rs"]
mod tests;
