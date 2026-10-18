//! Package-manager work admitted to the workspace sandbox.
//!
//! Scripts, builds, tests and version probes run workspace code the sandbox
//! bounds. Registry verbs and every other package ecosystem keep their
//! existing admission.
//!
//! `uv run` joins them because its project environment is the workspace's own
//! `.venv`: the interpreter it starts is already an executable root, and a
//! synced environment needs neither the network nor uv's host cache. Its
//! installing verbs stay out, so a command that would have to fetch keeps the
//! admission it has today instead of failing inside the sandbox.
//!
//! Cargo stays out even with a committed `Cargo.lock` and `--locked`. Its
//! `build.rs` scripts and proc macros run dependency code like npm scripts,
//! but a Node project keeps its tools and dependencies in `node_modules`
//! inside the workspace. A rustup toolchain lives in `~/.rustup` and crate
//! sources in `~/.cargo/registry`, beside `~/.cargo/credentials.toml`, all
//! outside what the sandbox may read, so a contained `cargo check` cannot
//! start. Admitting it needs read grants for those trees first.
use crate::CanonicalCommandV1;
use std::path::Path;

// Node package managers. Their scripts, builds, tests and version probes run
// workspace code, which the sandbox bounds like any other local command.
const NODE_MANAGERS: &[&str] = &["npm", "pnpm", "yarn", "bun"];
pub(super) const NODE_PACKAGE_EXTENSION: &str = "command.package.node";
const PYTHON_PACKAGE_EXTENSION: &str = "command.package.python";
// The package-firewall permissions that mark a manager's use. They record
// which ecosystem ran, not a risk the run carries, so a local verb below one
// of them is still ordinary workspace work.
pub(super) const PACKAGE_EXTENSIONS: &[&str] = &[NODE_PACKAGE_EXTENSION, PYTHON_PACKAGE_EXTENSION];
// uv drives a project environment the workspace holds. Only the verbs that
// read it are local: `pip`, `add`, `tool` and the rest reach a registry.
const UV_LOCAL_VERBS: &[&str] = &["run", "tree", "export", "version"];
// Verbs that fetch from, or publish to, a registry. Without network they would
// fail silently, so they keep supply-chain admission or consent instead. This
// excludes by effect; local verbs and script names are never enumerated.
const REGISTRY_VERBS: &[&str] = &[
    "install",
    "i",
    "in",
    "ins",
    "inst",
    "insta",
    "instal",
    "isnt",
    "isnta",
    "isntal",
    "isntall",
    "add",
    "a",
    "update",
    "up",
    "upgrade",
    "upgrade-interactive",
    "self-update",
    "udpate",
    "ci",
    "clean-install",
    "ic",
    "install-clean",
    "isntall-clean",
    "it",
    "cit",
    "install-test",
    "install-ci-test",
    "clean-install-test",
    "sit",
    "uninstall",
    "un",
    "unlink",
    "remove",
    "rm",
    "r",
    "link",
    "ln",
    "exec",
    "x",
    "dlx",
    "create",
    "import",
    "dedupe",
    "ddp",
    "prune",
    "audit",
    "outdated",
    "fetch",
    "cache",
    "store",
    "pm",
    "env",
    "set",
    "plugin",
    "publish",
    "unpublish",
    "login",
    "logout",
    "adduser",
    "add-user",
    "token",
    "deprecate",
    "dist-tag",
    "owner",
    "access",
    "team",
    "org",
    "star",
    "unstar",
    "view",
    "v",
    "info",
    "show",
    "search",
    "s",
    "se",
    "find",
    "ping",
    "doctor",
];

/// Whether `uv` runs a local verb against an environment the workspace
/// already holds. uv materializes a project environment before it runs
/// anything, so without `.venv` the run would have to install, which the
/// sandbox has no network for; those commands keep the admission they have.
fn local_uv_work(arguments: &[&str], workspace: &Path) -> bool {
    arguments
        .first()
        .is_some_and(|verb| UV_LOCAL_VERBS.contains(&verb.to_ascii_lowercase().as_str()))
        && workspace.join(".venv").is_dir()
}

/// Whether every package-manager segment is a manager running a local verb.
/// A registry verb anywhere before `--` keeps the whole command out, so
/// option spellings that hide the verb from a parser cannot slip one through.
/// With `installed_runners`, the caller has proved every package runner starts
/// an installed project tool, so those segments count as local work.
pub(super) fn local_package_work(
    model: &CanonicalCommandV1,
    installed_runners: bool,
    workspace: &Path,
) -> bool {
    model.segments.iter().all(|segment| {
        if installed_runners && super::runner::runner_arguments(segment).is_some() {
            return true;
        }
        let Some(executable) = segment.executable.as_deref() else {
            return false;
        };
        let name = super::super::executable_basename(executable).to_ascii_lowercase();
        if name == "uv" {
            let arguments: Vec<&str> = segment
                .arguments
                .iter()
                .map(String::as_str)
                .take_while(|argument| *argument != "--")
                .collect();
            return local_uv_work(&arguments, workspace);
        }
        if !NODE_MANAGERS.contains(&name.as_str()) {
            return !super::super::generic::is_package_tool(executable);
        }
        let arguments: Vec<&str> = segment
            .arguments
            .iter()
            .map(String::as_str)
            .take_while(|argument| *argument != "--")
            .collect();
        // A bare `yarn` (or `yarn --frozen-lockfile`) installs, so the verb must
        // come first; `npm init <name>` runs a fetched initializer. A leading
        // option such as `--cwd dir` hides the verb and keeps the command out.
        let version_probe = arguments
            .iter()
            .all(|argument| matches!(*argument, "-v" | "--version" | "-h" | "--help"));
        let leading_verb = arguments
            .first()
            .is_some_and(|argument| !argument.starts_with('-'));
        let positional_init = arguments
            .iter()
            .position(|argument| *argument == "init")
            .is_some_and(|index| {
                arguments[index + 1..]
                    .iter()
                    .any(|argument| !argument.starts_with('-'))
            });
        !arguments.is_empty()
            && (leading_verb || version_probe)
            && !positional_init
            && !arguments
                .iter()
                .any(|argument| REGISTRY_VERBS.contains(&argument.to_ascii_lowercase().as_str()))
    })
}

#[cfg(test)]
#[path = "workspace_contained_cargo_tests.rs"]
mod cargo_tests;

#[cfg(test)]
#[path = "workspace_contained_uv_tests.rs"]
mod uv_tests;
