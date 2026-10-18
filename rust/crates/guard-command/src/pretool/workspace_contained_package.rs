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
//! Cargo joins them for the verbs that compile what the workspace already
//! has. Its `build.rs` scripts and proc macros run dependency code like npm
//! scripts, which is what the sandbox bounds. The crate sources it reads live
//! in `~/.cargo/registry` and `~/.cargo/git` and its toolchain in `~/.rustup`,
//! each granted read-only; the run gets its own `CARGO_HOME`, with those two
//! caches linked in, so cargo takes its locks and writes its own state inside
//! the private tree. `~/.cargo/config.toml` and `~/.cargo/credentials.toml`
//! stay out, which keeps registry tokens out of the run, and the fetching
//! verbs keep the admission they have today.
use crate::CanonicalCommandV1;
use std::path::Path;

// Node package managers. Their scripts, builds, tests and version probes run
// workspace code, which the sandbox bounds like any other local command.
const NODE_MANAGERS: &[&str] = &["npm", "pnpm", "yarn", "bun"];
pub(super) const NODE_PACKAGE_EXTENSION: &str = "command.package.node";
const PYTHON_PACKAGE_EXTENSION: &str = "command.package.python";
const GO_PACKAGE_EXTENSION: &str = "command.package.go";
const RUST_PACKAGE_EXTENSION: &str = "command.package.rust";
// The package-firewall permissions that mark a manager's use. They record
// which ecosystem ran, not a risk the run carries, so a local verb below one
// of them is still ordinary workspace work.
pub(super) const PACKAGE_EXTENSIONS: &[&str] = &[
    NODE_PACKAGE_EXTENSION,
    PYTHON_PACKAGE_EXTENSION,
    GO_PACKAGE_EXTENSION,
    RUST_PACKAGE_EXTENSION,
];
// The Python managers the package firewall watches. Each installs what it
// runs, so none of their verbs is local work; `uv` is the exception below.
const PYTHON_MANAGERS: &[&str] = &["pip", "pip3", "pipx", "uvx", "poetry", "pipenv"];
// uv drives a project environment the workspace holds. Only the verbs that
// read it are local: `pip`, `add`, `tool` and the rest reach a registry.
const UV_LOCAL_VERBS: &[&str] = &["run", "tree", "export", "version"];
// A Go build compiles the sources the module cache already holds and writes
// its objects to a private build cache. Only the verbs that stay there are
// local: `get`, `install`, `mod` and `work` reach a registry, and `tool` and
// `clean` are neither a build nor a read.
const GO_LOCAL_VERBS: &[&str] = &[
    "build", "test", "vet", "fmt", "list", "doc", "env", "version", "run", "generate",
];
// A cargo build compiles the crate sources the registry cache already holds
// into a target directory the workspace owns. Only the verbs that stay there
// are local: `install`, `add`, `update`, `publish` and the rest reach a
// registry, and `vendor` and `fetch` exist to populate a cache.
const CARGO_LOCAL_VERBS: &[&str] = &[
    "build", "b", "test", "t", "check", "c", "clippy", "fmt", "doc", "d", "run", "r", "bench",
    "tree", "metadata", "version", "nextest",
];
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

/// Whether `go` runs a local verb inside a module the workspace holds.
/// Outside a module these verbs read the wider GOPATH, and the sandbox has no
/// network to resolve a package by import path, so they keep the admission
/// they have.
fn local_go_work(arguments: &[&str], workspace: &Path) -> bool {
    arguments
        .first()
        .is_some_and(|verb| GO_LOCAL_VERBS.contains(&verb.to_ascii_lowercase().as_str()))
        && workspace.join("go.mod").is_file()
}

/// Whether `cargo` runs a local verb against a package the workspace holds.
/// A leading `+toolchain` selects a rustup toolchain, which the run may read.
/// Outside a package cargo has nothing to compile and would search upward out
/// of the workspace, so those commands keep the admission they have.
fn local_cargo_work(arguments: &[&str], workspace: &Path) -> bool {
    arguments
        .iter()
        .find(|argument| !argument.starts_with('+'))
        .is_some_and(|verb| CARGO_LOCAL_VERBS.contains(&verb.to_ascii_lowercase().as_str()))
        && workspace.join("Cargo.toml").is_file()
}

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

/// Whether any segment runs a manager this module decides a verb for. The
/// fallback in [`local_package_work`] admits every executable that is not a
/// package tool, which is right for the other half of a mixed command but is
/// no evidence on its own that a manager did local work: `npx` names neither
/// a manager nor a package tool, and the package it fetches is the point.
pub(super) fn names_a_manager(model: &CanonicalCommandV1) -> bool {
    model.segments.iter().any(|segment| {
        segment.executable.as_deref().is_some_and(|executable| {
            let name = super::super::executable_basename(executable).to_ascii_lowercase();
            NODE_MANAGERS.contains(&name.as_str())
                || PYTHON_MANAGERS.contains(&name.as_str())
                || matches!(name.as_str(), "uv" | "go")
        })
    })
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
        if name == "go" {
            let arguments: Vec<&str> = segment
                .arguments
                .iter()
                .map(String::as_str)
                .take_while(|argument| *argument != "--")
                .collect();
            return local_go_work(&arguments, workspace);
        }
        if name == "cargo" {
            let arguments: Vec<&str> = segment
                .arguments
                .iter()
                .map(String::as_str)
                .take_while(|argument| *argument != "--")
                .collect();
            return local_cargo_work(&arguments, workspace);
        }
        if PYTHON_MANAGERS.contains(&name.as_str()) {
            // Every other Python manager installs what it runs, and `uvx`
            // fetches the tool it names, so each reaches a registry.
            return false;
        }
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

#[cfg(test)]
#[path = "workspace_contained_go_tests.rs"]
mod go_tests;
