//! The files a frozen install reads: the lockfile, the manager's project and
//! user configuration, and any workspace root above the project that could
//! make the manager install somewhere else.

use super::Manager;
use crate::jsonc::{loads_jsonc_pairs_checked, JsoncError, JsoncPairs};
use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::time::Instant;

const MAX_LOCKFILE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org/";

/// pnpm-workspace.yaml settings that only choose packages, versions or which
/// build scripts may run (none do under `--ignore-scripts`). Anything else,
/// such as a pnpmfile or a registry, is refused.
const PNPM_WORKSPACE_KEYS: &[&str] = &[
    "packages",
    "catalog",
    "catalogs",
    "onlyBuiltDependencies",
    "ignoredBuiltDependencies",
    "neverBuiltDependencies",
    "overrides",
    "patchedDependencies",
    "peerDependencyRules",
    "packageExtensions",
];

/// bunfig.toml `[install]` settings that do not move the registry, the
/// credentials or the lockfile.
const BUNFIG_INSTALL_KEYS: &[&str] = &[
    "exact",
    "frozenLockfile",
    "production",
    "optional",
    "dev",
    "peer",
    "saveTextLockfile",
    "linker",
    "auto",
];

pub(super) fn directory_ready(
    manager: Manager,
    context: super::super::PathContext<'_>,
    xdg_config_home: Option<&str>,
    deadline: Option<Instant>,
) -> bool {
    let (Some(directory), Some(home)) =
        (context.cwd.map(Path::new), context.home_dir.map(Path::new))
    else {
        return false;
    };
    if !directory.is_absolute()
        || !home.is_absolute()
        || !super::super::npm_reads::configuration_inert(context)
        || !regular(&directory.join("package.json"), MAX_CONFIG_BYTES)
        || !no_workspace_root_above(directory)
    {
        return false;
    }
    let (lockfile, absent): (&str, &[&str]) = match manager {
        Manager::Bun => ("bun.lock", &["bun.lockb"]),
        Manager::Pnpm => ("pnpm-lock.yaml", &[".pnpmfile.cjs", ".pnpmfile.mjs"]),
        Manager::Npm => ("package-lock.json", &["npm-shrinkwrap.json"]),
    };
    let lockfile = directory.join(lockfile);
    if !absent.iter().all(|name| missing(&directory.join(name)))
        || !regular(&lockfile, MAX_LOCKFILE_BYTES)
    {
        return false;
    }
    let Ok(text) = fs::read_to_string(&lockfile) else {
        return false;
    };
    // Both managers read user settings from the XDG configuration directory,
    // `~/.config` when it is unset.
    let mut config_dirs = vec![home.join(".config")];
    match xdg_config_home.map(Path::new) {
        Some(xdg) if xdg.is_absolute() => config_dirs.push(xdg.to_path_buf()),
        Some(_) => return false,
        None => {}
    }
    match manager {
        Manager::Bun => {
            let mut bunfigs = vec![directory.join("bunfig.toml"), home.join(".bunfig.toml")];
            bunfigs.extend(config_dirs.iter().map(|dir| dir.join(".bunfig.toml")));
            bunfigs.iter().all(|path| bunfig_inert(path)) && bun_lock_registry_only(&text, deadline)
        }
        Manager::Pnpm => {
            // pnpm's own global rc uses the npmrc format.
            let mut rcs = vec![home.join("Library/Preferences/pnpm/rc")];
            rcs.extend(config_dirs.iter().map(|dir| dir.join("pnpm/rc")));
            rcs.iter()
                .all(|path| super::super::npm_reads::npmrc_inert(path))
                && pnpm_workspace_inert(&directory.join("pnpm-workspace.yaml"))
                && pnpm_lock_registry_only(&text)
        }
        Manager::Npm => package_lock_registry_only(&text, deadline),
    }
}

fn missing(path: &Path) -> bool {
    fs::symlink_metadata(path).is_err_and(|error| error.kind() == ErrorKind::NotFound)
}

/// A regular file, not a link, no larger than `limit`.
fn regular(path: &Path, limit: u64) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file() && metadata.len() <= limit)
}

/// `path` is missing, or a regular file whose text passes `inert`.
fn optional_text(path: &Path, inert: impl FnOnce(&str) -> bool) -> bool {
    missing(path)
        || (regular(path, MAX_CONFIG_BYTES) && fs::read_to_string(path).is_ok_and(|t| inert(&t)))
}

/// Bun and npm look upward for a `package.json` whose `workspaces` include the
/// project, and pnpm for a `pnpm-workspace.yaml`. Either would install for
/// that root, with its lockfile and configuration, instead of this one.
fn no_workspace_root_above(directory: &Path) -> bool {
    let Ok(physical) = fs::canonicalize(directory) else {
        return false;
    };
    directory
        .ancestors()
        .skip(1)
        .chain(physical.ancestors().skip(1))
        .all(|ancestor| {
            missing(&ancestor.join("pnpm-workspace.yaml"))
                && optional_text(&ancestor.join("package.json"), |text| {
                    !text.contains("\"workspaces\"")
                })
        })
}

fn bunfig_inert(path: &Path) -> bool {
    optional_text(path, |text| {
        let Ok(table) = toml::from_str::<toml::Table>(text) else {
            return false;
        };
        match table.get("install") {
            None => true,
            Some(toml::Value::Table(install)) => install
                .keys()
                .all(|key| BUNFIG_INSTALL_KEYS.contains(&key.as_str())),
            Some(_) => false,
        }
    })
}

/// Top-level keys only: the file is YAML, and a nested value cannot name a
/// pnpmfile or a registry under the keys allowed here.
fn pnpm_workspace_inert(path: &Path) -> bool {
    optional_text(path, |text| {
        text.lines().all(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || line.starts_with([' ', '-']) {
                return !line.starts_with('\t');
            }
            if trimmed == "---" {
                return true;
            }
            line.split_once(':').is_some_and(|(key, _)| {
                let key = key.trim().trim_matches(['"', '\'']);
                PNPM_WORKSPACE_KEYS.contains(&key)
            })
        })
    })
}

/// Every resolution is a registry integrity hash: pnpm fetches those from the
/// configured registry, which the npmrc checks keep at the default. A git
/// commit, tarball URL or local directory resolution is refused, and so is
/// anything this line scan could misread (block style, escapes, explicit keys).
fn pnpm_lock_registry_only(text: &str) -> bool {
    text.lines().all(|line| {
        let trimmed = line.trim();
        if trimmed.contains(['\\', '\t']) || trimmed.starts_with(['?', '&', '*', '!']) {
            return false;
        }
        if trimmed.contains("tarball") {
            return false;
        }
        let key = trimmed
            .split_once(':')
            .map(|(key, _)| key.trim().trim_matches(['"', '\'']));
        if key != Some("resolution") {
            return true;
        }
        trimmed
            .strip_prefix("resolution: {integrity: ")
            .and_then(|rest| rest.strip_suffix('}'))
            .is_some_and(|hash| {
                !hash.is_empty()
                    && hash
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-'))
            })
    })
}

fn parse(text: &str, deadline: Option<Instant>) -> Option<JsoncPairs> {
    let mut check = || match deadline {
        Some(deadline) if Instant::now() >= deadline => {
            Err(JsoncError::Decode("deadline exceeded".into()))
        }
        _ => Ok(()),
    };
    let parsed = loads_jsonc_pairs_checked(text, &mut check).ok()?;
    unique_keys(&parsed).then_some(parsed)
}

/// A repeated key lets two readers disagree about which value counts.
fn unique_keys(value: &JsoncPairs) -> bool {
    match value {
        JsoncPairs::Object(pairs) => {
            let mut seen = HashSet::new();
            pairs
                .iter()
                .all(|(key, value)| seen.insert(key.as_str()) && unique_keys(value))
        }
        JsoncPairs::Array(items) => items.iter().all(unique_keys),
        _ => true,
    }
}

fn field<'a>(pairs: &'a [(String, JsoncPairs)], name: &str) -> Option<&'a JsoncPairs> {
    pairs
        .iter()
        .find_map(|(key, value)| (key == name).then_some(value))
}

/// `package-lock.json` v2 or v3, where every package resolves from the
/// default registry or links a workspace folder.
fn package_lock_registry_only(text: &str, deadline: Option<Instant>) -> bool {
    let Some(JsoncPairs::Object(root)) = parse(text, deadline) else {
        return false;
    };
    let version = matches!(field(&root, "lockfileVersion"),
        Some(JsoncPairs::Number(version)) if [2.0, 3.0].contains(version));
    let Some(JsoncPairs::Object(packages)) = field(&root, "packages") else {
        return false;
    };
    version
        && packages.iter().all(|(_, entry)| {
            let JsoncPairs::Object(entry) = entry else {
                return false;
            };
            let link = matches!(field(entry, "link"), Some(JsoncPairs::Bool(true)));
            let resolved = match field(entry, "resolved") {
                None => true,
                Some(JsoncPairs::String(url)) if link => !url.contains(':'),
                Some(JsoncPairs::String(url)) => {
                    url.starts_with(DEFAULT_REGISTRY) && !url.contains(['?', '#', '\\'])
                }
                Some(_) => false,
            };
            let version = match field(entry, "version") {
                None => true,
                Some(JsoncPairs::String(version)) => !version.contains(':'),
                Some(_) => false,
            };
            resolved && version
        })
}

/// `bun.lock`, where every package is `name@version` from the default
/// registry (an empty registry field) or a workspace member.
fn bun_lock_registry_only(text: &str, deadline: Option<Instant>) -> bool {
    let Some(JsoncPairs::Object(root)) = parse(text, deadline) else {
        return false;
    };
    let Some(JsoncPairs::Object(packages)) = field(&root, "packages") else {
        return false;
    };
    packages.iter().all(|(_, entry)| {
        let JsoncPairs::Array(entry) = entry else {
            return false;
        };
        let Some(JsoncPairs::String(identity)) = entry.first() else {
            return false;
        };
        let Some(spec) = identity
            .rfind('@')
            .filter(|at| *at > 0)
            .map(|at| &identity[at + 1..])
        else {
            return false;
        };
        if let Some(member) = spec.strip_prefix("workspace:") {
            return !member.contains(':');
        }
        !spec.is_empty()
            && spec
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
            && matches!(entry.get(1), Some(JsoncPairs::String(registry)) if registry.is_empty())
    })
}
