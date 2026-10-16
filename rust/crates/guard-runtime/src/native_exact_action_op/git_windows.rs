//! Where Git for Windows reads configuration a read-only git could act on.
//!
//! The system files sit in the install that holds the bound `git.exe`, not at
//! `/etc/gitconfig`, and git finds the user files from `HOME`, then
//! `HOMEDRIVE` + `HOMEPATH`, then `USERPROFILE`. The shell git runs from may
//! pick any of those, so every home Guard can see is a candidate, and one it
//! cannot pin to a drive-rooted path leaves the read once-only.

use super::context::Ctx;
use super::fs_path;
use super::launch_windows::{env_value, under_install_root};
use super::reasons::{Proof, UNPROVEN_LAUNCH};

/// The MSYS2 environments a Git for Windows install ships its tools under.
const ARCH_DIRS: [&str; 3] = ["mingw64", "mingw32", "clangarm64"];

/// The system config and attribute files of the install holding `git`.
///
/// Only the launcher layouts Git for Windows installs (`cmd\git.exe`,
/// `bin\git.exe`, `<arch>\bin\git.exe`) under an administrator-owned install
/// root are known; any other copy of git could read files this proof does
/// not list.
pub(super) fn system_files(git: &str, ctx: &Ctx) -> Proof<Vec<String>> {
    let bin = fs_path::parent(git);
    let above = fs_path::parent(&bin);
    let above_name = fs_path::name(&above).to_ascii_lowercase();
    let root = match fs_path::name(&bin).to_ascii_lowercase().as_str() {
        "cmd" => above,
        "bin" if ARCH_DIRS.contains(&above_name.as_str()) => fs_path::parent(&above),
        "bin" => above,
        _ => return Err(UNPROVEN_LAUNCH),
    };
    if !under_install_root(&root) {
        return Err(UNPROVEN_LAUNCH);
    }
    let mut files = vec![
        fs_path::join(&root, "etc\\gitconfig"),
        fs_path::join(&root, "etc\\gitattributes"),
    ];
    for arch in ARCH_DIRS {
        let prefix = fs_path::join(&root, arch);
        if fs_path::is_dir(&prefix) {
            files.push(fs_path::join(&prefix, "etc\\gitconfig"));
            files.push(fs_path::join(&prefix, "etc\\gitattributes"));
        }
    }
    if let Some(data) = env_value(ctx.env, "PROGRAMDATA")? {
        files.push(fs_path::join(&drive_rooted(data)?, "Git\\config"));
    }
    Ok(files)
}

/// `XDG_CONFIG_HOME` and every home git may resolve, each drive-rooted.
pub(super) fn user_config_roots(ctx: &Ctx) -> Proof<(Option<String>, Vec<String>)> {
    let xdg = match env_value(ctx.env, "XDG_CONFIG_HOME")? {
        Some(value) if !value.is_empty() => Some(drive_rooted(value)?),
        _ => None,
    };
    let mut homes: Vec<String> = Vec::new();
    let joined = match (
        env_value(ctx.env, "HOMEDRIVE")?,
        env_value(ctx.env, "HOMEPATH")?,
    ) {
        (Some(drive), Some(path)) if !drive.is_empty() && !path.is_empty() => {
            Some(format!("{drive}{path}"))
        }
        _ => None,
    };
    let named = [
        ctx.home.map(str::to_owned),
        env_value(ctx.env, "HOME")?.map(str::to_owned),
        joined,
        env_value(ctx.env, "USERPROFILE")?.map(str::to_owned),
    ];
    for home in named.into_iter().flatten().filter(|home| !home.is_empty()) {
        let home = drive_rooted(&home)?;
        if !homes.iter().any(|seen| seen.eq_ignore_ascii_case(&home)) {
            homes.push(home);
        }
    }
    Ok((xdg, homes))
}

/// An include or hooks path git resolves the way this proof does: drive-rooted,
/// or relative to the including file. `~` follows git's own `HOME`, and a
/// rooted, drive-relative or `%(prefix)` spelling follows the install or a
/// per-drive cwd.
pub(super) fn config_reference_is_pinned(value: &str) -> bool {
    fs_path::is_abs(value)
        || !(fs_path::is_anchored(value) || value.starts_with(['~', '%', '/', '\\']))
}

fn drive_rooted(value: &str) -> Proof<String> {
    if fs_path::is_abs(value) {
        Ok(fs_path::norm(value))
    } else {
        Err(UNPROVEN_LAUNCH)
    }
}
