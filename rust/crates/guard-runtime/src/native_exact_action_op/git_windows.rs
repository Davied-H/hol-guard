//! Where Git for Windows reads configuration a read-only git could act on.
//!
//! The system files sit in the install that holds the bound `git.exe`, not at
//! `/etc/gitconfig`, and git finds the user files from `HOME`, then
//! `HOMEDRIVE` + `HOMEPATH`, then `USERPROFILE`. The shell git runs from may
//! pick any of those, so every home Guard can see is a candidate, and one it
//! cannot pin to a drive-rooted path leaves the read once-only.

use super::context::Ctx;
use super::fs_path;
use super::git_config::Found;
use super::launch_windows::{env_value, under_install_root};
use super::reasons::{Proof, GIT_HELPER_CONFIG, UNPROVEN_LAUNCH};

/// The MSYS2 environments a Git for Windows install ships its tools under.
const ARCH_DIRS: [&str; 3] = ["mingw64", "mingw32", "clangarm64"];
/// `git log` options that print no diff, so no text converter runs.
const PLAIN_LOG_OPTIONS: [&str; 9] = [
    "--",
    "--oneline",
    "--graph",
    "--decorate",
    "--no-decorate",
    "--all",
    "--reverse",
    "--no-color",
    "--first-parent",
];
const PLAIN_LOG_PREFIXES: [&str; 3] = ["--max-count=", "--format=", "--pretty="];
/// Subcommands that hash worktree files, which runs the clean filter.
const WORKTREE_READERS: [&str; 3] = ["status", "diff", "ls-files"];
const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;

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

/// Git for Windows runs `astextplain` (and the converters it calls) and
/// `git-lfs` through a `PATH` lookup the digest cannot bind, so a reusable
/// invocation must never start them: no text conversion while the
/// `astextplain` driver is configured, and no worktree hashing while the LFS
/// filter is configured and an attribute could route a path to it.
pub(super) fn path_helpers_stay_idle(
    found: &Found,
    invocation: &[String],
    root: &str,
    git_dir: &str,
) -> Proof<()> {
    let (subcommand, rest) = invocation.split_first().ok_or(GIT_HELPER_CONFIG)?;
    if found.astextplain && may_textconv(subcommand, rest) {
        return Err(GIT_HELPER_CONFIG);
    }
    if found.lfs_filter
        && WORKTREE_READERS.contains(&subcommand.as_str())
        && (found.attributes_name_lfs || index_supplies_attributes(root, git_dir)?)
    {
        return Err(GIT_HELPER_CONFIG);
    }
    Ok(())
}

/// Whether a read-only invocation can print a diff, which text-converts.
fn may_textconv(subcommand: &str, rest: &[String]) -> bool {
    if rest.iter().any(|argument| argument == "--no-textconv") {
        return false;
    }
    let mut options = rest.iter().filter(|argument| argument.starts_with('-'));
    match subcommand {
        "status" => options.any(|option| {
            option == "--verbose" || (!option.starts_with("--") && option.contains('v'))
        }),
        "log" => !options.all(|option| {
            PLAIN_LOG_OPTIONS.contains(&option.as_str())
                || PLAIN_LOG_PREFIXES
                    .iter()
                    .any(|prefix| option.starts_with(prefix))
                || (option.len() > 1 && option[1..].bytes().all(|byte| byte.is_ascii_digit()))
        }),
        "rev-parse" | "ls-files" | "branch" | "remote" | "worktree" => false,
        _ => true,
    }
}

/// Whether git could take attributes from the index: it reads an indexed
/// `.gitattributes` there when the worktree copy is missing or the entry is
/// sparse, and the digest binds only worktree files. An index this parser
/// cannot read (version 4, SHA-256, damaged) fails closed.
fn index_supplies_attributes(root: &str, git_dir: &str) -> Proof<bool> {
    let path = fs_path::join(git_dir, "index");
    if !fs_path::is_file(&path) {
        return Ok(false);
    }
    let data = fs_path::read_bounded(&path, MAX_INDEX_BYTES).ok_or(UNPROVEN_LAUNCH)?;
    let word = |at: usize| {
        data.get(at..at + 4)
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            .ok_or(UNPROVEN_LAUNCH)
    };
    let version = word(4)?;
    if !data.starts_with(b"DIRC") || !(2..=3).contains(&version) {
        return Err(UNPROVEN_LAUNCH);
    }
    let mut at = 12;
    for _ in 0..word(8)? {
        let flags = data
            .get(at + 60..at + 62)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
            .ok_or(UNPROVEN_LAUNCH)?;
        let extended = flags & 0x4000 != 0;
        let start = at + if extended { 64 } else { 62 };
        let length = data
            .get(start..)
            .and_then(|rest| rest.iter().position(|byte| *byte == 0))
            .ok_or(UNPROVEN_LAUNCH)?;
        if (extended && version < 3) || usize::from(flags & 0xFFF) != length.min(0xFFF) {
            return Err(UNPROVEN_LAUNCH);
        }
        let name =
            std::str::from_utf8(&data[start..start + length]).map_err(|_| UNPROVEN_LAUNCH)?;
        let name = name.to_ascii_lowercase();
        if (name == ".gitattributes" || name.ends_with("/.gitattributes"))
            && (extended || !fs_path::is_file(&fs_path::join(root, &name)))
        {
            return Ok(true);
        }
        at += (start - at + length + 8) & !7;
    }
    Ok(false)
}
