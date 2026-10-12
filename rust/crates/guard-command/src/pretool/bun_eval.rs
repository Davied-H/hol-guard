//! `bun -e "console.log(<constant>)"` proven without review.
//!
//! The program itself is the same constant print the Node proof accepts. Bun
//! differs in what runs before it: a `bunfig.toml` beside the working
//! directory, or a global `.bunfig.toml`, can name `preload` modules, and
//! `BUN_OPTIONS` prepends arguments such as `--preload`. The proof holds only
//! when the stamped environment and the filesystem rule all of those out.
use crate::CanonicalCommandV1;
use std::path::{Path, PathBuf};

pub(super) fn exact_safe_command(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let [segment] = model.segments.as_slice() else {
        return false;
    };
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || segment.executable.as_deref() != Some("bun")
        || !segment.environment_names.is_empty()
    {
        return false;
    }
    let stripped = super::segment_proof::without_stderr_merge(segment);
    let segment = stripped.as_ref().unwrap_or(segment);
    let Some(environment) =
        execution_environment.filter(|environment| environment.has_valid_shape())
    else {
        return false;
    };
    let (Some(home), Some(cwd)) = (context.home_dir, context.cwd) else {
        return false;
    };
    let (Ok(home), Ok(cwd)) = (std::fs::canonicalize(home), std::fs::canonicalize(cwd)) else {
        return false;
    };
    super::pure_expression::safe_inline_expression("bun", &segment.arguments)
        && !environment
            .environment_names
            .iter()
            .any(|name| stamped_loader_name(name))
        && resolved_outside_workspace(&environment.path, &cwd, &home)
        && !preload_config_present(environment, &home, &cwd)
}

/// `BUN_OPTIONS` and dynamic-loader injection run code before the print.
fn stamped_loader_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("BUN_OPTIONS")
        || matches!(
            name.to_ascii_uppercase().as_str(),
            "LD_PRELOAD" | "LD_AUDIT" | "DYLD_INSERT_LIBRARIES"
        )
}

/// The `bun` the shell executes comes from an absolute `PATH` entry, and that
/// file is outside the repository that contains the working directory.
fn resolved_outside_workspace(path: &str, cwd: &Path, home: &Path) -> bool {
    let root = repository_root(cwd, home);
    for directory in std::env::split_paths(path) {
        // An empty or relative entry is resolved by the shell against the
        // command cwd. Skipping it would let a later absolute `bun` hide one
        // the repository supplies.
        if !directory.is_absolute() {
            return false;
        }
        let candidate = directory.join("bun");
        if !executable_file(&candidate) {
            continue;
        }
        return std::fs::canonicalize(&candidate).is_ok_and(|binary| !binary.starts_with(root));
    }
    false
}

/// Outermost `.git` ancestor of `cwd` that does not contain the session home.
///
/// The session home often lives inside a checkout. That checkout's `.git` is
/// not the repository the command is running in.
fn repository_root<'a>(cwd: &'a Path, home: &'a Path) -> &'a Path {
    cwd.ancestors()
        .filter(|ancestor| {
            !home.starts_with(ancestor) && std::fs::symlink_metadata(ancestor.join(".git")).is_ok()
        })
        .last()
        .unwrap_or(cwd)
}

fn executable_file(candidate: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(candidate) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

/// Any Bun configuration that could name a preload. Bun reads `bunfig.toml`
/// from the working directory; ancestors are refused as well so a version that
/// searches upward cannot change the answer.
fn preload_config_present(
    environment: &guard_contracts::GuardExecutionEnvironmentV1,
    home: &Path,
    cwd: &Path,
) -> bool {
    let mut candidates: Vec<PathBuf> = cwd
        .ancestors()
        .flat_map(|directory| {
            [
                directory.join("bunfig.toml"),
                directory.join(".bunfig.toml"),
            ]
        })
        .collect();
    candidates.push(home.join(".bunfig.toml"));
    if let Some(shell_home) = environment.home.as_deref() {
        candidates.push(Path::new(shell_home).join(".bunfig.toml"));
    }
    if let Some(xdg) = environment.xdg_config_home.as_deref() {
        candidates.push(Path::new(xdg).join(".bunfig.toml"));
    } else {
        candidates.push(home.join(".config/.bunfig.toml"));
        if let Some(shell_home) = environment.home.as_deref() {
            candidates.push(Path::new(shell_home).join(".config/.bunfig.toml"));
        }
    }
    candidates.iter().any(|candidate| {
        std::fs::symlink_metadata(candidate).map_or_else(
            |error| error.kind() != std::io::ErrorKind::NotFound,
            |_| true,
        )
    })
}
