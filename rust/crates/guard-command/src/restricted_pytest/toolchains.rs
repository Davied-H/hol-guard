//! Vetted toolchain roots a workspace sandbox may execute, derived from the
//! host PATH. A root is accepted only when it is a trusted system prefix, a
//! known version-manager directory or one of the caller's sealed tool
//! directories, and is not writable by anyone else.
use super::*;
use std::os::unix::fs::MetadataExt;

#[path = "user_tools.rs"]
mod user_tools;
pub(super) use user_tools::{host_corepack_home, host_go_module_cache};

/// Where `xcode-select -s` records the developer directory: the current
/// location first, then the one older macOS releases used.
const DEVELOPER_LINKS: &[&str] = &[
    "/private/var/select/developer_dir",
    "/private/var/db/xcode_select_link",
];
/// What `/usr/bin` shims use when no developer directory was selected.
const DEFAULT_DEVELOPER_DIRS: &[&str] = &[
    "/Applications/Xcode.app/Contents/Developer",
    "/Library/Developer/CommandLineTools",
];
const DEVELOPER_PREFIXES: &[&str] = &["/Library/Developer", "/Applications"];
/// Frameworks that a trusted prefix links its binaries into, such as
/// python.org's `/usr/local/bin/python3`.
const LINKED_FRAMEWORKS: &[(&str, &str)] =
    &[("/usr/local", "/Library/Frameworks/Python.framework")];
/// macOS gives the `admin` group write access to Homebrew and python.org
/// installs. Its members can already administer the machine, so that write
/// bit does not let anyone else plant code.
#[cfg(target_os = "macos")]
const TRUSTED_WRITER_GROUPS: &[u32] = &[0, 80];
#[cfg(not(target_os = "macos"))]
const TRUSTED_WRITER_GROUPS: &[u32] = &[0];
/// Version-manager prefixes under HOME. `true` grants the version directory
/// that owns a `bin` entry; `false` grants only the `bin` directory, because
/// its parent can hold credentials.
const MANAGED_HOME_PREFIXES: &[(&str, bool)] = &[
    (".nvm/versions", true),
    (".pyenv/versions", true),
    (".asdf/installs", true),
    (".bun/bin", false),
    (".cargo/bin", false),
];
/// Package-manager prefixes whose binaries are symlinks into these siblings.
const PACKAGE_SIBLINGS: &[&str] = &["Cellar", "opt"];

/// Owned by root or the caller, not writable by others, and writable by its
/// group only when that group is root's or the administrators'.
fn owned_and_sealed(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    let uid = nix::unistd::geteuid().as_raw();
    metadata.is_dir()
        && (metadata.uid() == 0 || metadata.uid() == uid)
        && metadata.mode() & 0o002 == 0
        && (metadata.mode() & 0o020 == 0 || TRUSTED_WRITER_GROUPS.contains(&metadata.gid()))
}

/// This account's HOME and the caller's, canonical.
fn homes(home: Option<&Path>) -> Vec<PathBuf> {
    host_home_directory()
        .into_iter()
        .chain(home.map(|h| h.canonicalize().unwrap_or_else(|_| h.to_path_buf())))
        .collect()
}

fn forbidden(path: &Path, home: Option<&Path>) -> bool {
    let homes = homes(home);
    homes.is_empty() || homes.iter().any(|h| sensitive_for_exec(path, h))
}

fn sensitive_for_exec(path: &Path, home: &Path) -> bool {
    // HOME and its ancestors would expose the whole profile directory.
    if path == home || home.ancestors().any(|ancestor| ancestor == path) {
        return true;
    }
    path.strip_prefix(home).is_ok_and(|relative| {
        relative.components().next().is_some_and(|first| {
            matches!(
                first.as_os_str().to_str(),
                Some(
                    ".aws"
                        | ".azure"
                        | ".config"
                        | ".docker"
                        | ".gnupg"
                        | ".kube"
                        | ".ssh"
                        | "Library"
                )
            )
        })
    })
}

fn accept_entry(entry: &Path, home: Option<&Path>, workspace: &Path) -> Option<Vec<PathBuf>> {
    let canonical = entry.canonicalize().ok()?;
    // Any other directory must be one of the caller's sealed tool directories.
    let user_tool = || {
        let homes = homes(home);
        user_tools::tool_root(&canonical, &homes, workspace).map(|root| {
            let mut roots = vec![root.clone()];
            roots.extend(user_tools::shim_siblings(&root, &homes, workspace));
            roots
        })
    };
    if forbidden(&canonical, home) || !owned_and_sealed(&canonical) {
        return user_tool();
    }
    if let Some(prefix) = TRUSTED_EXECUTABLE_ROOTS
        .iter()
        .find(|root| path_is_within(&canonical, root))
    {
        let mut roots = vec![canonical.clone()];
        for (owner, framework) in LINKED_FRAMEWORKS {
            let framework = Path::new(framework);
            if prefix.as_path() == Path::new(owner) && owned_and_sealed(framework) {
                roots.extend(framework.canonicalize().ok());
            }
        }
        for sibling in PACKAGE_SIBLINGS {
            let candidate = prefix.join(sibling);
            if candidate.exists() {
                if let Ok(resolved) = candidate.canonicalize() {
                    if owned_and_sealed(&resolved) && path_is_within(&resolved, prefix) {
                        roots.push(resolved);
                    }
                }
            }
        }
        return Some(roots);
    }
    for home in home.into_iter().chain(host_home_directory().as_deref()) {
        for (prefix, grant_parent) in MANAGED_HOME_PREFIXES {
            let base = home.join(prefix);
            if !path_is_within(&canonical, &base) {
                continue;
            }
            let root = match canonical.parent() {
                Some(parent)
                    if *grant_parent
                        && canonical.file_name().and_then(OsStr::to_str) == Some("bin")
                        && parent != base
                        && path_is_within(parent, &base) =>
                {
                    parent.to_path_buf()
                }
                _ => canonical.clone(),
            };
            if owned_and_sealed(&root) && !forbidden(&root, Some(home)) {
                return Some(vec![root]);
            }
        }
    }
    user_tool()
}

/// The Xcode or CommandLineTools root `/usr/bin` shims forward into. Inside
/// an app bundle the whole bundle is granted, because the developer
/// directory loads frameworks and `Info.plist` from beside it.
fn developer_dir() -> Option<PathBuf> {
    let selected = DEVELOPER_LINKS
        .iter()
        .find_map(|link| fs::read_link(link).ok());
    let target = match selected {
        Some(target) => target,
        None => DEFAULT_DEVELOPER_DIRS
            .iter()
            .map(PathBuf::from)
            .find(|candidate| candidate.is_dir())?,
    };
    let resolved = target.canonicalize().ok()?;
    let root = developer_root(&resolved)?;
    owned_and_sealed(&root).then_some(root)
}

fn developer_root(resolved: &Path) -> Option<PathBuf> {
    let prefix = DEVELOPER_PREFIXES
        .iter()
        .map(Path::new)
        .find(|prefix| path_is_within(resolved, prefix))?;
    if prefix != Path::new("/Applications") {
        return Some(resolved.to_path_buf());
    }
    let bundle = prefix.join(resolved.strip_prefix(prefix).ok()?.components().next()?);
    (bundle.extension() == Some(OsStr::new("app"))).then_some(bundle)
}

/// A workspace venv's `bin` and the install roots its launchers link to. The
/// directory keeps its place on the sandbox PATH, because a bare `python` has
/// to find the same launcher inside the sandbox as the session found outside
/// it, and the install becomes an executable root, because that launcher is a
/// symlink to a file the workspace does not hold.
fn workspace_venv(entry: &Path, workspace: &Path) -> Option<(PathBuf, Vec<PathBuf>)> {
    let canonical = entry.canonicalize().ok()?;
    if !path_is_within(&canonical, workspace) {
        return None;
    }
    let roots = super::venv::workspace_base_roots(&canonical, workspace);
    // The interpreter needs every root it was given; a run that can start but
    // cannot read its standard library would fail inside the sandbox instead.
    (!roots.is_empty() && roots.iter().all(|root| owned_and_sealed(root)))
        .then_some((canonical, roots))
}

/// A directory of the workspace's own that the session finds its tools in,
/// such as `node_modules/.bin`. It needs no grant, because the sandbox reads
/// and runs the workspace already; what it needs is its place on the sandbox
/// PATH, so a bare `vite` or `tsc` resolves to the same file inside the
/// sandbox that the session resolved outside it. Without it the sandbox
/// cannot start the program the command names, and ordinary project work is
/// contained and then refused.
fn workspace_tools(entry: &Path, workspace: &Path) -> Option<PathBuf> {
    let canonical = entry.canonicalize().ok()?;
    // A directory anyone else can write could answer for a project's tool
    // with a file the session never saw.
    (path_is_within(&canonical, workspace) && owned_and_sealed(&canonical)).then_some(canonical)
}

/// Keep `canonical` on the sandbox PATH, in the place the session gave it.
fn keep_entry(entries: &mut Vec<String>, canonical: &Path) {
    let text = canonical.to_string_lossy().into_owned();
    if !text.contains(':') && !entries.contains(&text) {
        entries.push(text);
    }
}

/// Executable roots and the sandbox PATH for `search_path`, plus the developer
/// directory and Corepack's cache. Entries that fail any check are dropped,
/// so their tools are simply unavailable.
pub(super) fn workspace_exec_roots(
    search_path: &str,
    home: Option<&Path>,
    workspace: &Path,
    go: bool,
) -> (Vec<PathBuf>, String) {
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut entries: Vec<String> = Vec::new();
    for entry in search_path.split(':').take(64) {
        let path = Path::new(entry);
        if !path.is_absolute() {
            continue;
        }
        if path_is_within(path, workspace) {
            if let Some((bin, installs)) = workspace_venv(path, workspace) {
                keep_entry(&mut entries, &bin);
                for install in installs {
                    if !roots.contains(&install) {
                        roots.push(install);
                    }
                }
            } else if let Some(bin) = workspace_tools(path, workspace) {
                keep_entry(&mut entries, &bin);
            }
            continue;
        }
        let Some(accepted) = accept_entry(path, home, workspace) else {
            continue;
        };
        if let Ok(canonical) = path.canonicalize() {
            keep_entry(&mut entries, &canonical);
        }
        for root in accepted {
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
    }
    for system in ["/usr/bin", "/bin"] {
        if !entries.iter().any(|entry| entry == system) {
            entries.push(system.to_owned());
        }
    }
    roots.extend(developer_dir());
    // Corepack's shims (`pnpm`, `yarn`) read the package manager they run
    // from its cache; the launch environment points `COREPACK_HOME` there.
    if let Some(cache) = host_corepack_home() {
        if !roots.contains(&cache) {
            roots.push(cache);
        }
    }
    // A Go build compiles the dependency sources in the module cache; the
    // launch environment points `GOMODCACHE` there and writes its own build
    // cache into the private directory instead. Only a run that names the
    // toolchain gets it: the cache holds whatever `go mod download` fetched,
    // private modules included, and nothing else in a workspace reads it.
    if go {
        if let Some(cache) = host_go_module_cache() {
            if !roots.contains(&cache) {
                roots.push(cache);
            }
        }
    }
    (roots, entries.join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn dir_with(mode: u32) -> tempfile_like::Dir {
        tempfile_like::Dir::new(mode)
    }

    /// Minimal temp directory without an extra dependency.
    mod tempfile_like {
        use super::*;
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        pub(super) struct Dir(pub PathBuf);
        impl Dir {
            pub(super) fn new(mode: u32) -> Self {
                let path = std::env::temp_dir().join(format!(
                    "guard-toolchain-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                ));
                let _ = fs::remove_dir_all(&path);
                fs::create_dir_all(&path).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
                Self(path.canonicalize().unwrap())
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn rejects_world_writable_and_home_entries() {
        let open = dir_with(0o777);
        assert!(!owned_and_sealed(&open.0));
        let sealed = dir_with(0o755);
        assert!(owned_and_sealed(&sealed.0));
        assert!(sensitive_for_exec(&sealed.0, &sealed.0));
        assert!(sensitive_for_exec(sealed.0.parent().unwrap(), &sealed.0));
        assert!(sensitive_for_exec(&sealed.0.join(".ssh"), &sealed.0));
        assert!(!sensitive_for_exec(&sealed.0.join("tool"), &sealed.0));
    }

    #[test]
    fn group_write_is_trusted_only_for_administrator_groups() {
        let shared = dir_with(0o775);
        let gid = shared.0.metadata().unwrap().gid();
        assert_eq!(
            owned_and_sealed(&shared.0),
            TRUSTED_WRITER_GROUPS.contains(&gid)
        );
        assert!(!owned_and_sealed(&dir_with(0o757).0));
    }

    #[test]
    fn developer_directories_grant_their_app_bundle() {
        assert_eq!(
            developer_root(Path::new("/Applications/Xcode-beta.app/Contents/Developer")),
            Some(PathBuf::from("/Applications/Xcode-beta.app"))
        );
        assert_eq!(
            developer_root(Path::new("/Library/Developer/CommandLineTools")),
            Some(PathBuf::from("/Library/Developer/CommandLineTools"))
        );
        assert_eq!(
            developer_root(Path::new("/Applications/Tools/Developer")),
            None
        );
        assert_eq!(
            developer_root(Path::new("/opt/Xcode.app/Contents/Developer")),
            None
        );
    }

    #[test]
    fn unlisted_and_symlinked_entries_are_dropped() {
        let home = dir_with(0o755);
        let outside = dir_with(0o755);
        let link = home.0.join("link");
        symlink(&outside.0, &link).unwrap();
        let (roots, path) = workspace_exec_roots(
            &format!("{}:relative/bin", link.display()),
            Some(&home.0),
            Path::new("/nonexistent-workspace"),
            false,
        );
        assert!(!roots.contains(&outside.0) && !roots.contains(&link));
        assert_eq!(path, "/usr/bin:/bin");
    }

    #[test]
    fn the_go_module_cache_is_an_executable_root_only_for_a_go_run() {
        // The cache holds whatever `go mod download` fetched, a private
        // module included, and the plan grants each root as executable.
        let Some(cache) = host_go_module_cache() else {
            return;
        };
        let (without, _) = workspace_exec_roots("", None, Path::new("/nonexistent"), false);
        let (with, _) = workspace_exec_roots("", None, Path::new("/nonexistent"), true);
        assert!(!without.contains(&cache));
        assert!(with.contains(&cache));
    }
}
