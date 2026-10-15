//! Ignore-file negations that let `rg` reach hidden files.
//!
//! `rg` skips hidden entries on its own, but an entry an ignore rule
//! re-includes is searched even when it is hidden: `!.env` in a `.gitignore`,
//! `.ignore` or `.rgignore`, the repository's `info/exclude` or the global
//! Git excludes file makes a plain `rg foo` print `.env` lines. A content
//! search is proven only when no such rule can re-include a hidden entry
//! that exists below the search root. A negation component is harmless when
//! it is visible, names a benign dotfile such as `.gitkeep`, or is a wildcard
//! that passes the screen `-g` include globs get; any other component counts
//! only if it matches a hidden name the walk finds, so `!.env.example` in a
//! repository without that file does not hold every search.
//!
//! The walk reads only ignore files and names, never other contents. It
//! skips links and hidden directories other than benign ones, which `rg`
//! does not enter, and prunes directories a plain ignore rule names unless
//! some negation re-includes that name.
use super::tree;
use super::ReadContext;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_ENTRIES: usize = 100_000;
const MAX_DEPTH: usize = 64;
const MAX_IGNORE_BYTES: u64 = 64 * 1024;
const IGNORE_FILES: [&str; 3] = [".gitignore", ".ignore", ".rgignore"];

/// Negation components seen so far: every one, for re-entered directories,
/// and the ones that could name a hidden secret.
#[derive(Default)]
struct Negations {
    all: Vec<String>,
    risky: Vec<String>,
}

/// One plain directory name an ignore rule prunes.
#[derive(Clone)]
struct Rule {
    name: String,
    /// The rule starts with `/` and applies only in its own directory.
    rooted: bool,
    /// The rule comes from a `.gitignore`, which a nested repository stops.
    git: bool,
}

/// True when no ignore file can re-include a hidden entry below any of the
/// search's roots. Without roots `rg` searches the cwd. A shell glob root is
/// checked from the directory before its first wildcard, which holds every
/// expansion. A context-free classification has no tree to read, as with
/// path operands.
pub(super) fn roots_proven(roots: &[&str], context: ReadContext<'_>) -> bool {
    if context.home_dir.is_none() && context.cwd.is_none() {
        return true;
    }
    let roots = if roots.is_empty() { &["."][..] } else { roots };
    roots.iter().all(|root| {
        let prefix: Vec<&str> = root
            .split('/')
            .take_while(|part| !part.contains(['*', '?', '[', '{']))
            .collect();
        let prefix = match prefix.join("/") {
            prefix if prefix.is_empty() && root.starts_with('/') => "/".to_owned(),
            prefix if prefix.is_empty() => ".".to_owned(),
            prefix => prefix,
        };
        tree::expanded_operand(&prefix, context)
            .is_some_and(|path| no_hidden_whitelist(&path, context))
    })
}

/// True when no ignore file `rg` honors for a search of `root` can
/// re-include a hidden entry. A root that is not a directory has no walk.
fn no_hidden_whitelist(root: &Path, context: ReadContext<'_>) -> bool {
    let Ok(root) = std::fs::canonicalize(root) else {
        return true;
    };
    if !root.is_dir() {
        return true;
    }
    // The memo key's marker keeps this walk apart from the recursive-read
    // walks that share the same per-evaluation memo.
    super::walk_memo::memoized(&root, &[".rg-whitelist"], &[], false, || {
        let mut negations = Negations::default();
        let Some(repository) = outer_sources_safe(&root, context, &mut negations) else {
            return false;
        };
        let Some((pruned, hidden)) = walk(&root, repository, &mut negations) else {
            return false;
        };
        let matches = |patterns: &[String], names: &[String]| {
            patterns.iter().any(|pattern| {
                names.iter().any(|name| {
                    super::glob_matches(
                        pattern.to_ascii_lowercase().as_bytes(),
                        name.to_ascii_lowercase().as_bytes(),
                    )
                })
            })
        };
        !matches(&negations.all, &pruned) && !matches(&negations.risky, &hidden)
    })
}

/// Reads the ignore files `rg` honors above `root`: `.ignore` and
/// `.rgignore` in every ancestor, `.gitignore` up to the repository root,
/// the repository's excludes and the global Git excludes file. Returns
/// whether `root` is inside a Git repository.
fn outer_sources_safe(
    root: &Path,
    context: ReadContext<'_>,
    negations: &mut Negations,
) -> Option<bool> {
    let mut files = Vec::new();
    let mut repository = None;
    for directory in root.ancestors().take(MAX_DEPTH) {
        if directory != root {
            files.extend([directory.join(".ignore"), directory.join(".rgignore")]);
            if repository.is_none() {
                files.push(directory.join(".gitignore"));
            }
        }
        let git = directory.join(".git");
        if repository.is_none() && std::fs::symlink_metadata(&git).is_ok() {
            repository = Some(git);
        }
    }
    if let Some(git) = &repository {
        let directories = git_directories(git)?;
        files.extend(directories.iter().map(|git| git.join("info/exclude")));
    }
    if let Some(home) = context.home_dir.map(Path::new) {
        files.push(home.join(".config/git/ignore"));
        for config in [home.join(".gitconfig"), home.join(".config/git/config")] {
            if let Some(lines) = ignore_lines(&config)? {
                files.extend(excludes_files(&lines, home));
            }
        }
    }
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        files.push(PathBuf::from(xdg).join("git/ignore"));
    }
    for file in files {
        ignore_rules(&file, false, negations)?;
    }
    Some(repository.is_some())
}

/// The Git directory a `.git` entry names, and its common directory when
/// that is a linked worktree's.
fn git_directories(git: &Path) -> Option<Vec<PathBuf>> {
    let metadata = std::fs::symlink_metadata(git).ok()?;
    if metadata.is_dir() {
        return Some(vec![git.to_path_buf()]);
    }
    let text = read_bounded(git)?;
    let named = text.lines().next()?.strip_prefix("gitdir:")?.trim();
    let directory = git.parent()?.join(named);
    let mut directories = vec![directory.clone()];
    if let Some(common) = read_bounded(&directory.join("commondir")) {
        directories.push(directory.join(common.trim()));
    }
    Some(directories)
}

/// `core.excludesFile` values in a Git config file, with `~/` expanded.
fn excludes_files(lines: &[String], home: &Path) -> Vec<PathBuf> {
    lines
        .iter()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            key.trim().eq_ignore_ascii_case("excludesfile").then(|| {
                let value = value.trim().trim_matches('"');
                match value.strip_prefix("~/") {
                    Some(rest) => home.join(rest),
                    None => PathBuf::from(value),
                }
            })
        })
        .collect()
}

/// Walks the directories `rg` may enter below `root`, reading each ignore
/// file there. Returns the directory names it pruned by a plain rule and
/// the hidden names it saw.
fn walk(
    root: &Path,
    repository: bool,
    negations: &mut Negations,
) -> Option<(Vec<String>, Vec<String>)> {
    let mut pruned = Vec::new();
    let mut hidden = Vec::new();
    let mut pending = vec![(root.to_path_buf(), 0usize, Vec::<Rule>::new())];
    let mut entries = 0usize;
    while let Some((directory, depth, mut rules)) = pending.pop() {
        if depth > MAX_DEPTH {
            return None;
        }
        let nested = depth > 0 && std::fs::symlink_metadata(directory.join(".git")).is_ok();
        if nested {
            // A nested repository's own `.gitignore` replaces the outer ones.
            rules.retain(|rule| !rule.git);
        }
        for name in IGNORE_FILES {
            let git = name == ".gitignore";
            let found = ignore_rules(&directory.join(name), git, negations)?;
            // `rg` honors a `.gitignore` only inside a repository.
            if !git || repository || nested {
                rules.extend(found);
            }
        }
        for entry in std::fs::read_dir(&directory).ok()? {
            entries += 1;
            if entries > MAX_ENTRIES {
                return None;
            }
            let entry = entry.ok()?;
            let name = entry.file_name();
            let name = name.to_str()?;
            if name.starts_with('.') && name != ".git" {
                hidden.push(name.to_owned());
            }
            if !entry.file_type().ok()?.is_dir()
                || name == ".git"
                || (name.starts_with('.') && !benign_hidden(name))
            {
                continue;
            }
            // `rg` matches case-sensitively; an exact match prunes no more
            // than it does.
            if rules.iter().any(|rule| rule.name == name) {
                pruned.push(name.to_owned());
                continue;
            }
            let inherited = rules.iter().filter(|rule| !rule.rooted).cloned();
            pending.push((entry.path(), depth + 1, inherited.collect()));
        }
    }
    Some((pruned, hidden))
}

/// Records the negations in one ignore file and returns the plain directory
/// names its other rules ignore. A missing file has no rules; an unreadable
/// or oversized one fails.
fn ignore_rules(path: &Path, git: bool, negations: &mut Negations) -> Option<Vec<Rule>> {
    let Some(lines) = ignore_lines(path)? else {
        return Some(Vec::new());
    };
    let mut rules = Vec::new();
    for line in &lines {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(pattern) = line.strip_prefix('!') {
            record_negation(pattern, negations);
            continue;
        }
        let name = line.strip_suffix('/').unwrap_or(line);
        let (name, rooted) = match name.strip_prefix('/') {
            Some(name) => (name, true),
            None => (name.strip_prefix("**/").unwrap_or(name), false),
        };
        if plain_name(name) {
            rules.push(Rule {
                name: name.to_owned(),
                rooted,
                git,
            });
        }
    }
    Some(rules)
}

/// Records each component of a negated pattern, marking the ones that could
/// name a hidden secret. An escape or empty component matches anything.
fn record_negation(pattern: &str, negations: &mut Negations) {
    let pattern = pattern.strip_prefix('/').unwrap_or(pattern);
    let pattern = pattern.strip_suffix('/').unwrap_or(pattern);
    for component in pattern.split('/') {
        if component.is_empty() || component.contains('\\') {
            negations.all.push("*".to_owned());
            negations.risky.push("*".to_owned());
            continue;
        }
        negations.all.push(component.to_owned());
        let screened = !super::sensitive_path_argument(component)
            && !super::glob_can_select_sensitive_path(component);
        let harmless = if plain_name(component) {
            !component.starts_with('.') || (screened && benign_hidden(component))
        } else {
            screened
        };
        if !harmless {
            negations.risky.push(component.to_owned());
        }
    }
}

fn benign_hidden(name: &str) -> bool {
    tree::descendant_allowed(Path::new(name), Path::new(""), false)
}

/// A name of letters, digits, `_`, `-` and `.` that matches only itself.
fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// `None` when the file exists but cannot be read within the budget,
/// `Some(None)` when it does not exist.
fn ignore_lines(path: &Path) -> Option<Option<Vec<String>>> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(None),
        Err(_) => None,
        Ok(_) => read_bounded(path).map(|text| Some(text.lines().map(str::to_owned).collect())),
    }
}

fn read_bounded(path: &Path) -> Option<String> {
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_IGNORE_BYTES + 1)
        .read_to_string(&mut text)
        .ok()?;
    (text.len() as u64 <= MAX_IGNORE_BYTES).then_some(text)
}
