//! The code Python's `site` module runs before a script: each `.pth` file in
//! a site directory (its `import` lines run, its other lines extend the
//! module path), the modules those lines import, and any `sitecustomize` or
//! `usercustomize` the module path holds. An interpreter whose standard
//! library the proof cannot place keeps the launch once-only.

use std::io::Read;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use super::super::fs_path;
use super::super::python_modules::{REFUSED_MODULES, STANDARD_MODULES};
use super::super::python_source::scan;
use super::super::reasons::{Proof, MUTABLE_LAUNCHER};
use super::{Graph, COMPILED_SUFFIXES};

/// A site directory can hold thousands of installed packages.
const MAX_SITE_LISTING: usize = 65_536;
const MAX_STARTUP_FILES: usize = 256;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const CUSTOMIZE: [&str; 2] = ["sitecustomize", "usercustomize"];

/// Whether the import system runs the cached bytecode at `pyc` in place of a
/// source with `source` metadata. A hash-based file is bound whether or not
/// Python checks its hash; a timestamp file only when it records the
/// source's modification second and size. Python skips a file it cannot read.
pub(super) fn runs_in_place(source: &std::fs::Metadata, pyc: &str) -> bool {
    let mut header = [0u8; 16];
    if std::fs::File::open(pyc)
        .and_then(|mut file| file.read_exact(&mut header))
        .is_err()
    {
        return false;
    }
    let word = |at: usize| {
        u32::from_le_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]])
    };
    match word(4) {
        0 => {
            let Some(seconds) = source
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            else {
                return true;
            };
            word(8) == seconds.as_secs() as u32 && word(12) == source.len() as u32
        }
        1 | 3 => true,
        _ => false,
    }
}

/// `__import__('name')` with a literal name, as `.pth` import lines write it.
fn literal_import() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r#"__import__\(\s*(?:'([A-Za-z_][\w.]*)'|"([A-Za-z_][\w.]*)")\s*\)"#)
            .expect("static pattern")
    })
}

/// Where an interpreter's `site` module looks.
struct Layout {
    /// Standard-library directories, ahead of every site directory.
    library: Vec<String>,
    /// Site directories in the order `site` adds them.
    site: Vec<String>,
}

/// Directories below `parent` whose names start with `prefix`.
fn entries_with_prefix(parent: &str, prefix: &str) -> Proof<Vec<String>> {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Ok(Vec::new());
    };
    let mut found = Vec::new();
    for entry in entries {
        let name = entry.map_err(|_| MUTABLE_LAUNCHER)?.file_name();
        let name = name.into_string().map_err(|_| MUTABLE_LAUNCHER)?;
        if name.starts_with(prefix) {
            found.push(fs_path::join(parent, &name));
        }
        if found.len() > MAX_STARTUP_FILES {
            return Err(MUTABLE_LAUNCHER);
        }
    }
    found.sort();
    Ok(found)
}

/// The installation prefix: the nearest ancestor of `start` holding a
/// `lib/python3.*/os.py` standard library, as CPython's path search finds it.
fn prefix_from(start: &str) -> Proof<Option<String>> {
    let mut directory = fs_path::norm(start);
    loop {
        for library in entries_with_prefix(&fs_path::join(&directory, "lib"), "python3")? {
            if fs_path::is_file(&fs_path::join(&library, "os.py")) {
                return Ok(Some(directory));
            }
        }
        let parent = fs_path::parent(&directory);
        if parent == directory {
            return Ok(None);
        }
        directory = parent;
    }
}

/// `key = value` settings of a virtual environment's `pyvenv.cfg`.
fn venv_setting(config: &str, key: &str) -> Option<String> {
    config.lines().find_map(|line| {
        let (name, value) = line.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case(key)
            .then(|| value.trim().to_owned())
    })
}

impl Layout {
    fn of(executable: &Value, user_site: bool, home: Option<&str>) -> Proof<Self> {
        let text = |key: &str| executable.get(key).and_then(Value::as_str);
        if text("file_format") != Some("native") {
            return Err(MUTABLE_LAUNCHER);
        }
        let launch = text("launch_path")
            .filter(|path| fs_path::is_abs(path))
            .ok_or(MUTABLE_LAUNCHER)?;
        let real = text("path")
            .filter(|path| fs_path::is_abs(path))
            .ok_or(MUTABLE_LAUNCHER)?;
        // `pyvenv.cfg` beside the launched (not resolved) interpreter, or one
        // directory up, makes a virtual environment.
        let bin = fs_path::parent(launch);
        let venv = [bin.clone(), fs_path::parent(&bin)]
            .into_iter()
            .find(|directory| fs_path::is_file(&fs_path::join(directory, "pyvenv.cfg")));
        let (prefix, include_base) = match &venv {
            Some(venv) => {
                let config =
                    fs_path::read_bounded(&fs_path::join(venv, "pyvenv.cfg"), MAX_CONFIG_BYTES)
                        .and_then(|bytes| String::from_utf8(bytes).ok())
                        .ok_or(MUTABLE_LAUNCHER)?;
                let base = venv_setting(&config, "home")
                    .filter(|path| fs_path::is_abs(path))
                    .ok_or(MUTABLE_LAUNCHER)?;
                let mut prefix = None;
                if let Some(base_real) =
                    fs_path::resolve_strict(&fs_path::join(&base, &fs_path::name(launch)))
                {
                    prefix = prefix_from(&fs_path::parent(&base_real))?;
                }
                if prefix.is_none() {
                    prefix = prefix_from(&base)?;
                }
                let include = venv_setting(&config, "include-system-site-packages")
                    .is_some_and(|value| value.eq_ignore_ascii_case("true"));
                (prefix, include)
            }
            None => (prefix_from(&fs_path::parent(real))?, true),
        };
        let prefix = prefix.ok_or(MUTABLE_LAUNCHER)?;
        let mut layout = Layout {
            library: Vec::new(),
            site: Vec::new(),
        };
        for lib in ["lib", "lib64"] {
            for library in entries_with_prefix(&fs_path::join(&prefix, lib), "python3")? {
                if fs_path::name(&library).ends_with(".zip") {
                    // A zipped standard library is searched before the site directories.
                    return Err(MUTABLE_LAUNCHER);
                }
                layout.library.push(fs_path::join(&library, "lib-dynload"));
                layout.library.push(library);
            }
        }
        if let Some(venv) = &venv {
            for lib in ["lib", "lib64"] {
                for library in entries_with_prefix(&fs_path::join(venv, lib), "python3")? {
                    layout.site.push(fs_path::join(&library, "site-packages"));
                }
            }
        }
        if include_base {
            let mut roots = vec![prefix.clone()];
            if prefix == "/usr" {
                roots.push("/usr/local".to_owned());
            }
            for root in roots {
                for lib in ["lib", "lib64"] {
                    for library in entries_with_prefix(&fs_path::join(&root, lib), "python3")? {
                        layout.site.push(fs_path::join(&library, "site-packages"));
                        layout.site.push(fs_path::join(&library, "dist-packages"));
                    }
                }
            }
            if prefix.contains(".framework/") {
                for version in entries_with_prefix("/Library/Python", "3")? {
                    layout.site.push(fs_path::join(&version, "site-packages"));
                }
            }
        }
        if user_site && include_base {
            let home = home
                .filter(|path| fs_path::is_abs(path))
                .ok_or(MUTABLE_LAUNCHER)?;
            for library in entries_with_prefix(&fs_path::join(home, ".local/lib"), "python3")? {
                layout.site.push(fs_path::join(&library, "site-packages"));
            }
            for version in entries_with_prefix(&fs_path::join(home, "Library/Python"), "3")? {
                layout
                    .site
                    .push(fs_path::join(&version, "lib/python/site-packages"));
            }
        }
        layout
            .library
            .retain(|directory| fs_path::is_dir(directory));
        layout.site.retain(|directory| fs_path::is_dir(directory));
        layout.site.dedup();
        Ok(layout)
    }
}

impl Graph<'_> {
    fn bind_startup(&mut self, path: &str) -> Proof<Vec<u8>> {
        let (digest, bytes) = self.digest(path)?;
        self.startup.insert(path.to_owned(), digest);
        if path.ends_with(".py") {
            self.add_bytecode(path)?;
        }
        if self.startup.len() > MAX_STARTUP_FILES {
            return Err(MUTABLE_LAUNCHER);
        }
        Ok(bytes)
    }

    /// Bind a module a `.pth` line imports: a standard module by name, or
    /// the first site directory's source module or package files.
    fn bind_imported(&mut self, sites: &[String], name: &str) -> Proof<()> {
        let top = name.split('.').next().unwrap_or_default();
        if REFUSED_MODULES.contains(&top) {
            return Err(MUTABLE_LAUNCHER);
        }
        if STANDARD_MODULES.contains(&top) {
            return Ok(());
        }
        for site in sites {
            let Some(source) = self.find(site, top)? else {
                continue;
            };
            if fs_path::name(&source) != "__init__.py" {
                return self.bind_startup(&source).map(drop);
            }
            let package = fs_path::parent(&source);
            let entries = self.listing(&package)?.clone();
            for entry in entries {
                let suffix = entry.rsplit('.').next().unwrap_or_default();
                if COMPILED_SUFFIXES.contains(&suffix) {
                    return Err(MUTABLE_LAUNCHER);
                }
                let path = fs_path::join(&package, &entry);
                if entry.ends_with(".py") && fs_path::is_file(&path) {
                    self.bind_startup(&path)?;
                }
            }
            return Ok(());
        }
        Err(MUTABLE_LAUNCHER)
    }

    /// Bind a `.pth` file and what its lines run; returns the directories its
    /// other lines add to the module path.
    fn add_pth(&mut self, sites: &[String], path: &str) -> Proof<Vec<String>> {
        if !fs_path::is_file(path) {
            return Ok(Vec::new());
        }
        let bytes = self.bind_startup(path)?;
        let text = String::from_utf8(bytes).map_err(|_| MUTABLE_LAUNCHER)?;
        let text = text.trim_start_matches('\u{feff}');
        if text.replace("\r\n", "\n").contains('\r') {
            return Err(MUTABLE_LAUNCHER);
        }
        let site = fs_path::parent(path);
        let mut added = Vec::new();
        for line in text.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            if line.starts_with("import ") || line.starts_with("import\t") {
                let mut names = Vec::new();
                let rewritten = literal_import().replace_all(line, |captures: &regex::Captures| {
                    let name = captures
                        .get(1)
                        .or_else(|| captures.get(2))
                        .map_or("", |m| m.as_str());
                    names.push(name.to_owned());
                    "_imported_"
                });
                let scanned = scan(&rewritten).ok_or(MUTABLE_LAUNCHER)?;
                names.extend(scanned.imports.into_iter().map(|import| {
                    if import.level > 0 {
                        String::new()
                    } else {
                        import.module
                    }
                }));
                for name in names {
                    if name.is_empty() {
                        return Err(MUTABLE_LAUNCHER);
                    }
                    self.bind_imported(sites, &name)?;
                }
                continue;
            }
            let directory = fs_path::join(&site, line.trim_end());
            if fs_path::is_dir(&directory) {
                added.push(directory);
            }
        }
        Ok(added)
    }

    /// Bind a `sitecustomize` or `usercustomize` source in `directory`; any
    /// other form of either keeps the launch once-only.
    fn add_customize(&mut self, directory: &str) -> Proof<()> {
        let found: Vec<String> = self
            .listing_within(directory, MAX_SITE_LISTING)?
            .iter()
            .filter(|entry| {
                CUSTOMIZE.iter().any(|name| {
                    entry.as_str() == *name
                        || entry
                            .strip_prefix(name)
                            .is_some_and(|rest| rest.starts_with('.'))
                })
            })
            .cloned()
            .collect();
        for entry in found {
            let path = fs_path::join(directory, &entry);
            let source = CUSTOMIZE
                .iter()
                .any(|name| entry.strip_suffix(".py") == Some(name));
            if !source || !fs_path::is_file(&path) {
                return Err(MUTABLE_LAUNCHER);
            }
            self.bind_startup(&path)?;
        }
        Ok(())
    }

    /// Bind the code `site` runs before the script, and refuse a standard
    /// name a site directory also holds: the interpreter loads that copy
    /// when its own library lacks the module.
    pub(super) fn add_startup(&mut self, executable: &Value, user_site: bool) -> Proof<()> {
        let layout = Layout::of(executable, user_site, self.ctx.home)?;
        let mut path_directories = layout.site.clone();
        for site in &layout.site {
            self.listing_within(site, MAX_SITE_LISTING)?;
        }
        for site in &layout.site {
            let pth: Vec<String> = self
                .listing_within(site, MAX_SITE_LISTING)?
                .iter()
                .filter(|entry| entry.ends_with(".pth"))
                .cloned()
                .collect();
            for entry in pth {
                let added = self.add_pth(&layout.site, &fs_path::join(site, &entry))?;
                path_directories.extend(added);
            }
        }
        for directory in layout.library.iter().chain(&path_directories) {
            self.add_customize(directory)?;
        }
        let standard: Vec<String> = self.standard.iter().cloned().collect();
        for directory in &path_directories {
            let entries = self.listing_within(directory, MAX_SITE_LISTING)?;
            let shadowed = standard.iter().any(|name| {
                entries.iter().any(|entry| {
                    entry == name
                        || entry
                            .strip_prefix(name.as_str())
                            .and_then(|rest| rest.strip_prefix('.'))
                            .is_some_and(|rest| {
                                rest == "py"
                                    || COMPILED_SUFFIXES
                                        .contains(&rest.rsplit('.').next().unwrap_or_default())
                            })
                })
            });
            if shadowed {
                return Err(MUTABLE_LAUNCHER);
            }
        }
        Ok(())
    }
}
