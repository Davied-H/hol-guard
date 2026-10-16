//! Content-bound launch identity for `python <script>`.
//!
//! A script launch is persistable only when every module it can load is
//! bound: the script and each module found beside it by content (with any
//! cached bytecode Python may run in its place) and each standard module by
//! name. An installed package, a module that loads code by a computed name,
//! evaluates strings, starts processes or reaches the import system keeps
//! the launch once-only, as do a graph that writes files and imports a local
//! module, an option or environment variable that loads other code or moves
//! module lookup, and a compiled or extension module beside a source module.
//! The scan (`python_source`) is lexical and errs toward refusal: a refused
//! launch keeps today's approve-once behaviour.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

use guard_command::secret_path_probe::is_request_secret_path;
use serde_json::{json, Value};

use super::context::Ctx;
use super::fs_path;
use super::python_source::{scan, Import, REFUSED_MODULES};
use super::reasons::{Proof, MUTABLE_LAUNCHER, SENSITIVE_PATH};

/// Single-letter options that run the script without loading other code.
/// `I` and `P` also keep the script's directory off the module path.
const INERT_FLAGS: &str = "bBdEIOPqsSuvx";
/// Variables that load code, move module lookup or bytecode, or make the
/// interpreter read more code after the script.
const LOADER_ENVIRONMENT: [&str; 11] = [
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONUSERBASE",
    "PYTHONSTARTUP",
    "PYTHONINSPECT",
    "PYTHONWARNINGS",
    "PYTHONPYCACHEPREFIX",
    "PYTHONPLATLIBDIR",
    "PYTHONEXECUTABLE",
    "PYTHONBREAKPOINT",
    "PYTHONCASEOK",
];
/// Suffixes the import system loads before (or instead of) a `.py` source.
const COMPILED_SUFFIXES: [&str; 4] = ["so", "pyd", "pyc", "pyo"];
const MAX_MODULES: usize = 64;
const MAX_MODULE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LISTING: usize = 4096;

/// Standard modules a script may import by name (`sys.stdlib_module_names`,
/// public names). An import the script's directory does not shadow resolves
/// to the interpreter's own copy.
const STANDARD_MODULES: &[&str] = &[
    "__future__",
    "abc",
    "annotationlib",
    "argparse",
    "array",
    "ast",
    "asyncio",
    "atexit",
    "base64",
    "binascii",
    "bisect",
    "bz2",
    "calendar",
    "cmath",
    "cmd",
    "codecs",
    "collections",
    "colorsys",
    "compression",
    "concurrent",
    "configparser",
    "contextlib",
    "contextvars",
    "copy",
    "copyreg",
    "csv",
    "curses",
    "dataclasses",
    "datetime",
    "dbm",
    "decimal",
    "difflib",
    "dis",
    "email",
    "encodings",
    "enum",
    "errno",
    "faulthandler",
    "fcntl",
    "filecmp",
    "fileinput",
    "fnmatch",
    "fractions",
    "ftplib",
    "functools",
    "genericpath",
    "getopt",
    "getpass",
    "gettext",
    "glob",
    "graphlib",
    "grp",
    "gzip",
    "hashlib",
    "heapq",
    "hmac",
    "html",
    "http",
    "imaplib",
    "io",
    "ipaddress",
    "itertools",
    "json",
    "keyword",
    "linecache",
    "locale",
    "logging",
    "lzma",
    "mailbox",
    "math",
    "mimetypes",
    "mmap",
    "msvcrt",
    "netrc",
    "ntpath",
    "nturl2path",
    "numbers",
    "opcode",
    "operator",
    "optparse",
    "os",
    "pathlib",
    "platform",
    "plistlib",
    "poplib",
    "posixpath",
    "pprint",
    "pstats",
    "pwd",
    "pyclbr",
    "pyexpat",
    "queue",
    "quopri",
    "random",
    "re",
    "readline",
    "reprlib",
    "resource",
    "rlcompleter",
    "sched",
    "secrets",
    "select",
    "selectors",
    "shlex",
    "shutil",
    "signal",
    "smtplib",
    "socket",
    "socketserver",
    "sqlite3",
    "sre_compile",
    "sre_constants",
    "sre_parse",
    "ssl",
    "stat",
    "statistics",
    "string",
    "stringprep",
    "struct",
    "symtable",
    "sys",
    "sysconfig",
    "syslog",
    "tabnanny",
    "tarfile",
    "tempfile",
    "termios",
    "textwrap",
    "this",
    "threading",
    "time",
    "token",
    "tokenize",
    "tomllib",
    "traceback",
    "tracemalloc",
    "tty",
    "types",
    "typing",
    "unicodedata",
    "unittest",
    "urllib",
    "uuid",
    "warnings",
    "wave",
    "weakref",
    "winreg",
    "winsound",
    "wsgiref",
    "xml",
    "xmlrpc",
    "zipfile",
    "zlib",
    "zoneinfo",
];

/// The script and whether the script's directory is on the module path, or
/// `None` for an option that loads other code or reads the program elsewhere.
fn script_argument(arguments: &[String]) -> Option<(&str, bool)> {
    let mut script_directory = true;
    for argument in arguments {
        let Some(flags) = argument.strip_prefix('-') else {
            return Some((argument, script_directory));
        };
        if flags.is_empty() || !flags.chars().all(|flag| INERT_FLAGS.contains(flag)) {
            return None;
        }
        script_directory &= !flags.contains(['I', 'P']);
    }
    None
}

struct Graph<'a> {
    ctx: &'a Ctx<'a>,
    cwd: &'a str,
    /// The script's directory: the first module-path entry.
    root: String,
    script_directory: bool,
    modules: BTreeMap<String, String>,
    bytecode: BTreeMap<String, String>,
    standard: BTreeSet<String>,
    listings: BTreeMap<String, Vec<String>>,
    queue: VecDeque<String>,
    total: u64,
}

impl Graph<'_> {
    fn digest(&mut self, path: &str) -> Proof<(String, Vec<u8>)> {
        self.ctx.check()?;
        let resolved = fs_path::resolve_strict(path).ok_or(MUTABLE_LAUNCHER)?;
        for candidate in [path, resolved.as_str()] {
            if is_request_secret_path(
                candidate,
                Some(Path::new(self.cwd)),
                self.ctx.home.map(Path::new),
            ) {
                return Err(SENSITIVE_PATH);
            }
        }
        let bytes = fs_path::read_bounded(&resolved, MAX_MODULE_BYTES).ok_or(MUTABLE_LAUNCHER)?;
        self.total += bytes.len() as u64;
        if self.total > MAX_TOTAL_BYTES {
            return Err(MUTABLE_LAUNCHER);
        }
        Ok((fs_path::sha256_hex(&bytes), bytes))
    }

    fn listing(&mut self, directory: &str) -> Proof<&Vec<String>> {
        if !self.listings.contains_key(directory) {
            self.ctx.check()?;
            let mut names = Vec::new();
            if let Ok(entries) = std::fs::read_dir(directory) {
                for entry in entries {
                    let name = entry.map_err(|_| MUTABLE_LAUNCHER)?.file_name();
                    names.push(name.into_string().map_err(|_| MUTABLE_LAUNCHER)?);
                    if names.len() > MAX_LISTING {
                        return Err(MUTABLE_LAUNCHER);
                    }
                }
            }
            self.listings.insert(directory.to_owned(), names);
        }
        Ok(&self.listings[directory])
    }

    /// The source the import system loads for `name` in `directory`: a
    /// package's `__init__.py` or a `.py` module. `None` when neither exists
    /// (or only a namespace directory does); an error when compiled or
    /// extension code could load in the source's place.
    fn find(&mut self, directory: &str, name: &str) -> Proof<Option<String>> {
        let entries = self.listing(directory)?;
        let shadowed = entries.iter().any(|entry| {
            entry
                .strip_prefix(name)
                .and_then(|rest| rest.strip_prefix('.'))
                .and_then(|rest| rest.rsplit('.').next())
                .is_some_and(|suffix| COMPILED_SUFFIXES.contains(&suffix))
        });
        let has_entry = entries.iter().any(|entry| entry == name);
        let has_module = entries
            .iter()
            .any(|entry| entry.strip_suffix(".py") == Some(name));
        if shadowed {
            return Err(MUTABLE_LAUNCHER);
        }
        let package = fs_path::join(directory, name);
        if has_entry && fs_path::is_dir(&package) {
            if let Some(init) = self.find(&package, "__init__")? {
                return Ok(Some(init));
            }
        }
        let module = fs_path::join(directory, &format!("{name}.py"));
        Ok((has_module && fs_path::is_file(&module)).then_some(module))
    }

    /// Queue a module and bind the cached bytecode Python may run in its
    /// place.
    fn add_module(&mut self, path: String) -> Proof<()> {
        if self.modules.contains_key(&path) || self.queue.contains(&path) {
            return Ok(());
        }
        if self.modules.len() + self.queue.len() >= MAX_MODULES {
            return Err(MUTABLE_LAUNCHER);
        }
        let stem = fs_path::name(&path)
            .strip_suffix(".py")
            .ok_or(MUTABLE_LAUNCHER)?
            .to_owned();
        let cache = fs_path::join(&fs_path::parent(&path), "__pycache__");
        if fs_path::is_dir(&cache) {
            let cached: Vec<String> = self
                .listing(&cache)?
                .iter()
                .filter(|entry| {
                    entry
                        .strip_prefix(stem.as_str())
                        .is_some_and(|rest| rest.starts_with('.') && rest.ends_with(".pyc"))
                })
                .cloned()
                .collect();
            for entry in cached {
                let file = fs_path::join(&cache, &entry);
                let (digest, _) = self.digest(&file)?;
                self.bytecode.insert(file, digest);
            }
        }
        self.queue.push_back(path);
        Ok(())
    }

    /// Bind `parts` below `directory` (each package's `__init__.py` and the
    /// last module) and any submodule a `from` import takes by name. Every
    /// part must exist as source.
    fn add_local(&mut self, directory: &str, parts: &[&str], names: &[String]) -> Proof<()> {
        let mut directory = directory.to_owned();
        let mut is_package = true;
        for part in parts {
            if !is_package {
                return Err(MUTABLE_LAUNCHER);
            }
            let source = self.find(&directory, part)?.ok_or(MUTABLE_LAUNCHER)?;
            is_package = fs_path::name(&source) == "__init__.py";
            directory = fs_path::parent(&source);
            self.add_module(source)?;
        }
        if is_package {
            for name in names {
                if let Some(source) = self.find(&directory, name)? {
                    self.add_module(source)?;
                }
            }
        }
        Ok(())
    }

    fn resolve(&mut self, importer: &str, is_script: bool, import: &Import) -> Proof<()> {
        let parts: Vec<&str> = import
            .module
            .split('.')
            .filter(|part| !part.is_empty())
            .collect();
        if import.level > 0 {
            // A relative import resolves inside the importer's package, which
            // must sit below the script's directory.
            let mut directory = fs_path::parent(importer);
            for _ in 1..import.level {
                directory = fs_path::parent(&directory);
            }
            if is_script || directory == self.root || !fs_path::is_inside(&directory, &self.root) {
                return Err(MUTABLE_LAUNCHER);
            }
            return self.add_local(&directory, &parts, &import.names);
        }
        let top = *parts.first().ok_or(MUTABLE_LAUNCHER)?;
        if REFUSED_MODULES.contains(&top) {
            return Err(MUTABLE_LAUNCHER);
        }
        if self.script_directory {
            let root = self.root.clone();
            if self.find(&root, top)?.is_some() {
                return self.add_local(&root, &parts, &import.names);
            }
        }
        if STANDARD_MODULES.contains(&top) {
            self.standard.insert(top.to_owned());
            return Ok(());
        }
        Err(MUTABLE_LAUNCHER)
    }
}

/// The bound module graph of `python <script>`, or the reason it stays
/// once-only.
pub(super) fn python_script(arguments: &[String], cwd: &str, ctx: &Ctx) -> Proof<Value> {
    let mut script_directory = true;
    for (name, value) in ctx.env {
        if value.is_empty() {
            continue;
        }
        if LOADER_ENVIRONMENT
            .iter()
            .any(|refused| name.eq_ignore_ascii_case(refused))
        {
            return Err(MUTABLE_LAUNCHER);
        }
        if name.eq_ignore_ascii_case("PYTHONSAFEPATH") {
            script_directory = false;
        }
    }
    let (script, on_path) = script_argument(arguments).ok_or(MUTABLE_LAUNCHER)?;
    let candidate = if fs_path::is_abs(script) {
        script.to_owned()
    } else {
        fs_path::join(cwd, script)
    };
    if !fs_path::is_file(&candidate) {
        return Err(MUTABLE_LAUNCHER);
    }
    let resolved = fs_path::resolve_strict(&candidate).ok_or(MUTABLE_LAUNCHER)?;
    if !fs_path::name(&resolved).ends_with(".py") {
        return Err(MUTABLE_LAUNCHER);
    }
    let mut graph = Graph {
        ctx,
        cwd,
        root: fs_path::parent(&resolved),
        script_directory: script_directory && on_path,
        modules: BTreeMap::new(),
        bytecode: BTreeMap::new(),
        standard: BTreeSet::new(),
        listings: BTreeMap::new(),
        queue: VecDeque::new(),
        total: 0,
    };
    // Python never runs cached bytecode for the script itself.
    graph.queue.push_back(resolved.clone());
    let mut writes = false;
    while let Some(module) = graph.queue.pop_front() {
        let (digest, bytes) = graph.digest(&module)?;
        let source = String::from_utf8(bytes).map_err(|_| MUTABLE_LAUNCHER)?;
        let scanned = scan(source.trim_start_matches('\u{feff}')).ok_or(MUTABLE_LAUNCHER)?;
        graph.modules.insert(module.clone(), digest);
        writes |= scanned.writes;
        for import in &scanned.imports {
            graph.resolve(&module, module == resolved, import)?;
        }
    }
    // A local module is bound as it was before launch; a graph that can
    // write files could replace one before it is imported.
    if writes && graph.modules.len() > 1 {
        return Err(MUTABLE_LAUNCHER);
    }
    let entries = |map: &BTreeMap<String, String>| -> Vec<Value> {
        map.iter()
            .map(|(path, digest)| json!({"path": path, "sha256": digest}))
            .collect()
    };
    Ok(json!({
        "script": resolved,
        "modules": entries(&graph.modules),
        "bytecode": entries(&graph.bytecode),
        "standard": graph.standard.into_iter().collect::<Vec<_>>(),
    }))
}

#[cfg(all(test, unix))]
#[path = "python_script_tests.rs"]
mod tests;
