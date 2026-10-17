//! Whether a script only reads. Windows has no workspace sandbox, so there an
//! ordinary script runs in the read-only evaluation boundary only when its
//! source shows no write, process launch, dynamic code or import beyond the
//! standard library's read-only modules. Any other script keeps its review
//! instead of failing inside that boundary. The boundary itself, not this
//! scan, withholds the network, credentials and workspace writes.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use super::{read_text, standalone_clean, Language};

/// Standard library modules a report reads files with. Anything else, a
/// package or a module that launches processes, keeps the review.
const PYTHON_MODULES: &[&str] = &[
    "__future__",
    "abc",
    "argparse",
    "ast",
    "base64",
    "bisect",
    "collections",
    "configparser",
    "contextlib",
    "copy",
    "csv",
    "dataclasses",
    "datetime",
    "decimal",
    "difflib",
    "enum",
    "fnmatch",
    "fractions",
    "functools",
    "glob",
    "hashlib",
    "heapq",
    "io",
    "itertools",
    "json",
    "math",
    "operator",
    "os",
    "pathlib",
    "pprint",
    "re",
    "statistics",
    "string",
    "sys",
    "textwrap",
    "time",
    "tokenize",
    "tomllib",
    "typing",
    "unicodedata",
];

/// Node built-ins a report reads files with, with or without `node:`.
const NODE_MODULES: &[&str] = &[
    "assert",
    "assert/strict",
    "buffer",
    "crypto",
    "events",
    "fs",
    "fs/promises",
    "os",
    "path",
    "path/posix",
    "path/win32",
    "perf_hooks",
    "process",
    "querystring",
    "readline",
    "stream",
    "stream/promises",
    "string_decoder",
    "timers",
    "timers/promises",
    "url",
    "util",
    "zlib",
];

static PYTHON_EFFECTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\.\s*(?:write_text|write_bytes|touch|mkdir|unlink|rmdir|rename|symlink_to|hardlink_to|link_to|chmod|lchmod)\s*\(",
        r"|\bos\s*\.\s*(?:system|popen|exec\w*|spawn\w*|posix_spawn\w*|fork\w*|kill\w*|remove|unlink|rmdir|removedirs|mkdir|makedirs|rename|renames|replace|chmod|chown|lchown|link|symlink|truncate|ftruncate|write|open|mkfifo|mknod|utime|startfile|putenv|unsetenv)\b",
        r"|(?:^|[^.\w])(?:eval|exec|compile|__import__|breakpoint)\s*\(|\b__builtins__\b",
        r#"|\bopen\s*\([^)\n]*,\s*(?:mode\s*=\s*)?["'][rbtU]*[wax+]"#,
    ))
    .unwrap()
});
static PYTHON_IMPORTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*(?:from[ \t]+([\w.]+)[ \t]+import\b|import[ \t]+([^\n#]+))").unwrap()
});

static NODE_EFFECTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\b(?:writeFile|writeFileSync|appendFile|appendFileSync|mkdir|mkdirSync|mkdtemp|mkdtempSync|rm|rmSync|rmdir|rmdirSync|unlink|unlinkSync|rename|renameSync|copyFile|copyFileSync|cp|cpSync|symlink|symlinkSync|link|linkSync|chmod|chmodSync|chown|chownSync|lchown|lchownSync|truncate|truncateSync|ftruncate|ftruncateSync|createWriteStream|open|openSync|utimes|utimesSync|futimes|futimesSync|lutimes|lutimesSync|writeSync|writev|writevSync)\s*\(",
        r"|\b(?:eval|Function)\s*\(|\bnew\s+Function\b|\bimport\s*\(|\bWebAssembly\b",
        r"|\bprocess\s*\.\s*(?:binding|dlopen|kill|chdir|setuid|setgid)\b",
        r#"|\brequire\s*\(\s*[^"'\s]"#,
    ))
    .unwrap()
});
static NODE_SPECIFIERS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:\bfrom\s*|\bimport\s*|\brequire\s*\(\s*)["']([^"'\n]*)["']"#).unwrap()
});

/// Whether the script at `path` is `standalone_clean` and only reads. The
/// whole source is scanned, comments included, so a note that names a write
/// keeps the review rather than hiding one.
pub(in crate::pretool) fn read_only(language: Language, path: &Path) -> bool {
    if !standalone_clean(language, path) {
        return false;
    }
    let Some(source) = read_text(path) else {
        return false;
    };
    // A backslash continues a Python statement, such as an import, onto the
    // next line.
    let source = source.replace("\\\r\n", " ").replace("\\\n", " ");
    match language {
        Language::Python => !PYTHON_EFFECTS.is_match(&source) && python_imports_read_only(&source),
        Language::Node => {
            !NODE_EFFECTS.is_match(&source)
                && NODE_SPECIFIERS.captures_iter(&source).all(|found| {
                    let module = &found[1];
                    NODE_MODULES.contains(&module.strip_prefix("node:").unwrap_or(module))
                })
        }
    }
}

fn python_imports_read_only(source: &str) -> bool {
    // `import a; import b` puts two statements on a line.
    let source = source.replace(';', "\n");
    PYTHON_IMPORTS.captures_iter(&source).all(|found| {
        let names: Vec<&str> = match (found.get(1), found.get(2)) {
            (Some(module), _) => vec![module.as_str()],
            (None, Some(list)) => list
                .as_str()
                .split(',')
                .map(|item| item.split_whitespace().next().unwrap_or(""))
                .collect(),
            (None, None) => return false,
        };
        names.iter().all(|name| {
            PYTHON_MODULES.contains(&name.split('.').next().unwrap_or(""))
                && (*name == "os" || *name == "os.path" || !name.starts_with("os."))
        })
    })
}

#[cfg(test)]
#[path = "read_only_tests.rs"]
mod tests;
