//! Seatbelt composition for `workspace-contained-v1`, kept apart from
//! `compose_macos_profile` so the existing profile bytes stay fixed.
use super::*;

/// Absolute names a sandboxed command must never execute; mirrors the
/// classifier's privilege exclusion so a shell cannot reach them by name.
const PRIVILEGE_NAMES: &[&str] = &[
    "sudo",
    "doas",
    "su",
    "login",
    "chmod",
    "chown",
    "chgrp",
    "chflags",
    "xattr",
    "setfacl",
    "launchctl",
    "crontab",
    "at",
    "security",
    "osascript",
    "open",
    "defaults",
    "dscl",
    "spctl",
    "csrutil",
    "kill",
    "killall",
    "pkill",
];
const PROTECTED_DIRECTORIES: &[&str] = &[
    ".agents",
    ".claude",
    ".codex",
    ".cursor",
    ".bzr",
    ".hg",
    ".jj",
    ".pijul",
    ".svn",
    "_darcs",
    ".vscode",
    ".idea",
    ".devcontainer",
];
const PROTECTED_FILES: &[&str] = &[
    "agents.md",
    "claude.md",
    "copilot-instructions.md",
    ".clinerules",
    ".cursorrules",
    ".windsurfrules",
    ".mcp.json",
];

fn invalid() -> RestrictedPytestError {
    RestrictedPytestError::new(
        PYTEST_INVALID_COMMAND_REASON_CODE,
        "Invalid workspace sandbox request.",
    )
}

/// Case-insensitive regex for a literal. Specials become one-character
/// classes, so no backslash semantics are involved; the volume may be
/// case-insensitive, so letters match both cases.
fn ci(value: &str) -> Result<String, RestrictedPytestError> {
    let mut result = String::new();
    for c in value.chars() {
        match c {
            // `[^]` would open a negated class, so `^` is rejected outright.
            '\\' | '\n' | '\r' | '\0' | '^' => return Err(invalid()),
            c if c.is_ascii_alphabetic() => result.push_str(&format!(
                "[{}{}]",
                c.to_ascii_lowercase(),
                c.to_ascii_uppercase()
            )),
            '.' | '+' | '*' | '?' | '(' | ')' | '{' | '}' | '|' | '$' | '[' => {
                result.push('[');
                result.push(c);
                result.push(']');
            }
            ']' => result.push_str("[]]"),
            c => result.push(c),
        }
    }
    Ok(result)
}

fn alternatives(names: &[&str]) -> Result<String, RestrictedPytestError> {
    Ok(names
        .iter()
        .map(|name| ci(name))
        .collect::<Result<Vec<_>, _>>()?
        .join("|"))
}

/// Git execution configuration at any depth, so nested repositories are
/// covered. The trailing `?$` also denies creating, renaming or deleting the
/// `.git` entry itself, which blocks gitfile redirects and directory swaps.
pub(crate) fn git_exec_pattern(workspace: &Path) -> Result<String, RestrictedPytestError> {
    let root = ci(&workspace.to_string_lossy())?;
    let git = ci(".git")?;
    let config = format!("{}({}|{})?", ci("config")?, ci(".worktree")?, ci(".lock")?);
    let files = format!("{config}|{}|{}", ci("commondir")?, ci("gitdir")?);
    let trees = alternatives(&["hooks", "info", "modules", "worktrees", "objects/info"])?;
    Ok(format!(
        "^{root}/(.*/)?{git}(/({files})|/({trees})(/.*)?)?$"
    ))
}

pub(crate) fn protected_patterns(workspace: &Path) -> Result<Vec<String>, RestrictedPytestError> {
    let root = ci(&workspace.to_string_lossy())?;
    Ok(vec![
        format!(
            "^{root}/(.*/)?({})(/.*)?$",
            alternatives(PROTECTED_DIRECTORIES)?
        ),
        format!("^{root}/(.*/)?({})$", alternatives(PROTECTED_FILES)?),
        format!("^{root}/(.*/)?{}(/.*)?$", ci(".github/workflows")?),
    ])
}

fn regex_rule(operations: &str, pattern: &str) -> String {
    format!("(deny {operations} (regex {}))", seatbelt_string(pattern))
}

pub(super) fn compose(
    input: &Input,
    system_roots: &[PathBuf],
    files: &[PathBuf],
) -> Result<String, RestrictedPytestError> {
    let workspace = &input.workspace;
    if !workspace.is_absolute() || !input.private_root.is_absolute() {
        return Err(invalid());
    }
    let mut extra_reads = existing(&[
        "/bin",
        "/usr/bin",
        "/private/var/select",
        "/private/var/db/timezone",
    ]);
    extra_reads.extend(input.exec_roots.iter().cloned());
    extra_reads.extend(input.read_only_roots.iter().cloned());
    let mut roots = vec![workspace.clone(), input.private_root.clone()];
    roots.extend_from_slice(system_roots);
    roots.extend(extra_reads.iter().cloned());
    let mut metadata = vec![PathBuf::from("/")];
    metadata.extend(ancestor_paths(&roots));
    let mut executable = vec![workspace.clone()];
    executable.extend(existing(&["/bin", "/usr/bin"]));
    executable.extend(input.exec_roots.iter().cloned());
    let privileged: Vec<PathBuf> = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        .iter()
        .flat_map(|dir| {
            PRIVILEGE_NAMES
                .iter()
                .map(move |name| Path::new(dir).join(name))
        })
        .collect();
    let mut lines = vec![
        "(version 1)".to_owned(),
        "(deny default)".to_owned(),
        "(deny file-link)".to_owned(),
        "(allow process-fork)".to_owned(),
        format!("(allow process-exec {})", filter(&executable, "subpath")),
        format!("(deny process-exec {})", filter(&privileged, "literal")),
        "(allow signal (target self) (target children))".to_owned(),
        "(allow sysctl-read)".to_owned(),
        "(allow file-read-data (literal \"/\"))".to_owned(),
        format!(
            "(allow file-read-metadata {})",
            filter(&metadata, "literal")
        ),
        format!(
            "(allow file-read* {} {})",
            filter(&roots, "subpath"),
            filter(files, "literal")
        ),
        format!(
            "(allow file-write* {} (literal \"/dev/null\"))",
            filter(&[workspace.clone(), input.private_root.clone()], "subpath")
        ),
        regex_rule("file-write*", &git_exec_pattern(workspace)?),
    ];
    for pattern in protected_patterns(workspace)? {
        lines.push(regex_rule("file-write*", &pattern));
    }
    if !input.write_denials.is_empty() {
        lines.push(format!(
            "(deny file-write* {})",
            filter(&input.write_denials, "subpath")
        ));
    }
    // Last, so no earlier allow can reopen a credential for reading or writing.
    for pattern in patterns() {
        lines.push(regex_rule("file-read* file-write*", &pattern));
    }
    Ok(lines.join("\n"))
}
