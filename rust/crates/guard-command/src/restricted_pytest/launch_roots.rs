//! Whether the workspace sandbox could run the programs a command launches.
//!
//! The sandbox executes only from the workspace, the system directories and
//! the toolchain roots `workspace_exec_roots` accepts, and it searches only
//! the PATH entries it accepted. A program the agent's shell would find
//! elsewhere, or whose script interpreter lives elsewhere, cannot run inside
//! it, so containing that command would only trade a review for a failure.
use super::*;

/// Shebang lines longer than this are not read.
const SHEBANG_BYTES: usize = 256;

/// Whether any of `programs`, resolved the way the agent's shell resolves it
/// on `search_path`, is something the workspace sandbox could not execute.
/// A bare name the shell cannot find is left to the shell (a builtin or a
/// function), and a program that resolves to another file inside the
/// sandbox than outside it counts as unreachable.
pub(crate) fn launches_outside_exec_roots<'a>(
    programs: impl IntoIterator<Item = &'a str>,
    search_path: &str,
    home: Option<&Path>,
    workspace: &Path,
    cwd: &Path,
) -> bool {
    let (roots, sandbox_path) = workspace_exec_roots(search_path, home, workspace);
    let executable = executable_roots(workspace, roots);
    programs.into_iter().any(|program| {
        let Some(found) = locate(program, search_path, cwd) else {
            return false;
        };
        let Ok(canonical) = found.canonicalize() else {
            return true;
        };
        let reaches = |path: &Path| path_is_within_any(path, &executable);
        if !reaches(&canonical) {
            return true;
        }
        if !program.contains('/')
            && locate(program, &sandbox_path, cwd)
                .and_then(|inside| inside.canonicalize().ok())
                .as_deref()
                != Some(canonical.as_path())
        {
            return true;
        }
        interpreter(&canonical).is_some_and(|interpreter| {
            match locate(&interpreter, &sandbox_path, cwd) {
                Some(path) => !path.canonicalize().is_ok_and(|path| reaches(&path)),
                None => true,
            }
        })
    })
}

/// Directories the sandbox may execute from on this platform.
fn executable_roots(workspace: &Path, exec_roots: Vec<PathBuf>) -> Vec<PathBuf> {
    let system: &[&str] = if cfg!(target_os = "macos") {
        &["/bin", "/usr/bin"]
    } else {
        &["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64"]
    };
    let mut roots = vec![workspace.to_path_buf()];
    roots.extend(
        system
            .iter()
            .map(PathBuf::from)
            .filter(|root| root.exists()),
    );
    roots.extend(exec_roots);
    roots
}

/// The file `program` names: a path relative to `cwd`, or a bare name on
/// `search_path`. Names a shell would expand are not resolved.
fn locate(program: &str, search_path: &str, cwd: &Path) -> Option<PathBuf> {
    if program.is_empty() || program.contains(['$', '~', '`', '*', '?', '[', '\\', '\n']) {
        return None;
    }
    if program.contains('/') {
        let candidate = cwd.join(program);
        return executable_file(&candidate).then_some(candidate);
    }
    shutil_which(program, Some(search_path))
}

/// The program a `#!` line runs: its interpreter, or for `/usr/bin/env` the
/// first operand that is not an option or an assignment.
fn interpreter(script: &Path) -> Option<String> {
    let mut head = [0_u8; SHEBANG_BYTES];
    let read = std::fs::File::open(script).ok()?.read(&mut head).ok()?;
    let line = head[..read].strip_prefix(b"#!")?;
    // A line the buffer cuts off is not read as a shorter interpreter.
    let end = match line.iter().position(|byte| *byte == b'\n') {
        Some(end) => end,
        None if read < SHEBANG_BYTES => line.len(),
        None => return None,
    };
    let line = &line[..end];
    let mut words = std::str::from_utf8(line).ok()?.split_ascii_whitespace();
    let first = words.next()?;
    if Path::new(first).file_name().and_then(OsStr::to_str) != Some("env") {
        return Some(first.to_owned());
    }
    words
        .find(|word| !word.starts_with('-') && !word.contains('='))
        .map(str::to_owned)
}

#[cfg(test)]
#[path = "launch_roots_tests.rs"]
mod tests;
