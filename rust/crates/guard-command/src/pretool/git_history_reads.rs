//! `git blame`, `git describe` and `git reflog` forms that only print history.
//!
//! All three read committed history and the refs that name it, and none of
//! them writes. They still page (`pager.blame`, `pager.reflog`, `core.pager`)
//! and blame converts blobs through `diff.<driver>.textconv`, so the
//! configuration probe clears the read before it is proven. Options outside
//! these lists keep their review, which is what refuses `blame --textconv`
//! and every `reflog` form that expires or deletes entries.

/// `blame` flags that take no value. `-C`, `-M` and `--abbrev` carry an
/// optional inline count instead, which [`blame_read_form`] checks.
const BLAME_FLAGS: [&str; 30] = [
    "-b",
    "--root",
    "--no-root",
    "--show-stats",
    "-c",
    "--score-debug",
    "-f",
    "--show-name",
    "-n",
    "--show-number",
    "-s",
    "-e",
    "--show-email",
    "-w",
    "-l",
    "-t",
    "-p",
    "--porcelain",
    "--line-porcelain",
    "--incremental",
    "--reverse",
    "--first-parent",
    "--minimal",
    "--color-lines",
    "--no-color-lines",
    "--color-by-age",
    "--no-color-by-age",
    "--progress",
    "--no-progress",
    "--no-textconv",
];

/// `blame` options whose value is a revision, a path or a date format. A
/// path value is screened by the caller's read-path check.
const BLAME_VALUES: [&str; 5] = [
    "--contents",
    "--ignore-rev",
    "--ignore-revs-file",
    "--date",
    "--encoding",
];

/// `describe` flags that take no value. `--dirty`, `--broken` and `--abbrev`
/// carry an optional inline value instead.
const DESCRIBE_FLAGS: [&str; 8] = [
    "--all",
    "--tags",
    "--contains",
    "--long",
    "--always",
    "--first-parent",
    "--debug",
    "--exact-match",
];

/// `describe` options whose value is a ref pattern or a count.
const DESCRIBE_VALUES: [&str; 3] = ["--candidates", "--match", "--exclude"];

/// `describe` options that may carry an inline value and nothing else.
const DESCRIBE_OPTIONAL: [&str; 3] = ["--dirty", "--broken", "--abbrev"];

/// `reflog` flags that take no value.
const REFLOG_FLAGS: [&str; 8] = [
    "--all",
    "--single-worktree",
    "--no-abbrev",
    "--oneline",
    "--relative-date",
    "--no-decorate",
    "--decorate",
    "-q",
];

/// `reflog` options whose value is a count, a date or a pretty format.
const REFLOG_VALUES: [&str; 5] = ["-n", "--max-count", "--date", "--format", "--pretty"];

/// `reflog` operations that rewrite or drop entries.
const REFLOG_WRITES: [&str; 4] = ["expire", "delete", "drop", "write"];

/// Whether `subcommand rest...` is a proven history read.
pub(super) fn read_form(subcommand: &str, rest: &[String]) -> bool {
    match subcommand {
        "blame" => blame_read_form(rest),
        "describe" => describe_read_form(rest),
        "reflog" => reflog_read_form(rest),
        _ => false,
    }
}

/// Whether the option count a `-C`, `-M`, `-n` or `--abbrev` spelling carries
/// inline is a plain number. An empty rest means the bare flag.
fn inline_count(rest: &str) -> bool {
    rest.is_empty() || rest.bytes().all(|byte| byte.is_ascii_digit())
}

fn blame_read_form(rest: &[String]) -> bool {
    let mut arguments = rest.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            return arguments.all(|operand| !operand.is_empty());
        }
        if !argument.starts_with('-') {
            if argument.is_empty() {
                return false;
            }
            continue;
        }
        if BLAME_FLAGS.contains(&argument.as_str()) {
            continue;
        }
        // `-C`, `-CC` and `-C3` all detect copies; `-M` detects moves.
        if let Some(rest) = argument
            .strip_prefix("-C")
            .map(|rest| rest.trim_start_matches('C'))
            .or_else(|| argument.strip_prefix("-M"))
        {
            if inline_count(rest) {
                continue;
            }
            return false;
        }
        if let Some(rest) = argument.strip_prefix("--abbrev") {
            if rest.is_empty() || rest.strip_prefix('=').is_some_and(inline_count) {
                continue;
            }
            return false;
        }
        // `-L1,20` and `-L 1,20` are the same range; so are `-S<file>` and
        // `-S <file>`, and the caller screens the path either way.
        if let Some(value) = argument
            .strip_prefix("-L")
            .or_else(|| argument.strip_prefix("-S"))
        {
            if value.is_empty() && arguments.next().is_none() {
                return false;
            }
            continue;
        }
        let (name, inline) = split_option(argument);
        if !BLAME_VALUES.contains(&name) {
            return false;
        }
        if inline.is_none() && arguments.next().is_none() {
            return false;
        }
    }
    true
}

fn describe_read_form(rest: &[String]) -> bool {
    let mut arguments = rest.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            return arguments.all(|operand| !operand.is_empty());
        }
        if !argument.starts_with('-') {
            if argument.is_empty() {
                return false;
            }
            continue;
        }
        if DESCRIBE_FLAGS.contains(&argument.as_str()) {
            continue;
        }
        let (name, inline) = split_option(argument);
        if DESCRIBE_OPTIONAL.contains(&name) {
            // `--abbrev=<n>` takes a count; `--dirty=<mark>` takes a suffix.
            if name == "--abbrev" && inline.is_some_and(|value| !inline_count(value)) {
                return false;
            }
            continue;
        }
        if !DESCRIBE_VALUES.contains(&name) {
            return false;
        }
        if inline.is_none() && arguments.next().is_none() {
            return false;
        }
    }
    true
}

fn reflog_read_form(rest: &[String]) -> bool {
    let mut arguments = rest.iter().peekable();
    // `git reflog` is `git reflog show`; any other operation name may write.
    if arguments
        .peek()
        .is_some_and(|argument| REFLOG_WRITES.contains(&argument.as_str()))
    {
        return false;
    }
    if arguments.peek().is_some_and(|argument| *argument == "show") {
        arguments.next();
    }
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            return arguments.all(|operand| !operand.is_empty());
        }
        if !argument.starts_with('-') {
            if argument.is_empty() {
                return false;
            }
            continue;
        }
        if REFLOG_FLAGS.contains(&argument.as_str()) {
            continue;
        }
        // `-5` and `-n5` are the same entry limit.
        if let Some(rest) = argument.strip_prefix("-n").or_else(|| {
            argument
                .strip_prefix('-')
                .filter(|rest| !rest.starts_with('-'))
        }) {
            if !rest.is_empty() && inline_count(rest) {
                continue;
            }
        }
        if let Some(rest) = argument.strip_prefix("--abbrev") {
            if rest.is_empty() || rest.strip_prefix('=').is_some_and(inline_count) {
                continue;
            }
            return false;
        }
        let (name, inline) = split_option(argument);
        if !REFLOG_VALUES.contains(&name) {
            return false;
        }
        if inline.is_none() && arguments.next().is_none() {
            return false;
        }
    }
    true
}

fn split_option(argument: &str) -> (&str, Option<&str>) {
    match argument.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (argument, None),
    }
}

#[cfg(test)]
#[path = "git_history_reads_tests.rs"]
mod tests;
