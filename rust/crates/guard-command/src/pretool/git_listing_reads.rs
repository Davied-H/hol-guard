//! `git shortlog` and `git check-ignore`, the two listings that only print.
//!
//! `shortlog` counts the commits history already holds and `check-ignore`
//! answers which ignore rule a path matches. Neither writes a ref, an object
//! or a file. Both still run under the repository's configuration, so the
//! configuration probe clears them before the read is proven, and options
//! outside these lists keep their review.

/// `shortlog` flags that take no value. `-w` carries an optional inline
/// width instead, which [`shortlog_read_form`] checks.
const SHORTLOG_FLAGS: [&str; 10] = [
    "-n",
    "--numbered",
    "-s",
    "--summary",
    "-e",
    "--email",
    "-c",
    "--committer",
    "--all",
    "--no-merges",
];

/// `shortlog` options whose value names a grouping or a commit range.
///
/// `--format` and `--pretty` are not here. A pretty format expands `%G`,
/// which verifies signatures through the configured program, so a shortlog
/// that carries one keeps its review the way every other history read with
/// one does.
const SHORTLOG_VALUES: [&str; 2] = ["--group", "--max-count"];

/// `check-ignore` flags. All of them change what is printed and nothing else.
const CHECK_IGNORE_FLAGS: [&str; 6] = ["-q", "--quiet", "-v", "--verbose", "-z", "--no-index"];

/// Whether `subcommand rest...` is a proven listing read.
pub(super) fn read_form(subcommand: &str, rest: &[String]) -> bool {
    match subcommand {
        "shortlog" => shortlog_read_form(rest),
        "check-ignore" => check_ignore_read_form(rest),
        _ => false,
    }
}

/// Whether the width a `-w` spelling carries inline is a plain comma-separated
/// count. An empty rest means the bare flag.
fn inline_width(rest: &str) -> bool {
    rest.is_empty()
        || rest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b',')
}

fn shortlog_read_form(rest: &[String]) -> bool {
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
        if SHORTLOG_FLAGS.contains(&argument.as_str()) {
            continue;
        }
        if let Some(width) = argument.strip_prefix("-w") {
            if inline_width(width) {
                continue;
            }
            return false;
        }
        if let Some((name, _)) = argument.split_once('=') {
            if SHORTLOG_VALUES.contains(&name) {
                continue;
            }
            return false;
        }
        if SHORTLOG_VALUES.contains(&argument.as_str()) {
            if arguments.next().is_none() {
                return false;
            }
            continue;
        }
        return false;
    }
    true
}

fn check_ignore_read_form(rest: &[String]) -> bool {
    let mut names = 0_usize;
    let mut arguments = rest.iter();
    let mut stdin = false;
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            let operands = arguments.as_slice();
            return operands.iter().all(|operand| !operand.is_empty())
                && (names + operands.len() > 0 || stdin);
        }
        if !argument.starts_with('-') {
            if argument.is_empty() {
                return false;
            }
            names += 1;
            continue;
        }
        if CHECK_IGNORE_FLAGS.contains(&argument.as_str()) {
            continue;
        }
        // `--stdin` takes the paths from the pipe the command already has,
        // and the command prints which rule matched each of them.
        if argument == "--stdin" {
            stdin = true;
            continue;
        }
        return false;
    }
    names > 0 || stdin
}
