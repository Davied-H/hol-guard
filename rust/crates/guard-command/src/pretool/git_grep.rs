//! `git grep` reads proven without review.
//!
//! Grep prints matching lines of tracked content, which `git show` and
//! `git log -p` already print. What it can run is a pager, which the shared
//! configuration probe checks, and a textconv driver, which runs only with
//! `--textconv`. `-O`/`--open-files-in-pager` starts a program, `-f` reads
//! patterns from any file, and `--no-index`, `--untracked` and
//! `--recurse-submodules` widen the search past the tracked tree, so only the
//! options below are admitted. The pattern is search text rather than a path,
//! so the sensitive-path screen applies to the revisions and pathspecs only.

/// Flags that change only how matches are selected or printed.
const FLAGS: &[&str] = &[
    "--cached",
    "--files-with-matches",
    "--name-only",
    "--files-without-match",
    "--count",
    "--quiet",
    "--line-number",
    "--column",
    "--ignore-case",
    "--word-regexp",
    "--invert-match",
    "--full-name",
    "--extended-regexp",
    "--basic-regexp",
    "--fixed-strings",
    "--perl-regexp",
    "--null",
    "--only-matching",
    "--heading",
    "--break",
    "--no-color",
    "--color=never",
    "--all-match",
];
/// Short flags that may be clustered (`-il`): the long forms above plus `-I`
/// (skip binary files) and `-h`/`-H` (file name display).
const SHORT_FLAGS: &str = "lLcqniIwvhHEGFPzo";
/// Options that take a count.
const COUNTS: &[&str] = &[
    "-A",
    "-B",
    "-C",
    "-m",
    "--after-context",
    "--before-context",
    "--context",
    "--max-count",
    "--max-depth",
    "--threads",
];

/// Whether the arguments after `grep` form a bounded read.
pub(super) fn safe_read(arguments: &[String]) -> bool {
    let mut pattern_given = false;
    let mut options = true;
    let mut operands = Vec::new();
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        let word = argument.as_str();
        index += 1;
        if !options || !word.starts_with('-') || word == "-" {
            if word.is_empty() {
                return false;
            }
            if options && !pattern_given {
                // The first operand is the pattern unless `-e` gave one.
                pattern_given = true;
            } else {
                operands.push(word);
            }
            continue;
        }
        if word == "--" {
            options = false;
            pattern_given = true;
        } else if word == "-e" {
            if arguments.get(index).is_none() {
                return false;
            }
            index += 1;
            pattern_given = true;
        } else if let Some(name) = COUNTS.iter().find(|name| word.starts_with(**name)) {
            let value = match word[name.len()..].strip_prefix('=') {
                Some(value) if name.starts_with("--") => value,
                None if word.len() == name.len() => {
                    let Some(value) = arguments.get(index) else {
                        return false;
                    };
                    index += 1;
                    value.as_str()
                }
                None if !name.starts_with("--") => &word[name.len()..],
                _ => return false,
            };
            if value.is_empty() || value.len() > 6 || !value.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
        } else if !(FLAGS.contains(&word)
            || word
                .strip_prefix('-')
                .filter(|cluster| !cluster.starts_with('-') && !cluster.is_empty())
                .is_some_and(|cluster| cluster.chars().all(|flag| SHORT_FLAGS.contains(flag))))
        {
            return false;
        }
    }
    pattern_given
        && operands.iter().all(|value| {
            !value.starts_with(':') && !super::super::sensitive_read_path_argument(value)
        })
}

#[cfg(test)]
mod tests {
    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn bounded_grep_forms_are_reads() {
        for arguments in [
            "-l SOME_TOKEN_NAME HEAD",
            "-l report HEAD -- scripts",
            "-n -i -e retry -- src",
            "-il -C 3 retry",
            "-A2 --max-count=5 retry HEAD~1",
            "--cached -c retry",
        ] {
            assert!(super::safe_read(&words(arguments)), "{arguments}");
        }
        for arguments in [
            "",
            "-O id retry",
            "--open-files-in-pager=id retry",
            "--textconv retry",
            "-f patterns.txt",
            "--no-index retry /etc",
            "--untracked retry",
            "--recurse-submodules retry",
            "-p retry",
            "retry HEAD -- .env",
            "retry :/secrets",
            "-A x retry",
            "-e",
        ] {
            assert!(!super::safe_read(&words(arguments)), "{arguments}");
        }
    }
}
