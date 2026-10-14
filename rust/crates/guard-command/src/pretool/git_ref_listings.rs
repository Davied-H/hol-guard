//! `git show-ref` and `git for-each-ref` forms that only print references.
//!
//! Both list refs and the objects they name; no option starts a helper or
//! writes. They still honor `pager.<name>`, and printing an object's type or
//! contents can make a partial clone fetch it, so the configuration probe
//! clears the read before it is proven. Options outside these lists, such as
//! `--exclude-existing` and `--stdin` (which read stdin), keep their review.

const SHOW_REF_FLAGS: [&str; 13] = [
    "--head",
    "--heads",
    "--branches",
    "--tags",
    "-d",
    "--dereference",
    "-s",
    "--hash",
    "--abbrev",
    "-q",
    "--quiet",
    "--verify",
    "--exists",
];

/// `for-each-ref` options. A pattern operand is only a ref name.
const FOR_EACH_REF_OPTIONS: [&str; 16] = [
    "--count",
    "--sort",
    "--format",
    "--shell",
    "--perl",
    "--python",
    "--tcl",
    "--points-at",
    "--merged",
    "--no-merged",
    "--contains",
    "--no-contains",
    "--ignore-case",
    "--omit-empty",
    "--exclude",
    "--include-root-refs",
];

/// `for-each-ref` options that take the next argument as their value when
/// it is not inline. `--merged` and its kin take it whenever one follows.
const FOR_EACH_REF_VALUES: [&str; 9] = [
    "--count",
    "--sort",
    "--format",
    "--points-at",
    "--exclude",
    "--merged",
    "--no-merged",
    "--contains",
    "--no-contains",
];

/// Whether `subcommand rest...` is a proven reference listing.
pub(super) fn read_form(subcommand: &str, rest: &[String]) -> bool {
    let options: &[&str] = match subcommand {
        "show-ref" => &SHOW_REF_FLAGS,
        "for-each-ref" => &FOR_EACH_REF_OPTIONS,
        _ => return false,
    };
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
        let (name, inline) = match argument.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (argument.as_str(), None),
        };
        if !options.contains(&name) {
            return false;
        }
        match (subcommand, inline) {
            // `--hash=<n>` and `--abbrev=<n>` take only a digit count.
            ("show-ref", Some(digits)) => {
                if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                    return false;
                }
            }
            ("for-each-ref", None) if FOR_EACH_REF_VALUES.contains(&name) => {
                // The value is a format, sort key, count, pattern or revision;
                // none of them is a path or starts a helper.
                arguments.next();
            }
            _ => {}
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::read_form;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn listings_are_read_forms() {
        for (subcommand, rest) in [
            ("show-ref", ""),
            ("show-ref", "--heads"),
            ("show-ref", "--tags -d"),
            ("show-ref", "--verify --quiet refs/heads/main"),
            ("show-ref", "--hash=12 --abbrev main"),
            ("for-each-ref", ""),
            ("for-each-ref", "--format=%(refname) refs/remotes"),
            (
                "for-each-ref",
                "--format %(refname:short) --sort -committerdate refs/heads",
            ),
            ("for-each-ref", "--count=5 --merged origin/main refs/heads"),
            ("for-each-ref", "--shell --format=%(refname) -- refs/tags"),
        ] {
            assert!(read_form(subcommand, &args(rest)), "{subcommand} {rest}");
        }
    }

    #[test]
    fn other_forms_keep_review() {
        for (subcommand, rest) in [
            ("show-ref", "--exclude-existing"),
            ("show-ref", "--remotes"),
            ("show-ref", "--hash=x"),
            ("for-each-ref", "--stdin"),
            ("for-each-ref", "--output=refs.txt"),
            ("update-ref", "refs/heads/main HEAD"),
        ] {
            assert!(!read_form(subcommand, &args(rest)), "{subcommand} {rest}");
        }
    }
}
