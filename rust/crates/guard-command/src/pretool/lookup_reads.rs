//! Command lookups (`type`, `command -v`) that only report how names resolve.
//!
//! Neither builtin runs the program it names. `type` may print a shell
//! function's body, which the agent's own shell defined. Operands are plain
//! command names, so a path or expansion is never treated as a lookup.

/// Whether a `type` or `command` segment is a lookup of plain names.
pub(super) fn safe_lookup_arguments(executable: &str, arguments: &[String]) -> bool {
    let letters = match executable {
        "type" => "afpPt",
        "command" => "pvV",
        _ => return false,
    };
    let mut names = 0;
    let mut options = true;
    for argument in arguments {
        if options && argument == "--" {
            options = false;
        } else if options && argument.len() > 1 && argument.starts_with('-') {
            if !argument[1..].chars().all(|letter| letters.contains(letter)) {
                return false;
            }
        } else if plain_name(argument) {
            options = false;
            names += 1;
        } else {
            return false;
        }
    }
    // `command` without `-v`/`-V` runs the named program.
    names > 0
        && (executable == "type"
            || crate::parser_wrappers::is_command_lookup(Some(executable), arguments))
}

fn plain_name(argument: &str) -> bool {
    !argument.starts_with('-')
        && argument
            .chars()
            .all(|letter| letter.is_ascii_alphanumeric() || "._+-".contains(letter))
}
