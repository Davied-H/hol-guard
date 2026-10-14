//! POSIX output-redirection detection that ignores quoted `>` characters.

/// True when POSIX text has a `>` the shell would treat as an output
/// redirection: unquoted, or inside a command substitution. Only the inert
/// `2>&1` and `2>/dev/null` forms are excluded; an escaped `\>` still counts.
pub(super) fn unquoted_redirect(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut quote: Option<char> = None;
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        match quote {
            Some('\'') if character == '\'' => quote = None,
            Some('\'') => {}
            Some(_) if character == '\\' => index += 1,
            Some(_) if character == '"' => quote = None,
            // A substitution inside double quotes runs its own redirections.
            Some(_)
                if character == '`' || (character == '$' && chars.get(index + 1) == Some(&'(')) =>
            {
                return text.contains('>');
            }
            Some(_) => {}
            None if matches!(character, '\'' | '"') => quote = Some(character),
            None if character == '>' => {
                let inert =
                    crate::parser_segments::is_stderr_to_stdout_redirect(&chars, index, false)
                        || index.checked_sub(1).is_some_and(|start| {
                            crate::parser_segments::is_stderr_to_null_redirect(&chars, start, false)
                        });
                if !inert {
                    return true;
                }
            }
            None if character == '\\' && chars.get(index + 1) == Some(&'>') => return true,
            None if character == '\\' => index += 1,
            None if character == '`'
                || (character == '$' && chars.get(index + 1) == Some(&'(')) =>
            {
                return text.contains('>');
            }
            None => {}
        }
        index += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::unquoted_redirect;

    #[test]
    fn quoted_and_inert_forms_are_not_redirects() {
        for text in [
            "gh pr comment 7 --body 'Replace <placeholder> -> value'",
            "gh pr comment 7 --body \"Use <name> => done\"",
            "gh pr comment 7 --body \"a \\` b > c\" 2>&1",
            "gh pr comment 7 --body \"x \\\" > y\"",
        ] {
            assert!(!unquoted_redirect(text), "{text}");
        }
        // Only Unix has the fixed stderr sink the parser treats as inert.
        assert_eq!(
            unquoted_redirect("gh pr comment 7 --body ok 2>/dev/null"),
            !cfg!(unix)
        );
    }

    #[test]
    fn real_and_hidden_redirects_still_count() {
        for text in [
            "gh pr view 7 > .env",
            "gh pr view 7 >> notes.md",
            "gh pr view 7 2> err.log",
            "gh pr view 7 1>&2",
            "gh pr view 7 2>&1>out.log",
            "echo a\\>b",
            "gh pr comment 7 --body \"$(cat x > ~/.netrc)\"",
            "gh pr comment 7 --body \"`cat x > ~/.netrc`\"",
            "gh pr comment 7 --body 'a'>b",
            "cat <(true) >(tee .env)",
        ] {
            assert!(unquoted_redirect(text), "{text}");
        }
    }
}
