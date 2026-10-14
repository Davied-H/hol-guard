//! Assignment values that name where a credential comes from, not the credential.
//!
//! Source files read keys from the environment (`process.env.API_KEY`),
//! declare their types (`apiKey: string`) and document the variables they
//! need (`API_KEY=key_...`, `TOKEN=<your-token>`). Each shape matches the
//! credential assignment rule, but none carries secret material, so reading
//! ordinary source that configures a client stopped agents mid-task.
//!
//! The rule stops an unquoted value at the first space or quote, so a
//! reference can sit in front of a literal (`apiKey: string = "..."`,
//! `os.getenv("TOKEN", "...")`). The rest of that expression is checked, and
//! any string literal there keeps the match, apart from a placeholder or the
//! variable name a lookup is given.

use regex::Regex;
use std::sync::LazyLock;

/// References that only hold as written code: a quoted value is a string
/// literal, apart from the shell parameters below.
static UNQUOTED_REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        // Environment lookups, with only identifier, index and call syntax
        // after them, so an appended literal is not hidden behind one.
        r"^(?:(?:process\.env|import\.meta\.env|Bun\.env|os\.environ)(?:\.[A-Za-z_][A-Za-z0-9_]*|\[)?",
        r"|(?:os\.getenv|os\.environ\.get|Deno\.env\.get|(?:std::)?env::var)\()",
        r"[A-Za-z0-9_\[\]()]*;?$",
        // Type annotations.
        r"|^(?:string|number|boolean|bigint|unknown|any|never|null|undefined|str|bytes|bool|None|String|SecretStr)(?:\[\])?[;)>|]?$",
        // Shell and dotenv variable and positional parameter references,
        // braced with an empty or short numeric default (`${TOKEN:-}`). An
        // unbraced name counts only in the conventional upper case, so
        // `$Pa55word` stays a literal password.
        r"|^\$(?:[A-Z_][A-Z0-9_]*|[0-9]|\{[A-Za-z_][A-Za-z0-9_]*(?::?-[0-9]{0,3})?\}?)$",
        // The default of `${TOKEN:-}` itself, cut at the closing brace.
        r"|^-[0-9]{0,3}$",
        // Command-line arguments.
        r"|^(?:sys|process)\.argv\[[0-9]\]$",
    ))
    .expect("credential reference rule must compile")
});

/// Shell parameters that stay references inside quotes: a positional
/// parameter or a closed braced variable, which no password spells.
static QUOTED_PARAMETER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\$(?:[0-9]|\{[A-Za-z_][A-Za-z0-9_]*(?::?-[0-9]{0,3})?\})$")
        .expect("quoted parameter rule must compile")
});

/// An upper-case shell variable, a reference only where double quotes expand it.
static EXPANDED_VARIABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\$[A-Z_][A-Z0-9_]*$").expect("expanded variable rule must compile")
});

/// Documentation placeholders: a short visible prefix and an ellipsis, or a
/// bracketed name. These carry no secret quoted or not.
static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[A-Za-z0-9_-]{0,12}(?:\.\.\.|…)[\])>;]*|<[A-Za-z0-9_.-]{1,64}>[;)]*)$")
        .expect("credential placeholder rule must compile")
});

/// An environment variable name passed to a lookup, such as `"API_KEY"`.
static VARIABLE_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Z][A-Z0-9]{0,15}(?:_[A-Z0-9]{1,15})*$")
        .expect("variable name rule must compile")
});

/// Whether a credential assignment match is a reference or placeholder, not a
/// credential. `rest_of_line` is the text after the match on the same line.
pub(crate) fn is_reference(matched: &str, rest_of_line: &str) -> bool {
    let Some(index) = matched.find([':', '=']) else {
        return false;
    };
    let value = matched[index + 1..].trim();
    let double = value.len() >= 2 && value.starts_with('"') && value.ends_with('"');
    let single = value.len() >= 2 && value.starts_with('\'') && value.ends_with('\'');
    if double || single {
        let literal = &value[1..value.len() - 1];
        return PLACEHOLDER.is_match(literal)
            || QUOTED_PARAMETER.is_match(literal)
            || (double && EXPANDED_VARIABLE.is_match(literal));
    }
    (PLACEHOLDER.is_match(value) || UNQUOTED_REFERENCE.is_match(value))
        && !hides_literal(value, rest_of_line)
}

/// Whether the expression that `value` starts carries a string literal later
/// on the line: a default, a fallback or the value assigned after a type
/// annotation. A variable name directly inside a call or index, such as
/// `getenv("TOKEN"` or `environ["TOKEN"`, is the lookup's argument.
fn hides_literal(value: &str, rest: &str) -> bool {
    let mut depth = 0i32;
    for character in value.chars() {
        match character {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' | '>' => depth -= 1,
            _ => {}
        }
    }
    if depth < 0 || value.ends_with(';') {
        return false;
    }
    let mut previous = value.chars().last();
    let mut index = 0usize;
    while let Some(character) = rest[index..].chars().next() {
        index += character.len_utf8();
        match character {
            '"' | '\'' | '`' => {
                let body = &rest[index..];
                let length = body.find(character).unwrap_or(body.len());
                let argument = matches!(previous, Some('(' | '['));
                if is_hidden_value(&body[..length], argument) {
                    return true;
                }
                index += (length + character.len_utf8()).min(body.len());
            }
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            ',' | ';' if depth == 0 => return false,
            _ => {}
        }
        if !character.is_whitespace() {
            previous = Some(character);
        }
    }
    false
}

/// Whether a literal can hold a credential: anything not blank, apart from a
/// documentation placeholder or a lookup's variable-name argument.
fn is_hidden_value(literal: &str, argument: bool) -> bool {
    !literal.trim().is_empty()
        && !PLACEHOLDER.is_match(literal)
        && !(argument && VARIABLE_NAME.is_match(literal))
}

#[cfg(test)]
#[path = "reference_value_tests.rs"]
mod tests;
