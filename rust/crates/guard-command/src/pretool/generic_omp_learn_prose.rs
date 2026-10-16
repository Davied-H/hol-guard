//! What a stored note may say and still be inert. A memory is read back into
//! a later run, so a note that reads as an instruction, names a destination,
//! spells a command or carries a credential is not a lesson about the project
//! however it is worded. These readings are deliberately literal: anything
//! they are unsure about keeps the review it has today, so the allow below
//! them covers plain prose only.

/// A note that tells a later run what to do. The agent reads its own bank back
/// at the top of a run, so a standing instruction stored here is an
/// instruction the next run follows.
const DIRECTIVES: [&str; 12] = [
    "always ",
    "never ",
    "from now on",
    "whenever you",
    "before you",
    "make sure to",
    "be sure to",
    "you must",
    "you should always",
    "ignore ",
    "do not tell",
    "don't tell",
];

/// Shell punctuation. Prose about a project does not need it, and a note that
/// carries it is spelling something to run.
const SHELL_MARKS: [&str; 9] = ["&&", "||", "$(", "`", " | ", "; ", " > ", " >> ", " < "];

/// A word that introduces a credential. Paired with `:` or `=` on the same
/// line it is a stored secret even when it is too ordinary for the scanners.
const CREDENTIAL_WORDS: [&str; 9] = [
    "password",
    "passwd",
    "secret",
    "token",
    "api key",
    "api_key",
    "apikey",
    "credential",
    "private key",
];

/// Whether this text is a plain lesson: no instruction for a later run, no
/// destination, no command and no credential.
pub(super) fn inert_prose(text: &str) -> bool {
    if text.is_empty() {
        return true;
    }
    let lowered = text.to_ascii_lowercase();
    !names_a_destination(&lowered)
        && !directs_a_later_run(&lowered)
        && !spells_a_command(text, &lowered)
        && !holds_a_credential(&lowered)
}

/// A URL or a host. A note holding one is where a later run would send what it
/// reads, so it is reviewed rather than stored unseen.
fn names_a_destination(lowered: &str) -> bool {
    lowered.contains("://")
        || lowered.contains("www.")
        || lowered.contains("@")
        || lowered.split_whitespace().any(|token| {
            let token = token.trim_matches(|c: char| !c.is_ascii_alphanumeric());
            token.contains('.')
                && token.rsplit('.').next().is_some_and(|tld| {
                    tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
                })
                && !token.rsplit('.').next().is_some_and(is_file_suffix)
        })
}

/// A file this project owns, which a lesson may name. The destination reading
/// above stops at these so "the retry limit lives in settings.ts" stays a
/// lesson.
fn is_file_suffix(suffix: &str) -> bool {
    const SUFFIXES: [&str; 24] = [
        "ts", "tsx", "js", "jsx", "mjs", "cjs", "rs", "py", "go", "rb", "java", "kt", "swift", "c",
        "cc", "cpp", "h", "hpp", "json", "toml", "yaml", "yml", "md", "txt",
    ];
    SUFFIXES.contains(&suffix)
}

fn directs_a_later_run(lowered: &str) -> bool {
    DIRECTIVES.iter().any(|phrase| lowered.contains(phrase))
}

/// Shell punctuation, an option flag or a path outside this project. Each is
/// something to run or somewhere to reach rather than something to know.
fn spells_a_command(text: &str, lowered: &str) -> bool {
    SHELL_MARKS.iter().any(|mark| lowered.contains(mark))
        || text.split_whitespace().any(|token| {
            (token.len() > 2 && token.starts_with("--"))
                || token.starts_with('/')
                || token.starts_with("~/")
                || token.starts_with(r"\\")
                || token
                    .as_bytes()
                    .get(1..3)
                    .is_some_and(|drive| drive == br":\" || drive == b":/")
        })
}

fn holds_a_credential(lowered: &str) -> bool {
    lowered.lines().any(|line| {
        CREDENTIAL_WORDS.iter().any(|word| {
            line.find(word)
                .is_some_and(|at| line[at + word.len()..].trim_start().starts_with([':', '=']))
        })
    })
}
