//! `kill` forms the workspace sandbox can contain. A job specification names
//! a job of the shell that runs the command, so `npm run dev & ... kill %1`
//! stops only what this command started and reaches no other process on the
//! host. A pid operand names any process the user can signal, including a
//! daemon this session knows nothing about, so it keeps its review.

/// Whether `arguments` (after `kill`) name only the shell's own jobs.
pub(super) fn jobs_only(arguments: &[String]) -> bool {
    let mut words = arguments.iter();
    let mut jobs = 0;
    while let Some(word) = words.next() {
        // `-s TERM` and `-n 9` carry the signal in the next word.
        if word == "-s" || word == "-n" {
            if words.next().is_none() {
                return false;
            }
            continue;
        }
        if let Some(option) = word.strip_prefix('-') {
            // `-l` and `-L` list signal names and reach no process, but they
            // also name no job, so they are not this form.
            if option.is_empty() || option.starts_with('l') || option.starts_with('L') {
                return false;
            }
            continue;
        }
        if !job(word) {
            return false;
        }
        jobs += 1;
    }
    jobs > 0
}

/// A job specification: `%1`, `%%`, `%+`, `%-`, `%vite` or `%?build`. A name
/// built from an expansion names whatever that holds, which this text does
/// not show.
fn job(word: &str) -> bool {
    let Some(specification) = word.strip_prefix('%') else {
        return false;
    };
    if matches!(specification, "" | "%" | "+" | "-") {
        return true;
    }
    let name = specification.strip_prefix('?').unwrap_or(specification);
    !name.is_empty()
        && name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
}
