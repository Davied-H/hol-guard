//! Oh My Pi's `learn` writes one note into the agent's memory bank. The note
//! is prose the model wrote for itself, so no two calls carry the same text:
//! an exact-action approval can never be reused, and under review every call
//! stops the run again. What the note may carry is bounded instead. A plain
//! note into this project's own bank is allowed; a note holding a secret, an
//! instruction aimed at the harness or at Guard, a destination to send
//! something to, or a command shaped to be run later keeps its review under a
//! reason of its own. So does a global note, which reaches every project's
//! recall, and a call that also mints a skill file, which is a file write with
//! its own proof.

use crate::pretool::generic::extract::{note_intent, GenericSignals};
use crate::pretool::generic::result::{generic_action, generic_result};
use guard_contracts::{PreToolActionTypeV1, PreToolOperationV1, PreToolResultV1};
use serde_json::{Map, Value};

use super::{strict_tool_input, OmpContext};

/// A note longer than this is not the lesson the tool is for, and the readers
/// below are bounded by it.
const MAX_NOTE_BYTES: usize = 4096;

/// The keys Oh My Pi's `learn` schema carries for a memory note. `skill`
/// writes a managed skill file, so a call holding it is not one of these.
const NOTE_KEYS: [&str; 3] = ["memory", "context", "scope"];

/// What this reads in the text a `learn` call would store.
enum Reading {
    /// A lesson about this project and nothing else.
    Lesson,
    /// Text that would be read back into a later run as more than a lesson.
    MoreThanALesson,
}

/// `Some` for a note this can read; `None` keeps the ordinary review.
pub(super) fn evaluate(
    payload: &Value,
    signals: &GenericSignals,
    context: &OmpContext<'_>,
) -> Option<PreToolResultV1> {
    let input = strict_tool_input(payload)?;
    if !signals.path_values.is_empty() {
        return None;
    }
    let (minimum_action, reason_code, reason) = match read_note(input)? {
        Reading::Lesson => (
            "allow",
            "native_omp_learn_memory_note",
            "The Rust authority read this Oh My Pi learn call as a plain project memory note: it writes this project's own memory bank and carries no secret, no instruction aimed at the harness or at Guard, no destination and no command.",
        ),
        Reading::MoreThanALesson => (
            "review",
            "native_omp_learn_memory_sensitive",
            "HOL Guard requires review because this Oh My Pi learn call would store more than a lesson: the note carries a secret, an instruction aimed at the harness or at Guard, a destination, or a command, and a later run reads it back.",
        ),
    };
    Some(generic_result(
        generic_action(
            context.harness,
            context.event,
            PreToolActionTypeV1::Harness,
            PreToolOperationV1::Set,
            true,
            matches!(minimum_action, "review"),
        ),
        minimum_action,
        reason_code,
        reason,
    ))
}

/// A memory note into this project's own bank, which the store has already
/// written by the time a result comes back. The note's own content does not
/// have to read as plain here: the write happened, either because it was
/// allowed above or because a person approved it, and the acknowledgement it
/// returns adds no operation. A global note, which reaches every project's
/// recall, and a call that also mints a skill file are not these.
pub(super) fn note_input(input: &Map<String, Value>) -> bool {
    input.keys().all(|key| NOTE_KEYS.contains(&key.as_str()))
        && input
            .get("memory")
            .and_then(Value::as_str)
            .is_some_and(|memory| !memory.trim().is_empty())
        && input.get("context").is_none_or(Value::is_string)
        // A global lesson reaches every project's recall, so Oh My Pi itself
        // asks for it the way it asks for a file write, and so does this.
        && input
            .get("scope")
            .is_none_or(|scope| scope.as_str() == Some("project"))
}

/// `None` for a call this does not read as one project note at all.
fn read_note(input: &Map<String, Value>) -> Option<Reading> {
    if !note_input(input) {
        return None;
    }
    let memory = note_text(input.get("memory"))?;
    let context = match input.get("context") {
        None => "",
        value => note_text(value)?,
    };
    let written = [memory.to_owned(), context.to_owned()];
    let lesson = !note_intent(&written)
        && written.iter().all(|text| {
            text.is_empty()
                || (!crate::pretool::curl_reads::url_secrets::text_carries_secret(text)
                    && guard_scanner::secret_detection::scan_secret_text(
                        text, "", "memory", None, 1,
                    )
                    .findings
                    .is_empty())
        });
    Some(if lesson {
        Reading::Lesson
    } else {
        Reading::MoreThanALesson
    })
}

/// A bounded note string. A non-string or an oversized value is not one.
fn note_text(value: Option<&Value>) -> Option<&str> {
    let text = value?.as_str()?;
    (text.len() <= MAX_NOTE_BYTES).then_some(text)
}
