//! `dd` reading one bounded file to standard output.
//!
//! `dd if=FILE bs=N count=N skip=N` prints a slice of the file exactly like
//! `head -c` or `tail -c`, so the input goes through the same bounded,
//! sensitive-path-aware read proof. Any operand that names an output file,
//! converts, or seeks keeps review, which is what makes `dd` dangerous.

use super::safe_reads::command_read_target;
use super::search::SECRET_EXTENSIONS;

fn readable(value: &str, context: super::PathContext<'_>) -> bool {
    let extension = std::path::Path::new(value)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    !value.starts_with('-')
        && !SECRET_EXTENSIONS.contains(&extension.as_str())
        && command_read_target(value, context, false)
}

/// A block or byte count: digits with at most one size suffix.
fn size(value: &str) -> bool {
    let digits = value
        .strip_suffix(['c', 'w', 'b', 'k', 'K', 'M', 'G'])
        .unwrap_or(value);
    !digits.is_empty() && digits.len() <= 12 && digits.bytes().all(|byte| byte.is_ascii_digit())
}

pub(super) fn safe_dd_arguments(arguments: &[String], context: super::PathContext<'_>) -> bool {
    let mut input = false;
    for argument in arguments {
        let Some((name, value)) = argument.split_once('=') else {
            return false;
        };
        let accepted = match name {
            "if" if !input && readable(value, context) => {
                input = true;
                true
            }
            "bs" | "ibs" | "count" | "skip" => size(value),
            "status" => matches!(value, "none" | "noxfer"),
            _ => false,
        };
        if !accepted {
            return false;
        }
    }
    input
}

/// A whole `dd` segment that the native proof accepts as a read. It writes
/// nothing, so the compatibility layer does not count it as a destructive
/// command or a write to the paths it names.
pub(crate) fn proven_read_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    segment.executable.as_deref() == Some("dd")
        && super::segment_proof::exact_safe_segment_with_context(model, segment, false, context)
}
