//! Oh My Pi hooks the resident answers as the daemon does.
//!
//! The daemon reviews a `pi` or `omp` hook as it reviews any other, with two
//! steps of its own. It lets the edge resolve a `guard_source_ref` outside
//! the workspace, a flag that both the request digest and the decision
//! receipt carry, so the lane sets it as the daemon does. After a
//! `PostToolUse` it projects structured content mediation from the
//! harness's managed config, which only the daemon reads, so every such
//! hook keeps the daemon path.

use super::POST_TOOL_USE;

/// The harnesses the daemon treats as Oh My Pi.
const PI_HARNESSES: [&str; 2] = ["pi", "omp"];
/// The spellings `canonical_harness_name` maps onto them.
const PI_ALIASES: [(&str, &str); 3] = [
    ("pi-agent", "pi"),
    ("pi-coding-agent", "pi"),
    ("oh-my-pi", "omp"),
];

/// `value.strip().lower().replace("_", "-")`. Python strips the separators
/// U+001C to U+001F as whitespace; Rust does not.
fn normalized(value: &str) -> String {
    value
        .trim_matches(|character: char| {
            character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
        })
        .to_lowercase()
        .replace('_', "-")
}

/// `default_harness.strip().lower().replace("_", "-") in {"pi", "omp"}`, the
/// `source_ref_external_allowed` that `_review_native_edge_with_snapshot`
/// passes the edge.
pub(super) fn source_ref_external_allowed(harness: &str) -> bool {
    PI_HARNESSES.contains(&normalized(harness).as_str())
}

/// Whether `_apply_structured_mediation` projects this hook: a `PostToolUse`
/// for a harness `canonical_harness_name` names `pi` or `omp`.
pub(super) fn structured_mediation(harness: &str, event: &str) -> bool {
    if event != POST_TOOL_USE {
        return false;
    }
    let name = normalized(harness);
    let canonical = PI_ALIASES
        .iter()
        .find(|(alias, _)| *alias == name.as_str())
        .map_or(name.as_str(), |&(_, canonical)| canonical);
    PI_HARNESSES.contains(&canonical)
}
