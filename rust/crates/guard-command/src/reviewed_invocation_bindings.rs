//! Bind a reviewed literal invocation to the discovered operation that owns it.
//!
//! An extension author submits safe variants: exact argument vectors that a
//! reviewed operation is allowed to run. Review has to answer two questions
//! about each one - does it use only options the discovery found, and does the
//! grammar assign it to the operation that claims it - and both answers have to
//! come from the grammar that will later enforce the extension.
//!
//! Python answered them with matchers it built itself, so a vector could be
//! bound to one operation while review was running and matched by another once
//! the extension was installed. The matchers are the runtime's here, built from
//! the same node config a compiled program carries.
//!
//! Pure: the caller ships the discovery it parsed, and nothing here opens the
//! store, the catalog or an extension file.

use std::collections::BTreeSet;
use std::time::Instant;

use serde_json::json;

use crate::native_command_program::ExecutableInvocationMatcher;
use crate::{parse_command, CommandModelRequestV1};

/// Refusal codes, in the vocabulary the extension builder already reports.
pub const SAFE_VARIANT_SCOPE: &str = "safe_variant_scope";
pub const SAFE_VARIANT_OPTION: &str = "safe_variant_option";
pub const SAFE_VARIANT_CONFLICT: &str = "safe_variant_conflict";

/// One operation the discovery found, with the option vocabulary review may
/// accept for it.
#[derive(Debug, Clone, Default)]
pub struct ReviewedOperation {
    pub operation_id: String,
    pub path: Vec<String>,
    pub flags: BTreeSet<String>,
    pub options_with_values: BTreeSet<String>,
}

/// One reviewed literal vector and the operation that claims it.
#[derive(Debug, Clone, Default)]
pub struct ReviewedInvocation {
    pub operation_id: String,
    pub argv: Vec<String>,
}

/// The first row review refuses: its position and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedBindingRefusal {
    pub index: usize,
    pub code: &'static str,
}

/// `validate_reviewed_invocations` - the first reviewed row the grammar
/// refuses, or nothing.
///
/// A refusal is an answer the author can act on, not a runtime failure, so it
/// is returned rather than raised. `Err` is reserved for a request the grammar
/// cannot read at all: a row naming an operation the discovery does not carry,
/// a matcher config the compiler rejects, or a vector that will not parse.
pub fn validate_reviewed_invocations(
    executable: &str,
    operations: &[ReviewedOperation],
    rows: &[ReviewedInvocation],
    blocked_ids: &BTreeSet<String>,
    deadline: Option<Instant>,
) -> Result<Option<ReviewedBindingRefusal>, &'static str> {
    if rows.is_empty() {
        return Ok(None);
    }
    if executable.trim().is_empty() {
        return Err("native_reviewed_invocation_executable_empty");
    }
    let mut matchers = Vec::with_capacity(operations.len());
    for operation in operations {
        matchers.push(matcher_for(executable, operation)?);
    }
    for (index, row) in rows.iter().enumerate() {
        let owner = operations
            .iter()
            .find(|operation| operation.operation_id == row.operation_id)
            .ok_or("native_reviewed_invocation_operation_unknown")?;
        if let Some(code) = unknown_options(owner, &row.argv) {
            return Ok(Some(ReviewedBindingRefusal { index, code }));
        }
        let command = parse_command(&CommandModelRequestV1 {
            command: once_joined(executable, &row.argv),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-extension-review".to_owned(),
        })
        .map_err(|_| "native_reviewed_invocation_unparsed")?;
        let mut longest = -1_i64;
        let mut owners = BTreeSet::new();
        let mut blocked = false;
        for (operation, matcher) in operations.iter().zip(&matchers) {
            if !matcher.matches(&command, deadline)? {
                continue;
            }
            if blocked_ids.contains(&operation.operation_id) {
                blocked = true;
            }
            let length = operation.path.len() as i64;
            if length > longest {
                longest = length;
                owners.clear();
            }
            if length == longest {
                owners.insert(operation.operation_id.as_str());
            }
        }
        if blocked {
            return Ok(Some(ReviewedBindingRefusal {
                index,
                code: SAFE_VARIANT_CONFLICT,
            }));
        }
        if owners.len() != 1 || !owners.contains(owner.operation_id.as_str()) {
            return Ok(Some(ReviewedBindingRefusal {
                index,
                code: SAFE_VARIANT_SCOPE,
            }));
        }
    }
    Ok(None)
}

/// The matcher a compiled program would hold for this operation: every
/// invocation of the executable for a root operation, the operation's own path
/// otherwise.
fn matcher_for(
    executable: &str,
    operation: &ReviewedOperation,
) -> Result<ExecutableInvocationMatcher, &'static str> {
    if operation.path.is_empty() {
        return ExecutableInvocationMatcher::from_config(
            "executable.v1",
            json!({"executables": [executable]}),
        );
    }
    ExecutableInvocationMatcher::from_config(
        "executable-path-set.v1",
        json!({
            "executables": [executable],
            "paths": [operation.path],
            "allow_leading_options": true,
            "leading_options_with_values": operation.options_with_values,
            "interspersed_options_with_values": operation.options_with_values,
            "interspersed_flags": operation.flags,
            "fail_secure_unknown_options": true,
        }),
    )
}

/// `unknown_options` - the first argument past the operation's path that the
/// discovery never reported, if there is one.
///
/// A root operation owns no path, so it owns no operands either: anything after
/// the executable belongs to an operation review has not been shown.
fn unknown_options(operation: &ReviewedOperation, argv: &[String]) -> Option<&'static str> {
    let remaining = argv.get(operation.path.len()..).unwrap_or_default();
    let mut index = 0;
    let mut operands = false;
    while index < remaining.len() {
        let argument = remaining[index].as_str();
        if argument == "--" && !operation.path.is_empty() {
            operands = true;
        } else if operands || !argument.starts_with('-') {
            if operation.path.is_empty() {
                return Some(SAFE_VARIANT_SCOPE);
            }
        } else if !operation.flags.contains(argument) {
            let (name, separator) = match argument.split_once('=') {
                Some((name, _value)) => (name, true),
                None => (argument, false),
            };
            if !operation.options_with_values.contains(name) {
                return Some(SAFE_VARIANT_OPTION);
            }
            if !separator {
                index += 1;
                if index >= remaining.len() {
                    return Some(SAFE_VARIANT_OPTION);
                }
            }
        }
        index += 1;
    }
    None
}

/// The command text review parses: the executable and the reviewed vector, the
/// way the author will invoke it.
fn once_joined(executable: &str, argv: &[String]) -> String {
    let mut command = String::from(executable);
    for argument in argv {
        command.push(' ');
        command.push_str(argument);
    }
    command
}

#[cfg(test)]
#[path = "reviewed_invocation_bindings_tests.rs"]
mod tests;
