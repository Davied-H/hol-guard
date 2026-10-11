//! Content-bind the file operands of a command.

use serde_json::{json, Value};

use super::context::Ctx;
use super::fs_path;

const MAX_BOUND_OPERANDS: usize = 16;
const MAX_BOUND_OPERAND_BYTES: u64 = 4_194_304;

/// The value part of an argument: `--flag=value` binds `value`.
pub(super) fn argument_value(argument: &str) -> &str {
    if argument.starts_with('-') {
        argument.split_once('=').map_or("", |(_, value)| value)
    } else {
        argument
    }
}

/// Hash file operands (marking absent and non-file ones), or `None` when they
/// cannot be bound: too many, too large or unreadable.
pub(super) fn file_operand_hashes(arguments: &[String], cwd: &str, ctx: &Ctx) -> Option<Vec<Value>> {
    let mut bound: Vec<Value> = Vec::new();
    for argument in arguments {
        let value = argument_value(argument);
        if value.is_empty() || value.starts_with('-') {
            continue;
        }
        ctx.check().ok()?;
        let candidate = if fs_path::is_abs(value) { value.to_owned() } else { fs_path::join(cwd, value) };
        if !fs_path::is_file(&candidate) {
            // An absent operand is bound too, so creating the file re-prompts.
            let state = if fs_path::exists(&candidate) { "non-file" } else { "absent" };
            bound.push(json!({"argument": argument, "sha256": state}));
            continue;
        }
        let size = std::fs::metadata(&candidate).ok()?.len();
        if size > MAX_BOUND_OPERAND_BYTES || bound.len() >= MAX_BOUND_OPERANDS {
            return None;
        }
        let digest = fs_path::sha256_hex(&std::fs::read(&candidate).ok()?);
        bound.push(json!({"argument": argument, "sha256": digest}));
    }
    Some(bound)
}
