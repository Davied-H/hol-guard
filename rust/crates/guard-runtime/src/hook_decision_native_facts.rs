//! Verdicts the resident computes itself from the raw tool call.
//!
//! The transport forwards the payload's tool call and observed caller facts in
//! `native_request`; nothing here asks Python. A missing or oversized request
//! is "not benign", so the configured default is never relaxed on bad input.

use std::path::Path;

use guard_command::benign_request_api::is_benign_native_file_read;
use guard_command::Ctx;
use guard_contracts::{CodexToolOutputFactsV1, HookCompositionInputsV1};

use crate::codex_tool_output_op::ResidentInspectionHost;

const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_ENVIRONMENT: usize = 128;
const MAX_GROUPS: usize = 256;

fn path_is_bounded(value: &str) -> bool {
    value.len() <= MAX_TEXT_BYTES && !value.contains('\0')
}

fn host_is_bounded(host: &CodexToolOutputFactsV1) -> bool {
    path_is_bounded(&host.process_cwd)
        && path_is_bounded(&host.home)
        && host.account_home.as_deref().is_none_or(path_is_bounded)
        && host.git_executable.as_deref().is_none_or(path_is_bounded)
        && host.groups.len() <= MAX_GROUPS
        && host.environment.len() <= MAX_ENVIRONMENT
        && host
            .environment
            .iter()
            .all(|(key, value)| key.len() <= 256 && path_is_bounded(value))
}

/// `is_explicitly_benign_native_file_read_request` for the hook's tool call.
pub(crate) fn benign_native_file_read(inputs: &HookCompositionInputsV1) -> bool {
    let Some(request) = &inputs.native_request else {
        return false;
    };
    let bounded_path = |value: &Option<String>| value.as_deref().is_none_or(path_is_bounded);
    if !host_is_bounded(&request.host)
        || !bounded_path(&request.cwd)
        || !bounded_path(&request.home_dir)
    {
        return false;
    }
    let host = ResidentInspectionHost {
        facts: &request.host,
    };
    let ctx = Ctx::new(&host, &request.host.process_cwd, &request.host.home);
    is_benign_native_file_read(
        &request.tool_name,
        &request.tool_input,
        request.cwd.as_deref().map(Path::new),
        request.home_dir.as_deref().map(Path::new),
        &ctx,
    )
}
