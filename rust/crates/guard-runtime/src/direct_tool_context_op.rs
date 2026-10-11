//! Resident-owned local tool recognition; one admitted request builds the context.
use std::collections::BTreeMap;
use std::path::Path;

use guard_command::direct_vitest::{self, DirectToolAuthority};
use guard_command::shims::{package_shim_status, HarnessContext};
use guard_contracts::{
    DirectToolV1, RequestContextBuildV1, RequestContextDirectFactsV1, RequestContextDirectToolV1,
    RequestContextRequestV1, RequestContextTrustedToolV1, MAX_REQUEST_CONTEXT_PATH_BYTES,
    MAX_REQUEST_CONTEXT_SCRIPT_BYTES,
};
use serde_json::{json, Value};

use crate::git_execution_safety_binary as binary;
use crate::request_context_op::Budget;

struct Authority<'a> {
    facts: &'a RequestContextDirectFactsV1,
    budget: &'a Budget,
}

impl DirectToolAuthority for Authority<'_> {
    fn environment(&self) -> &BTreeMap<String, String> {
        &self.facts.environment
    }
    fn temp_directory(&self) -> &Path {
        Path::new(&self.facts.temp_dir)
    }
    fn within_budget(&self) -> bool {
        self.budget.check().is_ok()
    }
    fn deadline(&self) -> Option<std::time::Instant> {
        Some(self.budget.deadline())
    }
    fn executable_file(&self, path: &Path) -> bool {
        binary::executable_file(path)
    }
    fn trusted_path(&self, path: &Path, cwd: &Path) -> bool {
        self.within_budget()
            && binary::binary_path_is_trusted(
                path,
                cwd,
                Path::new(&self.facts.caller_home),
                &self.facts.groups,
            )
    }
    fn trusted_command(&self, command: &str, cwd: &Path, home: &Path) -> bool {
        if !self.within_budget() {
            return false;
        }
        let Some(found) = binary::which_for_cwd(
            command,
            cwd,
            &self.facts.environment,
            Path::new(&self.facts.caller_home),
        ) else {
            return false;
        };
        let Ok(resolved) = found.canonicalize() else {
            return false;
        };
        if self.trusted_path(&resolved, cwd) {
            return true;
        }
        if command != "bun" {
            return false;
        }
        let status = package_shim_status(
            &HarnessContext {
                guard_home: home.join(".hol-guard"),
                home_dir: Some(home.to_path_buf()),
                workspace_dir: Some(cwd.to_path_buf()),
                home_override_explicit: false,
            },
            Some(
                self.facts
                    .environment
                    .get("PATH")
                    .map_or("", String::as_str),
            ),
        );
        self.within_budget()
            && status
                .get("manager_details")
                .and_then(Value::as_array)
                .is_some_and(|details| {
                    details.iter().any(|d| {
                        d.get("manager").and_then(Value::as_str) == Some("bun")
                            && d.get("integrity").and_then(Value::as_str) == Some("ok")
                            && d.get("path_active").and_then(Value::as_bool) == Some(true)
                            && d.get("shim_path").and_then(Value::as_str)
                                == Some(resolved.to_string_lossy().as_ref())
                    })
                })
    }
}

fn admit(facts: &RequestContextDirectFactsV1, budget: &Budget) -> Result<(), &'static str> {
    budget.check()?;
    for value in [
        &facts.cwd,
        &facts.home_dir,
        &facts.caller_home,
        &facts.temp_dir,
    ] {
        if value.is_empty()
            || value.len() > MAX_REQUEST_CONTEXT_PATH_BYTES
            || value.contains('\0')
            || !Path::new(value).is_absolute()
        {
            return Err("native_request_context_direct_path_invalid");
        }
    }
    if facts.groups.len() > 1024 || facts.environment.len() > 512 {
        return Err("native_request_context_direct_facts_too_large");
    }
    let mut bytes = 0usize;
    for (key, value) in &facts.environment {
        bytes = bytes.saturating_add(key.len()).saturating_add(value.len());
        if key.is_empty()
            || key.contains(['\0', '='])
            || value.contains('\0')
            || key.len() > 256
            || value.len() > 64 * 1024
            || bytes > 128 * 1024
        {
            return Err("native_request_context_direct_environment_invalid");
        }
    }
    Ok(())
}

pub(crate) fn direct(
    request: &RequestContextRequestV1,
    body: &RequestContextDirectToolV1,
    budget: &Budget,
) -> Result<Value, &'static str> {
    admit(&body.facts, budget)?;
    if body.script.len() > MAX_REQUEST_CONTEXT_SCRIPT_BYTES || body.script.contains('\0') {
        return Err("native_request_context_script_too_large");
    }
    let authority = Authority {
        facts: &body.facts,
        budget,
    };
    let cwd = Some(Path::new(&body.facts.cwd));
    let home = Path::new(&body.facts.home_dir);
    let context = match body.tool {
        DirectToolV1::Vitest => direct_vitest::direct_local_vitest_execution_context(
            &body.script,
            cwd,
            home,
            &authority,
        ),
        DirectToolV1::Typescript => direct_vitest::direct_local_typescript_execution_context(
            &body.script,
            cwd,
            home,
            &authority,
        ),
    };
    budget.check()?;
    let context = match context {
        None => Value::Null,
        Some(context) => {
            let shell = crate::request_context_shell::context_report(&context, budget)?;
            let build = RequestContextBuildV1 {
                cwd: Some(body.facts.cwd.clone()),
                home_dir: Some(body.facts.home_dir.clone()),
                workspace: context
                    .workspace_root
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned()),
                script: Some(body.script.clone()),
                ..Default::default()
            };
            crate::request_context_op::build_with_shell_report(request, &build, shell, budget)?
        }
    };
    Ok(json!({"kind": "direct_tool", "accepted": !context.is_null(), "context": context}))
}

pub(crate) fn trusted(
    body: &RequestContextTrustedToolV1,
    budget: &Budget,
) -> Result<Value, &'static str> {
    admit(&body.facts, budget)?;
    if body.command.is_empty()
        || body.command.len() > MAX_REQUEST_CONTEXT_PATH_BYTES
        || body.command.contains('\0')
    {
        return Err("native_request_context_direct_command_invalid");
    }
    let authority = Authority {
        facts: &body.facts,
        budget,
    };
    let trusted = authority.trusted_command(
        &body.command,
        Path::new(&body.facts.cwd),
        Path::new(&body.facts.home_dir),
    );
    budget.check()?;
    Ok(json!({"kind": "trusted_tool", "trusted": trusted}))
}
