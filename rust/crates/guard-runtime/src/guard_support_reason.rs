//! Hook reason and harness copy for runtime artifacts. Ports the former
//! `cli/commands_support_prompts.py` message builders; every string is pinned
//! by vectors recorded from that Python.

use serde_json::{Map, Value};

use crate::guard_support_text::{py_strip, str_field, terminal_punctuation};

const HARD_BLOCK_CLASS: &str = "guard_bypass_intent";
const CREDENTIAL_OUTPUT_SIGNAL: &str = "tool output contains credential-looking material";
const FLAGGED_ACTIONS: [&str; 4] = ["review", "require-reapproval", "sandbox-required", "block"];

pub(crate) struct Artifact<'a> {
    artifact_type: &'a str,
    metadata: &'a Map<String, Value>,
}

impl<'a> Artifact<'a> {
    pub(crate) fn from_value(value: &'a Value) -> Result<Self, String> {
        let object = value.as_object().ok_or("invalid_artifact")?;
        let metadata = object
            .get("metadata")
            .and_then(Value::as_object)
            .ok_or("invalid_artifact_metadata")?;
        Ok(Self {
            artifact_type: str_field(object, "artifact_type").unwrap_or(""),
            metadata,
        })
    }

    fn meta_str(&self, key: &str) -> Option<&'a str> {
        str_field(self.metadata, key)
    }

    fn requires_hard_block(&self) -> bool {
        match self.metadata.get("prompt_request_classes") {
            Some(Value::Array(items)) => items
                .iter()
                .any(|item| item.as_str() == Some(HARD_BLOCK_CLASS)),
            _ => self.meta_str("prompt_request_class") == Some(HARD_BLOCK_CLASS),
        }
    }

    fn has_secret_read_class(&self) -> bool {
        match self.metadata.get("prompt_request_classes") {
            Some(Value::Array(items)) => items
                .iter()
                .any(|item| item.as_str() == Some("secret_read")),
            _ => self.meta_str("prompt_request_class") == Some("secret_read"),
        }
    }
}

fn prompt_context(artifact: &Artifact) -> &'static str {
    if artifact.requires_hard_block() {
        "HOL Guard blocked this prompt because it asks to bypass or disable Guard."
    } else if artifact.has_secret_read_class() {
        "HOL Guard flagged this prompt because it asks for direct local secret access and is protecting your local secrets. If that is intentional, continue and Guard will ask again on the actual tool call."
    } else {
        "HOL Guard flagged this prompt as higher risk. Continue only if you expect the next tool call to need explicit approval."
    }
}

fn decision_message(response: &Map<String, Value>) -> Option<String> {
    let message = response
        .get("decision_v2_json")?
        .as_object()?
        .get("harness_message")?
        .as_str()?;
    let stripped = py_strip(message);
    (!stripped.is_empty()).then(|| stripped.to_owned())
}

fn has_data_flow_signal(response: &Map<String, Value>) -> bool {
    let Some(Value::Array(signals)) = response
        .get("decision_v2_json")
        .and_then(|v| v.get("signals"))
    else {
        return false;
    };
    signals.iter().filter_map(Value::as_object).any(|signal| {
        str_field(signal, "detector") == Some("data_flow.exfiltration")
            || str_field(signal, "signal_id").is_some_and(|id| id.starts_with("data-flow:"))
    })
}

fn use_decision_message(response: &Map<String, Value>, message: &str) -> bool {
    if has_data_flow_signal(response) {
        return true;
    }
    const GENERIC: [&str; 2] = [
        "HOL Guard blocked this action.",
        "HOL Guard wants this action reviewed and run in a sandboxed path.",
    ];
    const REAPPROVAL: [&str; 2] = [
        "HOL Guard needs a fresh approval because this action changed.",
        "HOL Guard needs a fresh approval before this action can run.",
    ];
    !GENERIC
        .iter()
        .chain(REAPPROVAL.iter())
        .any(|prefix| message.starts_with(prefix))
}

fn prompt_request_reason(artifact: &Artifact, response: &Map<String, Value>) -> String {
    if str_field(response, "harness") == Some("codex") && artifact.has_secret_read_class() {
        let credential_file = artifact
            .meta_str("prompt_summary")
            .is_some_and(|summary| summary.contains("credential-looking local file"));
        let target = if credential_file {
            "a credential-looking local file"
        } else {
            "a sensitive local file"
        };
        return format!("HOL Guard stopped this Codex prompt before Codex could open {target}. Codex does not expose native approval prompts for Read-tool file reads, so Guard blocks this request at prompt time.");
    }
    let action = str_field(response, "policy_action");
    if matches!(action, Some("block" | "sandbox-required")) && !artifact.requires_hard_block() {
        return "HOL Guard blocked this prompt because it requests guarded local secret access."
            .to_owned();
    }
    prompt_context(artifact).to_owned()
}

fn tool_path_reason(path_class: &str, tool_name: &str, response: &Map<String, Value>) -> String {
    let harness = str_field(response, "harness");
    if harness == Some("claude-code")
        && str_field(response, "policy_action") == Some("require-reapproval")
    {
        return format!("HOL Guard intercepted Claude's attempt to use {tool_name} for {path_class} to protect your local secrets. The approval flow came from HOL Guard, not from Claude alone. HOL Guard will ask you to choose Allow once, Allow during this session, or Keep blocked before Claude retries this action.");
    }
    let label = match harness {
        Some("claude-code") => "Claude",
        Some("codex") => "Codex",
        _ => "the harness",
    };
    format!("HOL Guard blocked {label}'s attempt to use {tool_name} for {path_class} to protect your local secrets. This request cannot continue in the current approval flow.")
}

fn credential_output_reason(artifact: &Artifact) -> String {
    if let Some(source) = artifact
        .meta_str("secret_source_family")
        .map(py_strip)
        .filter(|s| !s.is_empty())
    {
        return format!("HOL Guard blocked this tool output because it contains sensitive content from {source}. The command already ran; review the flagged output in the approval center before trusting it.");
    }
    if let Some(summary) = artifact.meta_str("runtime_request_summary") {
        if !py_strip(summary).is_empty()
            && !summary.starts_with("Requests a sensitive native tool action")
        {
            return py_strip(summary).to_owned();
        }
    }
    "HOL Guard blocked this tool output because it may contain sensitive content. The command already ran; review the flagged output in the approval center before trusting it.".to_owned()
}

fn risk_summary_reason(summary: &str, artifact: &Artifact) -> String {
    let mut trimmed = py_strip(summary).to_owned();
    if trimmed.chars().count() > 180 {
        let head: String = trimmed.chars().take(177).collect();
        trimmed = format!("{}...", head.trim_end());
    }
    if artifact.meta_str("action_class") == Some("credential exfiltration shell command")
        && !trimmed.to_lowercase().contains("credential-looking output")
    {
        trimmed = format!("{trimmed} Guard also detected credential-looking output.");
    }
    format!("HOL Guard flagged this request: {trimmed}")
}

pub(crate) fn native_reason(artifact: &Artifact, response: &Map<String, Value>) -> String {
    if let Some(guidance) = str_field(response, "blocked_request_guidance")
        .map(py_strip)
        .filter(|s| !s.is_empty())
    {
        return guidance.to_owned();
    }
    if let Some(message) = decision_message(response).filter(|m| use_decision_message(response, m))
    {
        return message;
    }
    if artifact.artifact_type == "prompt_request" {
        return prompt_request_reason(artifact, response);
    }
    if let (Some(path_class), Some(tool_name)) = (
        artifact.meta_str("path_class"),
        artifact.meta_str("tool_name"),
    ) {
        return tool_path_reason(path_class, tool_name, response);
    }
    let flagged =
        str_field(response, "policy_action").is_some_and(|a| FLAGGED_ACTIONS.contains(&a));
    let credential_signal = matches!(artifact.metadata.get("runtime_request_signals"),
        Some(Value::Array(items)) if items.iter().any(|item| item.as_str() == Some(CREDENTIAL_OUTPUT_SIGNAL)));
    if flagged && credential_signal {
        return credential_output_reason(artifact);
    }
    match str_field(response, "risk_summary").filter(|s| !py_strip(s).is_empty()) {
        Some(summary) => risk_summary_reason(summary, artifact),
        None => "HOL Guard flagged this request for review.".to_owned(),
    }
}

pub(crate) fn claude_additional_context(
    claude_harness: bool,
    event_name: &str,
    policy_action: &str,
    artifact: &Artifact,
    reason: &str,
) -> Option<String> {
    if !claude_harness
        || event_name != "UserPromptSubmit"
        || policy_action != "require-reapproval"
        || artifact.requires_hard_block()
    {
        return None;
    }
    let briefing = if artifact.has_secret_read_class() {
        "HOL Guard will intercept Claude's next attempt to access local secrets and open a branded approval question to protect you."
    } else {
        "HOL Guard will intercept Claude's next sensitive action and open a branded approval question."
    };
    Some(format!(
        "{} Do not ask for approval at the prompt stage. Attempt the intended sensitive tool once so HOL Guard can evaluate the exact tool, path, and arguments, then route that concrete action into a HOL Guard approval question with Allow once, Allow during this session, and Keep blocked. First tell the user exactly: '{briefing}' Attempt that sensitive tool at most once. If HOL Guard or Claude denies it, do not retry the same sensitive action automatically. Instead, tell the user approval is required in Claude to continue.",
        terminal_punctuation(reason)
    ))
}

pub(crate) fn claude_system_message(
    event_name: &str,
    policy_action: &str,
    artifact: &Artifact,
    reason: &str,
) -> Option<String> {
    let blocking = matches!(policy_action, "block" | "sandbox-required");
    match event_name {
        "UserPromptSubmit"
            if policy_action == "require-reapproval" && !artifact.requires_hard_block() =>
        {
            let subject = if artifact.has_secret_read_class() {
                "asks Claude to access local secrets"
            } else {
                "leads to a sensitive action"
            };
            Some(format!("HOL Guard intercepted this prompt because it {subject}. If Claude asks to continue, HOL Guard will route the decision through a branded approval prompt."))
        }
        "UserPromptSubmit" if blocking => Some(terminal_punctuation(reason)),
        "PreToolUse" if blocking || policy_action == "require-reapproval" => {
            Some(terminal_punctuation(reason))
        }
        _ => None,
    }
}

pub(crate) fn codex_block_message(policy_action: &str, reason: &str) -> Option<String> {
    (FLAGGED_ACTIONS.contains(&policy_action) && reason.to_lowercase().contains("open hol guard"))
        .then(|| format!("HOL Guard paused your Codex prompt. {reason}"))
}
