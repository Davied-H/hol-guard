//! `SecretsScan` — resident op owning the `hol-guard-secrets` command
//! surface: repository, history and staged secret scans, the pre-commit hook
//! install/uninstall and the public detector rule catalog.
//!
//! The detection, Git reads and hook edits live in `guard_scanner`; Python
//! only parses the command line and renders text. A malformed request or an
//! unusable target fails with a typed `error` result, and the caller fails
//! closed. Raw secret values never leave the scanner: the payload is the
//! scanner's public (value-free) result.

use guard_contracts::{
    SecretsScanBoundsV1, SecretsScanRequestV1, SecretsScanResultV1, SECRETS_SCAN_MAX_BYTES,
    SECRETS_SCAN_REQUEST_SCHEMA, SECRETS_SCAN_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use guard_scanner::precommit::{install_precommit_hook, uninstall_precommit_hook};
use guard_scanner::repository_scanner::{scan_repository_secrets, RepositoryScanOptions};
use guard_scanner::secret_detection::{detector_version, secret_rule_catalog};
use guard_scanner::staged_scanner::{scan_staged_secrets, StagedScanOptions};
use serde_json::{json, Value};
use std::path::Path;

use super::context_digest_json::write_canonical_json_with_limit;

const ERR_INVALID: &str = "native_secrets_scan_invalid";
const ERR_SCHEMA: &str = "native_secrets_scan_schema_mismatch";
const ERR_TOO_LARGE: &str = "native_secrets_scan_request_too_large";
const ERR_INTERNAL: &str = "native_secrets_scan_internal";
const REFUSED: &str = "secrets_scan_refused";

/// A user-facing refusal (`Error: ...` on the CLI) or a typed failure code.
enum Outcome {
    Payload(Value),
    Refused(String),
    Failed(&'static str),
}

/// Digest of the canonical request, matching Python `_canonical_request_sha256`.
fn request_digest(request: &SecretsScanRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| ERR_INVALID)?;
    let mut canonical = Vec::with_capacity(512);
    if write_canonical_json_with_limit(&material, &mut canonical, SECRETS_SCAN_MAX_BYTES).is_err() {
        return Err(if canonical.len() > SECRETS_SCAN_MAX_BYTES {
            ERR_TOO_LARGE
        } else {
            ERR_INVALID
        });
    }
    if canonical.len() > SECRETS_SCAN_MAX_BYTES {
        return Err(ERR_TOO_LARGE);
    }
    Ok(digest_bytes(&canonical))
}

fn bound(value: u64) -> Result<usize, &'static str> {
    usize::try_from(value).map_err(|_| ERR_INVALID)
}

/// Pretty JSON text of the catalog, byte-identical to the literal the Python
/// CLI used to print: two-space indent, sorted keys, trailing newline.
fn rules_json() -> Result<String, &'static str> {
    let catalog = secret_rule_catalog();
    let payload = json!({
        "detector_version": detector_version(),
        "rules": catalog,
        "schema": "guard-secret-rules.v1",
    });
    let mut text = serde_json::to_string_pretty(&payload).map_err(|_| ERR_INTERNAL)?;
    text.push('\n');
    Ok(text)
}

fn rules_text() -> String {
    let mut text = format!("HOL Guard Secrets detector {}\n", detector_version());
    for rule in secret_rule_catalog() {
        if rule.validation == "none" {
            text.push_str(&format!("- {} ({})\n", rule.family, rule.severity));
        } else {
            text.push_str(&format!(
                "- {} ({}, validates via {})\n",
                rule.family, rule.severity, rule.validation
            ));
        }
    }
    text.push('\n');
    text
}

fn scan(request: &SecretsScanRequestV1, bounds: &SecretsScanBoundsV1) -> Outcome {
    let (max_files, max_file_bytes, max_total_bytes, max_findings) = match (
        bound(bounds.max_files),
        bound(bounds.max_file_bytes),
        bound(bounds.max_total_bytes),
        bound(bounds.max_findings),
    ) {
        (Ok(files), Ok(file_bytes), Ok(total), Ok(findings)) => {
            (files, file_bytes, total, findings)
        }
        _ => return Outcome::Failed(ERR_INVALID),
    };
    let target = Path::new(&request.target);
    let result = if request.action == "staged" {
        if bounds.include_history {
            return Outcome::Failed(ERR_INVALID);
        }
        scan_staged_secrets(
            target,
            &StagedScanOptions {
                max_files,
                max_file_bytes,
                max_total_bytes,
                max_findings,
            },
        )
    } else {
        let Ok(max_commits) = bound(bounds.max_commits) else {
            return Outcome::Failed(ERR_INVALID);
        };
        match scan_repository_secrets(
            target,
            &RepositoryScanOptions {
                include_history: bounds.include_history,
                max_commits,
                max_files,
                max_file_bytes,
                max_total_bytes,
                max_findings,
            },
        ) {
            Ok(result) => result,
            Err(error) => return Outcome::Refused(error.to_string()),
        }
    };
    match result.to_public_dict() {
        Ok(public) => serde_json::to_value(public)
            .map(Outcome::Payload)
            .unwrap_or(Outcome::Failed(ERR_INTERNAL)),
        Err(_) => Outcome::Failed(ERR_INTERNAL),
    }
}

fn hook(request: &SecretsScanRequestV1, install: bool) -> Outcome {
    let target = Path::new(&request.target);
    let result = if install {
        install_precommit_hook(target)
    } else {
        uninstall_precommit_hook(target)
    };
    match result {
        Ok(result) => Outcome::Payload(result.to_public_dict()),
        Err(error) => Outcome::Refused(error.to_string()),
    }
}

fn run(request: &SecretsScanRequestV1) -> Outcome {
    if request.schema != SECRETS_SCAN_REQUEST_SCHEMA {
        return Outcome::Failed(ERR_SCHEMA);
    }
    if request.guard_home.is_empty() {
        return Outcome::Failed(ERR_INVALID);
    }
    let has_target = Path::new(&request.target).is_absolute();
    match (request.action.as_str(), request.bounds.as_ref()) {
        ("scan" | "staged", Some(bounds)) if has_target => scan(request, bounds),
        ("install_hook", None) if has_target => hook(request, true),
        ("uninstall_hook", None) if has_target => hook(request, false),
        ("rules", None) if request.target.is_empty() => match rules_json() {
            Ok(json_text) => Outcome::Payload(json!({ "json": json_text, "text": rules_text() })),
            Err(code) => Outcome::Failed(code),
        },
        _ => Outcome::Failed(ERR_INVALID),
    }
}

fn result(
    request: &SecretsScanRequestV1,
    request_sha256: String,
    code: &str,
    payload: Option<Value>,
    message: Option<String>,
) -> SecretsScanResultV1 {
    SecretsScanResultV1 {
        schema: SECRETS_SCAN_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: if code == "ok" { "ok" } else { "error" }.to_owned(),
        code: code.to_owned(),
        payload,
        message,
    }
}

pub(crate) fn evaluate_secrets_scan(request: &SecretsScanRequestV1) -> Result<Vec<u8>, String> {
    // Digest/size failures are this op's own typed error result, not a
    // transport error (which the resident would redact to invalid-json).
    let request_sha256 = match request_digest(request) {
        Ok(digest) => digest,
        Err(code) => {
            return crate::encode_response(&result(request, String::new(), code, None, None));
        }
    };
    let answer = match run(request) {
        Outcome::Payload(payload) => result(request, request_sha256, "ok", Some(payload), None),
        Outcome::Refused(message) => result(request, request_sha256, REFUSED, None, Some(message)),
        Outcome::Failed(code) => result(request, request_sha256, code, None, None),
    };
    crate::encode_response(&answer)
}

#[cfg(test)]
#[path = "secrets_scan_op_tests.rs"]
mod tests;
