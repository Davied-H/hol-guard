//! `ProtectRequest` — resident op for install-time protect.
//!
//! Parses the wrapped command through
//! `guard_command::protect_request::parse_protect_command`, reads the store's
//! `publisher_cache` read-only, and evaluates the local verdict with
//! `evaluate_protect_request`. The store is never written.

use crate::local_store_read::{open_read_only, require_store_path, table_exists};
use crate::package_authority_op::request_digest_with_limit;
use guard_command::protect_request::{
    evaluate_protect_request, parse_protect_command, ProtectParseError, ProtectRequest,
    ProtectTarget,
};
use guard_contracts::{
    ProtectCachedAdvisoryV1, ProtectParsedRequestV1, ProtectRequestRequestV1,
    ProtectRequestResultV1, ProtectTargetV1, ProtectVerdictV1, PROTECT_REQUEST_MAX_BYTES,
    PROTECT_REQUEST_REQUEST_SCHEMA, PROTECT_REQUEST_RESULT_SCHEMA,
};
use serde_json::{Map, Value};

const STORE_UNAVAILABLE: &str = "native_protect_request_store_unavailable";
const CACHE_INVALID: &str = "native_protect_request_cache_invalid";

struct Failure {
    code: &'static str,
    detail: Option<String>,
}

impl From<&'static str> for Failure {
    fn from(code: &'static str) -> Self {
        Self { code, detail: None }
    }
}

pub(crate) fn evaluate_protect_request_op(
    request: &ProtectRequestRequestV1,
) -> Result<Vec<u8>, String> {
    // Bound the complete canonical request before any parsing or store work; an
    // oversized request has no digest to bind.
    let request_sha256 = request_digest_with_limit(request, PROTECT_REQUEST_MAX_BYTES)
        .map_err(|_| "native_protect_request_too_large".to_owned())?;
    let result = match evaluate(request) {
        Ok((parsed, verdict)) => ProtectRequestResultV1 {
            schema: PROTECT_REQUEST_RESULT_SCHEMA.to_owned(),
            request_id: request.request_id.clone(),
            request_sha256,
            status: "ok".to_owned(),
            code: "ok".to_owned(),
            detail: None,
            request: Some(parsed),
            verdict: Some(verdict),
        },
        Err(failure) => ProtectRequestResultV1 {
            schema: PROTECT_REQUEST_RESULT_SCHEMA.to_owned(),
            request_id: request.request_id.clone(),
            request_sha256,
            status: "error".to_owned(),
            code: failure.code.to_owned(),
            detail: failure.detail,
            request: None,
            verdict: None,
        },
    };
    crate::encode_response(&result)
}

fn evaluate(
    request: &ProtectRequestRequestV1,
) -> Result<(ProtectParsedRequestV1, ProtectVerdictV1), Failure> {
    if request.schema != PROTECT_REQUEST_REQUEST_SCHEMA {
        return Err("native_protect_request_schema_mismatch".into());
    }
    if request.command.is_empty() {
        return Err("native_protect_request_command_empty".into());
    }
    let parsed = parse_protect_command(&request.command).map_err(|error| match error {
        ProtectParseError::InvalidUrl(message) => Failure {
            code: "native_protect_request_invalid_url",
            detail: Some(message),
        },
        ProtectParseError::UnsupportedPayload => {
            Failure::from("native_protect_request_unsupported_payload")
        }
    })?;
    let rows = match &request.store_path {
        Some(store_path) => cached_advisories(store_path, &request.guard_home)?,
        None => Vec::new(),
    };
    let advisories: Vec<Value> = rows.iter().map(|(_, advisory)| advisory.clone()).collect();
    let verdict = evaluate_protect_request(&parsed, &advisories);
    Ok((
        parsed_request(&parsed),
        ProtectVerdictV1 {
            action: verdict.action.to_owned(),
            reason: verdict.reason,
            risk_signals: verdict.risk_signals,
            matched_advisories: verdict
                .matched
                .iter()
                .map(|index| rows[*index].0.clone())
                .collect(),
        },
    ))
}

/// Every dict-shaped `publisher_cache` row, newest first, as the raw row plus
/// the `{"cache_key", "updated_at", **payload}` advisory the matcher reads.
fn cached_advisories(
    store_path: &str,
    guard_home: &str,
) -> Result<Vec<(ProtectCachedAdvisoryV1, Value)>, Failure> {
    let path = require_store_path(store_path, guard_home)
        .map_err(|_| Failure::from("native_protect_request_store_path_invalid"))?;
    let Some(connection) = open_read_only(&path).map_err(|_| Failure::from(STORE_UNAVAILABLE))?
    else {
        return Ok(Vec::new());
    };
    if !table_exists(&connection, "publisher_cache").map_err(|_| STORE_UNAVAILABLE)? {
        return Ok(Vec::new());
    }
    let mut statement = connection
        .prepare(
            "SELECT publisher_key, payload_json, updated_at FROM publisher_cache \
             ORDER BY updated_at DESC",
        )
        .map_err(|_| STORE_UNAVAILABLE)?;
    let mut rows = statement.query([]).map_err(|_| STORE_UNAVAILABLE)?;
    let mut advisories = Vec::new();
    while let Some(row) = rows.next().map_err(|_| STORE_UNAVAILABLE)? {
        let text = |index: usize| -> Result<String, Failure> {
            match row.get_ref(index).map_err(|_| CACHE_INVALID)? {
                rusqlite::types::ValueRef::Text(raw) => std::str::from_utf8(raw)
                    .map(str::to_owned)
                    .map_err(|_| CACHE_INVALID.into()),
                _ => Err(CACHE_INVALID.into()),
            }
        };
        let raw = ProtectCachedAdvisoryV1 {
            cache_key: text(0)?,
            payload_json: text(1)?,
            updated_at: text(2)?,
        };
        let Value::Object(payload) =
            serde_json::from_str::<Value>(&raw.payload_json).map_err(|_| CACHE_INVALID)?
        else {
            continue;
        };
        let mut advisory = Map::new();
        advisory.insert("cache_key".to_owned(), Value::String(raw.cache_key.clone()));
        advisory.insert(
            "updated_at".to_owned(),
            Value::String(raw.updated_at.clone()),
        );
        advisory.extend(payload);
        advisories.push((raw, Value::Object(advisory)));
    }
    Ok(advisories)
}

fn parsed_request(request: &ProtectRequest) -> ProtectParsedRequestV1 {
    ProtectParsedRequestV1 {
        command: request.command.clone(),
        install_kind: request.install_kind.clone(),
        executor: request.executor.clone(),
        package_manager: request.package_manager.clone(),
        harness: request.harness.clone(),
        targets: request.targets.iter().map(target).collect(),
    }
}

fn target(target: &ProtectTarget) -> ProtectTargetV1 {
    ProtectTargetV1 {
        artifact_id: target.artifact_id.clone(),
        artifact_name: target.artifact_name.clone(),
        artifact_type: target.artifact_type.clone(),
        ecosystem: target.ecosystem.clone(),
        package_name: target.package_name.clone(),
        package_url: target.package_url.clone(),
        raw_spec: target.raw_spec.clone(),
        version: target.version.clone(),
        source_url: target.source_url.clone(),
        harness: target.harness.clone(),
    }
}

#[cfg(test)]
#[path = "protect_request_op_tests.rs"]
mod tests;
