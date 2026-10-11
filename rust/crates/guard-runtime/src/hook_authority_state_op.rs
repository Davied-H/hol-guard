//! `HookAuthorityState` - resident op that owns the signed Claude and Cursor
//! hook authority state persisted in `sync_state`.
//!
//! Replaces the Python helpers that signed, stored, verified, expired and
//! deleted these rows. Every row is bound to its own state key and to a
//! purpose-derived key: a row that is unsigned, signed for another purpose or
//! key, copied to another key, bound to another session, conversation, artifact
//! or command, or older than the 30 minute window is never returned. It is
//! deleted instead, and each integrity failure leaves a
//! `rule.ignored.local_integrity` audit row. The key material and the clock are
//! shipped by the transport; the Python-owned command fingerprints that name
//! the Cursor state keys are opaque here.

use std::time::Duration;

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::{
    utc_timestamp_micros, HookAuthorityStateRequestV1, HookAuthorityStateResultV1,
    HOOK_AUTHORITY_STATE_MAX_BYTES, HOOK_AUTHORITY_STATE_REQUEST_SCHEMA,
    HOOK_AUTHORITY_STATE_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use guard_policy_snapshot::local_authority_integrity::{
    sign_local_authority_payload, verify_local_authority_payload,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::{json, Map, Value};

use crate::guard_store_json::{dumps_default, py_strip};
use crate::package_authority_op::request_digest_with_limit;

/// Notices, pending states, indexes and allowances live for 30 minutes.
const MAX_AGE_SECONDS: i64 = 30 * 60;

type Object = Map<String, Value>;

/// One signed state family: its integrity purpose and its audit identity.
struct Kind {
    purpose: &'static str,
    harness: &'static str,
    source: &'static str,
}

const CLAUDE_NOTICE: Kind = Kind {
    purpose: "claude-permission-notice",
    harness: "claude-code",
    source: "claude-permission-notice",
};
const CLAUDE_PENDING: Kind = Kind {
    purpose: "claude-pending-permission",
    harness: "claude-code",
    source: "claude-pending-permission",
};
const CLAUDE_INDEX: Kind = Kind {
    purpose: "claude-pending-permission-index",
    harness: "claude-code",
    source: "claude-pending-permission-index",
};
const CURSOR_PENDING: Kind = Kind {
    purpose: "cursor-pending-shell",
    harness: "cursor",
    source: "cursor-pending-shell",
};
const CURSOR_INDEX: Kind = Kind {
    purpose: "cursor-pending-shell-index",
    harness: "cursor",
    source: "cursor-pending-shell-index",
};
const CURSOR_ALLOW: Kind = Kind {
    purpose: "cursor-native-shell-allow",
    harness: "cursor",
    source: "cursor-native-session",
};

/// A per-owner index of pending state keys.
struct Family {
    index_prefix: &'static str,
    item_prefix: &'static str,
    owner_field: &'static str,
    kind: &'static Kind,
}

const CLAUDE_FAMILY: Family = Family {
    index_prefix: "claude_pending_permissions:",
    item_prefix: "claude_pending_permission:",
    owner_field: "session_id",
    kind: &CLAUDE_INDEX,
};
const CURSOR_FAMILY: Family = Family {
    index_prefix: "cursor_pending_shells:",
    item_prefix: "cursor_pending_shell:",
    owner_field: "conversation_id",
    kind: &CURSOR_INDEX,
};

const ERROR_INVALID: &str = "native_hook_authority_state_invalid";
const ERROR_STORE: &str = "native_hook_authority_state_store_unavailable";

pub(crate) fn evaluate_hook_authority_state_request(
    request: &HookAuthorityStateRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, HOOK_AUTHORITY_STATE_MAX_BYTES)
        .map_err(|_| "native_hook_authority_state_too_large".to_owned())?;
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok", "ok".to_owned(), Some(payload)),
        Err(code) => ("error", code.to_owned(), None),
    };
    crate::encode_response(&HookAuthorityStateResultV1 {
        schema: HOOK_AUTHORITY_STATE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code,
        payload,
    })
}

pub(crate) fn evaluate(request: &HookAuthorityStateRequestV1) -> Result<Value, &'static str> {
    if request.schema != HOOK_AUTHORITY_STATE_REQUEST_SCHEMA {
        return Err("native_hook_authority_state_schema_mismatch");
    }
    if request.op == "state_is_fresh" {
        let max_age = request.max_age_seconds.ok_or(ERROR_INVALID)?;
        return Ok(
            json!({ "fresh": is_fresh(request.saved_at.as_deref(), &request.now, max_age) }),
        );
    }
    let connection =
        Connection::open_with_flags(&request.store_path, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(|_| ERROR_STORE)?;
    connection
        .busy_timeout(Duration::from_millis(5000))
        .map_err(|_| ERROR_STORE)?;
    let env = Env {
        connection: &connection,
        key: request
            .integrity_key_b64
            .as_deref()
            .and_then(|encoded| Base64UrlUnpadded::decode_vec(encoded).ok()),
        key_id: request.integrity_key_id.as_deref(),
        now: &request.now,
    };
    env.dispatch(request)
}

/// `_hook_authority_state_is_fresh`: `saved_at` is not in the future and no
/// older than `max_age_seconds`. An unreadable timestamp is never fresh.
fn is_fresh(saved_at: Option<&str>, now: &str, max_age_seconds: i64) -> bool {
    let Some(saved_at) = saved_at.map(py_strip).filter(|text| !text.is_empty()) else {
        return false;
    };
    let (Some(saved), Some(current)) = (utc_timestamp_micros(saved_at), utc_timestamp_micros(now))
    else {
        return false;
    };
    let age = i128::from(current) - i128::from(saved);
    (0..=i128::from(max_age_seconds) * 1_000_000).contains(&age)
}

/// What `sync_state` holds under a key, as the Python store read it.
enum Stored {
    Absent,
    Unreadable,
    InvalidJson,
    List,
    Object(Object),
}

fn fingerprint(state_key: &str) -> String {
    digest_bytes(state_key.as_bytes())[..16].to_owned()
}

fn opt_str(object: &Object, name: &str) -> Option<String> {
    let text = py_strip(object.get(name)?.as_str()?);
    (!text.is_empty()).then(|| text.to_owned())
}

fn exact_str<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    object.get(name)?.as_str()
}

fn claude_pending_key(session_id: &str, artifact_id: &str) -> String {
    let fingerprint = &digest_bytes(artifact_id.as_bytes())[..24];
    format!("claude_pending_permission:{session_id}:{fingerprint}")
}

fn notice_key(session_id: &str, tool_name: Option<&str>) -> String {
    match tool_name {
        Some(tool) => format!("claude_permission_notice:{session_id}:{tool}"),
        None => format!("claude_permission_notice:{session_id}"),
    }
}

fn dedupe(keys: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    keys.into_iter()
        .filter(|key| seen.insert(key.clone()))
        .collect()
}

struct Env<'a> {
    connection: &'a Connection,
    key: Option<Vec<u8>>,
    key_id: Option<&'a str>,
    now: &'a str,
}

fn required<'a>(value: &'a Option<String>) -> Result<&'a str, &'static str> {
    value.as_deref().ok_or(ERROR_INVALID)
}

impl Env<'_> {
    fn dispatch(&self, request: &HookAuthorityStateRequestV1) -> Result<Value, &'static str> {
        match request.op.as_str() {
            "claude_record_notice" => {
                let payload = request.payload.as_ref().ok_or(ERROR_INVALID)?;
                self.claude_record_notice(
                    required(&request.session_id)?,
                    request.tool_name.as_deref(),
                    payload,
                );
                Ok(json!({}))
            }
            "claude_load_notice" => Ok(json!({
                "notice": self.claude_load_notice(
                    required(&request.session_id)?,
                    request.tool_name.as_deref(),
                )
            })),
            "claude_mark_prompt_seen" => {
                self.claude_mark_prompt_seen(
                    required(&request.session_id)?,
                    required(&request.artifact_id)?,
                    required(&request.artifact_hash)?,
                    required(&request.command)?,
                );
                Ok(json!({}))
            }
            "claude_load_single_pending" => Ok(
                match self.claude_load_single_pending(required(&request.session_id)?) {
                    Some((key, pending)) => json!({ "pending_key": key, "pending": pending }),
                    None => json!({ "pending_key": null, "pending": null }),
                },
            ),
            "claude_load_pending" => Ok(json!({
                "pending": self.claude_load_pending(
                    required(&request.session_id)?,
                    required(&request.pending_key)?,
                    request.expected_artifact_id.as_deref(),
                    request.expected_artifact_hash.as_deref(),
                    request.expected_command.as_deref(),
                )
            })),
            "claude_remove_pending" => {
                self.claude_remove_pending(
                    required(&request.session_id)?,
                    required(&request.pending_key)?,
                );
                Ok(json!({}))
            }
            "claude_load_index" => Ok(json!({
                "pending_keys": self.load_index(&CLAUDE_FAMILY, required(&request.session_id)?)
            })),
            "cursor_load_index" => Ok(json!({
                "pending_keys": self.load_index(&CURSOR_FAMILY, required(&request.conversation_id)?)
            })),
            "cursor_store_index" => {
                let keys = request.pending_keys.as_ref().ok_or(ERROR_INVALID)?;
                Ok(json!({
                    "stored": self.store_index(&CURSOR_FAMILY, required(&request.conversation_id)?, keys)
                }))
            }
            "cursor_append_key" => Ok(json!({
                "stored": self.append_key(
                    &CURSOR_FAMILY,
                    required(&request.conversation_id)?,
                    required(&request.pending_key)?,
                )
            })),
            "cursor_store_pending_state" => {
                let payload = request.payload.as_ref().ok_or(ERROR_INVALID)?;
                Ok(json!({
                    "stored": self.store_signed(
                        required(&request.state_key)?,
                        payload,
                        &CURSOR_PENDING,
                    )
                }))
            }
            "cursor_load_pending_state" => Ok(json!({
                "pending": self.cursor_load_pending_state(
                    required(&request.conversation_id)?,
                    required(&request.command)?,
                    required(&request.state_key)?,
                    required(&request.expected_key)?,
                )
            })),
            "cursor_record_allow" => Ok(json!({
                "stored": self.cursor_record_allow(request)?
            })),
            "cursor_load_allowance" => Ok(json!({
                "allowance": self.cursor_load_allowance(
                    required(&request.conversation_id)?,
                    required(&request.command)?,
                    required(&request.state_key)?,
                )
            })),
            _ => Err(ERROR_INVALID),
        }
    }

    // ---- persistence ------------------------------------------------------

    fn read(&self, state_key: &str) -> Stored {
        let row = self
            .connection
            .query_row(
                "select payload_json from sync_state where state_key = ?1",
                params![state_key],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional();
        let text = match row {
            Err(_) => return Stored::Unreadable,
            Ok(None) => return Stored::Absent,
            Ok(Some(None)) => return Stored::InvalidJson,
            Ok(Some(Some(text))) => text,
        };
        match serde_json::from_str::<Value>(&text) {
            Err(_) => Stored::InvalidJson,
            Ok(Value::Object(object)) => Stored::Object(object),
            Ok(Value::Array(_)) => Stored::List,
            Ok(_) => Stored::Absent,
        }
    }

    fn delete(&self, state_key: &str) {
        let _ = self.connection.execute(
            "delete from sync_state where state_key = ?1",
            params![state_key],
        );
    }

    fn add_event(&self, name: &str, payload: &Value) {
        let Some(text) = dumps_default(payload) else {
            return;
        };
        let _ = self.connection.execute(
            "insert into guard_events (event_name, payload_json, occurred_at) values (?1, ?2, ?3)",
            params![name, text, self.now],
        );
    }

    fn record_failure(
        &self,
        kind: &Kind,
        state_key: &str,
        artifact_id: Value,
        status: &str,
        message: Option<&str>,
    ) {
        self.add_event(
            "rule.ignored.local_integrity",
            &json!({
                "decision_id": null,
                "harness": kind.harness,
                "artifact_id": artifact_id,
                "scope": "session",
                "source": kind.source,
                "integrity_status": status,
                "message": message,
                "state_key_fingerprint": fingerprint(state_key),
            }),
        );
    }

    /// Sign `payload` for `kind` and persist it under `state_key`. `false` when
    /// there is no key or the store refuses the write.
    fn store_signed(&self, state_key: &str, payload: &Value, kind: &Kind) -> bool {
        let (Some(key), Some(key_id)) = (self.key.as_deref(), self.key_id) else {
            return false;
        };
        let Value::Object(source) = payload else {
            return false;
        };
        let mut signed: Object = source
            .iter()
            .filter(|(name, _)| name.as_str() != "integrity")
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        signed.insert("state_key".to_owned(), Value::String(state_key.to_owned()));
        let Ok(fields) = sign_local_authority_payload(
            &Value::Object(signed.clone()),
            key,
            key_id,
            kind.purpose,
            self.now,
        ) else {
            return false;
        };
        signed.insert(
            "integrity".to_owned(),
            json!({
                "integrity_version": fields.integrity_version,
                "payload_hash": fields.payload_hash,
                "payload_mac": fields.payload_mac,
                "integrity_key_id": fields.integrity_key_id,
                "signed_at": fields.signed_at,
            }),
        );
        let Some(text) = dumps_default(&Value::Object(signed)) else {
            return false;
        };
        self.connection
            .execute(
                "insert into sync_state (state_key, payload_json, updated_at) values (?1, ?2, ?3) \
                 on conflict(state_key) do update set \
                 payload_json = excluded.payload_json, updated_at = excluded.updated_at",
                params![state_key, text, self.now],
            )
            .is_ok()
    }

    fn verify(
        &self,
        persisted: &Object,
        kind: &Kind,
        use_key: bool,
    ) -> (&'static str, Option<&'static str>) {
        let integrity = match persisted.get("integrity") {
            Some(value @ Value::Object(_)) => value.clone(),
            _ => json!({}),
        };
        let signed: Object = persisted
            .iter()
            .filter(|(name, _)| name.as_str() != "integrity")
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let (key, key_id) = if use_key {
            (self.key.as_deref(), self.key_id)
        } else {
            (None, None)
        };
        let result = verify_local_authority_payload(
            &Value::Object(signed),
            &integrity,
            key,
            key_id,
            kind.purpose,
        );
        (result.status, result.message)
    }

    /// The signed row under `state_key` when it is authentic, bound to its key
    /// and fresh. Anything else is recorded and deleted.
    fn load_verified(&self, state_key: &str, kind: &Kind) -> Option<Object> {
        let persisted = match self.read(state_key) {
            Stored::Unreadable | Stored::Absent => return None,
            Stored::InvalidJson => {
                self.record_failure(
                    kind,
                    state_key,
                    Value::Null,
                    "tampered",
                    Some("local_authority_integrity_payload_invalid_json"),
                );
                self.delete(state_key);
                return None;
            }
            Stored::List => {
                self.record_failure(
                    kind,
                    state_key,
                    Value::Null,
                    "missing_integrity",
                    Some("local_authority_integrity_metadata_missing"),
                );
                self.delete(state_key);
                return None;
            }
            Stored::Object(object) => object,
        };
        let (status, message) = self.verify(&persisted, kind, true);
        let context_matches = exact_str(&persisted, "state_key") == Some(state_key);
        if status != "valid" || !context_matches {
            let (status, message) = if status != "valid" {
                (status, message)
            } else {
                (
                    "tampered",
                    Some("local_authority_integrity_state_key_mismatch"),
                )
            };
            self.record_failure(
                kind,
                state_key,
                persisted.get("artifact_id").cloned().unwrap_or(Value::Null),
                status,
                message,
            );
            self.delete(state_key);
            return None;
        }
        if !is_fresh(
            persisted.get("saved_at").and_then(Value::as_str),
            self.now,
            MAX_AGE_SECONDS,
        ) {
            self.add_event(
                "approval.pending_state_expired",
                &json!({
                    "harness": kind.harness,
                    "source": kind.source,
                    "artifact_id": persisted.get("artifact_id").cloned().unwrap_or(Value::Null),
                    "state_key_fingerprint": fingerprint(state_key),
                }),
            );
            self.delete(state_key);
            return None;
        }
        Some(persisted)
    }

    fn invalidate(&self, state_key: &str, persisted: &Object, kind: &Kind, message: &str) {
        self.record_failure(
            kind,
            state_key,
            persisted.get("artifact_id").cloned().unwrap_or(Value::Null),
            "tampered",
            Some(message),
        );
        self.delete(state_key);
    }

    // ---- per-owner indexes -------------------------------------------------

    fn load_index(&self, family: &Family, owner: &str) -> Vec<String> {
        let index_key = format!("{}{owner}", family.index_prefix);
        let Some(persisted) = self.load_verified(&index_key, family.kind) else {
            return Vec::new();
        };
        let expected_prefix = format!("{}{owner}:", family.item_prefix);
        let keys = persisted
            .get("pending_keys")
            .and_then(Value::as_array)
            .and_then(|items| {
                items
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .filter(|text| text.starts_with(&expected_prefix))
                    })
                    .collect::<Option<Vec<&str>>>()
            });
        match keys {
            Some(keys) if exact_str(&persisted, family.owner_field) == Some(owner) => {
                dedupe(keys.into_iter().map(str::to_owned))
            }
            _ => {
                self.invalidate(
                    &index_key,
                    &persisted,
                    family.kind,
                    "local_authority_integrity_pending_index_context_mismatch",
                );
                Vec::new()
            }
        }
    }

    fn store_index(&self, family: &Family, owner: &str, keys: &[String]) -> bool {
        let index_key = format!("{}{owner}", family.index_prefix);
        if keys.is_empty() {
            self.delete(&index_key);
            return true;
        }
        let mut payload = Object::new();
        payload.insert(family.owner_field.to_owned(), json!(owner));
        payload.insert(
            "pending_keys".to_owned(),
            json!(dedupe(keys.iter().cloned())),
        );
        payload.insert("saved_at".to_owned(), json!(self.now));
        self.store_signed(&index_key, &Value::Object(payload), family.kind)
    }

    fn append_key(&self, family: &Family, owner: &str, pending_key: &str) -> bool {
        let mut keys = self.load_index(family, owner);
        if keys.iter().any(|key| key == pending_key) {
            return true;
        }
        keys.push(pending_key.to_owned());
        self.store_index(family, owner, &keys)
    }

    // ---- Claude ------------------------------------------------------------

    fn claude_record_notice(&self, session_id: &str, tool_name: Option<&str>, payload: &Value) {
        let Some(artifact_id) = payload.get("artifact_id").and_then(Value::as_str) else {
            return;
        };
        let notice_key = notice_key(session_id, tool_name);
        let pending_key = claude_pending_key(session_id, artifact_id);
        if !self.store_signed(&pending_key, payload, &CLAUDE_PENDING) {
            return;
        }
        if !self.append_key(&CLAUDE_FAMILY, session_id, &pending_key) {
            self.delete(&pending_key);
            return;
        }
        if !self.store_signed(&notice_key, payload, &CLAUDE_NOTICE) {
            self.claude_remove_pending(session_id, &pending_key);
        }
    }

    fn claude_load_pending(
        &self,
        session_id: &str,
        pending_key: &str,
        expected_artifact_id: Option<&str>,
        expected_artifact_hash: Option<&str>,
        expected_command: Option<&str>,
    ) -> Option<Object> {
        let persisted = self.load_verified(pending_key, &CLAUDE_PENDING)?;
        let artifact_id = opt_str(&persisted, "artifact_id");
        let artifact_hash = opt_str(&persisted, "artifact_hash");
        let command = opt_str(&persisted, "command");
        let expected_key = artifact_id
            .as_deref()
            .map(|id| claude_pending_key(session_id, id));
        let context_matches = exact_str(&persisted, "session_id") == Some(session_id)
            && artifact_id.is_some()
            && artifact_hash.is_some()
            && command.is_some()
            && expected_key.as_deref() == Some(pending_key)
            && expected_artifact_id.is_none_or(|expected| artifact_id.as_deref() == Some(expected))
            && expected_artifact_hash
                .is_none_or(|expected| artifact_hash.as_deref() == Some(expected))
            && expected_command.is_none_or(|expected| command.as_deref() == Some(expected));
        if context_matches {
            return Some(persisted);
        }
        self.invalidate(
            pending_key,
            &persisted,
            &CLAUDE_PENDING,
            "local_authority_integrity_pending_context_mismatch",
        );
        None
    }

    fn claude_load_notice(&self, session_id: &str, tool_name: Option<&str>) -> Option<Object> {
        let mut selected_tool = tool_name;
        let mut selected_key = notice_key(session_id, selected_tool);
        let mut persisted = self.load_verified(&selected_key, &CLAUDE_NOTICE);
        if persisted.is_none() && tool_name.is_some() {
            selected_tool = None;
            selected_key = notice_key(session_id, None);
            persisted = self.load_verified(&selected_key, &CLAUDE_NOTICE);
        }
        let persisted = persisted?;
        let artifact_id = opt_str(&persisted, "artifact_id");
        let artifact_hash = opt_str(&persisted, "artifact_hash");
        let command = opt_str(&persisted, "command");
        let stored_tool = opt_str(&persisted, "tool_name");
        let context_matches = exact_str(&persisted, "session_id") == Some(session_id)
            && artifact_id.is_some()
            && artifact_hash.is_some()
            && command.is_some()
            && stored_tool.as_deref() == selected_tool;
        let (Some(artifact_id), Some(artifact_hash), Some(command), true) =
            (artifact_id, artifact_hash, command, context_matches)
        else {
            self.invalidate(
                &selected_key,
                &persisted,
                &CLAUDE_NOTICE,
                "local_authority_integrity_notice_context_mismatch",
            );
            return None;
        };
        let pending_key = claude_pending_key(session_id, &artifact_id);
        let pending = self.claude_load_pending(
            session_id,
            &pending_key,
            Some(&artifact_id),
            Some(&artifact_hash),
            Some(&command),
        );
        if pending.is_none() {
            self.delete(&selected_key);
            return None;
        }
        Some(persisted)
    }

    fn claude_mark_prompt_seen(
        &self,
        session_id: &str,
        artifact_id: &str,
        artifact_hash: &str,
        command: &str,
    ) {
        let pending_key = claude_pending_key(session_id, artifact_id);
        let Some(mut updated) = self.claude_load_pending(
            session_id,
            &pending_key,
            Some(artifact_id),
            Some(artifact_hash),
            Some(command),
        ) else {
            return;
        };
        updated.insert("permission_prompt_seen".to_owned(), Value::Bool(true));
        updated.insert("permission_prompt_seen_at".to_owned(), json!(self.now));
        self.store_signed(&pending_key, &Value::Object(updated), &CLAUDE_PENDING);
    }

    fn claude_load_single_pending(&self, session_id: &str) -> Option<(String, Object)> {
        let mut items = Vec::new();
        for pending_key in self.load_index(&CLAUDE_FAMILY, session_id) {
            if let Some(pending) =
                self.claude_load_pending(session_id, &pending_key, None, None, None)
            {
                items.push((pending_key, pending));
            }
        }
        let seen = items
            .iter()
            .filter(|(_, pending)| {
                pending.get("permission_prompt_seen") == Some(&Value::Bool(true))
            })
            .count();
        if seen == 1 {
            let position = items.iter().position(|(_, pending)| {
                pending.get("permission_prompt_seen") == Some(&Value::Bool(true))
            })?;
            return Some(items.swap_remove(position));
        }
        if items.len() != 1 {
            return None;
        }
        items.pop()
    }

    fn claude_remove_pending(&self, session_id: &str, pending_key: &str) {
        self.delete(pending_key);
        let remaining: Vec<String> = self
            .load_index(&CLAUDE_FAMILY, session_id)
            .into_iter()
            .filter(|key| key != pending_key)
            .collect();
        self.store_index(&CLAUDE_FAMILY, session_id, &remaining);
    }

    // ---- Cursor ------------------------------------------------------------

    fn cursor_load_pending_state(
        &self,
        conversation_id: &str,
        command: &str,
        state_key: &str,
        expected_key: &str,
    ) -> Option<Object> {
        let persisted = self.load_verified(state_key, &CURSOR_PENDING)?;
        let context_matches = state_key == expected_key
            && exact_str(&persisted, "conversation_id") == Some(conversation_id)
            && opt_str(&persisted, "artifact_id").is_some()
            && opt_str(&persisted, "artifact_hash").is_some()
            && opt_str(&persisted, "command").as_deref() == Some(command);
        if context_matches {
            return Some(persisted);
        }
        self.invalidate(
            state_key,
            &persisted,
            &CURSOR_PENDING,
            "local_authority_integrity_pending_context_mismatch",
        );
        None
    }

    fn cursor_record_allow(
        &self,
        request: &HookAuthorityStateRequestV1,
    ) -> Result<bool, &'static str> {
        let state_key = required(&request.state_key)?;
        let payload = json!({
            "state_key": state_key,
            "conversation_id": required(&request.conversation_id)?,
            "saved_at": self.now,
            "action": "allow",
            "artifact_id": required(&request.artifact_id)?,
            "artifact_hash": required(&request.artifact_hash)?,
            "artifact_name": required(&request.artifact_name)?,
            "command": required(&request.command)?,
            "native_source": "cursor-native",
        });
        Ok(self.store_signed(state_key, &payload, &CURSOR_ALLOW))
    }

    fn cursor_load_allowance(
        &self,
        conversation_id: &str,
        command: &str,
        state_key: &str,
    ) -> Option<Object> {
        let approved = match self.read(state_key) {
            Stored::InvalidJson => {
                self.record_failure(
                    &CURSOR_ALLOW,
                    state_key,
                    Value::Null,
                    "tampered",
                    Some("local_authority_integrity_payload_invalid_json"),
                );
                self.delete(state_key);
                return None;
            }
            Stored::Object(object) => object,
            Stored::Absent | Stored::Unreadable | Stored::List => return None,
        };
        let has_integrity =
            matches!(approved.get("integrity"), Some(Value::Object(map)) if !map.is_empty());
        let (status, message) = self.verify(&approved, &CURSOR_ALLOW, has_integrity);
        let context_matches = exact_str(&approved, "state_key") == Some(state_key)
            && exact_str(&approved, "conversation_id") == Some(conversation_id)
            && exact_str(&approved, "command") == Some(command);
        let fresh = exact_str(&approved, "action") == Some("allow")
            && is_fresh(
                approved.get("saved_at").and_then(Value::as_str),
                self.now,
                MAX_AGE_SECONDS,
            );
        if status == "valid" && context_matches && fresh {
            return Some(approved);
        }
        if status == "valid" && context_matches {
            self.delete(state_key);
            return None;
        }
        let (status, message) = if status != "valid" {
            (status, message)
        } else {
            (
                "tampered",
                Some("local_authority_integrity_context_mismatch"),
            )
        };
        self.record_failure(
            &CURSOR_ALLOW,
            state_key,
            approved.get("artifact_id").cloned().unwrap_or(Value::Null),
            status,
            message,
        );
        self.delete(state_key);
        None
    }
}

#[cfg(all(test, unix))]
#[path = "hook_authority_state_vectors_tests.rs"]
mod vectors;
