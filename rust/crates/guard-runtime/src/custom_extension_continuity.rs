//! Plan signed custom-Extension continuity against exact local identities.
//!
//! Port of the former Python `custom_extension_continuity` planners (v1 exact
//! identity, v2 device-bound); parity vectors are recorded by
//! `scripts/record_custom_extension_continuity_vectors.py`. Pure: the client
//! sends a store snapshot and commits the returned plan in one transaction
//! guarded by the snapshot it sent.
//!
//! Stored payloads come back with sorted keys. Item order inside `items`
//! maps is returned separately so the client can keep the stored order.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::guard_store_json::dumps_sorted;
use super::guard_store_observed_mcp::is_local_cli_id;
use super::policy_bundle_time::from_isoformat;

const SCHEMA_V1: &str = "guard.custom-extension-continuity.v1";
const SCHEMA_V2: &str = "guard.custom-extension-continuity.v2";
const MAX_ITEMS: usize = 100;
const MAX_COMMANDS: usize = 101;
const MAX_COMMAND_DEPTH: usize = 4;
const MAX_DEVICE_BINDINGS: usize = 1;
const TOP_LEVEL_FIELDS: &[&str] = &[
    "expiresAt",
    "items",
    "observedAt",
    "revision",
    "schemaVersion",
];
const V1_ITEM_FIELDS: &[&str] = &["cliId", "identityHash", "settings"];
const V2_ITEM_FIELDS: &[&str] = &["deviceIdentityHashes", "identityHash", "state"];
const SETTINGS_FIELDS: &[&str] = &["commands", "state"];
const PUBLIC_FIELDS: &[&str] = &["cloud_revision", "reason", "status", "surface"];
const ERR_REQUEST: &str = "native_custom_extension_continuity_invalid_request";

enum Fail {
    Request,
    Refusal(String),
}

type Planned<T> = Result<T, Fail>;

fn refuse<T>(message: impl Into<String>) -> Planned<T> {
    Err(Fail::Refusal(message.into()))
}

/// Answer one continuity request. Refusals are part of the answer
/// (`{"error": message}`); only a malformed request is an error.
pub(crate) fn evaluate(request: &Value) -> Result<Value, &'static str> {
    let operation = request.get("operation").and_then(Value::as_str);
    let answer = match operation {
        Some("plan") => plan(request),
        Some("local_mutation") => local_mutation(request),
        Some("public_state") => public_state(request),
        _ => Err(Fail::Request),
    };
    match answer {
        Ok(value) => Ok(value),
        Err(Fail::Refusal(message)) => Ok(json!({ "error": message })),
        Err(Fail::Request) => Err(ERR_REQUEST),
    }
}

struct Snapshot<'a> {
    now: &'a str,
    authority: Authority<'a>,
    previous: &'a Value,
    previous_order: Vec<String>,
    removals: Map<String, Value>,
}

struct Authority<'a> {
    /// Locals keyed by `cli_id` in first-seen order, last row winning.
    locals: Vec<(&'a str, &'a Map<String, Value>)>,
    details: &'a Map<String, Value>,
    /// Locals whose details were read but not sent; the plan asks for them.
    missing: RefCell<BTreeSet<String>>,
}

impl<'a> Authority<'a> {
    fn local(&self, cli_id: &str) -> Option<&'a Map<String, Value>> {
        self.locals
            .iter()
            .find(|(id, _)| *id == cli_id)
            .map(|(_, local)| *local)
    }

    fn detail(&self, cli_id: &str, key: &str) -> Option<&'a Value> {
        let Some(detail) = self.details.get(cli_id) else {
            if self.local(cli_id).is_some() {
                self.missing.borrow_mut().insert(cli_id.to_owned());
            }
            return None;
        };
        detail.get(key)
    }

    fn grant(&self, cli_id: &str) -> Option<&'a Map<String, Value>> {
        self.detail(cli_id, "grant")?.as_object()
    }
}

struct Plan {
    updates: Vec<Value>,
    events: Vec<Value>,
    preconditions: Map<String, Value>,
    statuses: Vec<(String, Value)>,
}

impl Plan {
    fn new() -> Self {
        Self {
            updates: Vec::new(),
            events: Vec::new(),
            preconditions: Map::new(),
            statuses: Vec::new(),
        }
    }

    /// Python dict assignment: a repeated key keeps its first position.
    fn set_status(&mut self, key: &str, evidence: Value) {
        match self
            .statuses
            .iter_mut()
            .find(|(existing, _)| existing == key)
        {
            Some(slot) => slot.1 = evidence,
            None => self.statuses.push((key.to_owned(), evidence)),
        }
    }

    fn record(&mut self, key: &str, status: &str, evidence: Value) {
        self.events.push(json!([
            format!("custom_extension_continuity/{status}"),
            evidence.clone()
        ]));
        self.set_status(key, evidence);
    }

    fn answer(self, state: Map<String, Value>, stale: bool, removals: Value, v2: bool) -> Value {
        let order: Vec<&String> = self.statuses.iter().map(|(key, _)| key).collect();
        let mut state = state;
        state.insert(
            "items".to_owned(),
            Value::Object(self.statuses.iter().cloned().collect()),
        );
        json!({
            "error": null,
            "authority_updates": self.updates,
            "events": self.events,
            "observation_preconditions": self.preconditions,
            "state_item_order": order,
            "state": state,
            "write_last_good": !stale,
            "removals": removals,
            "v2": v2,
        })
    }
}

/// Plan against the sent details. The client starts with none; when the plan
/// reads details of a local that were not sent, the answer is
/// `{"need_details": [cli_id, ...]}` and the client asks again with them, so
/// only the locals the plan touches are loaded from the store.
fn plan(request: &Value) -> Planned<Value> {
    let snapshot = snapshot(request)?;
    let answer = plan_snapshot(request, &snapshot);
    if matches!(answer, Err(Fail::Request)) {
        return answer;
    }
    let missing = snapshot.authority.missing.take();
    if !missing.is_empty() {
        return Ok(json!({ "need_details": missing }));
    }
    answer
}

fn plan_snapshot(request: &Value, snapshot: &Snapshot<'_>) -> Planned<Value> {
    let continuity = request.get("continuity").ok_or(Fail::Request)?;
    let is_v2 = continuity
        .as_object()
        .is_some_and(|value| value.get("schemaVersion").and_then(Value::as_str) == Some(SCHEMA_V2));
    if !is_v2 {
        return plan_v1(continuity, snapshot);
    }
    let workspace = request
        .get("workspace_id")
        .and_then(Value::as_str)
        .filter(|workspace| !workspace.is_empty());
    let device = match request.get("device_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(device)) => Some(device.as_str()),
        Some(_) => return Err(Fail::Request),
    };
    match (workspace, device) {
        (Some(workspace), Some(device)) => plan_v2(continuity, snapshot, workspace, device),
        _ => refuse("v2 continuity requires workspace and device binding"),
    }
}

fn snapshot(request: &Value) -> Planned<Snapshot<'_>> {
    let locals = request
        .get("locals")
        .and_then(Value::as_array)
        .ok_or(Fail::Request)?;
    let mut deduped: Vec<(&str, &Map<String, Value>)> = Vec::new();
    for local in locals {
        let local = local.as_object().ok_or(Fail::Request)?;
        let cli_id = local
            .get("cli_id")
            .and_then(Value::as_str)
            .ok_or(Fail::Request)?;
        match deduped.iter_mut().find(|(id, _)| *id == cli_id) {
            Some(slot) => slot.1 = local,
            None => deduped.push((cli_id, local)),
        }
    }
    Ok(Snapshot {
        now: request
            .get("now")
            .and_then(Value::as_str)
            .ok_or(Fail::Request)?,
        authority: Authority {
            locals: deduped,
            details: request
                .get("details")
                .and_then(Value::as_object)
                .ok_or(Fail::Request)?,
            missing: RefCell::new(BTreeSet::new()),
        },
        previous: request.get("previous").unwrap_or(&Value::Null),
        previous_order: string_list(request.get("previous_item_order"))?,
        removals: request
            .get("removals")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default(),
    })
}

struct Frame<'a> {
    value: &'a Map<String, Value>,
    items: &'a [Value],
    revision: i128,
    expires: i64,
}

impl Frame<'_> {
    fn state(&self, schema: &str, stale: bool, digest: &str) -> Map<String, Value> {
        let mut state = Map::new();
        state.insert("schema_version".to_owned(), json!(schema));
        state.insert("cloud_revision".to_owned(), self.value["revision"].clone());
        state.insert("observed_at".to_owned(), self.value["observedAt"].clone());
        state.insert("expires_at".to_owned(), self.value["expiresAt"].clone());
        state.insert("stale".to_owned(), json!(stale));
        state.insert("observation_digest".to_owned(), json!(digest));
        state
    }

    fn evidence(&self) -> Map<String, Value> {
        let mut evidence = Map::new();
        evidence.insert("cloud_revision".to_owned(), self.value["revision"].clone());
        evidence
    }
}

fn frame<'a>(value: &'a Value, schema: &str) -> Planned<Frame<'a>> {
    let Some(object) = value
        .as_object()
        .filter(|object| has_exact_keys(object, TOP_LEVEL_FIELDS))
    else {
        return refuse("continuity observation contains unsupported fields");
    };
    if object.get("schemaVersion").and_then(Value::as_str) != Some(schema) {
        return refuse("unsupported continuity observation schema");
    }
    let Some(revision) = py_int(object.get("revision")).filter(|revision| *revision >= 1) else {
        return refuse("continuity revision must be positive");
    };
    let (Some(observed_at), Some(expires_at)) = (
        object.get("observedAt").and_then(Value::as_str),
        object.get("expiresAt").and_then(Value::as_str),
    ) else {
        return refuse("continuity timestamps are required");
    };
    let expires = timestamp(expires_at, "expiry")?;
    if expires <= timestamp(observed_at, "observation")? {
        return refuse("continuity expiry must follow observation");
    }
    match object.get("items").and_then(Value::as_array) {
        Some(items) if items.len() <= MAX_ITEMS => Ok(Frame {
            value: object,
            items,
            revision,
            expires,
        }),
        _ => refuse("continuity item limit exceeded"),
    }
}

struct V1Item<'a> {
    cli_id: &'a str,
    identity_hash: &'a str,
    state: &'a str,
    commands: &'a Map<String, Value>,
}

fn parse_v1_item<'a>(raw: &'a Value, seen: &mut BTreeSet<&'a str>) -> Planned<V1Item<'a>> {
    let Some(item) = raw
        .as_object()
        .filter(|item| has_exact_keys(item, V1_ITEM_FIELDS))
    else {
        return refuse("continuity item contains unsupported fields");
    };
    let Some(cli_id) = item
        .get("cliId")
        .and_then(Value::as_str)
        .filter(|cli_id| is_local_cli_id(cli_id) && !seen.contains(cli_id))
    else {
        return refuse("invalid or duplicate continuity identity");
    };
    let Some(identity_hash) = item
        .get("identityHash")
        .and_then(Value::as_str)
        .filter(|hash| is_sha256(hash))
    else {
        return refuse("invalid continuity identity hash");
    };
    seen.insert(cli_id);
    let Some(settings) = item
        .get("settings")
        .and_then(Value::as_object)
        .filter(|settings| has_exact_keys(settings, SETTINGS_FIELDS))
    else {
        return refuse("continuity settings contain unsupported fields");
    };
    let Some(state) = settings
        .get("state")
        .and_then(Value::as_str)
        .filter(|state| matches!(*state, "allowed" | "blocked"))
    else {
        return refuse("invalid continuity setting");
    };
    let Some(commands) = settings
        .get("commands")
        .and_then(Value::as_object)
        .filter(|commands| commands.len() <= MAX_COMMANDS)
    else {
        return refuse("invalid continuity command settings");
    };
    for (command_id, command_state) in commands {
        if !is_command_id(command_id) {
            return refuse("invalid continuity command identity");
        }
        if !matches!(command_state.as_str(), Some("inherit" | "allow" | "block")) {
            return refuse("invalid continuity command setting");
        }
    }
    Ok(V1Item {
        cli_id,
        identity_hash,
        state,
        commands,
    })
}

fn plan_v1(continuity: &Value, snapshot: &Snapshot<'_>) -> Planned<Value> {
    let frame = frame(continuity, SCHEMA_V1)?;
    let mut seen = BTreeSet::new();
    let items = frame
        .items
        .iter()
        .map(|raw| parse_v1_item(raw, &mut seen))
        .collect::<Planned<Vec<_>>>()?;
    let digest = sha256_hex(&dumps_sorted(continuity).ok_or(Fail::Request)?);
    require_monotonic(snapshot.previous, frame.revision, &digest)?;
    let stale = frame.expires <= timestamp(snapshot.now, "current time")?;
    let authority = &snapshot.authority;
    let mut plan = Plan::new();
    let mut remaining = snapshot.removals.clone();
    let mut removals_changed = false;
    for item in &items {
        let local = authority.local(item.cli_id);
        plan.preconditions
            .insert(item.cli_id.to_owned(), observation_precondition(local));
        let override_value = snapshot.removals.get(item.cli_id);
        let (status, reason) = if stale {
            ("stale", "cloud_observation_expired")
        } else if override_matches(override_value, item.identity_hash, frame.revision) {
            local_override_status(override_value)
        } else if let Some(local) = local.filter(|local| observed(local)) {
            if local.get("identity_hash").and_then(Value::as_str) != Some(item.identity_hash) {
                ("changed_identity", "identity_mismatch")
            } else {
                removals_changed |= remaining.remove(item.cli_id).is_some();
                if let Some(update) =
                    plan_exact_settings(authority, local, item.state, item.commands)?
                {
                    plan.updates.push(update);
                }
                ("applied", "same_identity")
            }
        } else {
            ("pending_observation", "local_identity_not_observed")
        };
        let mut evidence = Map::new();
        evidence.insert("cli_id".to_owned(), json!(item.cli_id));
        evidence.insert("identity_hash".to_owned(), json!(item.identity_hash));
        evidence.extend(frame.evidence());
        evidence.insert("status".to_owned(), json!(status));
        evidence.insert("reason".to_owned(), json!(reason));
        if let Some(surface) = local
            .and_then(|local| local.get("surface"))
            .filter(|surface| matches!(surface.as_str(), Some("cli" | "mcp" | "package-scripts")))
        {
            evidence.insert("surface".to_owned(), surface.clone());
        }
        plan.record(item.cli_id, status, Value::Object(evidence));
    }
    let state = frame.state(SCHEMA_V1, stale, &digest);
    let removals = if removals_changed {
        Value::Object(remaining)
    } else {
        Value::Null
    };
    Ok(plan.answer(state, stale, removals, false))
}

struct V2Item<'a> {
    identity_hash: &'a str,
    devices: Vec<&'a str>,
    state: &'a str,
}

fn parse_v2_item<'a>(raw: &'a Value, seen: &mut BTreeSet<&'a str>) -> Planned<V2Item<'a>> {
    let Some(item) = raw
        .as_object()
        .filter(|item| has_exact_keys(item, V2_ITEM_FIELDS))
    else {
        return refuse("continuity item contains unsupported fields");
    };
    let Some(identity_hash) = item
        .get("identityHash")
        .and_then(Value::as_str)
        .filter(|hash| is_sha256(hash) && !seen.contains(hash))
    else {
        return refuse("invalid or duplicate continuity identity");
    };
    let devices = item
        .get("deviceIdentityHashes")
        .and_then(Value::as_array)
        .filter(|devices| !devices.is_empty() && devices.len() <= MAX_DEVICE_BINDINGS)
        .and_then(|devices| {
            devices
                .iter()
                .map(|device| device.as_str().filter(|device| is_sha256(device)))
                .collect::<Option<Vec<&str>>>()
        })
        .filter(|devices| devices.iter().collect::<BTreeSet<_>>().len() == devices.len());
    let Some(mut devices) = devices else {
        return refuse("invalid continuity device binding");
    };
    let Some(state) = item
        .get("state")
        .and_then(Value::as_str)
        .filter(|state| matches!(*state, "allowed" | "blocked" | "removed"))
    else {
        return refuse("invalid continuity setting");
    };
    seen.insert(identity_hash);
    devices.sort_unstable();
    Ok(V2Item {
        identity_hash,
        devices,
        state,
    })
}

fn plan_v2(
    continuity: &Value,
    snapshot: &Snapshot<'_>,
    workspace: &str,
    device: &str,
) -> Planned<Value> {
    let frame = frame(continuity, SCHEMA_V2)?;
    let mut seen = BTreeSet::new();
    let mut items = frame
        .items
        .iter()
        .map(|raw| parse_v2_item(raw, &mut seen))
        .collect::<Planned<Vec<_>>>()?;
    items.sort_by(|left, right| left.identity_hash.cmp(right.identity_hash));
    let canonical = json!({
        "schemaVersion": frame.value["schemaVersion"],
        "revision": frame.value["revision"],
        "observedAt": frame.value["observedAt"],
        "expiresAt": frame.value["expiresAt"],
        "items": items.iter().map(|item| json!({
            "identityHash": item.identity_hash,
            "deviceIdentityHashes": item.devices,
            "state": item.state,
        })).collect::<Vec<_>>(),
    });
    let digest = sha256_hex(&dumps_sorted(&canonical).ok_or(Fail::Request)?);
    let device_hash = sha256_hex(&format!("{SCHEMA_V1}:device:{workspace}:{device}"));
    let binding = json!({
        "workspaceHash": sha256_hex(&format!("{SCHEMA_V1}:workspace:{workspace}")),
        "deviceHash": device_hash,
    });
    let previous = snapshot.previous.as_object();
    let same_context = previous.is_some_and(|previous| previous.get("binding") == Some(&binding));
    if same_context {
        require_monotonic(snapshot.previous, frame.revision, &digest)?;
    } else if previous.is_some_and(|previous| {
        previous.get("schema_version").and_then(Value::as_str) == Some(SCHEMA_V2)
            && !previous.get("binding").is_some_and(Value::is_object)
    }) {
        return refuse("prior v2 continuity binding is unavailable");
    }
    let stale = frame.expires <= timestamp(snapshot.now, "current time")?;
    let authority = &snapshot.authority;
    let mut by_scoped: BTreeMap<String, Vec<&Map<String, Value>>> = BTreeMap::new();
    for (_, local) in &authority.locals {
        if let Some(identity_hash) = local.get("identity_hash").and_then(Value::as_str) {
            by_scoped
                .entry(scoped_identity(workspace, identity_hash))
                .or_default()
                .push(local);
        }
    }
    let previous_items = previous
        .and_then(|previous| previous.get("items"))
        .and_then(Value::as_object);
    let previous_order = previous_items
        .map(|items| ordered_keys(items, &snapshot.previous_order))
        .unwrap_or_default();
    let mut plan = Plan::new();
    for item in &items {
        if !item.devices.contains(&device_hash.as_str()) {
            continue;
        }
        let scoped = item.identity_hash;
        let mut matches = by_scoped.get(scoped).cloned().unwrap_or_default();
        if matches.is_empty() {
            matches = previous_order
                .iter()
                .filter(|cli_id| {
                    previous_items
                        .and_then(|items| items.get(*cli_id))
                        .and_then(|prior| prior.get("workspace_identity_hash"))
                        .and_then(Value::as_str)
                        == Some(scoped)
                })
                .filter_map(|cli_id| authority.local(cli_id))
                .collect();
        }
        let evidence_for = |status: &str, reason: &str| {
            let mut evidence = Map::new();
            evidence.insert("workspace_identity_hash".to_owned(), json!(scoped));
            evidence.extend(frame.evidence());
            evidence.insert("status".to_owned(), json!(status));
            evidence.insert("reason".to_owned(), json!(reason));
            evidence
        };
        if matches.is_empty() {
            let pending = evidence_for("pending_observation", "local_identity_not_observed");
            plan.record(scoped, "pending_observation", Value::Object(pending));
            continue;
        }
        for local in matches {
            let cli_id = local["cli_id"].as_str().unwrap_or_default();
            let identity_hash = local.get("identity_hash").and_then(Value::as_str);
            if identity_hash.is_some() {
                plan.preconditions
                    .insert(cli_id.to_owned(), observation_precondition(Some(local)));
            }
            let (status, reason) = match identity_hash {
                _ if !observed(local) => ("pending_observation", "local_identity_not_observed"),
                _ if stale => ("stale", "cloud_observation_expired"),
                None => ("pending_observation", "local_identity_not_observed"),
                Some(hash) if scoped_identity(workspace, hash) != scoped => {
                    ("changed_identity", "identity_mismatch")
                }
                Some(hash)
                    if override_matches(snapshot.removals.get(cli_id), hash, frame.revision) =>
                {
                    ("locally_overridden", "local_authority_preserved")
                }
                Some(_) if item.state == "removed" => {
                    plan.updates.push(unset_update(local)?);
                    ("removed", "signed_cloud_tombstone")
                }
                Some(_) => {
                    if let Some(update) =
                        plan_exact_settings(authority, local, item.state, &Map::new())?
                    {
                        plan.updates.push(update);
                    }
                    ("applied", "same_scoped_identity")
                }
            };
            let mut evidence = evidence_for(status, reason);
            if let Some(hash) = identity_hash {
                evidence.insert("local_identity_hash".to_owned(), json!(hash));
            }
            plan.record(cli_id, status, Value::Object(evidence));
        }
    }
    if let (false, Some(previous)) = (same_context, previous) {
        plan_context_cleanup(&mut plan, snapshot, previous, &previous_order)?;
    }
    let mut state = frame.state(SCHEMA_V2, stale, &digest);
    state.insert("binding".to_owned(), binding);
    Ok(plan.answer(state, stale, Value::Null, true))
}

/// Unset prior applied grants that the new binding no longer projects.
fn plan_context_cleanup(
    plan: &mut Plan,
    snapshot: &Snapshot<'_>,
    previous: &Map<String, Value>,
    previous_order: &[String],
) -> Planned<()> {
    let Some(items) = previous.get("items").and_then(Value::as_object) else {
        return Ok(());
    };
    let cloud_revision = previous
        .get("cloud_revision")
        .filter(|revision| py_int(Some(revision)).is_some())
        .cloned()
        .unwrap_or_else(|| json!(0));
    let protected: BTreeSet<String> = plan.statuses.iter().map(|(key, _)| key.clone()).collect();
    let authority = &snapshot.authority;
    for cli_id in previous_order {
        let Some(raw) = items.get(cli_id).and_then(Value::as_object) else {
            continue;
        };
        if protected.contains(cli_id)
            || raw.get("status").and_then(Value::as_str) != Some("applied")
        {
            continue;
        }
        let prior_identity = raw
            .get("local_identity_hash")
            .or_else(|| raw.get("identity_hash"))
            .and_then(Value::as_str);
        let Some(prior_identity) = prior_identity else {
            continue;
        };
        let Some(local) = authority.local(cli_id).filter(|local| {
            local.get("identity_hash").and_then(Value::as_str) == Some(prior_identity)
                && observed(local)
        }) else {
            continue;
        };
        let revision = py_int(Some(&cloud_revision)).unwrap_or(0);
        if override_matches(snapshot.removals.get(cli_id), prior_identity, revision) {
            continue;
        }
        let granted = authority.grant(cli_id).is_some_and(|grant| {
            grant.get("identity_hash").and_then(Value::as_str) == Some(prior_identity)
        });
        if !granted {
            continue;
        }
        plan.preconditions
            .insert(cli_id.clone(), observation_precondition(Some(local)));
        plan.updates.push(unset_update(local)?);
        plan.events.push(json!([
            "custom_extension_continuity/removed",
            {
                "cloud_revision": cloud_revision,
                "status": "removed",
                "reason": "continuity_context_changed",
            }
        ]));
    }
    Ok(())
}

fn local_mutation(request: &Value) -> Planned<Value> {
    let text = |key: &str| {
        request
            .get(key)
            .and_then(Value::as_str)
            .ok_or(Fail::Request)
    };
    let (cli_id, identity_hash, state) = (text("cli_id")?, text("identity_hash")?, text("state")?);
    let now = request.get("now").ok_or(Fail::Request)?;
    let active = request.get("active").and_then(Value::as_object);
    let mut removals = request
        .get("removals")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let revision = active
        .and_then(|active| active.get("cloud_revision"))
        .filter(|revision| py_int(Some(revision)).is_some())
        .cloned()
        .unwrap_or_else(|| json!(0));
    removals.insert(
        cli_id.to_owned(),
        json!({
            "identity_hash": identity_hash,
            "cloud_revision": revision,
            "state": state,
            "updated_at": now,
        }),
    );
    let (status, reason) = if state == "unset" {
        ("removed", "removed_locally")
    } else {
        ("locally_overridden", "local_authority_preserved")
    };
    let updated = active.and_then(|active| {
        let mut items = active.get("items")?.as_object()?.clone();
        let mut item = items.get(cli_id)?.as_object()?.clone();
        item.insert("status".to_owned(), json!(status));
        item.insert("reason".to_owned(), json!(reason));
        items.insert(cli_id.to_owned(), Value::Object(item));
        let mut active = active.clone();
        active.insert("items".to_owned(), Value::Object(items));
        Some(active)
    });
    let order = string_list(request.get("active_item_order"))?;
    let active_order = updated
        .as_ref()
        .and_then(|active| active.get("items")?.as_object())
        .map(|items| ordered_keys(items, &order))
        .unwrap_or_default();
    let local = request.get("local").and_then(Value::as_object);
    Ok(json!({
        "removals": removals,
        "active": updated,
        "active_item_order": active_order,
        "event": [
            format!("custom_extension_continuity/{status}"),
            {
                "cli_id": cli_id,
                "identity_hash": identity_hash,
                "status": status,
                "reason": reason,
            }
        ],
        "observation_precondition": observation_precondition(local),
    }))
}

fn public_state(request: &Value) -> Planned<Value> {
    let now = request
        .get("now")
        .and_then(Value::as_str)
        .ok_or(Fail::Request)?;
    let stored = request.get("stored").and_then(Value::as_object);
    let items = stored
        .and_then(|stored| stored.get("items"))
        .and_then(Value::as_object);
    let expires_at = stored
        .and_then(|stored| stored.get("expires_at"))
        .and_then(Value::as_str);
    let (Some(items), Some(expires_at)) = (items, expires_at) else {
        return Ok(json!({ "states": {} }));
    };
    let stale = match (
        timestamp(expires_at, "expiry"),
        timestamp(now, "current time"),
    ) {
        (Ok(expires), Ok(now)) => expires <= now,
        _ => return Ok(json!({ "states": {} })),
    };
    let mut states = Map::new();
    for (cli_id, raw) in items {
        let Some(raw) = raw.as_object() else {
            continue;
        };
        let mut public: Map<String, Value> = raw
            .iter()
            .filter(|(key, _)| PUBLIC_FIELDS.contains(&key.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let keeps_status = matches!(
            public.get("status").and_then(Value::as_str),
            Some("removed" | "changed_identity")
        );
        if stale && !keeps_status {
            public.insert("status".to_owned(), json!("stale"));
            public.insert("reason".to_owned(), json!("cloud_observation_expired"));
        }
        states.insert(cli_id.clone(), Value::Object(public));
    }
    Ok(json!({ "states": states }))
}

/// Exact settings for one matched local; `None` when the grant already matches.
fn plan_exact_settings(
    authority: &Authority<'_>,
    local: &Map<String, Value>,
    state: &str,
    commands: &Map<String, Value>,
) -> Planned<Option<Value>> {
    let cli_id = local["cli_id"].as_str().unwrap_or_default();
    let catalog: BTreeSet<&str> = authority
        .detail(cli_id, "catalog_ids")
        .and_then(Value::as_array)
        .map(|ids| ids.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !commands
        .keys()
        .all(|command| catalog.contains(command.as_str()))
    {
        return refuse("continuity settings reference an unobserved command");
    }
    let identity = identity_from_local(local)?;
    let empty = Map::new();
    let current_commands = authority
        .detail(cli_id, "command_states")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let unchanged = authority.grant(cli_id).is_some_and(|grant| {
        grant.get("identity_hash") == local.get("identity_hash")
            && grant.get("state").and_then(Value::as_str) == Some(state)
            && current_commands == commands
    });
    if unchanged {
        return Ok(None);
    }
    Ok(Some(authority_update(identity, state, commands.clone())))
}

fn unset_update(local: &Map<String, Value>) -> Planned<Value> {
    Ok(authority_update(
        identity_from_local(local)?,
        "unset",
        Map::new(),
    ))
}

fn authority_update(
    mut identity: Map<String, Value>,
    state: &str,
    commands: Map<String, Value>,
) -> Value {
    identity.insert("state".to_owned(), json!(state));
    identity.insert("commands".to_owned(), Value::Object(commands));
    Value::Object(identity)
}

fn identity_from_local(local: &Map<String, Value>) -> Planned<Map<String, Value>> {
    if !matches!(
        local.get("kind").and_then(Value::as_str),
        Some("executable" | "script")
    ) {
        return refuse("local continuity identity kind is invalid");
    }
    Ok(pick(
        local,
        &[
            "cli_id",
            "name",
            "kind",
            "identity_hash",
            "example_label",
            "interpreter_name",
        ],
    ))
}

fn observation_precondition(local: Option<&Map<String, Value>>) -> Value {
    let Some(local) = local.filter(|local| observed(local)) else {
        return Value::Null;
    };
    let mut precondition = pick(
        local,
        &[
            "identity_hash",
            "kind",
            "name",
            "interpreter_name",
            "example_label",
            "observed_count",
            "surface",
        ],
    );
    let command_ids: Vec<&Value> = local
        .get("command_ids")
        .and_then(Value::as_array)
        .map(|ids| ids.iter().filter(|id| id.is_string()).collect())
        .unwrap_or_default();
    precondition.insert("command_ids".to_owned(), json!(command_ids));
    Value::Object(precondition)
}

fn pick(local: &Map<String, Value>, keys: &[&str]) -> Map<String, Value> {
    keys.iter()
        .map(|key| {
            (
                (*key).to_owned(),
                local.get(*key).cloned().unwrap_or(Value::Null),
            )
        })
        .collect()
}

fn observed(local: &Map<String, Value>) -> bool {
    py_int(local.get("observed_count")).is_some_and(|count| count >= 1)
}

fn require_monotonic(previous: &Value, revision: i128, digest: &str) -> Planned<()> {
    let Some(previous) = previous.as_object() else {
        return Ok(());
    };
    let Some(previous_revision) = py_int(previous.get("cloud_revision")) else {
        return Ok(());
    };
    if revision < previous_revision {
        return refuse("continuity revision cannot move backwards");
    }
    let previous_digest = previous.get("observation_digest").and_then(Value::as_str);
    if revision == previous_revision && previous_digest.is_some_and(|previous| previous != digest) {
        return refuse("continuity revision payload changed");
    }
    Ok(())
}

fn override_matches(value: Option<&Value>, identity_hash: &str, revision: i128) -> bool {
    value.and_then(Value::as_object).is_some_and(|value| {
        value.get("identity_hash").and_then(Value::as_str) == Some(identity_hash)
            && py_int(value.get("cloud_revision")).is_some_and(|stored| stored >= revision)
    })
}

fn local_override_status(value: Option<&Value>) -> (&'static str, &'static str) {
    let state = value
        .and_then(|value| value.get("state"))
        .and_then(Value::as_str);
    if matches!(state, Some("allowed" | "blocked")) {
        ("locally_overridden", "local_authority_preserved")
    } else {
        ("removed", "removed_locally")
    }
}

/// `datetime.fromisoformat(value.replace("Z", "+00:00"))` as UTC microseconds.
fn timestamp(value: &str, label: &str) -> Planned<i64> {
    let Some(parsed) = from_isoformat(&value.replace('Z', "+00:00")) else {
        return refuse(format!("invalid continuity {label}"));
    };
    if !parsed.is_aware() {
        return refuse(format!("continuity {label} must include a timezone"));
    }
    match parsed.utc_micros() {
        Some(micros) => Ok(micros),
        None => refuse(format!("invalid continuity {label}")),
    }
}

/// A Python `int` (not `bool`, not `float`) that fits in 128 bits.
fn py_int(value: Option<&Value>) -> Option<i128> {
    let Some(Value::Number(number)) = value else {
        return None;
    };
    let text = number.to_string();
    let digits = text.strip_prefix('-').unwrap_or(&text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn has_exact_keys(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_command_id(value: &str) -> bool {
    if matches!(value, "root" | "other") {
        return true;
    }
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() <= MAX_COMMAND_DEPTH
        && parts.iter().all(|part| {
            let mut bytes = part.bytes();
            bytes
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic())
                && part.len() <= 41
                && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
}

fn scoped_identity(workspace: &str, identity_hash: &str) -> String {
    sha256_hex(&format!("{SCHEMA_V1}:{workspace}:{identity_hash}"))
}

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn string_list(value: Option<&Value>) -> Planned<Vec<String>> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned).ok_or(Fail::Request))
            .collect(),
        Some(_) => Err(Fail::Request),
    }
}

/// Keys of `map` in the client's stored order, then any others sorted.
fn ordered_keys(map: &Map<String, Value>, order: &[String]) -> Vec<String> {
    let mut keys: Vec<String> = Vec::with_capacity(map.len());
    for key in order {
        if map.contains_key(key) && !keys.contains(key) {
            keys.push(key.clone());
        }
    }
    for key in map.keys() {
        if !keys.contains(key) {
            keys.push(key.clone());
        }
    }
    keys
}

#[cfg(test)]
#[path = "custom_extension_continuity_tests.rs"]
mod tests;
