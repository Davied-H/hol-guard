//! Parse the signed Managed Controls policy fields after the envelope is
//! authenticated.
//!
//! Port of the former Python `managed_controls_policy_fields_core` parser;
//! parity vectors are recorded by
//! `scripts/record_managed_controls_policy_fields_vectors.py`. Pure: the client
//! sends the policy document, the negotiated capabilities and a projection of
//! the command catalog, and gets back either the parsed projection or a
//! bounded `{code, message}` refusal.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

const CONTROLS_FIELD: &str = "x-hol-extension-controls";
const TARGETS_FIELD: &str = "x-hol-extension-targets";
const CONTROLS_SCHEMA: &str = "guard.extension-controls.v1";
const TARGETS_SCHEMA: &str = "guard.policy-extension-targets.v1";
const LAYER_CAP: &str = "extension-control-layer.v1";
const TARGETS_CAP: &str = "policy-extension-targets.v1";
const ATOMIC_CAP: &str = "managed-controls-atomic-apply.v1";
const PACKAGE_FIREWALL_CAP: &str = "package-firewall.v1";
const LEGACY_ALIASES: &[(&str, &str)] = &[
    ("guard.managed-extension-controls.v1", LAYER_CAP),
    ("guard.policy-extension-targets.v1", TARGETS_CAP),
    ("guard.managed-controls-atomic-apply.v1", ATOMIC_CAP),
];
const AUTHORITY_MODES: &[&str] = &["personal-shared", "workspace-shared", "managed-restrictive"];
const RESTRICTIVE: &str = "managed-restrictive";
const MAX_CONTROL_SET_RULES: usize = 1_024;
const MAX_CONTROL_SET_TARGETS: usize = 1_024;
const MAX_CONTROLS_PER_LAYER: usize = 512;
const MAX_ID_CHARS: usize = 256;
const ERR_REQUEST: &str = "native_managed_controls_policy_fields_invalid_request";

type Obj = Map<String, Value>;

struct Refusal {
    code: &'static str,
    message: String,
}

fn refuse(code: &'static str, message: impl Into<String>) -> Refusal {
    Refusal {
        code,
        message: message.into(),
    }
}

struct Extension {
    required: bool,
    delegated: bool,
}

struct Permission {
    extension_id: String,
    /// `None` when the owning Extension is not in the catalog.
    owner_delegated: Option<bool>,
    configurable: bool,
}

struct Catalog {
    extensions: BTreeMap<String, Extension>,
    permissions: BTreeMap<String, Permission>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Extension,
    Permission,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Extension => "extension",
            Self::Permission => "permission",
        }
    }
}

type Target = (Kind, String);

struct Control {
    target: Target,
    enabled: bool,
}

pub(crate) fn evaluate(request: &Value) -> Result<Value, &'static str> {
    let request = request.as_object().ok_or(ERR_REQUEST)?;
    let catalog = catalog(request.get("catalog")).ok_or(ERR_REQUEST)?;
    let capabilities = request
        .get("capabilities")
        .and_then(Value::as_array)
        .ok_or(ERR_REQUEST)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect::<Option<BTreeSet<String>>>()
        .ok_or(ERR_REQUEST)?;
    let document = request.get("document").ok_or(ERR_REQUEST)?;
    Ok(match parse(document, &capabilities, &catalog) {
        Ok(parsed) => json!({ "ok": parsed }),
        Err(refusal) => json!({ "error": { "code": refusal.code, "message": refusal.message } }),
    })
}

fn catalog(value: Option<&Value>) -> Option<Catalog> {
    let value = value?.as_object()?;
    let mut extensions = BTreeMap::new();
    for (id, entry) in value.get("extensions")?.as_object()? {
        let entry = entry.as_object()?;
        extensions.insert(
            id.clone(),
            Extension {
                required: entry.get("required")?.as_bool()?,
                delegated: entry.get("delegated")?.as_bool()?,
            },
        );
    }
    let mut permissions = BTreeMap::new();
    for (id, entry) in value.get("permissions")?.as_object()? {
        let entry = entry.as_object()?;
        let owner_delegated = match entry.get("owner_delegated")? {
            Value::Null => None,
            other => Some(other.as_bool()?),
        };
        permissions.insert(
            id.clone(),
            Permission {
                extension_id: entry.get("extension_id")?.as_str()?.to_owned(),
                owner_delegated,
                configurable: entry.get("configurable")?.as_bool()?,
            },
        );
    }
    Some(Catalog {
        extensions,
        permissions,
    })
}

fn mapping<'a>(
    value: Option<&'a Value>,
    code: &'static str,
    label: &str,
) -> Result<&'a Obj, Refusal> {
    value
        .and_then(Value::as_object)
        .ok_or_else(|| refuse(code, format!("{label} must be an object.")))
}

fn exact_keys(value: &Obj, allowed: &[&str], label: &str) -> Result<(), Refusal> {
    if value.keys().all(|key| allowed.contains(&key.as_str())) {
        Ok(())
    } else {
        Err(refuse(
            "unknown_field",
            format!("{label} contains unsupported fields."),
        ))
    }
}

fn rules_of(document: &Obj) -> Result<&Vec<Value>, Refusal> {
    let spec = mapping(
        document.get("spec"),
        "invalid_policy_document",
        "GuardPolicy spec",
    )?;
    spec.get("rules").and_then(Value::as_array).ok_or_else(|| {
        refuse(
            "invalid_policy_document",
            "GuardPolicy rules must be an array.",
        )
    })
}

fn rule_limit() -> Refusal {
    refuse(
        "rule_limit_exceeded",
        "Extension-targeted rules exceed the supported limit.",
    )
}

/// Reject explicit nulls and excessive targeted rules before projection.
fn validate_presence(document: &Obj) -> Result<(), Refusal> {
    if document.contains_key(CONTROLS_FIELD) {
        mapping(
            document.get(CONTROLS_FIELD),
            "invalid_extension_controls",
            CONTROLS_FIELD,
        )?;
    }
    let mut targeted = 0usize;
    for rule in rules_of(document)? {
        let rule = mapping(Some(rule), "invalid_policy_document", "GuardPolicy rule")?;
        if !rule.contains_key(TARGETS_FIELD) {
            continue;
        }
        targeted += 1;
        if targeted > MAX_CONTROL_SET_RULES {
            return Err(rule_limit());
        }
        mapping(
            rule.get(TARGETS_FIELD),
            "invalid_extension_targets",
            TARGETS_FIELD,
        )?;
    }
    Ok(())
}

fn normalize_capabilities(values: &BTreeSet<String>) -> BTreeSet<&'static str> {
    let mut normalized = BTreeSet::new();
    for item in values {
        if let Some(canonical) = [LAYER_CAP, TARGETS_CAP, ATOMIC_CAP, PACKAGE_FIREWALL_CAP]
            .into_iter()
            .find(|cap| cap == item)
        {
            normalized.insert(canonical);
        } else if let Some((_, canonical)) = LEGACY_ALIASES.iter().find(|(alias, _)| alias == item)
        {
            normalized.insert(*canonical);
        }
    }
    normalized
}

fn is_dotted_segments(text: &str) -> bool {
    // `[a-z0-9]+(?:[.-][a-z0-9]+)*`
    !text.is_empty()
        && text.split(['.', '-']).all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

fn is_extension_id(text: &str) -> bool {
    text.strip_prefix("command.")
        .is_some_and(is_dotted_segments)
}

fn is_permission_id(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("command.") else {
        return false;
    };
    // Any `.permission.` split whose halves both match the segment grammar.
    const SEPARATOR: &str = ".permission.";
    (0..rest.len()).any(|at| {
        rest.as_bytes()[at..].starts_with(SEPARATOR.as_bytes())
            && is_dotted_segments(&rest[..at])
            && is_dotted_segments(&rest[at + SEPARATOR.len()..])
    })
}

fn canonical_id(value: Option<&Value>, kind: Kind) -> Result<String, Refusal> {
    let (valid, code, message): (fn(&str) -> bool, _, _) = match kind {
        Kind::Extension => (
            is_extension_id,
            "invalid_extension_id",
            "Extension target ID is not canonical.",
        ),
        Kind::Permission => (
            is_permission_id,
            "invalid_permission_id",
            "Permission target ID is not canonical.",
        ),
    };
    match value.and_then(Value::as_str) {
        Some(text) if text.chars().count() <= MAX_ID_CHARS && valid(text) => Ok(text.to_owned()),
        _ => Err(refuse(code, message)),
    }
}

fn unknown_extension() -> Refusal {
    refuse(
        "unknown_extension_target",
        "Extension target is not in the current catalog.",
    )
}

fn unknown_permission() -> Refusal {
    refuse(
        "unknown_permission_target",
        "Permission target is not in the current catalog.",
    )
}

fn unknown_owner() -> Refusal {
    refuse(
        "unknown_extension_target",
        "Permission owner is not in the current catalog.",
    )
}

/// Whether the target's owning Extension delegates protection.
fn target_delegated(target: &Target, catalog: &Catalog) -> Result<bool, Refusal> {
    match target.0 {
        Kind::Extension => catalog
            .extensions
            .get(&target.1)
            .map(|extension| extension.delegated)
            .ok_or_else(unknown_extension),
        Kind::Permission => catalog
            .permissions
            .get(&target.1)
            .ok_or_else(unknown_permission)?
            .owner_delegated
            .ok_or_else(unknown_owner),
    }
}

fn parse_control(value: &Value, catalog: &Catalog) -> Result<(Control, bool), Refusal> {
    let control = mapping(Some(value), "invalid_control", "Extension control")?;
    exact_keys(
        control,
        &["targetKind", "targetId", "state"],
        "Extension control",
    )?;
    let kind = match control.get("targetKind").and_then(Value::as_str) {
        Some("extension") => Kind::Extension,
        Some("permission") => Kind::Permission,
        _ => {
            return Err(refuse(
                "invalid_target_kind",
                "Extension control target kind is invalid.",
            ))
        }
    };
    let enabled = match control.get("state").and_then(Value::as_str) {
        Some("enabled") => true,
        Some("disabled") => false,
        _ => {
            return Err(refuse(
                "invalid_control_state",
                "Extension control state is invalid.",
            ))
        }
    };
    let target = (kind, canonical_id(control.get("targetId"), kind)?);
    if kind == Kind::Extension && target.1.contains(".permission.") {
        // The control contract keeps permission segments out of Extension
        // targets.
        return Err(refuse(
            "invalid_extension_id",
            "Extension target ID is not canonical.",
        ));
    }
    let delegated = target_delegated(&target, catalog)?;
    Ok((Control { target, enabled }, delegated))
}

fn control_json(control: &Control) -> Value {
    json!({
        "target_kind": control.target.0.as_str(),
        "target_id": control.target.1,
        "state": if control.enabled { "enabled" } else { "disabled" },
    })
}

fn target_json(target: &Target) -> Value {
    json!({ "target_kind": target.0.as_str(), "target_id": target.1 })
}

struct Layer {
    authority_mode: String,
    projected: Vec<Control>,
    managed: Vec<Control>,
    global_lockdown: bool,
    delegated: BTreeSet<Target>,
}

/// `globalLockdown` may be absent, null or true. A number equal to one is
/// accepted as "not locked down", as the reference parser did.
fn global_lockdown(value: Option<&Value>) -> Option<bool> {
    match value {
        None | Some(Value::Null) => Some(false),
        Some(Value::Bool(true)) => Some(true),
        Some(Value::Number(number)) if number.as_f64() == Some(1.0) => Some(false),
        _ => None,
    }
}

fn parse_layer(field: &Obj, catalog: &Catalog, package_firewall: bool) -> Result<Layer, Refusal> {
    exact_keys(
        field,
        &[
            "schemaVersion",
            "authorityMode",
            "globalLockdown",
            "controls",
        ],
        CONTROLS_FIELD,
    )?;
    if field.get("schemaVersion").and_then(Value::as_str) != Some(CONTROLS_SCHEMA) {
        return Err(refuse(
            "unsupported_control_schema",
            "Extension control schema version is unsupported.",
        ));
    }
    let authority_mode = field
        .get("authorityMode")
        .and_then(Value::as_str)
        .filter(|mode| AUTHORITY_MODES.contains(mode))
        .ok_or_else(|| {
            refuse(
                "invalid_authority",
                "Managed Controls authority mode is invalid.",
            )
        })?;
    let restrictive = authority_mode == RESTRICTIVE;
    let global_lockdown = global_lockdown(field.get("globalLockdown")).ok_or_else(|| {
        refuse(
            "invalid_global_lockdown",
            "Global lockdown must be true when present.",
        )
    })?;
    if global_lockdown && !restrictive {
        return Err(refuse(
            "invalid_authority",
            "Global lockdown requires managed-restrictive authority.",
        ));
    }
    let controls = field
        .get("controls")
        .and_then(Value::as_array)
        .ok_or_else(|| refuse("invalid_shape", "Extension controls must be an array."))?;
    if controls.len() > MAX_CONTROLS_PER_LAYER {
        return Err(refuse(
            "control_limit_exceeded",
            "Extension control layer exceeds the supported limit.",
        ));
    }
    let mut states: BTreeMap<Target, bool> = BTreeMap::new();
    let mut generic = Vec::new();
    let mut managed = Vec::new();
    let mut delegated = BTreeSet::new();
    for raw in controls {
        let (control, owner_delegated) = parse_control(raw, catalog)?;
        if let Some(previous) = states.get(&control.target) {
            let reason = if *previous == control.enabled {
                "duplicate_target"
            } else {
                "conflicting_target"
            };
            return Err(refuse(
                reason,
                "Duplicate or conflicting Extension controls are not allowed.",
            ));
        }
        states.insert(control.target.clone(), control.enabled);
        if restrictive && control.enabled {
            return Err(refuse(
                "managed_restrictive_broadening",
                "Managed-restrictive controls cannot enable a capability.",
            ));
        }
        if owner_delegated {
            if !package_firewall {
                return Err(refuse(
                    "unsupported_delegated_protection",
                    "Package Firewall is required for this control target.",
                ));
            }
            delegated.insert(control.target);
            continue;
        }
        if restrictive {
            managed.push(control);
            continue;
        }
        if control.enabled {
            if control.target.0 != Kind::Permission {
                return Err(refuse(
                    "shared_enable_requires_permission",
                    "Shared Cloud enablement must target one configurable permission.",
                ));
            }
            if !catalog
                .permissions
                .get(&control.target.1)
                .is_some_and(|permission| permission.configurable)
            {
                return Err(refuse(
                    "immutable_floor",
                    "Shared Cloud enablement cannot weaken an immutable permission floor.",
                ));
            }
        }
        if control.target.0 == Kind::Extension
            && !control.enabled
            && catalog
                .extensions
                .get(&control.target.1)
                .is_some_and(|extension| extension.required)
        {
            return Err(refuse(
                "immutable_floor",
                "A required Extension cannot be disabled by shared Cloud posture.",
            ));
        }
        generic.push(control);
    }
    let (projected, managed) = if restrictive {
        (managed, Vec::new())
    } else {
        (generic, managed)
    };
    // In managed-restrictive mode the signed layer and managed controls are
    // the same list; the client duplicates it.
    Ok(Layer {
        authority_mode: authority_mode.to_owned(),
        projected,
        managed,
        global_lockdown,
        delegated,
    })
}

fn parse_ids(value: Option<&Value>, label: &str, kind: Kind) -> Result<Vec<String>, Refusal> {
    let items = value
        .and_then(Value::as_array)
        .ok_or_else(|| refuse("invalid_shape", format!("{label} must be an array.")))?;
    if items.len() > MAX_CONTROL_SET_TARGETS {
        return Err(refuse(
            "target_limit_exceeded",
            format!("{label} exceeds the supported limit."),
        ));
    }
    let mut parsed = items
        .iter()
        .map(|item| canonical_id(Some(item), kind))
        .collect::<Result<Vec<_>, _>>()?;
    parsed.sort();
    if parsed.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(refuse(
            "duplicate_target",
            format!("{label} contains a duplicate target."),
        ));
    }
    Ok(parsed)
}

fn package_firewall_required(what: &str) -> Refusal {
    refuse(
        "unsupported_delegated_protection",
        format!("Package Firewall is required for this {what} target."),
    )
}

fn parse_rule_targets(
    document: &Obj,
    catalog: &Catalog,
    package_firewall: bool,
) -> Result<(Vec<Value>, BTreeSet<Target>), Refusal> {
    let mut parsed = Vec::new();
    let mut delegated = BTreeSet::new();
    let mut total = 0usize;
    let mut targeted = 0usize;
    for rule in rules_of(document)? {
        let rule = mapping(Some(rule), "invalid_policy_document", "GuardPolicy rule")?;
        if !rule.contains_key(TARGETS_FIELD) {
            continue;
        }
        targeted += 1;
        if targeted > MAX_CONTROL_SET_RULES {
            return Err(rule_limit());
        }
        let targets = mapping(
            rule.get(TARGETS_FIELD),
            "invalid_extension_targets",
            TARGETS_FIELD,
        )?;
        exact_keys(
            targets,
            &["schemaVersion", "extensionIds", "permissionIds"],
            TARGETS_FIELD,
        )?;
        if targets.get("schemaVersion").and_then(Value::as_str) != Some(TARGETS_SCHEMA) {
            return Err(refuse(
                "unsupported_target_schema",
                "Extension target schema version is unsupported.",
            ));
        }
        let extension_ids =
            parse_ids(targets.get("extensionIds"), "extensionIds", Kind::Extension)?;
        let permission_ids = parse_ids(
            targets.get("permissionIds"),
            "permissionIds",
            Kind::Permission,
        )?;
        total += extension_ids.len() + permission_ids.len();
        if total > MAX_CONTROL_SET_TARGETS {
            return Err(refuse(
                "target_limit_exceeded",
                "Control Set targets exceed the supported limit.",
            ));
        }
        for extension_id in &extension_ids {
            let extension = catalog
                .extensions
                .get(extension_id)
                .ok_or_else(unknown_extension)?;
            if extension.delegated {
                if !package_firewall {
                    return Err(package_firewall_required("Extension"));
                }
                delegated.insert((Kind::Extension, extension_id.clone()));
            }
        }
        for permission_id in &permission_ids {
            let permission = catalog
                .permissions
                .get(permission_id)
                .ok_or_else(unknown_permission)?;
            if !extension_ids.is_empty() && !extension_ids.contains(&permission.extension_id) {
                return Err(refuse(
                    "target_owner_mismatch",
                    "Permission target is not owned by one of the rule's Extension targets.",
                ));
            }
            if permission.owner_delegated.ok_or_else(unknown_owner)? {
                if !package_firewall {
                    return Err(package_firewall_required("permission"));
                }
                delegated.insert((Kind::Permission, permission_id.clone()));
            }
        }
        let rule_id = rule
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                refuse(
                    "invalid_policy_document",
                    "Extension-targeted rule requires an ID.",
                )
            })?;
        parsed.push(json!({
            "rule_id": rule_id,
            "extension_ids": extension_ids,
            "permission_ids": permission_ids,
        }));
    }
    Ok((parsed, delegated))
}

fn parse(
    document: &Value,
    capabilities: &BTreeSet<String>,
    catalog: &Catalog,
) -> Result<Value, Refusal> {
    let document = mapping(Some(document), "invalid_policy_document", "GuardPolicy")?;
    validate_presence(document)?;
    let controls_present = document.contains_key(CONTROLS_FIELD);
    let targets_present = rules_of(document)?.iter().any(|rule| {
        rule.as_object()
            .is_some_and(|rule| rule.contains_key(TARGETS_FIELD))
    });
    if !controls_present && !targets_present {
        return Ok(json!({
            "authority_mode": null,
            "signed_cloud_layer": null,
            "managed_controls": [],
            "managed_global_lockdown": false,
            "rule_targets": [],
            "delegated_targets": [],
        }));
    }
    let negotiated = normalize_capabilities(capabilities);
    if ![LAYER_CAP, TARGETS_CAP, ATOMIC_CAP]
        .iter()
        .all(|cap| negotiated.contains(cap))
    {
        return Err(refuse(
            "unnegotiated_extension_semantics",
            "Managed Controls fields require the complete negotiated capability set.",
        ));
    }
    let package_firewall = negotiated.contains(PACKAGE_FIREWALL_CAP);
    let mut answer = json!({
        "authority_mode": null,
        "signed_cloud_layer": null,
        "managed_controls": [],
        "managed_global_lockdown": false,
    });
    let mut delegated = BTreeSet::new();
    if controls_present {
        let field = mapping(
            document.get(CONTROLS_FIELD),
            "invalid_extension_controls",
            CONTROLS_FIELD,
        )?;
        let layer = parse_layer(field, catalog, package_firewall)?;
        let restrictive = layer.authority_mode == RESTRICTIVE;
        let projected: Vec<Value> = layer.projected.iter().map(control_json).collect();
        let managed: Vec<Value> = if restrictive {
            projected.clone()
        } else {
            layer.managed.iter().map(control_json).collect()
        };
        answer["authority_mode"] = json!(layer.authority_mode);
        answer["signed_cloud_layer"] = json!({
            "global_lockdown": layer.global_lockdown,
            "controls": projected,
        });
        answer["managed_controls"] = json!(managed);
        answer["managed_global_lockdown"] = json!(layer.global_lockdown);
        delegated.extend(layer.delegated);
    }
    let (rule_targets, rule_delegated) = parse_rule_targets(document, catalog, package_firewall)?;
    delegated.extend(rule_delegated);
    answer["rule_targets"] = json!(rule_targets);
    answer["delegated_targets"] = json!(delegated.iter().map(target_json).collect::<Vec<_>>());
    Ok(answer)
}

#[cfg(test)]
#[path = "managed_controls_policy_fields_tests.rs"]
mod tests;
