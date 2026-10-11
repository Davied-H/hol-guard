//! Install-time protect request parsing and cached-advisory verdict, ported
//! from `protect.py` (`parse_protect_command`, `evaluate_protect_request`).
//!
//! Pure: the caller supplies the wrapped command and the cached advisory rows.
//! Parsing never touches the filesystem; `Path(...).name` and
//! `urlparse(...).path` are emulated on the token text.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::cloud_audit_sync::{urlparse_path_end, urlsplit};
use crate::command_launcher_floors::shlex_quote;
use crate::hook_adapter_pyjson::{parse_python_json, PyJsonError};
use crate::hook_adapter_value::OValue;
use crate::package_manager_command::strip_package_manager_global_options;
use crate::target_identities::{advisory_matches_target, build_package_url, py_str, py_truthy};
use crate::workspace_inventory::python_strip;

const URL_PREFIXES: [&str; 4] = ["http://", "https://", "git+", "file:"];

/// Typed failure the resident reports instead of a request; the caller raises
/// the same `ValueError` Python's `urlparse` would have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectParseError {
    /// `urllib.parse.urlparse` raised `ValueError` for a package spec.
    InvalidUrl(String),
    /// A registration payload is valid JSON the port cannot represent.
    UnsupportedPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectTarget {
    pub artifact_id: String,
    pub artifact_name: String,
    pub artifact_type: String,
    pub ecosystem: String,
    pub package_name: Option<String>,
    pub package_url: Option<String>,
    pub raw_spec: Option<String>,
    pub version: Option<String>,
    pub source_url: Option<String>,
    pub harness: Option<String>,
}

impl ProtectTarget {
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("artifact_id".into(), self.artifact_id.clone().into());
        map.insert("artifact_name".into(), self.artifact_name.clone().into());
        map.insert("artifact_type".into(), self.artifact_type.clone().into());
        map.insert("ecosystem".into(), self.ecosystem.clone().into());
        map.insert("package_name".into(), self.package_name.clone().into());
        map.insert("package_url".into(), self.package_url.clone().into());
        map.insert("raw_spec".into(), self.raw_spec.clone().into());
        map.insert("version".into(), self.version.clone().into());
        map.insert("source_url".into(), self.source_url.clone().into());
        map.insert("harness".into(), self.harness.clone().into());
        Value::Object(map)
    }

    /// `ProtectTargetIdentity` view used by `advisory_matches_target`.
    fn identity(&self) -> Value {
        let mut map = Map::new();
        map.insert("artifact_id".into(), self.artifact_id.clone().into());
        map.insert("artifact_name".into(), self.artifact_name.clone().into());
        map.insert("ecosystem".into(), self.ecosystem.clone().into());
        map.insert("package_name".into(), self.package_name.clone().into());
        map.insert("package_url".into(), self.package_url.clone().into());
        map.insert("source_url".into(), self.source_url.clone().into());
        Value::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectRequest {
    pub command: Vec<String>,
    pub install_kind: String,
    pub executor: String,
    pub package_manager: Option<String>,
    pub harness: Option<String>,
    pub targets: Vec<ProtectTarget>,
}

impl ProtectRequest {
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("command".into(), self.command.clone().into());
        map.insert("install_kind".into(), self.install_kind.clone().into());
        map.insert("executor".into(), self.executor.clone().into());
        map.insert(
            "package_manager".into(),
            self.package_manager.clone().into(),
        );
        map.insert("harness".into(), self.harness.clone().into());
        map.insert(
            "targets".into(),
            Value::Array(self.targets.iter().map(ProtectTarget::to_value).collect()),
        );
        Value::Object(map)
    }
}

/// Verdict over the cached advisories; `matched` indexes the input rows in
/// severity order (highest first, stable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectVerdict {
    pub action: &'static str,
    pub reason: String,
    pub risk_signals: Vec<String>,
    pub matched: Vec<usize>,
}

fn registration(
    command: &[String],
    executor: &str,
    harness: &str,
    target: ProtectTarget,
) -> ProtectRequest {
    ProtectRequest {
        command: command.to_vec(),
        install_kind: "harness_registration".into(),
        executor: executor.into(),
        package_manager: None,
        harness: Some(harness.into()),
        targets: vec![target],
    }
}

#[allow(clippy::too_many_arguments)]
fn target(
    artifact_id: String,
    artifact_name: &str,
    artifact_type: &str,
    ecosystem: &str,
    package_name: Option<String>,
    package_url: Option<String>,
    raw_spec: Option<String>,
    version: Option<String>,
    source_url: Option<String>,
    harness: Option<&str>,
) -> ProtectTarget {
    ProtectTarget {
        artifact_id,
        artifact_name: artifact_name.into(),
        artifact_type: artifact_type.into(),
        ecosystem: ecosystem.into(),
        package_name,
        package_url,
        raw_spec,
        version,
        source_url,
        harness: harness.map(str::to_owned),
    }
}

/// `Path(text).name` for the host's pathlib flavour.
fn path_name(text: &str) -> &str {
    #[cfg(windows)]
    let (text, separators): (&str, &[char]) = {
        let bytes = text.as_bytes();
        let text = if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
            &text[2..]
        } else {
            text
        };
        (text, &['/', '\\'])
    };
    #[cfg(not(windows))]
    let separators: &[char] = &['/'];
    text.split(separators)
        .rfind(|part| !part.is_empty() && *part != ".")
        .unwrap_or("")
}

fn starts_with_url(text: &str) -> bool {
    URL_PREFIXES.iter().any(|prefix| text.starts_with(prefix))
}

fn shlex_join(command: &[String]) -> String {
    command
        .iter()
        .map(|token| shlex_quote(token))
        .collect::<Vec<_>>()
        .join(" ")
}

fn command_fingerprint(command: &[String]) -> String {
    let digest = Sha256::digest(command.join("\u{0}").as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn option_value(command: &[String], option: &str) -> Option<String> {
    command
        .iter()
        .position(|value| value == option)
        .filter(|index| index + 1 < command.len())
        .map(|index| command[index + 1].clone())
}

fn first_url(command: &[String]) -> Option<String> {
    command.iter().find(|value| starts_with_url(value)).cloned()
}

fn remaining_positionals(args: &[String]) -> Vec<String> {
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        if token == "--" {
            positionals.extend(args[index + 1..].iter().cloned());
            break;
        }
        let takes_value = index + 1 < args.len() && !args[index + 1].starts_with('-');
        if token.starts_with("--") {
            index += if !token.contains('=') && takes_value {
                2
            } else {
                1
            };
            continue;
        }
        if token.starts_with('-') && token != "-" {
            index += if token.chars().count() == 2 && takes_value {
                2
            } else {
                1
            };
            continue;
        }
        positionals.push(token.clone());
        index += 1;
    }
    positionals
}

fn spec_name(spec: &str) -> Result<Option<String>, ProtectParseError> {
    if starts_with_url(spec) {
        let parts = urlsplit(spec).map_err(ProtectParseError::InvalidUrl)?;
        let path = &parts.path[..urlparse_path_end(&parts)];
        let candidate = path_name(if path.is_empty() { spec } else { path });
        return Ok(Some(
            if candidate.is_empty() {
                spec
            } else {
                candidate
            }
            .to_owned(),
        ));
    }
    if spec.starts_with("./") || spec.starts_with("../") || spec.starts_with('/') {
        let name = path_name(spec);
        return Ok(Some(if name.is_empty() { spec } else { name }.to_owned()));
    }
    Ok((!spec.is_empty()).then(|| spec.to_owned()))
}

fn spec_url(spec: &str) -> Option<String> {
    starts_with_url(spec).then(|| spec.to_owned())
}

fn target_name_from_spec(spec: &str) -> Result<String, ProtectParseError> {
    Ok(match spec_name(spec)? {
        Some(name) => name.strip_suffix(".git").unwrap_or(&name).to_owned(),
        None => spec.to_owned(),
    })
}

fn split_once_owned(spec: &str, separator: &str, last: bool) -> (Option<String>, Option<String>) {
    let split = if last {
        spec.rsplit_once(separator)
    } else {
        spec.split_once(separator)
    };
    let (name, version) = split.expect("separator presence checked by caller");
    (Some(name.to_owned()), Some(version.to_owned()))
}

fn parse_package_identity(
    ecosystem: &str,
    spec: &str,
) -> Result<(Option<String>, Option<String>), ProtectParseError> {
    if matches!(ecosystem, "pip" | "uv") && spec.contains("==") {
        return Ok(split_once_owned(spec, "==", false));
    }
    if ecosystem == "go" && spec.contains('@') {
        return Ok(split_once_owned(spec, "@", true));
    }
    if spec.starts_with('@') {
        if spec.matches('@').count() >= 2 {
            return Ok(split_once_owned(spec, "@", true));
        }
        return Ok((Some(spec.to_owned()), None));
    }
    if spec.contains('@') && !starts_with_url(spec) {
        return Ok(split_once_owned(spec, "@", true));
    }
    Ok((spec_name(spec)?, None))
}

fn package_target(ecosystem: &str, spec: &str) -> Result<ProtectTarget, ProtectParseError> {
    let (package_name, version) = parse_package_identity(ecosystem, spec)?;
    let package_name = package_name.map(|name| python_strip(&name).to_owned());
    let version = version.map(|version| python_strip(&version).to_owned());
    let source_url = spec_url(spec).or_else(|| version.as_deref().and_then(spec_url));
    let identity = package_name
        .clone()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| spec.to_owned());
    Ok(target(
        format!("install:{ecosystem}:{identity}"),
        &identity,
        &format!("{ecosystem}_package"),
        ecosystem,
        package_name.clone(),
        build_package_url(ecosystem, package_name.as_deref(), version.as_deref()),
        Some(spec.to_owned()),
        version,
        source_url,
        None,
    ))
}

fn collect_package_specs(values: &[String]) -> Vec<String> {
    const VALUE_OPTIONS: [&str; 6] = [
        "-r",
        "--extra-index-url",
        "--index-url",
        "--prefix",
        "--registry",
        "--requirement",
    ];
    let mut specs = Vec::new();
    let mut skip_next = false;
    for (index, value) in values.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if value.starts_with('-') {
            skip_next = VALUE_OPTIONS.contains(&value.as_str());
            continue;
        }
        if index > 0 && matches!(values[index - 1].as_str(), "-r" | "--requirement") {
            continue;
        }
        specs.push(value.clone());
    }
    specs
}

fn package_manager_request(
    command: &[String],
    ecosystem: &str,
    specs: &[String],
) -> Result<ProtectRequest, ProtectParseError> {
    let mut targets = specs
        .iter()
        .map(|spec| package_target(ecosystem, spec))
        .collect::<Result<Vec<_>, _>>()?;
    if targets.is_empty() {
        targets.push(target(
            format!(
                "install:{ecosystem}:{}",
                &command_fingerprint(command)[..16]
            ),
            ecosystem,
            "package_request",
            ecosystem,
            None,
            None,
            Some(shlex_join(command)),
            None,
            first_url(command),
            None,
        ));
    }
    Ok(ProtectRequest {
        command: command.to_vec(),
        install_kind: "package_install".into(),
        executor: ecosystem.into(),
        package_manager: Some(ecosystem.into()),
        harness: None,
        targets,
    })
}

fn specs_after(command: &[String], verbs: &[&str]) -> Vec<String> {
    if command.len() > 1 && verbs.contains(&command[1].as_str()) {
        collect_package_specs(&command[2..])
    } else {
        Vec::new()
    }
}

fn parse_package_manager(
    command: &[String],
    ecosystem: &str,
) -> Result<ProtectRequest, ProtectParseError> {
    let specs = match ecosystem {
        "go" => specs_after(command, &["get", "install"]),
        _ => {
            let normalized = strip_package_manager_global_options(command);
            match ecosystem {
                "npm" => specs_after(&normalized, &["install", "add", "i"]),
                "pnpm" => specs_after(&normalized, &["add", "install"]),
                "pip" => specs_after(&normalized, &["install"]),
                "yarn" => {
                    let working = if normalized.len() >= 4 && normalized[1] == "workspace" {
                        std::iter::once(normalized[0].clone())
                            .chain(normalized[3..].iter().cloned())
                            .collect()
                    } else {
                        normalized
                    };
                    specs_after(&working, &["add"])
                }
                _ => {
                    if normalized.len() >= 3 && normalized[1] == "pip" && normalized[2] == "install"
                    {
                        collect_package_specs(&normalized[3..])
                    } else {
                        specs_after(&normalized, &["add"])
                    }
                }
            }
        }
    };
    package_manager_request(command, ecosystem, &specs)
}

fn simple_registration(
    command: &[String],
    executor: &str,
    ecosystem: &str,
    artifact_type: &str,
) -> ProtectRequest {
    let name = &command[3];
    registration(
        command,
        executor,
        ecosystem,
        target(
            format!("install:{ecosystem}:{name}"),
            name,
            artifact_type,
            ecosystem,
            Some(name.clone()),
            None,
            Some(name.clone()),
            None,
            option_value(command, "--url"),
            Some(ecosystem),
        ),
    )
}

fn verb_is(command: &[String], first: &str, second: &str) -> bool {
    command[1] == first && command[2] == second
}

fn parse_codex(command: &[String]) -> Result<ProtectRequest, ProtectParseError> {
    if command.len() >= 4 && verb_is(command, "mcp", "add") {
        return Ok(simple_registration(command, "codex", "codex", "mcp_server"));
    }
    Ok(parse_custom(command))
}

fn parse_cursor(command: &[String]) -> Result<ProtectRequest, ProtectParseError> {
    if command.len() >= 4 && verb_is(command, "mcp", "add") {
        return Ok(simple_registration(
            command,
            "cursor",
            "cursor",
            "mcp_server",
        ));
    }
    Ok(parse_custom(command))
}

fn parse_opencode(command: &[String]) -> Result<ProtectRequest, ProtectParseError> {
    if command.len() >= 4
        && matches!(command[1].as_str(), "plugin" | "skill")
        && matches!(command[2].as_str(), "add" | "install")
    {
        let artifact_type = if command[1] == "plugin" {
            "plugin"
        } else {
            "skill"
        };
        return Ok(simple_registration(
            command,
            "opencode",
            "opencode",
            artifact_type,
        ));
    }
    Ok(parse_custom(command))
}

fn parse_claude(command: &[String]) -> Result<ProtectRequest, ProtectParseError> {
    if command.len() >= 5 && verb_is(command, "mcp", "add") {
        let positional = remaining_positionals(&command[3..]);
        if positional.len() < 2 {
            return Ok(parse_custom(command));
        }
        let (name, command_or_url) = (&positional[0], &positional[1]);
        let source_url = (command_or_url.starts_with("http://")
            || command_or_url.starts_with("https://"))
        .then(|| command_or_url.clone());
        return Ok(registration(
            command,
            "claude",
            "claude-code",
            target(
                format!("install:claude-code:mcp:{name}"),
                name,
                "mcp_server",
                "claude-code",
                Some(name.clone()),
                None,
                Some(command_or_url.clone()),
                None,
                source_url,
                Some("claude-code"),
            ),
        ));
    }
    if command.len() >= 5 && verb_is(command, "mcp", "add-json") {
        let positional = remaining_positionals(&command[3..]);
        if positional.len() < 2 {
            return Ok(parse_custom(command));
        }
        let target =
            json_registration_target(&positional[1], "claude-code", Some(&positional[0]), true)?;
        return Ok(registration(command, "claude", "claude-code", target));
    }
    Ok(parse_custom(command))
}

fn parse_gemini(command: &[String]) -> Result<ProtectRequest, ProtectParseError> {
    if command.len() >= 4 && verb_is(command, "extensions", "install") {
        return Ok(simple_registration(
            command,
            "gemini",
            "gemini",
            "extension",
        ));
    }
    if command.len() >= 4
        && (verb_is(command, "extensions", "link")
            || verb_is(command, "skills", "install")
            || verb_is(command, "skills", "link"))
    {
        let spec = &command[3];
        let name = target_name_from_spec(spec)?;
        let extension = command[1] == "extensions";
        let artifact_type = if extension { "extension" } else { "skill" };
        let package_name = extension.then(|| name.clone());
        return Ok(registration(
            command,
            "gemini",
            "gemini",
            target(
                format!("install:gemini:{artifact_type}:{name}"),
                &name,
                artifact_type,
                "gemini",
                package_name.clone(),
                build_package_url("gemini", package_name.as_deref(), None),
                Some(spec.clone()),
                None,
                spec_url(spec),
                Some("gemini"),
            ),
        ));
    }
    if command.len() >= 5 && verb_is(command, "mcp", "add") {
        let (name, command_or_url) = (&command[3], &command[4]);
        let transport =
            option_value(command, "--transport").or_else(|| option_value(command, "--type"));
        let source_url = is_remote_transport(command_or_url, transport.as_deref())
            .then(|| command_or_url.clone());
        return Ok(registration(
            command,
            "gemini",
            "gemini",
            target(
                format!("install:gemini:mcp:{name}"),
                name,
                "mcp_server",
                "gemini",
                Some(name.clone()),
                None,
                Some(command_or_url.clone()),
                None,
                source_url,
                Some("gemini"),
            ),
        ));
    }
    Ok(parse_custom(command))
}

fn parse_antigravity(command: &[String]) -> Result<ProtectRequest, ProtectParseError> {
    if let Some(extension) = option_value(command, "--install-extension") {
        return Ok(registration(
            command,
            "antigravity",
            "antigravity",
            target(
                format!("install:antigravity:extension:{extension}"),
                &extension,
                "extension",
                "antigravity",
                Some(extension.clone()),
                build_package_url("antigravity", Some(&extension), None),
                Some(extension.clone()),
                None,
                spec_url(&extension),
                Some("antigravity"),
            ),
        ));
    }
    if let Some(raw_payload) = option_value(command, "--add-mcp") {
        let target = json_registration_target(&raw_payload, "antigravity", None, false)?;
        return Ok(registration(command, "antigravity", "antigravity", target));
    }
    Ok(parse_custom(command))
}

/// `_parse_claude_mcp_target` / `_parse_antigravity_mcp_target`: a JSON MCP
/// server registration payload; anything but a JSON object reads as `{}`.
fn json_registration_target(
    raw_payload: &str,
    ecosystem: &str,
    name: Option<&String>,
    reads_transport: bool,
) -> Result<ProtectTarget, ProtectParseError> {
    let payload = match parse_python_json(raw_payload) {
        Ok(OValue::Map(map)) => Some(map),
        Ok(_) | Err(PyJsonError::Decode) => None,
        Err(PyJsonError::Unsupported) => return Err(ProtectParseError::UnsupportedPayload),
    };
    let text = |key: &str| match payload.as_ref().and_then(|map| map.get(key)) {
        Some(OValue::Str(value)) => Some(value.clone()),
        _ => None,
    };
    let name = match name {
        Some(name) => name.clone(),
        None => text("name").unwrap_or_else(|| "antigravity-mcp".to_owned()),
    };
    let transport = if reads_transport {
        text("transport")
    } else {
        None
    };
    let command_or_url = text("url").or_else(|| text("command"));
    let source_url =
        command_or_url.filter(|value| is_remote_transport(value, transport.as_deref()));
    let prefix = if ecosystem == "antigravity" {
        "install:antigravity:mcp"
    } else {
        "install:claude-code:mcp"
    };
    Ok(target(
        format!("{prefix}:{name}"),
        &name,
        "mcp_server",
        ecosystem,
        Some(name.clone()),
        None,
        Some(raw_payload.to_owned()),
        None,
        source_url,
        Some(ecosystem),
    ))
}

fn is_remote_transport(command_or_url: &str, transport: Option<&str>) -> bool {
    transport != Some("stdio")
        && (command_or_url.starts_with("http://") || command_or_url.starts_with("https://"))
}

fn parse_custom(command: &[String]) -> ProtectRequest {
    let executable = path_name(&command[0]);
    ProtectRequest {
        command: command.to_vec(),
        install_kind: "custom".into(),
        executor: executable.into(),
        package_manager: None,
        harness: None,
        targets: vec![target(
            format!("install:custom:{}", &command_fingerprint(command)[..16]),
            executable,
            "custom_command",
            "custom",
            None,
            None,
            Some(shlex_join(command)),
            None,
            first_url(command),
            None,
        )],
    }
}

/// `parse_protect_command`: dispatch on the lower-cased executable name.
pub fn parse_protect_command(command: &[String]) -> Result<ProtectRequest, ProtectParseError> {
    let Some(first) = command.first() else {
        return Ok(parse_custom(&[String::new()]));
    };
    match path_name(first).to_lowercase().as_str() {
        "npm" => parse_package_manager(command, "npm"),
        "pnpm" => parse_package_manager(command, "pnpm"),
        "yarn" => parse_package_manager(command, "yarn"),
        "pip" | "pip3" => parse_package_manager(command, "pip"),
        "uv" => parse_package_manager(command, "uv"),
        "go" => parse_package_manager(command, "go"),
        "claude" => parse_claude(command),
        "codex" => parse_codex(command),
        "cursor" => parse_cursor(command),
        "antigravity" => parse_antigravity(command),
        "gemini" => parse_gemini(command),
        "opencode" => parse_opencode(command),
        _ => Ok(parse_custom(command)),
    }
}

fn severity_rank(advisory: &Map<String, Value>) -> u8 {
    match advisory.get("severity").and_then(Value::as_str) {
        Some("low") => 0,
        Some("high") => 2,
        Some("critical") => 3,
        _ => 1,
    }
}

fn advisory_action(advisory: &Map<String, Value>) -> &'static str {
    match advisory.get("action").and_then(Value::as_str) {
        Some("allow") => "allow",
        Some("review") => "review",
        Some("block") => "block",
        _ if severity_rank(advisory) >= 2 => "block",
        _ => "review",
    }
}

fn advisory_headline(advisory: &Map<String, Value>) -> String {
    if let Some(headline) = advisory.get("headline").and_then(Value::as_str) {
        let stripped = python_strip(headline);
        if !stripped.is_empty() {
            return stripped.to_owned();
        }
    }
    let artifact = ["package", "name", "artifact_id"]
        .iter()
        .filter_map(|key| advisory.get(*key))
        .find(|value| py_truthy(value))
        .map_or_else(|| "Artifact".to_owned(), py_str);
    format!("{artifact} matched a Guard advisory.")
}

fn request_risk_signals(request: &ProtectRequest) -> Vec<String> {
    let joined = request.command.join(" ").to_lowercase();
    let mentions = |needles: &[&str]| needles.iter().any(|needle| joined.contains(needle));
    let mut signals: Vec<&str> = Vec::new();
    if request.install_kind == "harness_registration" {
        if request.targets.iter().any(|t| t.source_url.is_some()) {
            signals.push("registers a remote server endpoint");
        }
        if request
            .targets
            .iter()
            .any(|t| matches!(t.artifact_type.as_str(), "extension" | "plugin" | "skill"))
        {
            signals.push("registers executable harness code");
        }
        if mentions(&["http://", "https://", "curl ", "wget "]) {
            signals.push("can fetch or talk to a remote server during registration");
        }
    }
    if mentions(&[".env", "printenv", "process.env", "os.environ", "getenv("]) {
        signals.push("references local environment secrets");
    }
    if mentions(&[
        ".ssh",
        ".npmrc",
        ".pypirc",
        ".gitconfig",
        "id_rsa",
        "credentials",
    ]) {
        signals.push("mentions sensitive local files");
    }
    if mentions(&[
        "bash -c",
        "bash -lc",
        "sh -c",
        "zsh -c",
        "powershell -command",
    ]) {
        signals.push("runs through a shell wrapper");
    }
    for target in &request.targets {
        if target.artifact_type == "custom_command" {
            continue;
        }
        let spec = target.raw_spec.as_deref().unwrap_or("");
        if starts_with_url(spec)
            || spec.starts_with("./")
            || spec.starts_with("../")
            || spec.starts_with('/')
        {
            signals.push("installs from a non-registry source");
        }
    }
    let mut deduped: Vec<String> = Vec::new();
    for signal in signals {
        if !deduped.iter().any(|seen| seen == signal) {
            deduped.push(signal.to_owned());
        }
    }
    deduped
}

/// `evaluate_protect_request` over the cached advisory rows (each the
/// `list_cached_advisories` dict).
pub fn evaluate_protect_request(request: &ProtectRequest, advisories: &[Value]) -> ProtectVerdict {
    let risk_signals = request_risk_signals(request);
    let identities: Vec<Value> = request
        .targets
        .iter()
        .map(ProtectTarget::identity)
        .collect();
    let mut matched: Vec<usize> = advisories
        .iter()
        .enumerate()
        .filter(|(_, advisory)| {
            identities
                .iter()
                .any(|identity| advisory_matches_target(advisory, identity))
        })
        .map(|(index, _)| index)
        .collect();
    let row = |index: usize| {
        advisories[index]
            .as_object()
            .expect("matched rows are objects")
    };
    matched.sort_by_key(|index| std::cmp::Reverse(severity_rank(row(*index))));
    let first_with = |action: &str| {
        matched
            .iter()
            .copied()
            .find(|index| advisory_action(row(*index)) == action)
    };
    if let Some(index) = first_with("block") {
        return ProtectVerdict {
            action: "block",
            reason: format!(
                "{} Guard blocked the install before the artifact landed locally.",
                advisory_headline(row(index))
            ),
            risk_signals,
            matched,
        };
    }
    let review = first_with("review");
    if !risk_signals.is_empty() || review.is_some() {
        let reason = if let Some(index) = review {
            format!(
                "{} Guard paused this install for review.",
                advisory_headline(row(index))
            )
        } else if risk_signals
            .iter()
            .any(|s| s == "registers a remote server endpoint")
        {
            "This request registers a remote server endpoint. Guard paused it until you review the target.".to_owned()
        } else if risk_signals
            .iter()
            .any(|s| s == "installs from a non-registry source")
        {
            "This request pulls code from a non-registry source. Guard paused it for review before install.".to_owned()
        } else {
            "Guard found install-time risk signals that should be reviewed before this command runs."
                .to_owned()
        };
        return ProtectVerdict {
            action: "review",
            reason,
            risk_signals,
            matched,
        };
    }
    ProtectVerdict {
        action: "allow",
        reason: "Guard found no blocking advisory or risky install signal for this request."
            .to_owned(),
        risk_signals,
        matched,
    }
}

#[cfg(test)]
#[path = "protect_request_tests.rs"]
mod tests;
