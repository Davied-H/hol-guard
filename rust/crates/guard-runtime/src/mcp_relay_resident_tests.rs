use std::collections::BTreeMap;

use guard_contracts::McpToolArgumentsV1;
use serde_json::json;

use super::request::{arguments, delegated_tool, launcher_home, launcher_path, python_stable};
use super::*;
use crate::mcp_relay_decide::McpRelayDecideRequestV1;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mcp_relay_resident_{}_{}_{}",
        std::process::id(),
        tag,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn relay_args(guard_home: &Path, workspace: Option<PathBuf>) -> RelayArgs {
    RelayArgs {
        harness: "codex",
        elicitation_capable: true,
        guard_home: guard_home.to_path_buf(),
        home: None,
        workspace,
        server_name: "files".to_owned(),
        server_id: Some("srv".to_owned()),
        source_scope: "project".to_owned(),
        config_path: "/work/.codex/config.toml".to_owned(),
        transport: "stdio".to_owned(),
        command: "npx".to_owned(),
        args: vec!["-y".to_owned(), "server-files".to_owned()],
        server_env_keys: vec!["API_TOKEN".to_owned(), "REGION".to_owned()],
    }
}

fn launch(identity: Value) -> Launch {
    let launch_env: BTreeMap<String, String> = [
        ("PATH".to_owned(), "/usr/bin".to_owned()),
        ("API_TOKEN".to_owned(), "secret".to_owned()),
    ]
    .into_iter()
    .collect();
    Launch {
        argv: vec!["/usr/bin/npx".to_owned()],
        child_env: launch_env.clone(),
        launch_env,
        identity,
        cwd: PathBuf::from("/"),
    }
}

fn identity() -> Value {
    json!({
        "executable": {"path": "/usr/bin/npx", "sha256": "ab"},
        "launch_cwd": "/work",
        "entrypoint": {"kind": "not-applicable"},
    })
}

fn process(cwd: &Path) -> ProcessFacts {
    ProcessFacts {
        path: Some(OsString::from("/usr/bin:/bin")),
        home: Some(OsString::from("/home/user/")),
        cwd: Some(cwd.to_path_buf()),
    }
}

fn facts() -> RelayFacts {
    let guard_home = temp_dir("facts");
    let args = relay_args(&guard_home, None);
    relay_facts(&args, &launch(identity()), &process(&guard_home)).unwrap()
}

fn params(value: Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap()
}

#[test]
fn session_facts_bind_the_launch_once() {
    let guard_home = temp_dir("bind");
    let workspace = temp_dir("bind_ws");
    let args = relay_args(&guard_home, Some(workspace.clone()));
    let facts = relay_facts(&args, &launch(identity()), &process(&guard_home)).unwrap();
    let canonical = |path: &Path| {
        std::fs::canonicalize(path)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(facts.guard_home, canonical(&guard_home));
    assert_eq!(facts.workspace.as_deref(), workspace.to_str());
    assert_eq!(facts.hash_workspace, canonical(&workspace));
    assert_eq!(facts.launcher_path.as_deref(), Some("/usr/bin:/bin"));
    assert_eq!(facts.launcher_home, "/home/user");
    assert_eq!(
        facts.fingerprint["command"],
        json!(["npx", "-y", "server-files"])
    );
    assert_eq!(
        facts.fingerprint["resolved_executable"],
        json!({
            "path": "/usr/bin/npx",
            "sha256": "ab",
            "command": "npx",
            "launch_cwd": "/work",
            "entrypoint": {"kind": "not-applicable"},
        })
    );
    let hash = facts.fingerprint["configured_env_values_hash"]
        .as_str()
        .unwrap();
    assert_eq!(hash.len(), 64);
    assert_eq!(
        facts.server_identity["env_values_hash"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        facts.server_identity["env_keys"],
        json!(["API_TOKEN", "REGION"])
    );
    assert_eq!(facts.server_identity["transport"], json!("stdio"));
}

#[test]
fn session_facts_need_the_launch_identity_and_home() {
    let guard_home = temp_dir("need");
    let args = relay_args(&guard_home, None);
    let mut partial = identity();
    partial.as_object_mut().unwrap().remove("launch_cwd");
    assert!(relay_facts(&args, &launch(partial), &process(&guard_home)).is_none());
    let mut homeless = process(&guard_home);
    homeless.home = None;
    assert!(relay_facts(&args, &launch(identity()), &homeless).is_none());
    let missing = relay_args(&guard_home.join("absent"), None);
    assert!(relay_facts(&missing, &launch(identity()), &process(&guard_home)).is_none());
}

#[test]
fn launcher_path_anchors_relative_entries() {
    let mut facts = process(Path::new("/work"));
    assert_eq!(
        launcher_path(&facts),
        Some(Some("/usr/bin:/bin".to_owned()))
    );
    facts.path = Some(OsString::from("node_modules/.bin::/bin"));
    assert_eq!(
        launcher_path(&facts),
        Some(Some("/work/node_modules/.bin::/bin".to_owned()))
    );
    facts.cwd = Some(PathBuf::from("/"));
    assert_eq!(
        launcher_path(&facts),
        Some(Some("/node_modules/.bin::/bin".to_owned()))
    );
    facts.cwd = None;
    assert_eq!(launcher_path(&facts), None);
    facts.path = None;
    assert_eq!(launcher_path(&facts), Some(None));
}

#[test]
fn launcher_home_drops_trailing_separators() {
    assert_eq!(
        launcher_home(&OsString::from("/home/u//")).unwrap(),
        "/home/u"
    );
    assert_eq!(launcher_home(&OsString::from("/")).unwrap(), "/");
    assert_eq!(launcher_home(&OsString::from("")).unwrap(), "/");
}

#[test]
fn shell_and_composio_tools_are_not_sent() {
    for name in [
        "bash",
        " Shell ",
        "RUN_COMMAND",
        "composio_x",
        "a__COMPOSIO_SEARCH_TOOLS",
    ] {
        assert!(delegated_tool(name), "{name}");
    }
    for name in ["read", "bash_history", "my_composio_x", "composio__read"] {
        assert!(!delegated_tool(name), "{name}");
    }
}

#[test]
fn arguments_keep_the_host_order() {
    let value = json!({"b": 1, "a": "x"});
    let order = ["b".to_owned(), "a".to_owned()];
    assert_eq!(
        arguments(Some(&value), Some(&order[..])),
        Some(McpToolArgumentsV1::Mapping {
            entries: vec![("b".to_owned(), json!(1)), ("a".to_owned(), json!("x"))],
        })
    );
    assert_eq!(arguments(Some(&value), None), None);
    assert_eq!(arguments(Some(&value), Some(&order[..1])), None);
    let wrong = ["b".to_owned(), "c".to_owned()];
    assert_eq!(arguments(Some(&value), Some(&wrong[..])), None);
    let single = json!({"a": [1, -2, 0]});
    assert!(arguments(Some(&single), None).is_some());
    assert_eq!(
        arguments(None, None),
        Some(McpToolArgumentsV1::Other { value: Value::Null })
    );
    assert_eq!(
        arguments(Some(&json!("{\"a\":1}")), None),
        Some(McpToolArgumentsV1::Json {
            text: "{\"a\":1}".to_owned()
        })
    );
    let command = json!({"cmd": ""});
    assert_eq!(arguments(Some(&command), None), None);
}

#[test]
fn only_integers_keep_their_number_text() {
    let parse = |text: &str| serde_json::from_str::<Value>(text).unwrap();
    for text in ["0", "-7", "12345678901234567890123", "[1,{\"a\":2}]"] {
        assert!(python_stable(&parse(text)), "{text}");
    }
    for text in ["1.5", "1e5", "-0", "[1.0]", "{\"a\":2E1}"] {
        assert!(!python_stable(&parse(text)), "{text}");
    }
}

#[test]
fn request_matches_the_decide_wire_shape() {
    let facts = facts();
    let catalog = RelayCatalog::default();
    let call = params(json!({"name": "read", "arguments": {"path": "a.txt"}}));
    let (payload, expected) = decide_request(&facts, &call, None, &catalog).unwrap();
    assert_eq!(expected, catalog.snapshot());
    let payload: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(payload["operation"], json!("mcp_relay_decide"));
    let request = payload["request"].clone();
    assert_eq!(
        request["build"]["tool"],
        json!({"kind": "catalog", "entry": null})
    );
    assert_eq!(request["build"]["provider_catalog_hash"], Value::Null);
    let fingerprint = &request["build"]["server_fingerprint"];
    assert_eq!(fingerprint["tool_catalog_state"], json!(expected.state));
    assert_eq!(
        fingerprint["tool_catalog_fingerprint"],
        json!(expected.fingerprint)
    );
    assert_eq!(request["params"], json!(call));
    let decoded: McpRelayDecideRequestV1 = serde_json::from_value(request).unwrap();
    assert_eq!(decoded.build.tool_name, "read");
    assert_eq!(decoded.hash_workspace, facts.hash_workspace);
}

#[test]
fn calls_the_relay_cannot_send_are_not_requested() {
    let facts = facts();
    let catalog = RelayCatalog::default();
    for call in [
        json!({"arguments": {}}),
        json!({"name": "", "arguments": {}}),
        json!({"name": 7}),
        json!({"name": "caf\u{e9}"}),
        json!({"name": "bash", "arguments": {}}),
        json!({"name": "read", "arguments": {"a": 1.5}}),
    ] {
        assert!(
            decide_request(&facts, &params(call.clone()), None, &catalog).is_none(),
            "{call}"
        );
    }
}

#[test]
fn replies_map_to_forward_or_block() {
    let forward = json!({"schema": RESULT_SCHEMA, "outcome": "forward"});
    assert_eq!(
        reply(&serde_json::to_vec(&forward).unwrap()),
        Some(Reply::Forward)
    );
    let block = json!({
        "schema": RESULT_SCHEMA,
        "outcome": "block",
        "message": "blocked",
        "data": {"guardPolicyAction": "block"},
    });
    assert_eq!(
        reply(&serde_json::to_vec(&block).unwrap()),
        Some(Reply::Block {
            message: "blocked".to_owned(),
            data: json!({"guardPolicyAction": "block"}),
        })
    );
    for other in [
        json!({"schema": RESULT_SCHEMA, "outcome": "defer", "reason": "x"}),
        json!({"schema": "other", "outcome": "forward"}),
        json!({"schema": RESULT_SCHEMA, "outcome": "block", "message": "m"}),
    ] {
        assert_eq!(reply(&serde_json::to_vec(&other).unwrap()), None);
    }
    assert_eq!(reply(b"not json"), None);
}

#[test]
fn without_a_resident_every_call_is_blocked() {
    let message = json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "read", "arguments": {}}});
    let call = params(message["params"].clone());
    let catalog = RelayCatalog::default();
    let expected = ToolCallVerdict::Respond(no_decision_response(message.get("id"), &call));
    let mut unbound = ResidentRelayAuthority {
        facts: None,
        resident: None,
    };
    assert_eq!(unbound.decide(&message, &call, None, &catalog), expected);
    let mut unreachable = ResidentRelayAuthority {
        facts: Some(facts()),
        resident: None,
    };
    assert_eq!(
        unreachable.decide(&message, &call, None, &catalog),
        expected
    );
}
