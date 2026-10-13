use super::{launch_cwd, may_meet_custom_rule, pre_tool_command};
use serde_json::{json, Map, Value};
use std::fs;

fn object(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn scratch(label: &str) -> String {
    let root = std::env::temp_dir().join(format!(
        "hook-direct-local-cli-{label}-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    fs::canonicalize(root).unwrap().to_str().unwrap().to_owned()
}

#[test]
fn the_command_follows_the_daemon_field_order() {
    let payload = object(json!({
        "toolInput": { "cmd": "  ", "shellCommand": "make" },
        "arguments": { "command": "ls" },
        "command": "pwd",
    }));
    assert_eq!(pre_tool_command(&payload), Ok(Some("make")));
    let payload = object(json!({ "tool_input": {}, "arguments": { "command": "ls" } }));
    assert_eq!(pre_tool_command(&payload), Ok(Some("ls")));
    let payload = object(json!({ "tool_input": { "file_path": "/tmp/a" } }));
    assert_eq!(pre_tool_command(&payload), Ok(None));
}

#[test]
fn the_launch_directory_must_exist_and_be_absolute() {
    let workspace = scratch("cwd");
    let payload = object(json!({ "cwd": " " }));
    assert_eq!(
        launch_cwd(&payload, &workspace),
        Ok(Some(workspace.clone()))
    );
    let payload = object(json!({ "cwd": "relative/dir" }));
    assert_eq!(launch_cwd(&payload, &workspace), Ok(None));
    let payload = object(json!({ "cwd": format!("{workspace}/absent") }));
    assert_eq!(launch_cwd(&payload, &workspace), Ok(None));
}

#[test]
fn only_a_command_with_a_local_cli_may_meet_a_rule() {
    let workspace = scratch("rule");
    fs::write(
        format!("{workspace}/package.json"),
        br#"{"name": "demo", "scripts": {"build": "tsc"}}"#,
    )
    .unwrap();
    let run = |command: &str| object(json!({ "tool_input": { "command": command } }));
    assert!(may_meet_custom_rule(
        &run("npm run build"),
        &workspace,
        &workspace
    ));
    assert!(!may_meet_custom_rule(&run("pwd"), &workspace, &workspace));
    assert!(!may_meet_custom_rule(
        &object(json!({ "tool_input": { "file_path": "README.md" } })),
        &workspace,
        &workspace
    ));
    let elsewhere = object(json!({
        "tool_input": { "command": "npm run build" },
        "cwd": format!("{workspace}/absent"),
    }));
    assert!(!may_meet_custom_rule(&elsewhere, &workspace, &workspace));
}
