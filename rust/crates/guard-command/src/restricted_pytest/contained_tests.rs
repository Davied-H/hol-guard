use super::*;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

fn expand(value: &Value, root: &str) -> Value {
    match value {
        Value::String(text) => json!(text.replace("$ROOT", root)),
        Value::Array(items) => json!(items.iter().map(|v| expand(v, root)).collect::<Vec<_>>()),
        Value::Object(items) => Value::Object(
            items
                .iter()
                .map(|(k, v)| (k.replace("$ROOT", root), expand(v, root)))
                .collect(),
        ),
        _ => value.clone(),
    }
}

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn recorded_original_contained_execution_outcomes() {
    let root = env::temp_dir().join(format!("guard-contained-parity-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let fixture = Fixture(root.canonicalize().unwrap());
    let workspace = fixture.0.join("project");
    fs::create_dir_all(workspace.join("bin")).unwrap();
    fs::create_dir(workspace.join("tests")).unwrap();
    fs::write(workspace.join("package.json"), "{}").unwrap();
    let manifest = workspace.join("node_modules/vitest/package.json");
    fs::create_dir_all(manifest.parent().unwrap()).unwrap();
    fs::write(manifest.with_file_name("vitest.mjs"), "").unwrap();
    let node = workspace.join("bin/node");
    fs::write(&node, b"\xcf\xfa\xed\xfenative-fixture").unwrap();
    let vectors: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/contained_execution_parity.json"
    ))
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&manifest, r#"{"name":"vitest","version":"4.0.0"}"#).unwrap();
        let mut input = expand(&case["input"], fixture.0.to_str().unwrap());
        if let Some(version) = input.as_object_mut().unwrap().remove("fixture_version") {
            fs::write(
                &manifest,
                json!({"name":"vitest","version":version}).to_string(),
            )
            .unwrap();
        }
        if let Some(mode) = input.as_object_mut().unwrap().remove("fixture_mode") {
            fs::set_permissions(
                &node,
                fs::Permissions::from_mode(mode.as_u64().unwrap() as u32),
            )
            .unwrap();
        }
        if let Some(files) = case.get("fixture_files") {
            for (path, bytes) in expand(files, fixture.0.to_str().unwrap())
                .as_object()
                .unwrap()
            {
                fs::write(path, hex::decode(bytes.as_str().unwrap()).unwrap()).unwrap();
            }
        }
        let operation = case["operation"].as_str().unwrap();
        let mut expected = expand(&case["expected"], fixture.0.to_str().unwrap());
        let actual = if let Some(grants) = case.get("system_grants") {
            super::profiles::replay_profile(&input, &expand(grants, fixture.0.to_str().unwrap()))
        } else {
            evaluate_with_deadline(operation, &input, Instant::now() + Duration::from_secs(10))
        };
        if let Some(records) = expected.get_mut("value").and_then(Value::as_array_mut) {
            for record in records {
                if record.get("identity") == Some(&json!("$IDENTITY")) {
                    let path = record["path"].as_str().unwrap();
                    let m = fs::metadata(path).unwrap();
                    record["identity"] = json!([
                        m.dev(),
                        m.ino(),
                        m.len(),
                        m.mtime() as i128 * 1_000_000_000 + m.mtime_nsec() as i128,
                        m.mode()
                    ]);
                }
            }
        }
        assert_eq!(actual, expected, "operation={operation}, input={input}");
    }
}

#[test]
fn mapping_deadline_and_packed_input_fail_closed() {
    let expired = Instant::now() - Duration::from_secs(1);
    let result = evaluate_with_deadline("mapping_evidence", &json!({}), expired);
    assert_eq!(result["reason_code"], "linux_mapping_unavailable");
    let malformed = evaluate_with_deadline(
        "mapping_evidence",
        &json!({"packed_json_gzip_v1":"invalid","decoded_bytes":1}),
        Instant::now() + Duration::from_secs(1),
    );
    assert_eq!(malformed["reason_code"], "linux_mapping_unavailable");
}

#[test]
fn profile_preserves_denials_and_readonly_workspace() {
    let input = json!({"profile_version":"vitest-readonly-v1","workspace":"/guard-project","cwd":"/guard-project",
        "private_root":"/guard-private","allowed_executables":["/usr/bin/node"],"command":["/usr/bin/node"]});
    let result = evaluate("macos_profile", &input);
    let profile = result["value"].as_str().unwrap();
    assert!(profile.starts_with("(version 1)\n(deny default)\n(deny file-link)"));
    assert!(profile.contains("(allow process-exec (literal \"/usr/bin/node\"))"));
    assert!(profile.contains("(deny file-write* (literal \"/usr/bin/node\"))"));
    assert!(profile
        .contains("(allow file-write* (subpath \"/guard-private\") (literal \"/dev/null\"))"));
    for denial in super::credentials::denials(true) {
        assert!(profile.contains(&denial));
    }
}
