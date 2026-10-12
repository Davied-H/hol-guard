use super::*;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

fn expand(value: &Value, root: &str) -> Value {
    match value {
        Value::String(text) => {
            let ancestors = Path::new(root)
                .ancestors()
                .skip(1)
                .filter(|p| *p != Path::new("/"))
                .map(|p| {
                    format!(
                        "(literal {})",
                        super::credentials::seatbelt_string(&p.to_string_lossy())
                    )
                })
                .collect::<Vec<_>>()
                .join(" ");
            json!(text
                .replace("$FIXTURE_ANCESTORS", &ancestors)
                .replace("$ROOT", root))
        }
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

fn fixture(prefix: &str) -> Fixture {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).unwrap();
    let root = env::temp_dir().join(format!("{prefix}-{}", hex::encode(random)));
    fs::create_dir(&root).unwrap();
    Fixture(root.canonicalize().unwrap())
}

#[test]
fn recorded_original_contained_execution_outcomes() {
    let fixture = fixture("guard-contained-parity");
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
        if case["operation"] == "process_ceiling_snapshot" {
            continue;
        }
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
fn large_ordinary_file_index_keeps_the_mapping_deadline_for_image_inspection() {
    let input = json!({"images":[],"read_files":(0..100000).map(|i|
        format!("/guard-fixture/workspace/a/b/c/d/e/f/ordinary-{i}.txt")).collect::<Vec<_>>(),
        "runtime_roots":["/guard-fixture/runtime"],"workspace":"/guard-fixture/workspace"});
    let result = evaluate_with_deadline(
        "mapping_evidence",
        &input,
        Instant::now() + Duration::from_secs(5),
    );
    assert_eq!(result, json!({"value":[]}));
}

#[test]
fn mapping_snapshot_is_descriptor_bound_and_can_exceed_an_ipc_frame() {
    use sha2::{Digest, Sha256};
    let fixture = fixture("hol-guard-mapping-parity");
    fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).unwrap();
    let path = fixture.0.join("mapping-index.json");
    let payload = json!({"read_files":(0..100000).map(|i|format!("/guard-fixture/library/module-{i}.so")).collect::<Vec<_>>()});
    let raw = serde_json::to_vec(&payload).unwrap();
    assert!(raw.len() > 2 * 1024 * 1024);
    fs::write(&path, &raw).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut input = json!({"mapping_snapshot":path,"decoded_bytes":raw.len(),"sha256":format!("{:x}",Sha256::digest(&raw))});
    assert_eq!(super::mapping_snapshot::read(&input).unwrap(), payload);
    let records = json!((0..1024)
        .map(
            |i| json!({"path":format!("/workspace/{}-{i}","module-".repeat(430)),
        "identity":[1,i,1,1,0o100500],"sha256":"0".repeat(64)})
        )
        .collect::<Vec<_>>());
    let result = super::mapping_snapshot::write(&input, &records).unwrap();
    assert!(result["decoded_bytes"].as_u64().unwrap() > 2 * 1024 * 1024);
    assert!(serde_json::to_vec(&result).unwrap().len() < 1024);
    let output = fixture.0.join("mapping-result.json");
    assert_eq!(fs::metadata(&output).unwrap().mode() & 0o077, 0);
    let bytes = fs::read(&output).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        result["sha256"].as_str().unwrap()
    );
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), records);
    input["sha256"] = json!("0".repeat(64));
    assert!(super::mapping_snapshot::read(&input).is_err());
    input["sha256"] = json!(format!("{:x}", Sha256::digest(&raw)));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(super::mapping_snapshot::read(&input).is_err());
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
