use super::*;

#[cfg(not(windows))]
#[test]
fn recorded_python_model_and_helpers() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/native_rich_command_model.json"
    ))
    .unwrap();
    for (index, vector) in fixture["vectors"].as_array().unwrap().iter().enumerate() {
        let actual = result(vector["action"].as_str().unwrap(), &vector["args"]);
        if let Some(error) = vector.get("error") {
            assert_eq!(
                actual.unwrap_err(),
                error.as_str().unwrap(),
                "vector {index}"
            );
        } else {
            assert_eq!(actual.unwrap(), vector["result"], "vector {index}");
        }
    }
}

#[test]
fn invalid_redirect_ranges_do_not_panic_or_mask_command() {
    for (start, end) in [(2, 1), (0, 99), (99, 100), (usize::MAX, 1)] {
        assert_eq!(
            result(
                "segment_tokens",
                &json!({
                    "command": "echo hi", "source_offset": 0,
                    "redirects": [{"operator": ">", "target": "out", "start": start, "end": end}]
                })
            )
            .unwrap(),
            json!(["echo", "hi"])
        );
    }
}

#[test]
fn response_is_bound_to_exact_request_and_rejects_unknown_inputs() {
    let request = RichCommandModelRequest {
        schema: REQUEST_SCHEMA.into(),
        request_id: "fixture".into(),
        guard_home: "/fixture".into(),
        action: "parse".into(),
        args: json!({"command": "echo hi"}),
    };
    let first: Value = serde_json::from_slice(&evaluate(&request).unwrap()).unwrap();
    let changed = RichCommandModelRequest {
        args: json!({"command": "echo bye"}),
        ..request
    };
    let second: Value = serde_json::from_slice(&evaluate(&changed).unwrap()).unwrap();
    assert_ne!(first["request_sha256"], second["request_sha256"]);
    assert!(result("parse", &json!({"command": "echo hi", "extra": true})).is_err());
    assert!(result("unknown", &json!({})).is_err());
}

#[test]
fn windows_token_errors_preserve_fallback_confidence() {
    assert_eq!(
        result("windows_tokens", &json!({"command": "echo \"unterminated"})).unwrap(),
        json!([["echo", "\"unterminated"], false])
    );
    assert_eq!(
        result(
            "windows_tokens",
            &json!({"command": "echo C:\\Work\\file.txt"})
        )
        .unwrap(),
        json!([["echo", "C:\\Work\\file.txt"], true])
    );
}
