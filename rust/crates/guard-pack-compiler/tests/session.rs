use serde_json::Value;
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn run(operation: &str, bytes: &[u8]) -> (i32, Value) {
    let mut process = Command::new(env!("CARGO_BIN_EXE_guard-pack-compiler"))
        .arg(operation)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    process.stdin.take().unwrap().write_all(bytes).unwrap();
    let result = process.wait_with_output().unwrap();
    (
        result.status.code().unwrap(),
        serde_json::from_slice(&result.stdout).unwrap(),
    )
}

#[test]
fn session_rejects_zero_truncated_and_invalid_records() {
    for (bytes, code) in [
        (vec![0; 8], "command_pack_session_length_invalid"),
        (vec![1], "command_pack_session_truncated"),
        (
            [10u64.to_be_bytes().as_slice(), b"HGPS"].concat(),
            "command_pack_stream_truncated",
        ),
    ] {
        let (status, result) = run("compile-packs-session", &bytes);
        assert_eq!(status, 2);
        assert_eq!(result["code"], code);
    }
}

#[test]
fn bootstrap_tool_cannot_export_or_evaluate_a_packaged_program() {
    for operation in [
        "export-built",
        "export-program",
        "evaluate-batch",
        "compile",
    ] {
        let (status, result) = run(operation, b"");
        assert_eq!(status, 2);
        assert_eq!(result["code"], "pack_compiler_operation_unsupported");
    }
    let (status, result) = run("schema", b"");
    assert_eq!(status, 0);
    assert!(result.is_object());
}
