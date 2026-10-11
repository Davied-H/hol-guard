//! Parity of the tokenization helpers against vectors recorded from the
//! retired Python implementation.

use std::io::Read;

use serde_json::Value;

use crate::sfrs_docker_args::{
    docker_build_args_are_sensitive, docker_buildx_subcommand_index,
    docker_subcommand_help_requested, docker_subcommand_index, shell_variable_names,
};
use crate::sfrs_shell_tokens::{
    iter_shell_command_segments, normalized_shell_command_name, shell_segment_primary_command,
    split_shell_parts,
};

fn records() -> Vec<Value> {
    let bytes = include_bytes!("../tests/fixtures/sfrs/intermediate_tokens.json.gz");
    let mut text = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut text)
        .expect("gzip");
    let document: Value = serde_json::from_str(&text).expect("json");
    document["tokens"].as_array().expect("tokens").clone()
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("list")
        .iter()
        .map(|item| item.as_str().expect("str").to_owned())
        .collect()
}

#[test]
fn tokenization_helpers_match_recorded_python() {
    let mut failures = Vec::new();
    for record in records() {
        let text = record["text"].as_str().expect("text");
        let parts = split_shell_parts(text);
        if parts != strings(&record["parts"]) {
            failures.push(format!("parts {text:?}: {parts:?} vs {}", record["parts"]));
            continue;
        }
        let segments = iter_shell_command_segments(&parts);
        let expected_segments: Vec<Vec<String>> = record["segments"]
            .as_array()
            .expect("segments")
            .iter()
            .map(strings)
            .collect();
        if segments != expected_segments {
            failures.push(format!("segments {text:?}"));
            continue;
        }
        for (index, segment) in segments.iter().enumerate() {
            let (name, at) = shell_segment_primary_command(segment);
            let expected = &record["primaries"][index];
            let actual = serde_json::json!([name, at]);
            if &actual != expected {
                failures.push(format!("primary {segment:?}: {actual} vs {expected}"));
            }
            let args = &segment[1..];
            let docker = &record["docker"][index];
            let actual = serde_json::json!([
                docker_subcommand_index(args),
                docker_build_args_are_sensitive(args),
                docker_buildx_subcommand_index(args),
                docker_subcommand_help_requested(args),
            ]);
            if &actual != docker {
                failures.push(format!("docker {segment:?}: {actual} vs {docker}"));
            }
        }
        if shell_variable_names(text) != strings(&record["variables"]) {
            failures.push(format!("variables {text:?}"));
        }
        let names: Vec<String> = parts
            .iter()
            .map(|part| normalized_shell_command_name(part))
            .collect();
        if names != strings(&record["names"]) {
            failures.push(format!("names {text:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} differ, first: {:#?}",
        failures.len(),
        &failures[..failures.len().min(8)]
    );
}
