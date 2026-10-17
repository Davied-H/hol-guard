//! Offline length-framed ingestion. Bounds apply to individual raw records;
//! compiled-program and catalog-admission budgets remain independently enforced.

use super::{catalog, contract::SourceDocument, json, mcp, validation, CompiledSourceCatalog};
use serde::Deserialize;
use serde_json::Value;
use std::io::Read;

const MAGIC: &[u8; 5] = b"HGCS\x01";
const MAX_RECORDS: usize = 512; // The current complete-program extension contract.

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    schema: String,
    sources: usize,
    mcp_sources: usize,
    trust: Value,
}

#[derive(Debug)]
pub struct SourceStreamError {
    pub code: &'static str,
    /// Zero-based position in command records followed by MCP records.
    pub record: Option<usize>,
}

impl From<&'static str> for SourceStreamError {
    fn from(code: &'static str) -> Self {
        Self { code, record: None }
    }
}

fn frame(reader: &mut impl Read) -> Result<Vec<u8>, &'static str> {
    let mut length = [0; 4];
    reader
        .read_exact(&mut length)
        .map_err(|_| "command_source_stream_truncated")?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > json::MAX_SOURCE_BYTES {
        return Err("command_source_bytes_invalid");
    }
    let mut bytes = vec![0; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| "command_source_stream_truncated")?;
    Ok(bytes)
}

/// Compile a complete release catalog from bounded records. No file paths,
/// includes, activation, or network authority is accepted by this protocol.
pub fn compile_source_stream(
    mut reader: impl Read,
) -> Result<CompiledSourceCatalog, SourceStreamError> {
    let mut magic = [0; 5];
    reader
        .read_exact(&mut magic)
        .map_err(|_| "command_source_stream_truncated")?;
    if &magic != MAGIC {
        return Err("command_source_stream_version_unsupported".into());
    }
    let header: Header = serde_json::from_value(json::decode(&frame(&mut reader)?)?)
        .map_err(|_| "command_source_stream_header_invalid")?;
    if header.schema != "guard.command-extension-source-stream.v1"
        || header
            .sources
            .checked_add(header.mcp_sources)
            .is_none_or(|count| count == 0 || count > MAX_RECORDS)
    {
        return Err("command_source_stream_header_invalid".into());
    }
    let trust = serde_json::to_vec(&header.trust).map_err(|_| "command_source_encoding_failed")?;
    catalog::validate_trust(&trust)?;
    let mut commands = Vec::new();
    let mut servers = Vec::new();
    let mut rules = 0usize;
    for record in 0..header.sources + header.mcp_sources {
        let mut ingest = || -> Result<Vec<u8>, &'static str> {
            let bytes = frame(&mut reader)?;
            // Duplicate keys, depth, values and typed unknown fields are checked
            // before compacting. Whitespace cannot consume another source's budget.
            let value = json::decode(&bytes)?;
            let document = if record < header.sources {
                serde_json::from_value::<SourceDocument>(value.clone())
                    .map_err(|_| "command_source_contract_invalid")?
            } else {
                mcp::lower(&bytes)?.document
            };
            validation::validate(&document, record >= header.sources)?;
            rules = rules
                .checked_add(document.extension.rules.len())
                .ok_or("command_source_program_rule_budget_exceeded")?;
            if rules > super::super::MAX_RULES {
                return Err("command_source_program_rule_budget_exceeded");
            }
            serde_json::to_vec(&value).map_err(|_| "command_source_encoding_failed")
        };
        let bytes = ingest().map_err(|code| SourceStreamError {
            code,
            record: Some(record),
        })?;
        if record < header.sources {
            commands.push(bytes);
        } else {
            servers.push(bytes);
        }
    }
    let mut trailing = [0];
    if reader
        .read(&mut trailing)
        .map_err(|_| "command_source_stream_read_failed")?
        != 0
    {
        return Err("command_source_stream_trailing_data".into());
    }
    let commands: Vec<_> = commands.iter().map(Vec::as_slice).collect();
    let servers: Vec<_> = servers.iter().map(Vec::as_slice).collect();
    Ok(catalog::compile_catalog_with_mcp(
        &commands, &servers, &trust,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn append(stream: &mut Vec<u8>, bytes: &[u8]) {
        stream.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        stream.extend_from_slice(bytes);
    }

    fn input(record: &[u8]) -> Vec<u8> {
        let mut stream = MAGIC.to_vec();
        append(
            &mut stream,
            &serde_json::to_vec(&json!({
                "schema":"guard.command-extension-source-stream.v1",
            "sources":1,"mcp_sources":0,"trust":{
                "schemaVersion":"guard.extension-trust-class-map.v1",
                "publishers":{"hol":{"id":"hol","displayName":"HOL"},
                              "hol-curated":{"id":"hol-curated","displayName":"HOL curated library"}},
                "classes":{"first-party":[],"trusted-library":[],"external":[]}
            }
            }))
            .unwrap(),
        );
        append(&mut stream, record);
        stream
    }

    #[test]
    fn strict_record_errors_keep_the_source_position() {
        let source = include_bytes!("../tests/fixtures/command-source-example.v1.json");
        let mut unknown: Value = serde_json::from_slice(source).unwrap();
        unknown["extension"]["unknown"] = json!(true);
        let nested = format!("{{\"extra\":{}0{}}}", "[".repeat(97), "]".repeat(97));
        for (record, code) in [
            (
                br#"{"extension":{},"extension":{}}"#.to_vec(),
                "command_source_json_invalid",
            ),
            (br#"{"value":NaN}"#.to_vec(), "command_source_json_invalid"),
            (nested.into_bytes(), "command_source_json_invalid"),
            (
                serde_json::to_vec(&unknown).unwrap(),
                "command_source_contract_invalid",
            ),
        ] {
            let error = compile_source_stream(input(&record).as_slice()).unwrap_err();
            assert_eq!(error.code, code);
            assert_eq!(error.record, Some(0));
        }
    }

    #[test]
    fn rejects_bad_frames_before_allocating_payloads() {
        let mut oversized = input(b"{}");
        oversized.truncate(oversized.len() - 6);
        oversized.extend_from_slice(&((json::MAX_SOURCE_BYTES + 1) as u32).to_be_bytes());
        assert_eq!(
            compile_source_stream(oversized.as_slice())
                .unwrap_err()
                .code,
            "command_source_bytes_invalid"
        );
        let mut truncated = input(b"{}");
        truncated.pop();
        assert_eq!(
            compile_source_stream(truncated.as_slice())
                .unwrap_err()
                .code,
            "command_source_stream_truncated"
        );
        for header in [
            json!({"schema":"guard.command-extension-source-stream.v1","sources":513,"mcp_sources":0,"trust":{}}),
            json!({"schema":"guard.command-extension-source-stream.v1","sources":0,"mcp_sources":0,"trust":{}}),
            json!({"schema":"guard.command-extension-source-stream.v1","sources":1,"mcp_sources":0,"trust":{},"extra":true}),
        ] {
            let mut stream = MAGIC.to_vec();
            append(&mut stream, &serde_json::to_vec(&header).unwrap());
            assert_eq!(
                compile_source_stream(stream.as_slice()).unwrap_err().code,
                "command_source_stream_header_invalid"
            );
        }
    }
}
