//! Portable bounded argv admission for contained Node, Vitest and inline runs.
#[cfg(test)]
#[path = "contained_argv_tests.rs"]
mod tests;
use crate::restricted_command::{normalized_command, RestrictedPytestError};
use regex::Regex;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::LazyLock;

const NODE_INVALID: &str = "node_test_restricted_invalid_command";
const VITEST_INVALID: &str = "vitest_restricted_invalid_command";

fn basename(command: &[String]) -> &str {
    command
        .first()
        .and_then(|v| Path::new(v).file_name())
        .and_then(|v| v.to_str())
        .unwrap_or("")
}

pub fn node_runtime_args(command: &[String]) -> Result<Vec<String>, RestrictedPytestError> {
    let argv = normalized_command(command)?;
    if argv.len() >= 2 && matches!(basename(&argv), "node" | "nodejs") {
        if let Some(value) = argv[1].strip_prefix("--max-old-space-size=") {
            // Python accepts arbitrarily many leading zeroes; bound the wire,
            // not numeric parsing, without rejecting that lexical form.
            let digits = value.trim_start_matches('0');
            let number = digits.parse::<u32>().ok();
            if value.is_empty()
                || !value.bytes().all(|v| v.is_ascii_digit())
                || !number.is_some_and(|v| (16..=131072).contains(&v))
            {
                return Err(RestrictedPytestError::new(
                    NODE_INVALID,
                    "Invalid bounded Node memory option.",
                ));
            }
            return Ok(vec![argv[1].clone()]);
        }
    }
    Ok(vec![])
}

pub fn test_script(script: &str) -> bool {
    static NAME: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"^(?:test_[A-Za-z0-9_-]*|[A-Za-z0-9_-]*_test|test|tests|runtests|run_tests)\.py$",
        )
        .unwrap()
    });
    !script.is_empty()
        && !script.starts_with(['-', '/', '~', '$'])
        && !script.contains(['\\', '$', '`'])
        && script
            .trim_end_matches('/')
            .split('/')
            .all(|v| !v.is_empty() && v != "..")
        && NAME.is_match(script.rsplit('/').next().unwrap_or(""))
}

pub fn python_runtime_args(command: &[String]) -> Option<Vec<String>> {
    let mut flags = 0;
    let mut index = 1;
    while let Some(arg) = command.get(index) {
        let bits = match arg.as_str() {
            "-I" => 1,
            "-S" => 2,
            "-IS" | "-SI" => 3,
            _ => break,
        };
        if flags & bits != 0 {
            return None;
        }
        flags |= bits;
        index += 1;
    }
    let inline = command.len() == index + 2 && command[index] == "-c";
    if !inline && !command.get(index).is_some_and(|v| test_script(v)) {
        return None;
    }
    Some(command[1..index].to_vec())
}

pub fn inline_eval(command: &[String]) -> Result<bool, RestrictedPytestError> {
    static PYTHON: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^python(?:\d+(?:\.\d+)*)?$").unwrap());
    if command.is_empty() {
        return Ok(false);
    }
    if PYTHON.is_match(basename(command)) {
        return Ok(python_runtime_args(command).is_some());
    }
    if !matches!(basename(command), "node" | "nodejs") {
        return Ok(false);
    }
    let index = 1 + node_runtime_args(command)?.len();
    Ok(command.len() == index + 2 && matches!(command[index].as_str(), "-e" | "--eval"))
}

pub fn bun_vitest_invocation(command: &[String]) -> Option<(Option<String>, Vec<String>)> {
    let name = basename(command);
    if !matches!(name, "bun" | "bunx") {
        return None;
    }
    let mut args = &command[1..];
    let mut directory = None;
    if args.first().is_some_and(|v| v == "--cwd") {
        let value = args.get(1)?;
        if value.is_empty() || value.starts_with('-') {
            return None;
        }
        directory = Some(value.clone());
        args = &args[2..];
    } else if let Some(value) = args.first().and_then(|v| v.strip_prefix("--cwd=")) {
        if value.is_empty() {
            return None;
        }
        directory = Some(value.to_owned());
        args = &args[1..];
    }
    if name == "bunx" {
        directory.as_ref()?;
    } else {
        if args.first()?.as_str() != "x" {
            return None;
        }
        args = &args[1..];
    }
    if args.first().is_some_and(|v| v == "--no-install") {
        args = &args[1..];
    }
    if args.len() < 2 || args[0] != "vitest" || args[1] != "run" {
        return None;
    }
    Some((directory, args[1..].to_vec()))
}

pub fn vitest_arguments(command: &[String]) -> Result<Vec<String>, RestrictedPytestError> {
    let argv = normalized_command(command)?;
    let name = basename(&argv);
    let runtime = node_runtime_args(&argv)?;
    let invocation = bun_vitest_invocation(&argv);
    let args = if let Some((_, args)) = invocation.filter(|_| matches!(name, "bun" | "bunx")) {
        args
    } else if matches!(name, "bunx" | "npx") {
        let mut args = &argv[1..];
        if args.first().is_some_and(|v| v == "--no-install") {
            args = &args[1..];
        }
        if args.first().is_none_or(|v| v != "vitest") {
            return invalid_vitest();
        }
        args[1..].to_vec()
    } else if name == "vitest" {
        argv[1..].to_vec()
    } else if matches!(name, "node" | "nodejs") {
        let args = &argv[1 + runtime.len()..];
        if args.len() < 2 || !args[0].ends_with("/node_modules/vitest/vitest.mjs") {
            return invalid_vitest();
        }
        args[1..].to_vec()
    } else {
        return invalid_vitest();
    };
    if args.first().is_none_or(|v| v != "run")
        || args
            .iter()
            .any(|v| matches!(v.as_str(), ";" | "&&" | "||" | "|" | "|&" | "&"))
    {
        return Err(RestrictedPytestError::new(
            VITEST_INVALID,
            "Protected Vitest requires direct run argv.",
        ));
    }
    Ok(args)
}

fn invalid_vitest<T>() -> Result<T, RestrictedPytestError> {
    Err(RestrictedPytestError::new(
        VITEST_INVALID,
        "Only local Vitest run is supported.",
    ))
}

pub fn evaluate(operation: &str, input: &Value) -> Option<Value> {
    if !matches!(
        operation,
        "node_runtime_args"
            | "python_runtime_args"
            | "inline_eval"
            | "test_script"
            | "bun_vitest_invocation"
            | "vitest_arguments"
            | "contained_kind"
    ) {
        return None;
    }
    let command = input.get("command").cloned().unwrap_or_else(|| json!([]));
    let Ok(command) = serde_json::from_value::<Vec<String>>(command) else {
        return Some(crate::restricted_command::error_reply(
            RestrictedPytestError::new(
                "pytest_restricted_invalid_command",
                "Invalid restricted execution request.",
            ),
        ));
    };
    let result = match operation {
        "node_runtime_args" => node_runtime_args(&command).map(|v| json!(v)),
        "python_runtime_args" => Ok(json!(python_runtime_args(&command))),
        "inline_eval" => inline_eval(&command).map(|v| json!(v)),
        "test_script" => Ok(json!(test_script(
            input.get("value").and_then(Value::as_str).unwrap_or("")
        ))),
        "bun_vitest_invocation" => Ok(json!(bun_vitest_invocation(&command))),
        "vitest_arguments" => vitest_arguments(&command).map(|v| json!(v)),
        "contained_kind" => contained_kind(&command),
        _ => unreachable!(),
    };
    Some(match result {
        Ok(value) => json!({"value":value}),
        Err(error) => crate::restricted_command::error_reply(error),
    })
}

fn contained_kind(command: &[String]) -> Result<Value, RestrictedPytestError> {
    let inline = inline_eval(command)?;
    let name = basename(command);
    let runtime = if matches!(name, "node" | "nodejs") {
        node_runtime_args(command)?
    } else {
        vec![]
    };
    let index = 1 + runtime.len();
    let node_test =
        command.get(index).is_some_and(|v| v == "--test") && matches!(name, "node" | "nodejs");
    let bun = bun_vitest_invocation(command);
    let entries = command.iter().skip(1).take(2);
    let vitest = !command.is_empty()
        && (matches!(name, "bunx" | "npx" | "vitest")
            || bun.is_some()
            || (matches!(name, "node" | "nodejs")
                && entries
                    .clone()
                    .any(|v| v.ends_with("/node_modules/vitest/vitest.mjs"))));
    let node_tool = bun.is_none()
        && !command.is_empty()
        && (matches!(name, "eslint" | "tsc" | "vite" | "bun" | "npm" | "pnpm")
            || (matches!(name, "bunx" | "npx")
                && entries
                    .clone()
                    .any(|v| matches!(v.as_str(), "eslint" | "tsc" | "vite")))
            || (matches!(name, "node" | "nodejs")
                && entries.clone().any(|v| {
                    [
                        "/node_modules/eslint/bin/eslint.js",
                        "/node_modules/typescript/bin/tsc",
                        "/node_modules/vite/bin/vite.js",
                    ]
                    .iter()
                    .any(|suffix| v.ends_with(suffix))
                })));
    Ok(
        json!({"inline_eval":inline,"node_test":node_test,"vitest":vitest,"git":name=="git","node_tool":node_tool}),
    )
}
