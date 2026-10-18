//! The script an argv launches, for a caller that has only the argv and its
//! working directory: the package shim's custom command (`bun tool.ts …`).
//!
//! The same reading the hooks apply decides what the script does. The
//! arguments after the script are the script's own data, so the caller can
//! judge them as data instead of as part of a command line.

use std::path::{Path, PathBuf};

use super::{
    code_lines, extension, first_operand, launched_script, python_network, read_graph, Entry,
    Language, CREDENTIAL_STORE, NODE_EXTENSIONS, NODE_NETWORK, NODE_VALUE_OPTIONS,
};

/// What the script an argv launches does.
pub(crate) enum ArgvScript {
    /// Not one interpreter launch of a script file: inline code, standard
    /// input, a wrapper, an environment prefix, or another program.
    NotAScript,
    /// A script launch whose source, or one of its local imports, could not
    /// be read whole.
    Unreadable,
    /// The script and its local imports were read.
    Read {
        /// One program both names a credential store and uses the network.
        exfiltrates: bool,
        /// The argv entries after the script, which it receives as data.
        arguments: Vec<String>,
    },
}

/// Read the script `argv` launches, resolving a relative script against
/// `cwd`. Without an absolute `cwd`, a relative script is not read.
pub(crate) fn argv_script(argv: &[String], cwd: Option<&Path>) -> ArgvScript {
    let Ok(model) = crate::parse_command(&crate::CommandModelRequestV1 {
        command: crate::command_launcher_floors::shlex_join(argv),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    }) else {
        return ArgvScript::NotAScript;
    };
    let [segment] = model.segments.as_slice() else {
        return ArgvScript::NotAScript;
    };
    if model.confidence != "exact"
        || !model.wrapper_chain.is_empty()
        || !segment.wrapper_chain.is_empty()
        || !segment.environment_names.is_empty()
    {
        return ArgvScript::NotAScript;
    }
    let Some((language, operand, path)) = script_operand(segment, cwd) else {
        return ArgvScript::NotAScript;
    };
    let Some(path) = path else {
        return ArgvScript::Unreadable;
    };
    let Some((sources, true)) = read_graph(language, Entry::File(path)) else {
        return ArgvScript::Unreadable;
    };
    let mut network = false;
    let mut credential_store = false;
    for source in &sources {
        let code = code_lines(language, source);
        network |= match language {
            Language::Python => python_network(&code),
            Language::Node => NODE_NETWORK.is_match(&code),
        };
        credential_store |= CREDENTIAL_STORE.is_match(&code);
    }
    let after = segment
        .arguments
        .iter()
        .position(|argument| argument == operand)
        .map_or(&[][..], |index| &segment.arguments[index + 1..]);
    ArgvScript::Read {
        exfiltrates: network && credential_store,
        arguments: after.to_vec(),
    }
}

/// The script `segment` launches, its operand and its readable file. A Node
/// launcher's link without an extension (`node_modules/.bin/omp`) counts when
/// it resolves to a Node script file.
fn script_operand<'a>(
    segment: &'a crate::CommandSegmentV1,
    cwd: Option<&Path>,
) -> Option<(Language, &'a str, Option<PathBuf>)> {
    if let Some((language, operand)) = launched_script(segment) {
        return Some((language, operand, file(operand, cwd)));
    }
    let name = super::super::executable_basename(segment.executable.as_deref()?);
    let arguments = match (name, segment.arguments.as_slice()) {
        ("bun" | "deno", [run, rest @ ..]) if run == "run" => rest,
        ("node" | "nodejs" | "bun" | "tsx" | "deno", rest) => rest,
        _ => return None,
    };
    let operand = first_operand(
        arguments,
        NODE_VALUE_OPTIONS,
        &["-e", "--eval", "-p", "--print", "-"],
    )?;
    let path = file(operand, cwd)?;
    NODE_EXTENSIONS
        .contains(&extension(&path).as_str())
        .then_some((Language::Node, operand, Some(path)))
}

/// `operand` as an existing file, resolved against an absolute `cwd`.
fn file(operand: &str, cwd: Option<&Path>) -> Option<PathBuf> {
    let path = Path::new(operand);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.filter(|cwd| cwd.is_absolute())?.join(path)
    };
    std::fs::canonicalize(path)
        .ok()
        .filter(|path| path.is_file())
}

#[cfg(test)]
#[path = "argv_tests.rs"]
mod tests;
