//! Bounded, non-executing Bash analysis for a frozen launch.
//!
//! This produces reachable argv and redirections, not permission. The resident
//! must resolve every command, judge current policy and bind actual execution
//! before using the result. Unknown shell syntax is never a partial success.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tree_sitter::{Node, ParseOptions, Parser};

pub mod delivery;
pub mod graph;
#[cfg(test)]
mod tests;
mod words;

pub const MAX_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_OPERATIONS: usize = 1024;
const MAX_LOOP_VALUES: usize = 64;
const MAX_DEPTH: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub argv: Vec<String>,
    pub line: usize,
    pub command_start: usize,
    pub command_end: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Redirect {
    pub path: String,
    pub append: bool,
    pub line: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Analysis {
    pub operations: Vec<Operation>,
    pub writes: Vec<Redirect>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Uncertainty {
    pub reason: &'static str,
    pub line: usize,
}

type Result<T> = std::result::Result<T, Uncertainty>;

/// Arguments include the original script path at index zero, as Bash sees it.
/// Environment must be the resident's selected launch environment. No lookup
/// falls back to the evaluator process's environment or filesystem.
pub fn analyze(
    source: &str,
    argv: &[String],
    environment: &BTreeMap<String, String>,
) -> Result<Analysis> {
    analyze_before(
        source,
        argv,
        environment,
        Instant::now() + Duration::from_millis(100),
    )
}

/// A graph shares one resident-owned deadline across its entry and helpers.
pub fn analyze_before(
    source: &str,
    argv: &[String],
    environment: &BTreeMap<String, String>,
    deadline: Instant,
) -> Result<Analysis> {
    let context_bytes = argv.iter().map(String::len).sum::<usize>()
        + environment
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>();
    if source.len() > MAX_SOURCE_BYTES
        || source.contains('\0')
        || argv.is_empty()
        || argv.len() > 256
        || context_bytes > MAX_SOURCE_BYTES
    {
        return Err(Uncertainty {
            reason: "bash_input_bounds",
            line: 1,
        });
    }
    if Instant::now() >= deadline {
        return Err(Uncertainty {
            reason: "bash_analysis_timeout",
            line: 1,
        });
    }
    if environment.keys().any(|key| {
        key.starts_with("BASH_FUNC_")
            || matches!(
                key.as_str(),
                "BASH_ENV" | "ENV" | "SHELLOPTS" | "BASHOPTS" | "POSIXLY_CORRECT"
            )
    }) {
        return Err(Uncertainty {
            reason: "bash_startup_inputs_unbound",
            line: 1,
        });
    }
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .map_err(|_| Uncertainty {
            reason: "bash_parser_unavailable",
            line: 1,
        })?;
    let mut read = |offset, _| source.as_bytes().get(offset..).unwrap_or_default();
    let mut cancelled = |_: &tree_sitter::ParseState| Instant::now() >= deadline;
    let options = ParseOptions::new().progress_callback(&mut cancelled);
    let tree = parser
        .parse_with_options(&mut read, None, Some(options))
        .ok_or(Uncertainty {
            reason: "bash_parse_incomplete",
            line: 1,
        })?;
    if tree.root_node().has_error() {
        return Err(Uncertainty {
            reason: "bash_syntax_error",
            line: 1,
        });
    }
    let mut state = State {
        source,
        argv,
        variables: environment.clone(),
        analysis: Analysis::default(),
        stopped: false,
        deadline,
        steps: 0,
    };
    state.walk(tree.root_node(), 0)?;
    Ok(state.analysis)
}

#[derive(Clone)]
struct State<'a> {
    source: &'a str,
    argv: &'a [String],
    variables: BTreeMap<String, String>,
    analysis: Analysis,
    stopped: bool,
    deadline: Instant,
    steps: usize,
}

impl State<'_> {
    fn text(&self, node: Node<'_>) -> &str {
        &self.source[node.byte_range()]
    }

    fn error(&self, node: Node<'_>, reason: &'static str) -> Uncertainty {
        Uncertainty {
            reason,
            line: node.start_position().row + 1,
        }
    }

    fn field<'a>(&self, node: Node<'a>, name: &str) -> Result<Node<'a>> {
        node.child_by_field_name(name)
            .ok_or_else(|| self.error(node, "bash_missing_field"))
    }

    fn walk(&mut self, node: Node<'_>, depth: usize) -> Result<()> {
        self.steps += 1;
        if Instant::now() >= self.deadline {
            return Err(self.error(node, "bash_analysis_timeout"));
        }
        if self.steps > 4096
            || depth > MAX_DEPTH
            || self.analysis.operations.len() + self.analysis.writes.len() > MAX_OPERATIONS
        {
            return Err(self.error(node, "bash_analysis_bounds"));
        }
        if self.stopped {
            return Ok(());
        }
        match node.kind() {
            "comment" => Ok(()),
            "program" | "do_group" => {
                for index in 0..node.child_count() {
                    let child = node.child(index).unwrap();
                    if !child.is_named() && !matches!(child.kind(), ";" | "do" | "done") {
                        return Err(self.error(child, "bash_control_operator"));
                    }
                }
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    self.walk(child, depth + 1)?;
                }
                Ok(())
            }
            "variable_assignment" => {
                let name = self.field(node, "name")?;
                if name.kind() != "variable_name" || !words::ordinary_variable(self.text(name)) {
                    return Err(self.error(name, "bash_special_assignment"));
                }
                let value_node = self.field(node, "value")?;
                if &self.source[name.end_byte()..value_node.start_byte()] != "=" {
                    return Err(self.error(node, "bash_assignment_operator"));
                }
                let value = self.word(value_node, true)?;
                self.variables.insert(self.text(name).to_owned(), value);
                Ok(())
            }
            "command" => self.command(node),
            "case_statement" => self.case(node, depth),
            "for_statement" => self.for_loop(node, depth),
            "redirected_statement" => {
                let body = self.field(node, "body")?;
                let mut cursor = node.walk();
                for redirect in node.children_by_field_name("redirect", &mut cursor) {
                    self.redirect(redirect)?;
                }
                self.walk(body, depth + 1)
            }
            "pipeline" => {
                for index in 0..node.child_count() {
                    let child = node.child(index).unwrap();
                    if !child.is_named() && child.kind() != "|" {
                        return Err(self.error(child, "bash_pipeline_operator"));
                    }
                }
                // Bash runs pipeline members in subshell environments. A
                // declaration inside one must not authorize a following line.
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    let variables = self.variables.clone();
                    self.walk(child, depth + 1)?;
                    self.variables = variables;
                    self.stopped = false;
                }
                Ok(())
            }
            _ => Err(self.error(node, "bash_unsupported_statement")),
        }
    }

    fn command(&mut self, node: Node<'_>) -> Result<()> {
        let name = self.field(node, "name")?;
        let name = name
            .named_child(0)
            .ok_or_else(|| self.error(name, "bash_dynamic_command"))?;
        if !matches!(name.kind(), "word" | "raw_string") {
            return Err(self.error(name, "bash_dynamic_command"));
        }
        let mut argv = vec![self.word(name, false)?];
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match node
                .field_name_for_child(child_index(node, child))
                .unwrap_or("")
            {
                "name" => (),
                "argument" => argv.push(self.word(child, false)?),
                "redirect" => self.redirect(child)?,
                _ => return Err(self.error(child, "bash_command_environment_or_subshell")),
            }
        }
        // These alter parsing, resolution or shell startup. They need their
        // own semantics and must never become ordinary allowlisted commands.
        if matches!(
            argv[0].as_str(),
            "eval"
                | "exec"
                | "source"
                | "."
                | "export"
                | "readonly"
                | "declare"
                | "typeset"
                | "alias"
                | "unalias"
                | "enable"
                | "builtin"
                | "command"
                | "trap"
                | "shopt"
                | "unset"
                | "read"
                | "mapfile"
                | "getopts"
                | "cd"
                | "pushd"
                | "popd"
        ) {
            return Err(self.error(node, "bash_dynamic_shell_state"));
        }
        if argv[0] == "set" && argv != ["set", "-euo", "pipefail"] {
            return Err(self.error(node, "bash_shell_options"));
        }
        if matches!(
            argv[0].as_str(),
            "bind"
                | "break"
                | "builtin"
                | "caller"
                | "compgen"
                | "complete"
                | "compopt"
                | "continue"
                | "dirs"
                | "disown"
                | "fc"
                | "fg"
                | "bg"
                | "hash"
                | "help"
                | "history"
                | "jobs"
                | "kill"
                | "let"
                | "local"
                | "logout"
                | "popd"
                | "pushd"
                | "pwd"
                | "readarray"
                | "return"
                | "select"
                | "shift"
                | "suspend"
                | "times"
                | "type"
                | "ulimit"
                | "umask"
                | "wait"
                | "enable"
        ) {
            return Err(self.error(node, "bash_unmodeled_builtin"));
        }
        if argv[0] == "printf" {
            let index = if argv.get(1).is_some_and(|arg| arg == "--") {
                2
            } else {
                1
            };
            let format = argv
                .get(index)
                .ok_or_else(|| self.error(node, "bash_printf_format"))?;
            let mut chars = format.chars();
            if format.starts_with('-') && index == 1 {
                return Err(self.error(node, "bash_printf_state"));
            }
            while let Some(character) = chars.next() {
                if character == '%' && !matches!(chars.next(), Some('%' | 's' | 'b' | 'q')) {
                    return Err(self.error(node, "bash_printf_state"));
                }
            }
        }
        if argv[0] == "exit" {
            if argv.len() > 2 || argv.get(1).is_some_and(|v| v.parse::<u8>().is_err()) {
                return Err(self.error(node, "bash_dynamic_exit"));
            }
            self.stopped = true;
        }
        self.analysis.operations.push(Operation {
            argv,
            line: node.start_position().row + 1,
            command_start: name.start_byte(),
            command_end: name.end_byte(),
        });
        Ok(())
    }

    fn redirect(&mut self, node: Node<'_>) -> Result<()> {
        if node.kind() != "file_redirect" || node.child_by_field_name("descriptor").is_some() {
            return Err(self.error(node, "bash_redirect_unsupported"));
        }
        let destination = self.field(node, "destination")?;
        let prefix = self.source[node.start_byte()..destination.start_byte()].trim();
        if !matches!(prefix, ">" | ">>") {
            return Err(self.error(node, "bash_redirect_unsupported"));
        }
        let path = self.word(destination, false)?;
        self.analysis.writes.push(Redirect {
            path,
            append: prefix == ">>",
            line: node.start_position().row + 1,
        });
        Ok(())
    }

    fn for_loop(&mut self, node: Node<'_>, depth: usize) -> Result<()> {
        let variable = self.field(node, "variable")?;
        if !words::ordinary_variable(self.text(variable)) {
            return Err(self.error(variable, "bash_special_assignment"));
        }
        let mut cursor = node.walk();
        let values = node
            .children_by_field_name("value", &mut cursor)
            .map(|value| self.word(value, false))
            .collect::<Result<Vec<_>>>()?;
        if values.is_empty() || values.len() > MAX_LOOP_VALUES {
            return Err(self.error(node, "bash_loop_bounds"));
        }
        let body = self.field(node, "body")?;
        for value in values {
            self.variables.insert(self.text(variable).to_owned(), value);
            self.walk(body, depth + 1)?;
            if self.stopped {
                break;
            }
        }
        Ok(())
    }

    fn case(&mut self, node: Node<'_>, depth: usize) -> Result<()> {
        let value = self.word(self.field(node, "value")?, true)?;
        let mut cursor = node.walk();
        for item in node
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "case_item")
        {
            if item.child_by_field_name("fallthrough").is_some() {
                return Err(self.error(item, "bash_case_fallthrough"));
            }
            let mut patterns_cursor = item.walk();
            let mut selected = false;
            for pattern in item.children_by_field_name("value", &mut patterns_cursor) {
                let raw = self.text(pattern);
                selected |= if raw == "*" {
                    true
                } else {
                    self.word(pattern, false)? == value
                };
            }
            if selected {
                let mut body_cursor = item.walk();
                for child in item.named_children(&mut body_cursor) {
                    if item.field_name_for_child(child_index(item, child)) != Some("value") {
                        self.walk(child, depth + 1)?;
                    }
                }
                break;
            }
        }
        Ok(())
    }
}

fn child_index(parent: Node<'_>, child: Node<'_>) -> u32 {
    (0..parent.child_count())
        .find(|index| parent.child(*index) == Some(child))
        .unwrap_or(parent.child_count()) as u32
}
