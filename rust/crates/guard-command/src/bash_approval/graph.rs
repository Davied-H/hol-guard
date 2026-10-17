//! A closed Bash/helper graph and source replacements for a bound launcher.
//!
//! The resolver is resident-owned. Neither a digest nor this graph authorizes
//! execution: the resident must judge every recorded invocation under current
//! policy and verify the platform's interpreter/system-image assurance.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use sha2::{Digest, Sha256};

use super::{analyze_before, Analysis, Operation, Result, Uncertainty, MAX_SOURCE_BYTES};

const MAX_CODE_INPUTS: usize = 64;
const MAX_GRAPH_CALLS: usize = 1024;
const MAX_RENDERED_BYTES: usize = 4 * MAX_SOURCE_BYTES;
// A helper uses one -c argument. Larger code needs a separate framed pipe,
// rather than silently exceeding a host's argument budget.
const MAX_HELPER_ARGUMENT_BYTES: usize = 64 * 1024;

/// Source is deliberately not serializable. Only its observed digest belongs
/// in a public descriptor; frozen bytes stay in the native launch boundary.
#[derive(Clone)]
pub struct Code {
    pub original_path: String,
    pub resolved_path: String,
    pub source: String,
}

impl std::fmt::Debug for Code {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Code")
            .field("original_path", &self.original_path)
            .field("resolved_path", &self.resolved_path)
            .field("source_bytes", &self.source.len())
            .finish()
    }
}

#[derive(Clone, Debug)]
pub enum Executable {
    Bash(Code),
    /// This is an acquisition result, not an immutable-execution claim.
    Native {
        resolved_path: String,
        content_sha256: String,
    },
}

pub trait Resolver {
    fn resolve(&self, argv: &[String]) -> std::result::Result<Executable, &'static str>;
}

#[derive(Clone, Debug)]
pub struct Invocation {
    pub source_path: String,
    pub operation: Operation,
    pub resolved_path: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CodeIdentity {
    pub original_path: String,
    pub resolved_path: String,
    pub content_sha256: String,
}

pub struct Graph {
    pub code: Vec<CodeIdentity>,
    pub native_images: BTreeMap<String, String>,
    pub invocations: Vec<Invocation>,
    pub writes: Vec<super::Redirect>,
    /// Ready for a pipe owned by the native launcher, not a mutable script path.
    pub frozen_source: String,
}

impl std::fmt::Debug for Graph {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Graph")
            .field("code", &self.code)
            .field("native_images", &self.native_images)
            .field("invocation_count", &self.invocations.len())
            .field("write_count", &self.writes.len())
            .field("frozen_bytes", &self.frozen_source.len())
            .finish()
    }
}

struct Builder<'a> {
    resolver: &'a dyn Resolver,
    environment: &'a BTreeMap<String, String>,
    deadline: Instant,
    code: BTreeMap<String, CodeIdentity>,
    snapshots: BTreeMap<String, String>,
    native_images: BTreeMap<String, String>,
    invocations: Vec<Invocation>,
    writes: Vec<super::Redirect>,
    active: BTreeSet<String>,
    bytes: usize,
}

/// Resolve and freeze every helper reached by these exact arguments.
pub fn build(
    entry: Code,
    argv: &[String],
    environment: &BTreeMap<String, String>,
    resolver: &dyn Resolver,
    deadline: Instant,
) -> Result<Graph> {
    let mut builder = Builder {
        resolver,
        environment,
        deadline,
        code: BTreeMap::new(),
        snapshots: BTreeMap::new(),
        native_images: BTreeMap::new(),
        invocations: Vec::new(),
        writes: Vec::new(),
        active: BTreeSet::new(),
        bytes: 0,
    };
    let frozen_source = builder.visit(&entry, argv)?;
    Ok(Graph {
        code: builder.code.into_values().collect(),
        native_images: builder.native_images,
        invocations: builder.invocations,
        writes: builder.writes,
        frozen_source,
    })
}

impl Builder<'_> {
    fn visit(&mut self, code: &Code, argv: &[String]) -> Result<String> {
        let error = |reason| Uncertainty { reason, line: 1 };
        if Instant::now() >= self.deadline {
            return Err(error("bash_analysis_timeout"));
        }
        if self.active.contains(&code.resolved_path) {
            return Err(error("bash_helper_cycle"));
        }
        let digest = hex::encode(Sha256::digest(code.source.as_bytes()));
        if let Some(previous) = self.snapshots.get(&code.resolved_path) {
            if previous != &digest {
                return Err(error("bash_code_changed_during_analysis"));
            }
        } else {
            self.bytes += code.source.len();
            if self.bytes > MAX_SOURCE_BYTES || self.snapshots.len() >= MAX_CODE_INPUTS {
                return Err(error("bash_graph_bounds"));
            }
            self.snapshots
                .insert(code.resolved_path.clone(), digest.clone());
        }
        // Original spellings are also identity: two symlinks can give a helper
        // different $0 semantics even when they name identical code bytes.
        if self.code.get(&code.original_path).is_some_and(|previous| {
            previous.resolved_path != code.resolved_path || previous.content_sha256 != digest
        }) {
            return Err(error("bash_resolution_changed_during_analysis"));
        }
        self.code.insert(
            code.original_path.clone(),
            CodeIdentity {
                original_path: code.original_path.clone(),
                resolved_path: code.resolved_path.clone(),
                content_sha256: digest,
            },
        );
        self.active.insert(code.resolved_path.clone());
        let analysis = analyze_before(&code.source, argv, self.environment, self.deadline)?;
        let transformed = self.operations(code, analysis)?;
        self.active.remove(&code.resolved_path);
        Ok(transformed)
    }

    fn operations(&mut self, code: &Code, analysis: Analysis) -> Result<String> {
        let mut replacements = BTreeMap::<(usize, usize), String>::new();
        let mut replacement_bytes = 0usize;
        for operation in analysis.operations {
            if self.invocations.len() >= MAX_GRAPH_CALLS {
                return Err(Uncertainty {
                    reason: "bash_graph_bounds",
                    line: operation.line,
                });
            }
            let mut invocation = Invocation {
                source_path: code.original_path.clone(),
                operation: operation.clone(),
                resolved_path: None,
            };
            let name = &operation.argv[0];
            let replacement = if matches!(
                name.as_str(),
                ":" | "printf" | "echo" | "set" | "test" | "[" | "exit" | "true" | "false"
            ) {
                None
            } else {
                let executable =
                    self.resolver
                        .resolve(&operation.argv)
                        .map_err(|reason| Uncertainty {
                            reason,
                            line: operation.line,
                        })?;
                match executable {
                    Executable::Native {
                        resolved_path,
                        content_sha256,
                    } => {
                        if !resolved_path.starts_with('/')
                            || content_sha256.len() != 64
                            || !content_sha256.bytes().all(|b| b.is_ascii_hexdigit())
                        {
                            return Err(Uncertainty {
                                reason: "bash_native_identity_invalid",
                                line: operation.line,
                            });
                        }
                        invocation.resolved_path = Some(resolved_path.clone());
                        if self
                            .native_images
                            .get(&resolved_path)
                            .is_some_and(|previous| previous != &content_sha256)
                        {
                            return Err(Uncertainty {
                                reason: "bash_code_changed_during_analysis",
                                line: operation.line,
                            });
                        }
                        self.native_images
                            .insert(resolved_path.clone(), content_sha256);
                        Some(quote(&resolved_path))
                    }
                    Executable::Bash(helper) => {
                        invocation.resolved_path = Some(helper.resolved_path.clone());
                        let mut helper_argv = operation.argv.clone();
                        helper_argv[0] = helper.original_path.clone();
                        let frozen = self.visit(&helper, &helper_argv)?;
                        if frozen.len() > MAX_HELPER_ARGUMENT_BYTES {
                            return Err(Uncertainty {
                                reason: "bash_helper_delivery_bounds",
                                line: operation.line,
                            });
                        }
                        // This closure uses Bash's protected system interpreter.
                        // The native backend must verify that assurance, enforce
                        // the argv size and attach the reviewed effect boundary.
                        let encoded = quote(&frozen);
                        if encoded.len() > MAX_HELPER_ARGUMENT_BYTES {
                            return Err(Uncertainty {
                                reason: "bash_helper_delivery_bounds",
                                line: operation.line,
                            });
                        }
                        Some(format!(
                            "/bin/bash --noprofile --norc -c {} {}",
                            encoded,
                            quote(&helper.original_path)
                        ))
                    }
                }
            };
            if self.invocations.len() >= MAX_GRAPH_CALLS {
                return Err(Uncertainty {
                    reason: "bash_graph_bounds",
                    line: operation.line,
                });
            }
            self.invocations.push(invocation);
            if let Some(replacement) = replacement {
                let span = (operation.command_start, operation.command_end);
                if replacements
                    .get(&span)
                    .is_some_and(|previous| previous != &replacement)
                {
                    // Different loop iterations may select different helper
                    // branches. Their source still must freeze identically.
                    return Err(Uncertainty {
                        reason: "bash_context_dependent_rewrite",
                        line: operation.line,
                    });
                }
                if let std::collections::btree_map::Entry::Vacant(entry) = replacements.entry(span)
                {
                    replacement_bytes += replacement.len();
                    if replacement_bytes + code.source.len() > MAX_RENDERED_BYTES {
                        return Err(Uncertainty {
                            reason: "bash_rendered_source_bounds",
                            line: operation.line,
                        });
                    }
                    entry.insert(replacement);
                }
            }
        }
        self.writes.extend(analysis.writes);
        let mut source = code.source.clone();
        for ((start, end), replacement) in replacements.into_iter().rev() {
            source.replace_range(start..end, &replacement);
        }
        Ok(source)
    }
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests;
