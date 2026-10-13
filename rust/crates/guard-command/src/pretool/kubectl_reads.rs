//! Read-only `kubectl` queries and the `export KUBECONFIG=...` that selects
//! their cluster.
//!
//! Only verbs that list, describe or print cluster state are proven, and every
//! option is allowlisted. Secrets stay reviewed under any spelling, and so do
//! options that move the API server, credentials or impersonation, raise log
//! verbosity (which prints bearer tokens), read templates from local files, or
//! hit raw API paths. Unknown verbs stay reviewed because `kubectl` runs a
//! `kubectl-<verb>` plugin from `PATH` for them.
//!
//! A kubeconfig can run code (`exec` credential plugins) and read local files
//! (`tokenFile`, client keys), so an explicitly named one must pass
//! [`trust::trusted_kubeconfig`].

#[path = "kubeconfig_trust.rs"]
mod trust;

/// Options that take no value.
const FLAGS: [&str; 15] = [
    "-A",
    "--all-namespaces",
    "--all-containers",
    "--containers",
    "--ignore-not-found",
    "--namespaced",
    "--no-headers",
    "-p",
    "--previous",
    "--prefix",
    "--recursive",
    "--show-events",
    "--show-kind",
    "--show-labels",
    "--timestamps",
];

/// Options whose value only filters, sorts or bounds the printed state.
const VALUE_OPTIONS: [&str; 20] = [
    "--api-group",
    "--api-version",
    "-c",
    "--chunk-size",
    "--container",
    "--context",
    "--field-selector",
    "-l",
    "-L",
    "--label-columns",
    "--limit-bytes",
    "--max-log-requests",
    "-n",
    "--namespace",
    "--request-timeout",
    "--selector",
    "--since",
    "--since-time",
    "--sort-by",
    "--tail",
];

/// Output formats printed to stdout. The `*-file` forms read a local file.
const OUTPUT_FORMATS: [&str; 8] = [
    "custom-columns",
    "go-template",
    "json",
    "jsonpath",
    "jsonpath-as-json",
    "name",
    "wide",
    "yaml",
];

const TOP_RESOURCES: [&str; 6] = ["no", "node", "nodes", "po", "pod", "pods"];

pub(super) fn safe_kubectl_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    if model.dialect != "posix" || segment.pipeline_index != 0 {
        return false;
    }
    let arguments = &segment.arguments;
    if arguments
        .iter()
        .any(|argument| argument.contains(['$', '`', '\n', '\r']))
    {
        return false;
    }
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if !argument.starts_with('-') || argument == "-" {
            positionals.push(argument);
            index += 1;
            continue;
        }
        let (name, inline) = match argument.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (argument, None),
        };
        if FLAGS.contains(&name) {
            if inline.is_some_and(|value| !matches!(value, "true" | "false")) {
                return false;
            }
            index += 1;
            continue;
        }
        let (value, consumed) = match inline {
            Some(value) => (value, 1),
            None => match arguments.get(index + 1) {
                Some(value) => (value.as_str(), 2),
                None => return false,
            },
        };
        if !option_value_safe(name, value, context) {
            return false;
        }
        index += consumed;
    }
    verb_safe(&positionals)
}

/// `export KUBECONFIG=<path>` naming a kubeconfig that passes the same trust
/// check as `--kubeconfig`. Any other exported name can change how a later
/// proven command runs, so it keeps the normal review.
pub(super) fn safe_export_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    model.dialect == "posix"
        && segment.pipeline_index == 0
        && !segment.arguments.is_empty()
        && segment.arguments.iter().all(|argument| {
            argument
                .strip_prefix("KUBECONFIG=")
                .is_some_and(|path| trust::trusted_kubeconfig(path, context))
        })
}

fn option_value_safe(name: &str, value: &str, context: super::PathContext<'_>) -> bool {
    if value.is_empty() || value.starts_with('-') {
        return false;
    }
    match name {
        "--kubeconfig" => trust::trusted_kubeconfig(value, context),
        "-o" | "--output" => {
            let format = value.split_once('=').map_or(value, |(format, _)| format);
            OUTPUT_FORMATS.contains(&format)
        }
        _ => VALUE_OPTIONS.contains(&name),
    }
}

fn verb_safe(positionals: &[&str]) -> bool {
    let Some((verb, rest)) = positionals.split_first() else {
        return false;
    };
    if rest
        .iter()
        .any(|token| crate::sfrs_kubernetes_support::resource_token_includes_secret(token))
    {
        return false;
    }
    match *verb {
        "get" | "describe" | "explain" => !rest.is_empty(),
        "logs" => !rest.is_empty() && rest.len() <= 2,
        "top" => matches!(rest, [resource, ..] if TOP_RESOURCES.contains(resource)),
        "api-resources" | "api-versions" | "cluster-info" => rest.is_empty(),
        "config" => matches!(rest, ["get-contexts" | "current-context", ..] if rest.len() <= 2),
        _ => false,
    }
}

#[cfg(test)]
#[path = "kubectl_reads_tests.rs"]
mod tests;
