//! What an explicit Git extension Allow may settle.
//!
//! The Allow is consent to the command Guard can read. Configuration that
//! makes Git run a program (a shell alias, a pager, a credential helper, an
//! included config file) carries text the shell interprets later, and
//! `--config-env` or `GIT_CONFIG_*` take the value from somewhere Guard never
//! sees, so those shapes keep the native decision instead.

use crate::CommandSegmentV1;

/// Sections in which no setting names a program, a config file, a filter or
/// a hook template for Git to run (`init.templateDir` copies hooks, so `init`
/// is not one).
const INERT_SECTIONS: &[&str] = &[
    "advice",
    "author",
    "blame",
    "branch",
    "checkout",
    "color",
    "column",
    "commit",
    "committer",
    "fetch",
    "gc",
    "grep",
    "http",
    "i18n",
    "log",
    "maintenance",
    "push",
    "rebase",
    "status",
    "tag",
    "user",
];

/// Inert settings in sections that also hold program-valued settings
/// (`core.pager`, `diff.external`, `merge.<driver>.driver`, ...).
const INERT_KEYS: &[&str] = &[
    "core.abbrev",
    "core.autocrlf",
    "core.commentchar",
    "core.eol",
    "core.filemode",
    "core.ignorecase",
    "core.longpaths",
    "core.precomposeunicode",
    "core.preloadindex",
    "core.quotepath",
    "core.safecrlf",
    "core.symlinks",
    "core.untrackedcache",
    "core.whitespace",
    "diff.algorithm",
    "diff.colormoved",
    "diff.context",
    "diff.indentheuristic",
    "diff.mnemonicprefix",
    "diff.noprefix",
    "diff.relative",
    "diff.renames",
    "init.defaultbranch",
    "merge.conflictstyle",
    "merge.ff",
    "merge.log",
    "protocol.version",
    "pull.ff",
    "pull.rebase",
];

/// Whether a Git segment carries configuration or options that can make Git
/// run a program Guard cannot read: any alias, a program-valued or unknown
/// key from `-c`, any non-inert key from `--config-env`, `--exec-path`, a
/// `GIT_*` environment prefix other than the commit identity, or a
/// subcommand option naming a local program. Unknown keys and unparseable
/// global options fail closed.
pub(crate) fn runs_configured_program(segment: &CommandSegmentV1) -> bool {
    if segment.executable.as_deref() != Some("git") {
        return false;
    }
    if segment
        .environment_names
        .iter()
        .any(|name| !crate::command_compatibility::inert_git_environment_name(name))
    {
        return true;
    }
    let arguments = &segment.arguments;
    let Some(command_index) = super::command_index(arguments) else {
        return true;
    };
    let mut index = 0;
    while index < command_index {
        let argument = arguments[index].as_str();
        let (setting, from_environment) = if argument == "-c" || argument == "--config-env" {
            index += 1;
            (arguments.get(index).map(String::as_str), argument != "-c")
        } else if let Some(setting) = argument.strip_prefix("--config-env=") {
            (Some(setting), true)
        } else if let Some(setting) = argument.strip_prefix("-c").filter(|rest| !rest.is_empty()) {
            (Some(setting), false)
        } else if argument.starts_with("--exec-path") {
            return true;
        } else {
            index += 1;
            continue;
        };
        index += 1;
        let Some(setting) = setting else {
            return true;
        };
        if config_setting_runs_program(setting, from_environment) {
            return true;
        }
    }
    subcommand_runs_program(&arguments[command_index..])
}

/// `-c <key>` sets the boolean true. `--config-env=<key>=<variable>` names a
/// variable, not the value.
fn config_setting_runs_program(setting: &str, from_environment: bool) -> bool {
    let (key, value) = setting.split_once('=').unwrap_or((setting, "true"));
    setting_runs_program(
        &key.to_ascii_lowercase(),
        (!from_environment).then_some(value),
    )
}

/// Subcommand options that make Git run a program locally: the pack programs
/// of a local transport, `--exec`, hook templates for a new repository, and
/// settings `clone` writes into the repository it creates. Git accepts any
/// unambiguous prefix of a long option, so prefixes count too. Options after
/// `--` are operands.
fn subcommand_runs_program(arguments: &[String]) -> bool {
    let Some((command, rest)) = arguments.split_first() else {
        return false;
    };
    let command = command.as_str();
    let mut index = 0;
    while let Some(argument) = rest.get(index) {
        index += 1;
        let argument = argument.as_str();
        if argument == "--" {
            break;
        }
        if let Some(long) = argument.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            let names = |option: &str| !name.is_empty() && option.starts_with(name);
            if names("upload-pack")
                || names("receive-pack")
                || names("exec")
                || (matches!(command, "clone" | "init") && names("template"))
            {
                return true;
            }
            if command == "clone" && names("config") {
                let setting = attached.or_else(|| rest.get(index).map(String::as_str));
                if attached.is_none() {
                    index += 1;
                }
                if setting.is_none_or(|setting| config_setting_runs_program(setting, false)) {
                    return true;
                }
            }
            continue;
        }
        let Some(cluster) = argument.strip_prefix('-').filter(|rest| !rest.is_empty()) else {
            continue;
        };
        match command {
            // `-u <program>` is `--upload-pack` here; for push, fetch and pull
            // it sets the upstream or updates HEAD.
            "ls-remote" if cluster.contains('u') => return true,
            "clone" => {
                for (offset, flag) in cluster.char_indices() {
                    let attached = &cluster[offset + flag.len_utf8()..];
                    match flag {
                        'u' => return true,
                        'c' | 'o' | 'b' | 'j' => {
                            let value = if attached.is_empty() {
                                index += 1;
                                rest.get(index - 1).map(String::as_str)
                            } else {
                                Some(attached)
                            };
                            if flag == 'c'
                                && value.is_none_or(|setting| {
                                    config_setting_runs_program(setting, false)
                                })
                            {
                                return true;
                            }
                            break;
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    false
}

fn setting_runs_program(key: &str, value: Option<&str>) -> bool {
    let section = key.split('.').next().unwrap_or(key);
    if INERT_SECTIONS.contains(&section) || INERT_KEYS.contains(&key) {
        return false;
    }
    // Every alias is held: a shell alias runs its body through `sh`, and any
    // other expands to a subcommand and options the parser never saw.
    let Some(value) = value.filter(|_| section != "alias") else {
        return true;
    };
    let disabled = |value: &str| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "false" | "0" | "no" | "off"
        )
    };
    // Settings that switch a program off rather than name one.
    let switched_off = match key {
        "core.fsmonitor" => disabled(value),
        "core.hookspath" => value == "/dev/null",
        "core.pager" => matches!(value, "" | "cat"),
        "credential.helper" => value.is_empty(),
        _ if section == "pager" => disabled(value) || matches!(value, "" | "cat"),
        _ => false,
    };
    !switched_off
}

/// Whether a Git segment runs in a repository Guard has proven: no environment
/// overrides, and every global option before the subcommand is either
/// configuration (judged by [`runs_configured_program`]) or a `-C` or
/// `--git-dir` route that verifies. Any other option, such as `--work-tree`,
/// fails closed.
pub(crate) fn repository_routes_verified(
    segment: &CommandSegmentV1,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    let arguments = &segment.arguments;
    let Some(command_index) = super::command_index(arguments) else {
        return false;
    };
    let mut routes = Vec::with_capacity(arguments.len() + 1);
    let mut index = 0;
    while index < command_index {
        let argument = &arguments[index];
        if argument == "-c" || argument == "--config-env" {
            index += 2;
            continue;
        }
        if let Some(target) = argument.strip_prefix("-C").filter(|rest| !rest.is_empty()) {
            routes.push("-C".to_owned());
            routes.push(target.to_owned());
        } else if !(argument.starts_with("-c")
            || argument.starts_with("--config-env=")
            || argument.starts_with("--exec-path"))
        {
            routes.push(argument.clone());
        }
        index += 1;
    }
    let command_length = arguments.len() - command_index;
    routes.extend_from_slice(&arguments[command_index..]);
    segment.environment_names.is_empty()
        && crate::pretool::directory_targets::drive_targets_quoted(segment)
        && crate::pretool::directory_targets::home_targets_unquoted(segment)
        // `routed` stops at the first option it does not model; the routes
        // verify only when it stopped at the subcommand itself.
        && super::routed(&routes, context, true).is_some_and(|rest| rest.len() == command_length)
}
