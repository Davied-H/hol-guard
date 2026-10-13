//! Proof that a package install cannot run lifecycle scripts.
//!
//! With `--ignore-scripts` (or yarn's `--mode=skip-build`) no lifecycle
//! script runs, so the installed `package_script` risk setting has nothing to
//! govern. The proof is deliberately narrow: one plain segment, no
//! environment prefix, no positional package names, no wrapper.

use crate::{parse_command, CommandModelRequestV1};

fn flag_disables_scripts(manager: &str, argument: &str) -> bool {
    match argument {
        "--ignore-scripts" | "--ignore-scripts=true" => true,
        "--mode=skip-build" => manager == "yarn",
        _ => false,
    }
}

fn flag_reenables_scripts(argument: &str) -> bool {
    let lowered = argument.to_ascii_lowercase();
    matches!(
        lowered.as_str(),
        "--ignore-scripts=false"
            | "--ignore-scripts=0"
            | "--no-ignore-scripts"
            | "--scripts"
            | "--foreground-scripts"
            | "--foreground-scripts=true"
    ) || (lowered.starts_with("--ignore-scripts=") && lowered != "--ignore-scripts=true")
        || lowered.starts_with("--mode=") && lowered != "--mode=skip-build"
}

/// True only for a lone `npm|pnpm|yarn|bun install|i|ci` with a flag that
/// disables lifecycle scripts and nothing that re-enables them.
pub fn no_script_install_command(command: &str) -> bool {
    let Ok(model) = parse_command(&CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    }) else {
        return false;
    };
    if model.confidence != "exact"
        || model.uncertainty_reason.is_some()
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
    {
        return false;
    }
    let [segment] = model.segments.as_slice() else {
        return false;
    };
    let Some(executable) = segment.executable.as_deref() else {
        return false;
    };
    let manager = executable.rsplit('/').next().unwrap_or(executable);
    if !matches!(manager, "npm" | "pnpm" | "yarn" | "bun")
        || !segment.environment_names.is_empty()
        || !segment.wrapper_chain.is_empty()
        || segment.path_overridden
        || segment.tokens.len() != segment.arguments.len() + 1
    {
        return false;
    }
    let Some((subcommand, flags)) = segment.arguments.split_first() else {
        return false;
    };
    if !matches!(subcommand.as_str(), "install" | "i" | "ci") {
        return false;
    }
    flags.iter().all(|flag| flag.starts_with("--"))
        && flags
            .iter()
            .any(|flag| flag_disables_scripts(manager, flag))
        && !flags.iter().any(|flag| flag_reenables_scripts(flag))
}

#[cfg(test)]
mod tests {
    use super::no_script_install_command;

    #[test]
    fn proves_only_the_plain_no_scripts_install_forms() {
        for command in [
            "bun install --frozen-lockfile --ignore-scripts",
            "npm ci --ignore-scripts",
            "npm install --ignore-scripts",
            "pnpm install --ignore-scripts",
            "yarn install --ignore-scripts",
            "yarn install --mode=skip-build",
            "/usr/bin/npm ci --ignore-scripts=true",
        ] {
            assert!(no_script_install_command(command), "{command}");
        }
        for command in [
            "bun install",
            "npm ci",
            "bun install --ignore-scripts=false",
            "bun install --ignore-scripts --ignore-scripts=false",
            "npm install --ignore-scripts --no-ignore-scripts",
            "npm install --ignore-scripts --foreground-scripts",
            "npm run build --ignore-scripts",
            "bun run build",
            "npm install left-pad --ignore-scripts",
            "npm install --ignore-scripts && npm run build",
            "bun install --ignore-scripts; rm x",
            "bun install --ignore-scripts | cat",
            "cd /tmp/w/app && bun install --ignore-scripts",
            "npm_config_ignore_scripts=false bun install --ignore-scripts",
            "FOO=1 bun install --ignore-scripts",
            "env FOO=1 bun install --ignore-scripts",
            "bun install --ignore-scripts > /tmp/w/out",
            "bun install --ignore-scripts $(id)",
            "npm install --mode=skip-build",
            "yarn install --mode=update-lockfile --ignore-scripts",
            "pip install --ignore-scripts",
        ] {
            assert!(!no_script_install_command(command), "{command}");
        }
    }
}
