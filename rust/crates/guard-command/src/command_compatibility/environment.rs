//! Assignment prefixes (`NAME=value cmd`) the compatibility layer can attribute.
//!
//! A prefix only changes the program's environment, so the observed program
//! and arguments still describe the command. That holds unless the name points
//! the program at other code or configuration. Those names, and every name on
//! tools whose compatibility rules depend on their configuration, keep the
//! segment unsupported.

use super::basename;
use crate::CommandSegmentV1;

/// Programs whose observed operation can change with any environment name
/// other than an inert one: Git, GitHub, container and cluster CLIs read
/// remotes, contexts and credentials from it, and network clients read config.
const CONFIGURED_PROGRAMS: &[&str] = &[
    "git", "gh", "docker", "kubectl", "oc", "curl", "wget", "nc", "netcat", "scp", "rsync", "sftp",
    "ftp", "ssh", "printenv", "env",
];

/// Names that load code or configuration before or instead of the program.
const LOADER_NAMES: &[&str] = &[
    "HOME",
    "ENV",
    "BASH_ENV",
    "ZDOTDIR",
    "SHELLOPTS",
    "BASHOPTS",
    "IFS",
    "PS4",
    "PROMPT_COMMAND",
    "NODE_OPTIONS",
    "BUN_OPTIONS",
    "DENO_OPTIONS",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONUSERBASE",
    "PYTHONINSPECT",
    "PERL5OPT",
    "PERL5LIB",
    "PERLLIB",
    "RUBYOPT",
    "RUBYLIB",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "CURL_HOME",
    "WGETRC",
    "PAGER",
    "MANPAGER",
    "EDITOR",
    "VISUAL",
    "BROWSER",
    "LESSOPEN",
    "LESSCLOSE",
    "SSH_ASKPASS",
    "SUDO_ASKPASS",
    "SHELL",
    "PERL5DB",
    "RUSTC",
    "RUSTC_WRAPPER",
];

const LOADER_PREFIXES: &[&str] = &[
    "LD_",
    "DYLD_",
    "GIT_",
    "XDG_",
    "NPM_CONFIG_",
    "BUN_CONFIG_",
    "CARGO_",
];

/// Names that only adjust output, locale or a build mode.
pub(crate) fn inert_environment_name(name: &str) -> bool {
    matches!(
        name,
        "CI" | "NODE_ENV"
            | "FORCE_COLOR"
            | "NO_COLOR"
            | "CLICOLOR"
            | "CLICOLOR_FORCE"
            | "TERM"
            | "TZ"
            | "LANG"
            | "LANGUAGE"
            | "COLUMNS"
            | "LINES"
            | "DEBUG"
            | "NODE_NO_WARNINGS"
            | "RUST_LOG"
            | "RUST_BACKTRACE"
            | "PYTHONUNBUFFERED"
            | "PYTHONDONTWRITEBYTECODE"
    ) || name.starts_with("LC_")
}

fn loader_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    LOADER_NAMES.contains(&upper.as_str())
        || LOADER_PREFIXES
            .iter()
            .any(|prefix| upper.starts_with(prefix))
}

pub(super) fn supported(segment: &CommandSegmentV1) -> bool {
    let names = &segment.environment_names;
    if names.iter().all(|name| inert_environment_name(name)) {
        return true;
    }
    !CONFIGURED_PROGRAMS.contains(&basename(segment).as_str())
        && !names.iter().any(|name| loader_name(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(executable: &str, names: &[&str]) -> CommandSegmentV1 {
        let prefix: String = names.iter().map(|name| format!("{name}=1 ")).collect();
        let model = crate::parse_command(
            &serde_json::from_value(
                serde_json::json!({"command": format!("{prefix}{executable} run")}),
            )
            .unwrap(),
        )
        .unwrap();
        model.segments.into_iter().next().unwrap()
    }

    #[test]
    fn inert_names_are_supported_on_every_program() {
        for program in ["git", "gh", "bun", "curl"] {
            assert!(supported(&segment(program, &["CI", "LC_ALL", "NO_COLOR"])));
        }
    }

    #[test]
    fn configured_programs_and_loader_names_stay_unsupported() {
        assert!(supported(&segment("bun", &["APP_FLAG", "NODE_PATH"])));
        assert!(!supported(&segment("git", &["APP_FLAG"])));
        assert!(!supported(&segment("/usr/bin/curl", &["APP_FLAG"])));
        for name in [
            "NODE_OPTIONS",
            "BUN_OPTIONS",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "GIT_SSH_COMMAND",
            "HOME",
            "npm_config_script_shell",
            "XDG_CONFIG_HOME",
            "PYTHONPATH",
        ] {
            assert!(!supported(&segment("bun", &[name])), "{name}");
        }
    }
}
