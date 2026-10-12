//! Harness launcher shims (`guard-<harness>`) and their shell-profile block.
//!
//! This renders what `shims.prepare_guard_shim` and
//! `durable_harness_launcher` used to: the POSIX launcher, the Windows `.cmd`
//! launcher and the managed PATH block. Reading the current profile and
//! publishing either file stays with the caller's install transaction.

use serde_json::{json, Value};

use super::generate::{is_transient_appimage_path, package_shim_interpreter, trusted_python_flags};
use super::profile::{
    fish_path_prepend, is_transient_path, managed_profile_content, posix_path_export, shell_name,
};
use super::template::TRUSTED_CLI_LAUNCHER;
use super::values::{py_repr_list, py_strip};
use super::{ShimFacts, ShimResult, GUARD_PROFILE_MARKER};
use crate::command_launcher_floors::shlex_quote;
use crate::hook_adapter_pytext::py_repr_str;

const CURRENT_HOL_GUARD_SHIM: &str = "current-hol-guard";

/// The `HarnessContext` and process values a launcher bakes in.
#[derive(Debug, Clone, Default)]
pub struct GuardShimInputs {
    pub harness: Option<String>,
    pub launcher_name: Option<String>,
    pub display_name: Option<String>,
    /// `str(context.guard_home)`.
    pub guard_home: String,
    /// `str(context.home_dir)`.
    pub home_dir: Option<String>,
    /// `str(context.workspace_dir)`.
    pub workspace_dir: Option<String>,
    pub home_override_explicit: bool,
    /// `merge_guard_launcher_env()`, in insertion order.
    pub launcher_env: Vec<(String, String)>,
    /// `sys.platform`.
    pub platform: String,
    pub existing_profile: Option<String>,
}

/// `_is_transient_path`. A caller that patched the seam sends one verdict for
/// every path; otherwise the resident applies the real check.
fn transient(facts: &ShimFacts, path: &str) -> bool {
    facts
        .shim_dir_transient
        .unwrap_or_else(|| is_transient_path(facts, path))
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.filter(|text| !text.is_empty())
}

/// `os.access(path, X_OK)` for a launcher that must be an existing file.
fn runnable(facts: &ShimFacts, path: &str) -> bool {
    facts.is_file(path) && (facts.windows || facts.is_executable(path))
}

/// `Path.resolve(strict=True)`: `None` when the path or a link target is missing.
fn resolve_strict(facts: &ShimFacts, path: &str) -> Option<String> {
    let resolved = facts.resolve(path).ok()?;
    facts.exists(&resolved).then_some(resolved)
}

/// `_home_override_args`.
fn home_override_args(facts: &ShimFacts, inputs: &GuardShimInputs) -> ShimResult<Vec<String>> {
    let Some(home) = non_empty(inputs.home_dir.as_deref()) else {
        return Ok(Vec::new());
    };
    if !inputs.home_override_explicit {
        let selected = facts.resolve(home)?;
        let current = facts.resolve(&facts.home)?;
        if facts.path_eq(&selected, &current) {
            return Ok(Vec::new());
        }
    }
    Ok(vec!["--home".to_owned(), home.to_owned()])
}

/// The normal path components of `path` (the anchor is dropped).
fn path_parts(facts: &ShimFacts, path: &str) -> Vec<String> {
    let normalized = facts.norm(path);
    let mut parts: Vec<String> = normalized
        .split(['/', '\\'])
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect();
    if facts.windows && parts.first().is_some_and(|part| part.ends_with(':')) {
        parts.remove(0);
    }
    parts
}

/// `_desktop_core_root`.
fn desktop_core_root(facts: &ShimFacts, executable: &str) -> Option<String> {
    let name = facts.name(executable).to_lowercase();
    if name != "hol-guard" && name != "hol-guard.exe" {
        return None;
    }
    let parts = path_parts(facts, executable);
    if parts.is_empty() {
        return None;
    }
    let mut ancestor = facts.parent(executable);
    let mut depth = parts.len() - 1;
    loop {
        let ancestor_name = facts.name(&ancestor).to_lowercase();
        let relative = &parts[depth.min(parts.len())..];
        if ancestor_name == "versions" && relative.len() == 2 {
            return Some(facts.parent(&ancestor));
        }
        if ancestor_name == "bundled" {
            let in_bin = relative.len() == 3 && relative[1] == "bin";
            let in_core =
                relative.len() == 4 && relative[1] == "lib" && relative[2] == "hol-guard-core";
            if in_bin || in_core {
                return Some(facts.parent(&ancestor));
            }
        }
        let next = facts.parent(&ancestor);
        if depth == 0 || next == ancestor {
            return None;
        }
        ancestor = next;
        depth -= 1;
    }
}

/// `desktop_core_shim_for_executable`.
fn desktop_core_shim_for_executable(facts: &ShimFacts, executable: &str) -> Option<String> {
    let parent = desktop_core_root(facts, executable)?;
    let unix = facts.join(&parent, CURRENT_HOL_GUARD_SHIM);
    let windows = facts.join(&parent, &format!("{CURRENT_HOL_GUARD_SHIM}.cmd"));
    if facts.windows {
        if facts.is_file(&windows) {
            return Some(windows);
        }
        if facts.is_file(&unix) {
            return Some(unix);
        }
        return Some(windows);
    }
    Some(unix)
}

/// `durable_desktop_current_hol_guard`.
fn durable_desktop_current_hol_guard(
    facts: &ShimFacts,
    platform: &str,
    home_dir: &str,
) -> ShimResult<Option<String>> {
    let home = facts.expanduser(home_dir)?;
    let mut roots: Vec<String> = Vec::new();
    let data_home = py_strip(
        facts
            .environ
            .get("XDG_DATA_HOME")
            .map_or("", String::as_str),
    );
    if !data_home.is_empty() {
        roots.push(facts.expanduser(data_home)?);
    }
    if platform == "darwin" {
        roots.push(facts.join(&facts.join(&home, "Library"), "Application Support"));
    } else if facts.windows {
        let appdata = py_strip(facts.environ.get("APPDATA").map_or("", String::as_str));
        if appdata.is_empty() {
            roots.push(facts.join(&facts.join(&home, "AppData"), "Roaming"));
        } else {
            roots.push(facts.expanduser(appdata)?);
        }
    }
    roots.push(facts.join(&facts.join(&home, ".local"), "share"));
    let mut seen: Vec<String> = Vec::new();
    for root in roots {
        let key = facts.resolve(&root).unwrap_or_else(|_| root.clone());
        if seen.iter().any(|entry| facts.path_eq(entry, &key)) {
            continue;
        }
        seen.push(key);
        let core = facts.join(&facts.join(&root, "org.hol.guard.desktop"), "core");
        let shim = facts.join(&core, CURRENT_HOL_GUARD_SHIM);
        if runnable(facts, &shim) {
            return Ok(Some(shim));
        }
    }
    Ok(None)
}

/// `durable_guard_cli_path`.
fn durable_guard_cli_path(
    facts: &ShimFacts,
    inputs: &GuardShimInputs,
    home_dir: &str,
    runtime_executable: Option<&str>,
) -> ShimResult<Option<String>> {
    let local = facts.join(
        &facts.join(&facts.join(home_dir, ".local"), "bin"),
        "hol-guard",
    );
    let candidates = [
        durable_desktop_current_hol_guard(facts, &inputs.platform, home_dir)?,
        facts
            .environ
            .get("HOL_GUARD_DESKTOP_RUNTIME_OWNER")
            .cloned(),
        Some(local),
        runtime_executable.map(str::to_owned),
    ];
    for candidate in candidates.into_iter().flatten() {
        if candidate.is_empty() {
            continue;
        }
        let invocation = facts.absolute(&facts.expanduser(&candidate)?);
        let Some(resolved) = resolve_strict(facts, &invocation) else {
            continue;
        };
        if let Some(desktop_shim) = desktop_core_shim_for_executable(facts, &resolved) {
            let Some(resolved_shim) = resolve_strict(facts, &desktop_shim) else {
                continue;
            };
            if facts.is_file(&desktop_shim)
                && facts.is_executable(&desktop_shim)
                && !transient(facts, &desktop_shim)
                && !transient(facts, &resolved_shim)
            {
                return Ok(Some(desktop_shim));
            }
            continue;
        }
        if !facts.is_file(&invocation) || !facts.is_executable(&invocation) {
            continue;
        }
        if transient(facts, &invocation) || transient(facts, &resolved) {
            continue;
        }
        return Ok(Some(invocation));
    }
    Ok(None)
}

/// `build_durable_cli_shim`; the second value is the generated argv (the
/// `# base_command` metadata line) the Windows launcher is derived from.
fn durable_cli_shim(
    facts: &ShimFacts,
    inputs: &GuardShimInputs,
    fixed_args: &[String],
    home_dir: &str,
    runtime_executable: &str,
) -> ShimResult<(String, Vec<String>)> {
    let quoted_args = fixed_args
        .iter()
        .map(|arg| shlex_quote(arg))
        .collect::<Vec<_>>()
        .join(" ");
    let official_cli = durable_guard_cli_path(facts, inputs, home_dir, Some(runtime_executable))?;
    let mut metadata_command = vec![official_cli
        .clone()
        .unwrap_or_else(|| "hol-guard".to_owned())];
    metadata_command.extend(fixed_args.iter().cloned());
    let quoted_cli = official_cli
        .as_deref()
        .map_or_else(|| "''".to_owned(), shlex_quote);
    let source = [
        "#!/bin/sh".to_owned(),
        format!("# base_command = {}", py_repr_list(&metadata_command)),
        format!("guard_cli={quoted_cli}"),
        "if [ ! -x \"$guard_cli\" ]; then".to_owned(),
        "        echo \"HOL Guard needs the durable official install. Run: pipx install --force hol-guard\" >&2"
            .to_owned(),
        "        exit 127".to_owned(),
        "fi".to_owned(),
        "original_count=$#".to_owned(),
        "for arg do".to_owned(),
        "    set -- \"$@\" \"--arg=$arg\"".to_owned(),
        "done".to_owned(),
        "shift \"$original_count\"".to_owned(),
        format!("exec \"$guard_cli\" {quoted_args} \"$@\""),
        String::new(),
    ]
    .join("\n");
    Ok((source, metadata_command))
}

/// `_cmd_quote_fixed_argument`.
fn cmd_quote_fixed_argument(value: &str) -> String {
    let mut result = String::from("\"");
    let mut backslashes = 0_usize;
    for character in value.replace('%', "%%").chars() {
        if character == '\\' {
            backslashes += 1;
            continue;
        }
        if character == '"' {
            result.push_str(&"\\".repeat(backslashes * 2 + 1));
            result.push('"');
        } else {
            result.push_str(&"\\".repeat(backslashes));
            result.push(character);
        }
        backslashes = 0;
    }
    result.push_str(&"\\".repeat(backslashes * 2));
    result.push('"');
    result
}

/// `build_windows_script` for a harness launcher.
fn windows_script(
    facts: &ShimFacts,
    posix_path: &str,
    generated: Option<&[String]>,
) -> ShimResult<String> {
    let interpreter = package_shim_interpreter(facts);
    if is_transient_appimage_path(facts, &interpreter)? {
        return Ok([
            "@echo off",
            "echo HOL Guard needs a durable Windows install before this launcher can run. 1>&2",
            "exit /b 127",
            "",
        ]
        .join("\r\n"));
    }
    if let Some([guard_cli, _, harness, context_args @ ..]) = generated {
        let mut command = vec![guard_cli.clone(), "run-shim".to_owned()];
        command.extend(context_args.iter().cloned());
        command.push(harness.clone());
        command.push("--".to_owned());
        let command_line = command
            .iter()
            .map(|value| cmd_quote_fixed_argument(value))
            .collect::<Vec<_>>()
            .join(" ");
        return Ok([
            "@echo off".to_owned(),
            "setlocal DisableDelayedExpansion".to_owned(),
            format!("{command_line} %*"),
            String::new(),
        ]
        .join("\r\n"));
    }
    Ok([
        "@echo off".to_owned(),
        format!("\"{interpreter}\" \"{posix_path}\" %*"),
        String::new(),
    ]
    .join("\r\n"))
}

/// `build_harness_shim` plus the Windows launcher: both rendered sources.
fn render_sources(
    facts: &ShimFacts,
    inputs: &GuardShimInputs,
    harness: &str,
    posix_path: &str,
) -> ShimResult<(String, String)> {
    let home_dir = non_empty(inputs.home_dir.as_deref()).unwrap_or(&facts.home);
    let override_args = home_override_args(facts, inputs)?;
    let workspace_args = inputs
        .workspace_dir
        .as_deref()
        .map_or_else(Vec::new, |workspace| {
            vec!["--workspace".to_owned(), workspace.to_owned()]
        });
    let desktop_cli = durable_desktop_current_hol_guard(facts, &inputs.platform, home_dir)?;
    let durable = desktop_cli.is_some()
        || facts.frozen
        || is_transient_appimage_path(facts, &facts.executable)?;
    let mut fixed_args = vec![
        "run".to_owned(),
        harness.to_owned(),
        "--guard-home".to_owned(),
        inputs.guard_home.clone(),
    ];
    fixed_args.extend(override_args);
    fixed_args.extend(workspace_args);
    if durable {
        let runtime_executable = desktop_cli.unwrap_or_else(|| facts.executable.clone());
        let (source, command) =
            durable_cli_shim(facts, inputs, &fixed_args, home_dir, &runtime_executable)?;
        let windows = windows_script(facts, posix_path, Some(command.as_slice()))?;
        return Ok((source, windows));
    }
    let mut command_args = vec![facts.executable.clone()];
    command_args.extend(trusted_python_flags(facts));
    command_args.extend([
        "-c".to_owned(),
        TRUSTED_CLI_LAUNCHER.to_owned(),
        facts.import_root.clone(),
        "codex_plugin_scanner.cli".to_owned(),
        "guard".to_owned(),
    ]);
    command_args.extend(fixed_args);
    let base_env = inputs
        .launcher_env
        .iter()
        .map(|(key, value)| format!("{}: {}", py_repr_str(key), py_repr_str(value)))
        .collect::<Vec<_>>()
        .join(", ");
    let source = [
        format!("#!{}", facts.executable),
        "from __future__ import annotations".to_owned(),
        "import os".to_owned(),
        "import sys".to_owned(),
        format!("base_command = {}", py_repr_list(&command_args)),
        format!("base_env = {{{base_env}}}"),
        "combined_env = {**os.environ, **base_env}".to_owned(),
        "if 'PYTHONPATH' in os.environ and 'PYTHONPATH' in base_env:".to_owned(),
        "    pythonpath_entries = []".to_owned(),
        "    os_pythonpath = os.environ['PYTHONPATH'].split(os.pathsep)".to_owned(),
        "    base_pythonpath = base_env['PYTHONPATH'].split(os.pathsep)".to_owned(),
        "    for entry in [*os_pythonpath, *base_pythonpath]:".to_owned(),
        "        normalized = entry.strip()".to_owned(),
        "        if normalized and normalized not in pythonpath_entries:".to_owned(),
        "            pythonpath_entries.append(normalized)".to_owned(),
        "    combined_env['PYTHONPATH'] = os.pathsep.join(pythonpath_entries)".to_owned(),
        "extra_args = [f\"--arg={arg}\" for arg in sys.argv[1:]]".to_owned(),
        "os.execvpe(base_command[0], [*base_command, *extra_args], combined_env)".to_owned(),
        String::new(),
    ]
    .join("\n");
    let windows = windows_script(facts, posix_path, None)?;
    Ok((source, windows))
}

/// `prepare_guard_shim`'s rendering: both launcher sources and the manifest.
pub fn render_guard_shim(facts: &ShimFacts, inputs: &GuardShimInputs) -> ShimResult<Value> {
    let harness = non_empty(inputs.harness.as_deref())
        .ok_or_else(|| "render_guard_shim requires a harness".to_owned())?;
    let shim_name = non_empty(inputs.launcher_name.as_deref()).unwrap_or(harness);
    let label = non_empty(inputs.display_name.as_deref()).unwrap_or(harness);
    let shim_dir = facts.join(&inputs.guard_home, "bin");
    let posix_path = facts.join(&shim_dir, &format!("guard-{shim_name}"));
    let windows_path = facts.join(&shim_dir, &format!("guard-{shim_name}.cmd"));
    let (posix_source, windows_source) = render_sources(facts, inputs, harness, &posix_path)?;
    let command = facts.name(&posix_path);
    Ok(json!({
        "posix_source": posix_source,
        "windows_source": windows_source,
        "manifest": {
            "shim_path": posix_path,
            "shim_dir": shim_dir,
            "shim_command": command,
            "windows_shim_path": windows_path,
            "notes": [
                format!("Launch {label} through {command} so Guard checks changes before the harness starts."),
                format!("Add {shim_dir} to PATH to use the wrapper command from any shell."),
            ],
        },
    }))
}

/// `_guard_shim_profile_target`.
fn guard_profile_target(facts: &ShimFacts, home: &str, shim_dir: &str) -> (String, String) {
    let marker = GUARD_PROFILE_MARKER;
    match shell_name(facts).as_str() {
        "fish" => (
            facts.join(
                &facts.join(&facts.join(home, ".config"), "fish"),
                "config.fish",
            ),
            format!("{marker}\n{}", fish_path_prepend(shim_dir)),
        ),
        "bash" => (
            facts.join(home, ".bashrc"),
            format!("{marker}\n{}", posix_path_export(shim_dir)),
        ),
        _ => (
            facts.join(home, ".zshrc"),
            format!("{marker}\n{}", posix_path_export(shim_dir)),
        ),
    }
}

/// `prepare_guard_shim_shell_profile` without the file access: whether the
/// profile is left alone, else its path and the content that should replace
/// `existing_profile`.
pub fn guard_profile_plan(facts: &ShimFacts, inputs: &GuardShimInputs) -> ShimResult<Value> {
    let shim_dir = facts.join(&inputs.guard_home, "bin");
    if facts.windows || transient(facts, &shim_dir) {
        return Ok(json!({
            "skip": true,
            "manifest": {
                "changed": false,
                "profile_path": null,
                "shim_dir": shim_dir,
                "restart_shell_required": false,
                "manual_path_required": true,
            },
        }));
    }
    let home = non_empty(inputs.home_dir.as_deref())
        .ok_or_else(|| "home_dir is required to plan a shell profile".to_owned())?;
    let (profile_path, export_line) = guard_profile_target(facts, home, &shim_dir);
    let content = managed_profile_content(
        inputs.existing_profile.as_deref().unwrap_or(""),
        &export_line,
        GUARD_PROFILE_MARKER,
    );
    Ok(json!({
        "skip": false,
        "profile_path": profile_path,
        "shim_dir": shim_dir,
        "content": content,
    }))
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::super::ShimFacts;
    use super::{
        cmd_quote_fixed_argument, desktop_core_root, guard_profile_plan, render_guard_shim,
        windows_script, GuardShimInputs,
    };

    fn facts(home: &str, executable: &str) -> ShimFacts {
        ShimFacts {
            environ: BTreeMap::from([("SHELL".to_owned(), "/bin/zsh".to_owned())]),
            home: home.to_owned(),
            cwd: "/".to_owned(),
            executable: executable.to_owned(),
            frozen: false,
            frozen_cli: String::new(),
            trusted_frozen_cli_paths: Vec::new(),
            python_version: (3, 12),
            import_root: "/opt/src".to_owned(),
            argv0: None,
            windows: false,
            sqlite_connect_timeout_seconds: 30.0,
            now: "2026-01-01T00:00:00+00:00".to_owned(),
            shim_dir_transient: Some(false),
        }
    }

    fn inputs(guard_home: &str, home: &str) -> GuardShimInputs {
        GuardShimInputs {
            harness: Some("codex".to_owned()),
            guard_home: guard_home.to_owned(),
            home_dir: Some(home.to_owned()),
            platform: "linux".to_owned(),
            ..GuardShimInputs::default()
        }
    }

    #[test]
    fn desktop_core_root_matches_versioned_and_bundled_layouts() {
        let facts = facts("/home/u", "/usr/bin/python3");
        assert_eq!(
            desktop_core_root(&facts, "/d/core/versions/1.2.3/hol-guard").as_deref(),
            Some("/d/core")
        );
        assert_eq!(
            desktop_core_root(&facts, "/d/core/bundled/1.2.3/bin/hol-guard").as_deref(),
            Some("/d/core")
        );
        assert_eq!(
            desktop_core_root(&facts, "/d/core/bundled/1.2.3/lib/hol-guard-core/hol-guard")
                .as_deref(),
            Some("/d/core")
        );
        assert_eq!(
            desktop_core_root(&facts, "/d/core/versions/1/x/hol-guard"),
            None
        );
        assert_eq!(
            desktop_core_root(&facts, "/d/core/versions/1.2.3/other"),
            None
        );
    }

    #[test]
    fn python_launcher_bakes_the_interpreter_and_environment() {
        let facts = facts("/home/u", "/usr/bin/python3");
        let mut request = inputs("/g", "/home/u");
        request.launcher_env = vec![("PYTHONPATH".to_owned(), "/opt/src".to_owned())];
        request.workspace_dir = Some("/work".to_owned());
        let rendered = render_guard_shim(&facts, &request).expect("render");
        let source = rendered["posix_source"].as_str().expect("source");
        assert!(source.starts_with("#!/usr/bin/python3\nfrom __future__ import annotations\n"));
        assert!(source.contains("base_env = {'PYTHONPATH': '/opt/src'}\n"));
        assert!(source.contains("'--guard-home', '/g', '--workspace', '/work']\n"));
        assert!(source.ends_with("combined_env)\n"));
        assert_eq!(rendered["manifest"]["shim_path"], "/g/bin/guard-codex");
        assert_eq!(rendered["manifest"]["shim_command"], "guard-codex");
        assert_eq!(
            rendered["windows_source"],
            "@echo off\r\n\"/usr/bin/python3\" \"/g/bin/guard-codex\" %*\r\n"
        );
    }

    #[test]
    fn durable_launcher_prefers_the_desktop_current_shim() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = fs::canonicalize(std::env::temp_dir())
            .expect("temp dir")
            .join(format!("hol-guard-harness-{stamp}"));
        let core = root.join(".local/share/org.hol.guard.desktop/core");
        fs::create_dir_all(&core).expect("core");
        let shim = core.join("current-hol-guard");
        fs::write(&shim, "#!/bin/sh\n").expect("shim");
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).expect("chmod");
        let home = root.to_str().expect("utf8");
        let facts = facts(home, "/usr/bin/python3");
        let rendered = render_guard_shim(&facts, &inputs("/g", home)).expect("render");
        let source = rendered["posix_source"].as_str().expect("source");
        assert!(
            source.starts_with("#!/bin/sh\n# base_command = ["),
            "{source}"
        );
        assert!(source.contains("exec \"$guard_cli\" run codex --guard-home /g \"$@\"\n"));
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn cmd_quoting_doubles_percent_and_escapes_quotes_and_trailing_backslashes() {
        assert_eq!(
            cmd_quote_fixed_argument(r"C:\work\100%\a&b"),
            r#""C:\work\100%%\a&b""#
        );
        assert_eq!(cmd_quote_fixed_argument(r"a\"), r#""a\\""#);
        assert_eq!(cmd_quote_fixed_argument(r#"x\"y"#), r#""x\\\"y""#);
        assert_eq!(cmd_quote_fixed_argument(""), r#""""#);
    }

    #[test]
    fn frozen_windows_launcher_invokes_guard_directly() {
        let guard_cli = r"C:\Program Files\HOL Guard\current-hol-guard.exe";
        let workspace = r"C:\work\100%\a&b";
        let command: Vec<String> = [
            guard_cli,
            "run",
            "omp",
            "--guard-home",
            "guard home",
            "--workspace",
            workspace,
        ]
        .iter()
        .map(|part| (*part).to_owned())
        .collect();
        let facts = facts("/home/u", "/usr/bin/python3");
        let script =
            windows_script(&facts, "/g/bin/guard-omp", Some(command.as_slice())).expect("script");
        assert_eq!(
            script,
            format!(
                "@echo off\r\nsetlocal DisableDelayedExpansion\r\n\"{guard_cli}\" \"run-shim\" \
                 \"--guard-home\" \"guard home\" \"--workspace\" \"C:\\work\\100%%\\a&b\" \"omp\" \"--\" %*\r\n"
            )
        );
        assert!(!script.contains("guard-omp"));
    }

    #[test]
    fn windows_launcher_without_a_generated_command_runs_the_posix_launcher() {
        let facts = facts("/home/u", "/usr/bin/python3");
        let script = windows_script(&facts, "/g/bin/guard-omp", None).expect("script");
        assert_eq!(
            script,
            "@echo off\r\n\"/usr/bin/python3\" \"/g/bin/guard-omp\" %*\r\n"
        );
    }

    #[test]
    fn a_transient_interpreter_gets_the_durable_install_notice_on_windows() {
        let facts = facts("/home/u", "/tmp/.mount_abc/usr/bin/python3");
        let script = windows_script(&facts, "/g/bin/guard-omp", None).expect("script");
        assert!(script.starts_with("@echo off\r\necho HOL Guard needs a durable Windows install"));
        assert!(script.ends_with("exit /b 127\r\n"));
    }

    #[test]
    fn the_durable_launcher_forwards_arguments_to_the_guard_cli() {
        use std::process::Command;

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = fs::canonicalize(std::env::temp_dir())
            .expect("temp dir")
            .join(format!("hol-guard-harness-run-{stamp}"));
        let bin = root.join(".local/bin");
        fs::create_dir_all(&bin).expect("bin");
        let cli = bin.join("hol-guard");
        fs::write(&cli, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n").expect("cli");
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o755)).expect("chmod");
        let home = root.to_str().expect("utf8");
        let mut facts = facts(home, "/usr/bin/python3");
        facts.frozen = true;
        facts.frozen_cli = "/usr/bin/hol-guard".to_owned();
        let rendered = render_guard_shim(&facts, &inputs("/g", home)).expect("render");
        let source = rendered["posix_source"].as_str().expect("source");
        let launcher = root.join("guard-codex");
        fs::write(&launcher, source).expect("launcher");
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755)).expect("chmod");
        let output = Command::new(&launcher)
            .args(["--help", "prompt with spaces"])
            .output()
            .expect("run launcher");
        assert!(output.status.success(), "{source}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "run\ncodex\n--guard-home\n/g\n--arg=--help\n--arg=prompt with spaces\n"
        );
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn profile_plan_honors_the_caller_bit_and_replaces_the_block() {
        let facts = facts("/home/u", "/usr/bin/python3");
        let mut request = inputs("/g", "/home/u");
        request.existing_profile = Some("alias a=b\n".to_owned());
        let plan = guard_profile_plan(&facts, &request).expect("plan");
        assert_eq!(plan["skip"], false);
        assert_eq!(plan["profile_path"], "/home/u/.zshrc");
        assert_eq!(
            plan["content"],
            "alias a=b\n# HOL Guard harness launchers\nexport PATH=/g/bin:$PATH\n"
        );
        let mut transient = facts.clone();
        transient.shim_dir_transient = Some(true);
        let skipped = guard_profile_plan(&transient, &request).expect("skip");
        assert_eq!(skipped["skip"], true);
        assert_eq!(skipped["manifest"]["manual_path_required"], true);
    }
}
