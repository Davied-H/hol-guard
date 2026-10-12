#![cfg(unix)]
//! `bun -e` constant prints proceed only when no Bun preload can run first.
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

/// A home holding a project and a `bin` directory with a stand-in `bun`. The
/// root stays below the target directory: `$TMPDIR` on macOS resolves under
/// `/private/var`, which the sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-bun-eval")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let home = root.join("home");
    std::fs::create_dir_all(home.join("project/sub")).unwrap();
    std::fs::create_dir_all(home.join("bin")).unwrap();
    std::fs::write(home.join("bin/bun"), "#!/bin/sh\n").unwrap();
    std::fs::canonicalize(home).unwrap()
}

fn environment(
    home: &Path,
    path: &Path,
    names: &[&str],
) -> guard_contracts::GuardExecutionEnvironmentV1 {
    guard_contracts::GuardExecutionEnvironmentV1 {
        path: path.to_str().unwrap().to_owned(),
        environment_names: names.iter().map(|name| (*name).to_owned()).collect(),
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: false,
        library_search_paths: Default::default(),
    }
}

fn classify(
    home: &Path,
    cwd: &str,
    environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    harness: &str,
    command: &str,
) -> guard_contracts::PreToolResultV1 {
    let cwd = home.join(cwd);
    evaluate_pre_tool_envelope_with_execution_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            ..PathContext::default()
        },
        environment,
    )
}

const PRINTS: &[&str] = &[
    "bun -e \"console.log('bun-ok')\"",
    "bun -e \"console.log('bun-eval-ok', 1+1)\"",
    "bun -e \"console.log('bun-ok', Bun.version)\"",
    "bun -e 'console.log(process.platform, process.arch)' 2>&1",
];

#[test]
fn constant_prints_proceed_without_a_preload() {
    let home = home();
    let plain = environment(&home, &home.join("bin"), &["HOME", "PATH", "BUN_INSTALL"]);
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in PRINTS {
            let result = classify(&home, "project", Some(&plain), harness, command);
            assert_eq!(result.decision, "allow", "{harness}: {command}");
        }
    }
    for command in [
        "bun -e \"console.log(require('fs').readFileSync('.env', 'utf8'))\"",
        "bun -e \"console.log(Bun.env)\"",
        "bun -e \"console.log('ok'); process.exit(1)\"",
        "bun -e \"console.log(Bun.file('.env'))\"",
        "bun -e \"console.log('a,b', Bun.spawnSync(['id']))\"",
        "bun --preload ./x.js -e \"console.log('ok')\"",
        "bun -e \"console.log('ok')\" > out.txt",
        "bun -e \"console.log('ok')\" | sh",
        "BUN_OPTIONS=--preload=./x.js bun -e \"console.log('ok')\"",
        "./bun -e \"console.log('ok')\"",
        "sudo bun -e \"console.log('ok')\"",
    ] {
        let result = classify(&home, "project", Some(&plain), "zcode", command);
        assert_ne!(result.decision, "allow", "{command}");
    }
}

#[test]
fn any_preload_source_keeps_the_review() {
    let home = home();
    let command = PRINTS[0];
    let plain = environment(&home, &home.join("bin"), &["HOME", "PATH"]);
    assert_eq!(
        classify(&home, "project", Some(&plain), "zcode", command).decision,
        "allow"
    );
    // No stamped environment, an inherited BUN_OPTIONS, or a `bun` the
    // project supplies.
    assert_ne!(
        classify(&home, "project", None, "zcode", command).decision,
        "allow"
    );
    let options = environment(&home, &home.join("bin"), &["HOME", "PATH", "BUN_OPTIONS"]);
    assert_ne!(
        classify(&home, "project", Some(&options), "zcode", command).decision,
        "allow"
    );
    std::fs::create_dir_all(home.join("project/bin")).unwrap();
    std::fs::write(home.join("project/bin/bun"), "#!/bin/sh\n").unwrap();
    let local = environment(&home, &home.join("project/bin"), &["HOME", "PATH"]);
    assert_ne!(
        classify(&home, "project", Some(&local), "zcode", command).decision,
        "allow"
    );
    // Configuration beside the working directory, above it, or global.
    for config in [
        "project/sub/bunfig.toml",
        "project/bunfig.toml",
        ".bunfig.toml",
        ".config/.bunfig.toml",
    ] {
        let file = home.join(config);
        std::fs::write(&file, "preload = [\"./x.js\"]\n").unwrap();
        let result = classify(&home, "project/sub", Some(&plain), "zcode", command);
        assert_ne!(result.decision, "allow", "{config}");
        std::fs::remove_file(file).unwrap();
    }
    assert_eq!(
        classify(&home, "project/sub", Some(&plain), "zcode", command).decision,
        "allow"
    );
}

#[test]
fn node_prints_accept_the_same_constants() {
    let home = home();
    let plain = environment(&home, &home.join("bin"), &["HOME", "PATH"]);
    for command in [
        "node -e \"console.log('node-ok', 1+1)\"",
        "node -e 'console.log(process.version)'",
        "python3 -c \"print('py-ok', 2)\"",
    ] {
        let result = classify(&home, "project", Some(&plain), "codex", command);
        assert_eq!(result.decision, "allow", "{command}");
    }
    for command in [
        "node -e \"console.log(Bun.version)\"",
        "python3 -c \"print('ok', open('.env').read())\"",
        "python3 -c \"print(process.version)\"",
    ] {
        let result = classify(&home, "project", Some(&plain), "codex", command);
        assert_ne!(result.decision, "allow", "{command}");
    }
}
