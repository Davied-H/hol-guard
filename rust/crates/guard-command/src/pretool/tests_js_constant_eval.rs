#![cfg(unix)]

use crate::pretool::*;

fn environment(names: &[&str]) -> guard_contracts::GuardExecutionEnvironmentV1 {
    guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: names.iter().map(|name| (*name).to_owned()).collect(),
        environment_digest: "0".repeat(64),
        home: None,
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        library_search_paths: Default::default(),
    }
}

fn fixture(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("guard-js-eval-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("project")).unwrap();
    root
}

fn allowed(home: &std::path::Path, cwd: &std::path::Path, command: &str, names: &[&str]) -> bool {
    let environment = environment(names);
    evaluate_pre_tool_with_execution_context(
        &CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        },
        home.to_str(),
        cwd.to_str(),
        None,
        Some(&environment),
    )
    .is_ok_and(|decision| decision.minimum_action == "allow")
}

const CLEAN: [&str; 3] = ["HOME", "PATH", "BUN_INSTALL"];

#[test]
fn constant_bun_and_node_programs_run_quietly() {
    let home = fixture("constant");
    let cwd = home.join("project");
    for command in [
        "bun -e \"console.log('bun-ok')\"",
        "bun -e 'console.log(1 + 1)'",
        "bun --print 42",
        "node -e \"console.log('node-ok')\"",
        "node -p '7 * 6'",
        "node -e 'console.log(7 % 2)'",
        "bun -e 'console.log(Bun.version)'",
        "bun -e \"console.log('bun-ok', Bun.version, process.platform)\"",
    ] {
        assert!(allowed(&home, &cwd, command, &CLEAN), "{command}");
    }
    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn programs_with_effects_or_extra_arguments_keep_review() {
    let home = fixture("effects");
    let cwd = home.join("project");
    for command in [
        "bun -e \"require('fs').readFileSync('.env')\"",
        "bun -e 'console.log(process.env)'",
        "bun -e 'console.log(Bun.version())'",
        "bun -e 'console.log(Bun.env)'",
        "bun -e 'console.log(Bun.version.constructor)'",
        "bun -e 'console.log(1)' extra",
        "bun -e 'await fetch(\"https://x.example\")'",
        "bun --preload ./x.js -e 'console.log(1)'",
        "bun -e 'console.log(`${1}`)'",
        "bun run -e 'console.log(1)'",
        "node -e \"console.log(require('os').homedir())\"",
        "node --require ./startup.js -e 'console.log(1)'",
        "node -e 'console.log(1); process.exit()'",
    ] {
        assert!(!allowed(&home, &cwd, command, &CLEAN), "{command}");
    }
    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn loader_options_in_the_environment_keep_review() {
    let home = fixture("loader");
    let cwd = home.join("project");
    for names in [
        &["HOME", "PATH", "NODE_OPTIONS"][..],
        &["HOME", "PATH", "BUN_OPTIONS"][..],
        &["HOME", "PATH", "node_options"][..],
    ] {
        for command in ["bun -e 'console.log(1)'", "node -e 'console.log(1)'"] {
            assert!(!allowed(&home, &cwd, command, names), "{command} {names:?}");
        }
    }
    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn a_bun_config_that_can_preload_keeps_bun_review() {
    for (name, path, body) in [
        ("cwd", "project/bunfig.toml", "preload = [\"./x.ts\"]\n"),
        ("parent", "bunfig.toml", "preload = [\"./x.ts\"]\n"),
        ("global", ".bunfig.toml", "[run]\nshell = \"system\"\n"),
        ("xdg", ".config/.bunfig.toml", "preload = [\"./x.ts\"]\n"),
    ] {
        let home = fixture(name);
        let cwd = home.join("project");
        let target = home.join(path);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, body).unwrap();
        assert!(
            !allowed(&home, &cwd, "bun -e 'console.log(1)'", &CLEAN),
            "{name}"
        );
        assert!(
            allowed(&home, &cwd, "node -e 'console.log(1)'", &CLEAN),
            "{name}"
        );
        let _ = std::fs::remove_dir_all(home);
    }
    let home = fixture("install-only");
    let cwd = home.join("project");
    std::fs::write(
        cwd.join("bunfig.toml"),
        "[install]\nlinker = \"isolated\"\n",
    )
    .unwrap();
    assert!(allowed(&home, &cwd, "bun -e 'console.log(1)'", &CLEAN));
    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn a_bun_config_in_the_directory_a_command_moves_into_clears_the_bun_proof() {
    let home = fixture("cd-target");
    let cwd = home.join("project");
    let tool = cwd.join("tool");
    let plain = cwd.join("plain");
    std::fs::create_dir_all(&tool).unwrap();
    std::fs::create_dir_all(&plain).unwrap();
    std::fs::write(tool.join("bunfig.toml"), "preload = [\"./x.ts\"]\n").unwrap();
    let context = crate::pretool::PathContext {
        home_dir: home.to_str(),
        cwd: cwd.to_str(),
        bun_config_absent: true,
        ..Default::default()
    };
    assert!(
        context
            .in_directory(cwd.to_str().unwrap())
            .bun_config_absent
    );
    assert!(
        context
            .in_directory(plain.to_str().unwrap())
            .bun_config_absent
    );
    assert!(
        !context
            .in_directory(tool.to_str().unwrap())
            .bun_config_absent
    );
    let unproven = crate::pretool::PathContext {
        bun_config_absent: false,
        ..context
    };
    assert!(
        !unproven
            .in_directory(plain.to_str().unwrap())
            .bun_config_absent
    );
    let _ = std::fs::remove_dir_all(home);
}
