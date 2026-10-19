use std::path::{Path, PathBuf};

fn write(path: PathBuf, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn fixture(name: &str) -> (PathBuf, PathBuf) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/grep-reach")
        .join(format!("{}-{name}", std::process::id()));
    let home = root.join("home");
    let repo = home.join("work/app");
    write(repo.join("src/index.ts"), "export const handler = 1;\n");
    write(
        repo.join("workers/api/src/index.ts"),
        "export default {};\n",
    );
    write(
        repo.join("workers/api/.dev.vars"),
        "API_TOKEN=placeholder\n",
    );
    write(repo.join(".env.bak"), "COOKIE_NAME=synthetic\n");
    (
        crate::runtime_read_paths::canonicalize_text(&home).unwrap(),
        crate::runtime_read_paths::canonicalize_text(&repo).unwrap(),
    )
}

fn reason(command: &str, home: &Path, repo: &Path) -> Option<String> {
    let model = crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap();
    let context = crate::pretool::PathContext {
        home_dir: home.to_str(),
        cwd: repo.to_str(),
        ..Default::default()
    };
    super::sensitive_reach_reason(&model, context)
}

#[test]
fn a_plain_pattern_absent_from_the_sensitive_files_needs_no_reason() {
    let (home, repo) = fixture("cleared");
    for command in [
        "grep -rn handler .",
        "grep -rn handler workers",
        "grep -rln handler . | head -5",
    ] {
        assert_eq!(reason(command, &home, &repo), None, "{command}");
    }
    std::fs::remove_dir_all(home.parent().unwrap()).unwrap();
}

#[test]
fn the_reason_names_the_sensitive_file_the_search_would_reach() {
    let (home, repo) = fixture("named");
    for (command, shown) in [
        ("grep -rn api_token workers", "workers/api/.dev.vars"),
        ("grep -rn cookie_name .", ".env.bak"),
        ("grep -rln \"cookie.*name\" .", ".env.bak"),
        ("grep -rln \"cookie.*name\" . | head -5", ".env.bak"),
        ("grep -rnv handler .", ".env.bak"),
    ] {
        let reason = reason(command, &home, &repo).unwrap_or_default();
        assert!(
            reason.contains(&format!("the search would reach `{shown}`")),
            "{command}: {reason}"
        );
        assert!(
            reason.contains("which Guard treats as sensitive") && reason.contains("--exclude="),
            "{command}: {reason}"
        );
    }
    std::fs::remove_dir_all(home.parent().unwrap()).unwrap();
}

#[test]
fn a_command_that_is_not_one_recursive_search_has_no_reach_reason() {
    let (home, repo) = fixture("other");
    for command in [
        "grep -n cookie_name .env.bak",
        "grep -rn handler . ; echo done",
        "echo done && grep -rn cookie_name .",
        "cat src/index.ts | grep -rn cookie_name .",
        "grep -rn --exclude=.env.bak --exclude=.dev.vars cookie_name .",
        "VAR=1 grep -rn cookie_name .",
        "grep -rn cookie_name ../../..",
        "grep -rn cookie_name missing",
    ] {
        assert_eq!(reason(command, &home, &repo), None, "{command}");
    }
    std::fs::remove_dir_all(home.parent().unwrap()).unwrap();
}
