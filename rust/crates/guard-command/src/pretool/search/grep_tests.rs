#[test]
fn a_missing_root_beside_real_ones_is_proven_but_not_a_sensitive_one() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/grep-absent-roots")
        .join(std::process::id().to_string());
    let home = root.join("home");
    let repo = home.join("work/app");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::write(repo.join("src/index.ts"), "export const x = 1;\n").unwrap();
    let (home, repo) = (
        crate::runtime_read_paths::canonicalize_text(&home).unwrap(),
        crate::runtime_read_paths::canonicalize_text(&repo).unwrap(),
    );
    let context = crate::pretool::PathContext {
        home_dir: home.to_str(),
        cwd: repo.to_str(),
        ..Default::default()
    };
    let r = repo.display();
    let h = home.display();
    for (command, allowed) in [
        (format!("-rln x {r}/src {r}/lib"), true),
        (format!("-n x {r}/src/index.ts {r}/lib/index.ts"), true),
        ("-rn x src tests".to_owned(), true),
        (format!("-rln x {r}/src {h}/.ssh/missing"), false),
        (format!("-rln x {r}/src {r}/missing/.env"), false),
        (format!("-rln x {r}/src {r}/missing/id_rsa"), false),
        (format!("-n x {h}/.ssh/missing"), false),
    ] {
        let arguments: Vec<String> = command.split(' ').map(str::to_owned).collect();
        assert_eq!(
            super::safe_grep_arguments(&arguments, context),
            allowed,
            "{command}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_missing_operand_is_not_proven_beside_a_step_that_could_create_it() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/grep-absent-chains")
        .join(std::process::id().to_string());
    let home = root.join("home");
    let repo = home.join("work/app");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::write(repo.join("src/index.ts"), "export const x = 1;\n").unwrap();
    let (home, repo) = (
        crate::runtime_read_paths::canonicalize_text(&home).unwrap(),
        crate::runtime_read_paths::canonicalize_text(&repo).unwrap(),
    );
    let context = crate::pretool::PathContext {
        home_dir: home.to_str(),
        cwd: repo.to_str(),
        ..Default::default()
    };
    let r = repo.display();
    for (command, allowed) in [
        (format!("grep -rln x {r}/src {r}/cfg"), true),
        (format!("grep -rn x {r}/src {r}/cfg | head -5"), true),
        (format!("cd {r} && grep -rn x src cfg"), true),
        (
            format!("cat {r}/src/index.ts && grep -n x {r}/cfg/app.json"),
            true,
        ),
        (
            format!("ln -s {r}/src {r}/cfg && grep -rn . {r}/cfg/"),
            false,
        ),
        (
            format!("ln -s {r}/src {r}/cfg && grep -n x {r}/cfg/app.json"),
            false,
        ),
        (format!("mkdir -p {r}/cfg && grep -rn x {r}/cfg"), false),
        (format!("touch {r}/cfg && grep -n x {r}/cfg"), false),
        (format!("echo x > {r}/cfg; grep -n x {r}/cfg"), false),
        (format!("cat {r}/src/index.ts && grep -rn x {r}/cfg"), false),
    ] {
        let model = crate::parse_command(&crate::CommandModelRequestV1 {
            command: command.clone(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        })
        .unwrap();
        // An output redirect leaves the model uncertain with no
        // segments, which no proof admits.
        let Some(segment) = model
            .segments
            .iter()
            .find(|segment| segment.executable.as_deref() == Some("grep"))
        else {
            assert!(!allowed, "{command}");
            continue;
        };
        assert_eq!(
            super::safe_grep_segment(&model, segment, context),
            allowed,
            "{command}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn stdin_proof_cannot_open_files_or_recurse() {
    for (arguments, allowed) in [
        (vec!["-n", "-e", "fixture"], true),
        (vec!["-efixt"], true),
        (vec!["--regexp=fixture"], true),
        (vec!["-f", "one.txt"], false),
        (vec!["-nfone.txt"], false),
        (vec!["--file=one.txt"], false),
        (vec!["fixture", "one.txt"], false),
        (vec!["-r", "fixture"], false),
        (vec!["--directories=recurse", "fixture"], false),
        (vec!["-e", "fixture", "-f", "one.txt"], false),
        (vec!["--", "fixture", "one.txt"], false),
        (vec![], false),
    ] {
        let arguments: Vec<String> = arguments.into_iter().map(str::to_owned).collect();
        assert_eq!(
            super::safe_stdin_arguments(&arguments),
            allowed,
            "{arguments:?}"
        );
    }
}

#[test]
fn a_plain_pattern_clears_the_sensitive_files_it_cannot_match() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/grep-clearance")
        .join(std::process::id().to_string());
    let home = root.join("home");
    let repo = home.join("work/app");
    let write = |relative: &str, text: &str| {
        let path = repo.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    write("src/index.ts", "export const handler = 1;\n");
    write("workers/api/.dev.vars", "API_TOKEN=placeholder\n");
    write(".env.bak", "COOKIE_NAME=synthetic\n");
    write("keys/server.key", "placeholder\n");
    write("stores/.aws/credentials", "placeholder\n");
    write("links/real.txt", "placeholder\n");
    std::os::unix::fs::symlink(repo.join("links/real.txt"), repo.join("links/.env.link")).unwrap();
    let (home, repo) = (
        crate::runtime_read_paths::canonicalize_text(&home).unwrap(),
        crate::runtime_read_paths::canonicalize_text(&repo).unwrap(),
    );
    let context = crate::pretool::PathContext {
        home_dir: home.to_str(),
        cwd: repo.to_str(),
        ..Default::default()
    };
    for (command, allowed) in [
        ("-rn handler .", true),
        ("-rn handler workers", true),
        ("-rni HANDLER workers", true),
        ("-rn foo|handler .", true),
        ("-rn -e handler .", true),
        ("-rn api_token workers", false),
        ("-rn API_TOKEN workers", false),
        ("-rn foo|cookie_name .", false),
        ("-rn cookie.name .", false),
        ("-rn ha.*er .", false),
        ("-rn ^handler .", false),
        ("-rn -ehandler .", false),
        ("-rn -e handler -e other .", false),
        ("-rnv handler .", false),
        ("-rnL handler .", false),
        ("-rn --invert-match handler .", false),
        ("-rn handler keys", false),
        ("-rn handler stores", false),
        ("-rn handler links", false),
    ] {
        let arguments: Vec<String> = command.split(' ').map(str::to_owned).collect();
        assert_eq!(
            super::safe_grep_arguments(&arguments, context),
            allowed,
            "{command}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
