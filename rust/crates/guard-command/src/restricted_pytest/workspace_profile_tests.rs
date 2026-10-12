use super::*;

fn input(workspace: &str) -> Input {
    Input {
        profile_version: WORKSPACE_CONTAINED_PROFILE.into(),
        workspace: PathBuf::from(workspace),
        cwd: PathBuf::from(workspace),
        private_root: PathBuf::from("/private/tmp/guard-private"),
        ..Input::default()
    }
}

fn git_regex(workspace: &str) -> Regex {
    Regex::new(&workspace_profile::git_exec_pattern(Path::new(workspace)).unwrap()).unwrap()
}

#[test]
fn git_execution_config_is_denied_at_any_depth_and_case() {
    let re = git_regex("/w/proj");
    for denied in [
        "/w/proj/.git",
        "/w/proj/.GIT/Config",
        "/w/proj/.git/config.lock",
        "/w/proj/.git/hooks",
        "/w/proj/a/b/.git/hooks/pre-commit",
        "/w/proj/sub/.git",
        "/w/proj/.git/objects/info/alternates",
        "/w/proj/.git/modules/x/config",
    ] {
        assert!(re.is_match(denied), "{denied}");
    }
    for allowed in [
        "/w/proj/.github/x",
        "/w/proj/src/git/config",
        "/w/proj/.git/index",
        "/w/proj/.git/objects/ab/cdef",
        "/w/proj/.git/refs/heads/main",
        "/w/other/.git/config",
    ] {
        assert!(!re.is_match(allowed), "{allowed}");
    }
}

#[test]
fn literals_with_regex_specials_are_escaped_and_backslashes_rejected() {
    let re = git_regex("/w/a+b(c)");
    assert!(re.is_match("/w/a+b(c)/.git/config"));
    assert!(!re.is_match("/w/aab(c)/.git/config"));
    assert!(workspace_profile::git_exec_pattern(Path::new("/w/a\\b")).is_err());
    assert!(workspace_profile::git_exec_pattern(Path::new("/w/a^b")).is_err());
    assert!(workspace_profile::protected_patterns(Path::new("/w/a^b")).is_err());
}

#[test]
fn protected_paths_are_denied_for_writes() {
    let patterns = workspace_profile::protected_patterns(Path::new("/w/proj")).unwrap();
    let denied = |path: &str| {
        patterns
            .iter()
            .any(|p| Regex::new(p).unwrap().is_match(path))
    };
    assert!(denied("/w/proj/.claude/settings.json"));
    assert!(denied("/w/proj/pkg/.codex/x"));
    assert!(denied("/w/proj/CLAUDE.md"));
    assert!(denied("/w/proj/.mcp.json"));
    assert!(denied("/w/proj/.github/workflows/ci.yml"));
    assert!(!denied("/w/proj/src/main.rs"));
}

#[test]
fn composed_profile_orders_denials_last_and_covers_credentials() {
    let mut value = input("/w/proj");
    value.write_denials = vec![PathBuf::from("/w/proj/tools/hook")];
    let profile = workspace_profile::compose(&value, &[], &[]).unwrap();
    let lines: Vec<&str> = profile.lines().collect();
    assert_eq!(
        &lines[..3],
        ["(version 1)", "(deny default)", "(deny file-link)"]
    );
    assert!(!profile.contains("network"));
    let credential = lines
        .iter()
        .rposition(|line| line.starts_with("(deny file-read* file-write* (regex"))
        .unwrap();
    assert_eq!(credential, lines.len() - 1);
    assert!(profile.contains("(deny file-write* (subpath \"/w/proj/tools/hook\"))"));
    let allow = lines
        .iter()
        .position(|line| line.starts_with("(allow file-write*"))
        .unwrap();
    let git = lines
        .iter()
        .position(|line| line.starts_with("(deny file-write* (regex"))
        .unwrap();
    assert!(allow < git);
}

#[test]
fn privileged_binaries_are_denied_execution() {
    let profile = workspace_profile::compose(&input("/w/proj"), &[], &[]).unwrap();
    assert!(profile.contains("(deny process-exec (literal \"/usr/bin/sudo\")"));
}

#[test]
fn existing_profiles_ignore_the_new_fields_and_linux_rejects_this_one() {
    let error = bubblewrap_argv(&input("/w/proj")).unwrap_err();
    assert_eq!(error.reason_code, PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE);
}
