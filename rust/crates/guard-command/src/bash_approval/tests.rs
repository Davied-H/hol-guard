use super::*;

const SCRIPT: &str = include_str!("../../../../../tests/fixtures/script_approvals/maintenance.sh");
const HELPER: &str =
    include_str!("../../../../../tests/fixtures/script_approvals/fixture-registry");

fn environment() -> BTreeMap<String, String> {
    BTreeMap::from([("HOME".to_owned(), "/isolated/home".to_owned())])
}

#[test]
fn expanded_words_and_repeated_operations_are_bounded() {
    let argv = ["script.sh".into()];
    let oversized = format!("printf '%s' '{}'", "x".repeat(MAX_WORD_BYTES + 1));
    assert!(analyze(&oversized, &argv, &environment()).is_err());
    let expanded = format!(
        "value='{}'; for item in {}; do printf '%s' \"$value\"; done",
        "x".repeat(MAX_WORD_BYTES),
        "x ".repeat(64)
    );
    assert!(analyze(&expanded, &argv, &environment()).is_err());
    let zero_args = "true;".repeat(MAX_OPERATIONS + 1);
    assert!(analyze(&zero_args, &argv, &environment()).is_err());
}

#[test]
fn realistic_dry_and_delete_have_distinct_reachable_operations() {
    let dry = analyze(
        SCRIPT,
        &["maintenance.sh".into(), "dry".into()],
        &environment(),
    )
    .unwrap();
    let delete = analyze(
        SCRIPT,
        &["maintenance.sh".into(), "delete".into()],
        &environment(),
    )
    .unwrap();
    let calls = |analysis: &Analysis| {
        analysis
            .operations
            .iter()
            .filter(|op| op.argv[0] == "fixture-registry")
            .map(|op| op.argv.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        calls(&dry),
        vec![
            vec!["fixture-registry", "list", "alpha"],
            vec!["fixture-registry", "inspect", "alpha"],
            vec!["fixture-registry", "list", "beta"],
            vec!["fixture-registry", "inspect", "beta"]
        ]
    );
    assert_eq!(
        calls(&delete),
        vec![
            vec!["fixture-registry", "list", "alpha"],
            vec!["fixture-registry", "delete", "alpha", "obsolete"],
            vec!["fixture-registry", "list", "beta"],
            vec!["fixture-registry", "delete", "beta", "obsolete"]
        ]
    );
    assert_eq!(dry.writes.len(), 5);
    assert!(dry
        .writes
        .iter()
        .all(|write| write.path == "/isolated/home/maintenance-report.tsv"));
}

#[test]
fn helper_mode_dispatch_exposes_deletion_only_for_delete() {
    let run = |mode: &str| {
        analyze(
            HELPER,
            &[
                "fixture-registry".into(),
                mode.into(),
                "alpha".into(),
                "obsolete".into(),
            ],
            &environment(),
        )
        .unwrap()
    };
    assert!(!run("list").operations.iter().any(|op| op.argv[0] == "rm"));
    assert!(run("delete")
        .operations
        .iter()
        .any(|op| op.argv == ["rm", "--", "/isolated/home/fixture-registry/alpha/obsolete"]));
}

#[test]
fn dynamic_and_hidden_shell_effects_never_produce_partial_success() {
    for source in [
        "printf x; eval \"$code\"",
        "$(printf rm) file",
        "printf %s $HOME",
        "source ./helper.sh",
        "PATH=/other; tool",
        "for item in $(cat names); do tool \"$item\"; done",
        "trap 'rm file' EXIT",
        "tool > >(rm file)",
        "tool & rm file",
        "printf x |& cat",
        "IFS=/; tool",
        "mode=delete; mode+=dry; tool \"$mode\"",
        "case x in x) tool ;& y) rm file;; esac",
    ] {
        assert!(
            analyze(source, &["script.sh".into()], &environment()).is_err(),
            "accepted {source}"
        );
    }
}

#[test]
fn default_arguments_and_quoted_values_match_bash() {
    let result = analyze(
        "mode=${1:-dry}\nprintf '%s' \"$mode\"",
        &["script.sh".into()],
        &environment(),
    )
    .unwrap();
    assert_eq!(result.operations[0].argv, ["printf", "%s", "dry"]);
    let result = analyze(
        "printf '%s' \"${1:-dry}\"",
        &["script.sh".into(), "two words*".into()],
        &environment(),
    )
    .unwrap();
    assert_eq!(result.operations[0].argv, ["printf", "%s", "two words*"]);
}

#[test]
fn startup_and_builtin_state_cannot_hide_reachable_operations() {
    for key in [
        "BASH_ENV",
        "ENV",
        "BASH_FUNC_tool%%",
        "SHELLOPTS",
        "BASHOPTS",
        "POSIXLY_CORRECT",
    ] {
        let mut context = environment();
        context.insert(key.into(), "unbound startup input".into());
        assert_eq!(
            analyze("tool", &["script.sh".into()], &context)
                .unwrap_err()
                .reason,
            "bash_startup_inputs_unbound"
        );
    }
    for code in [
        "printf -v mode delete; tool \"$mode\"",
        "mode=dry; printf '%n' mode; tool \"$mode\"",
        "let mode=1; tool \"$mode\"",
        "shift; tool \"$1\"",
        "tool \"$_\"",
        "ulimit -n 1; tool",
    ] {
        assert!(
            analyze(code, &["script.sh".into(), "dry".into()], &environment()).is_err(),
            "accepted {code}"
        );
    }
}

#[test]
fn quoted_case_wildcard_is_literal_and_analysis_is_bounded() {
    let result = analyze(
        "case dry in '*') delete ;; dry) inspect ;; esac",
        &["script.sh".into()],
        &environment(),
    )
    .unwrap();
    assert_eq!(result.operations[0].argv, ["inspect"]);
    assert_eq!(
        analyze_before(
            "tool",
            &["script.sh".into()],
            &environment(),
            Instant::now()
        )
        .unwrap_err()
        .reason,
        "bash_analysis_timeout"
    );
    let code = "tool\n".repeat(1100);
    assert!(analyze(&code, &["script.sh".into()], &environment()).is_err());
}
