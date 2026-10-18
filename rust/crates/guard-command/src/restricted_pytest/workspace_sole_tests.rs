use super::*;

#[test]
fn one_plain_invocation_names_its_program() {
    for text in ["lanectl status", "lanectl status --name 'a b'", "lanectl"] {
        assert_eq!(sole_program(text).as_deref(), Some("lanectl"), "{text}");
    }
}

#[test]
fn another_program_in_the_same_shell_names_no_sole_program() {
    for text in [
        "lanectl status && git init",
        "lanectl status ; git init",
        "lanectl status || git init",
        "lanectl status | tee out",
        "git init && lanectl status",
        "FOO=1 lanectl status",
        "env lanectl status",
        "",
    ] {
        assert_eq!(sole_program(text), None, "{text}");
    }
}

#[test]
fn only_a_text_that_names_the_toolchain_reaches_the_go_module_cache() {
    // The cache below the real HOME holds whatever `go mod download` fetched,
    // a private module included, and the plan grants it as an executable
    // root. A workspace run that never names `go` has no reason to reach it.
    for text in [
        "go build ./...",
        "go test ./... && go vet ./...",
        "/usr/local/go/bin/go build ./...",
        "cd services/api && go test ./...",
    ] {
        assert!(runs_go(text), "{text}");
    }
    for text in [
        "pnpm test",
        "cargo build",
        "pytest -q",
        "npm run golden",
        "./scripts/gogo.sh",
    ] {
        assert!(!runs_go(text), "{text}");
    }
}
