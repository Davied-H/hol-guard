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
