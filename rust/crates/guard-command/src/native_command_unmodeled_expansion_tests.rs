//! An unquoted `${NAME}` names its programs the way `$NAME` does.
use super::tests::{controls, decision, github};

const FAILED: &str = "native_command_extension_evaluation_failed";

/// `$NAME` and `"${NAME}"` model exactly and reach their owner's floor. The
/// unquoted braced spelling of the same value reached an evaluation failure
/// instead, so one way of writing a path blocked an ordinary build outright
/// while the other two let it through.
#[test]
fn an_unquoted_braced_expansion_reaches_its_owners_floor() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "echo ${HOME}",
        "ls ${HOME}/projects",
        "cd ${HOME}/app && npm run build",
        "npm run build --prefix ${PWD}/web",
        "python3 -m pytest tests -k ${CASE}",
        "git clone ${REPO}",
        "docker run --rm ${IMAGE}",
        // A default or an alternate value is still a value, not a command.
        "git log --oneline -5 ${BRANCH:-main}",
        "cargo build ${PROFILE:+--release}",
        // The length and the suffix forms expand to text as well.
        "echo ${#PATH}",
        "tar -czf out.tgz ${DIR%/}",
    ] {
        let (action, code) = decision(&controls, command);
        assert_ne!(code, FAILED, "{command}");
        assert_eq!(action, "review", "{command}: {code}");
    }
}

/// Splitting an expansion makes operands, never operators, so the only way a
/// `${...}` can hide a program is by standing where the program stands, or by
/// holding a substitution that runs one. Both keep the evaluation failure.
#[test]
fn an_expansion_that_could_name_the_program_keeps_the_failure() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "${CMD} --force",
        "${HOME}/bin/deploy --now",
        "FOO=1 ${CMD}",
        "npm run build; ${CMD}",
        // Bash runs the commands inside `${ ...; }` and `${| ...; }`.
        "${ gh pr merge 17 --squash; }",
        "${| gh pr merge 17 --squash; }",
        // A substitution inside the expansion still runs its own program.
        "git log --oneline -5 ${BRANCH:-$(gh pr view --json headRefName -q .headRefName)}",
        "echo ${X:-`gh pr merge 17`}",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}

/// The expansion changes nothing about the proofs the other uncertainty
/// reasons carry: a redirect to a path the text does not spell, or an
/// interpreter fed the expansion, stays unreadable.
#[test]
fn an_expansion_beside_an_unproven_redirect_keeps_the_failure() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "gh pr list > ${OUT}",
        "sh -c ${SCRIPT}",
        "bash ${SCRIPT}",
        "eval ${CMD}",
        "xargs ${CMD} < list.txt",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}
