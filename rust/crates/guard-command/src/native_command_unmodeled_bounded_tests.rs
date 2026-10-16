//! An `xargs` names the program it runs in the command text: standard input
//! supplies its arguments, not its program.
use super::tests::{controls, decision, github};
use super::xargs_names_its_program;

const FAILED: &str = "native_command_extension_evaluation_failed";

#[test]
fn an_xargs_that_names_its_program_is_reviewable() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "xargs rm -f < list.txt",
        "xargs -0 -n 20 rm -f < list.txt",
        "cat list.txt | xargs -0 rm -f",
    ] {
        let (action, code) = decision(&controls, command);
        assert_ne!(code, FAILED, "{command}");
        assert_eq!(action, "review", "{command}: {code}");
    }
}

/// Reading the program out of an `xargs` leaves the operands standard input
/// supplies unread, so it must not turn an extension's own floor into a
/// review. Enabling a permission accepts a review of the commands it owns, not
/// of a launch whose arguments are not in the text.
#[test]
fn an_xargs_into_an_enabled_extension_keeps_its_floor() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "xargs gh pr merge 17 --squash < list.txt",
        "cat list.txt | xargs gh pr close",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}

#[test]
fn an_xargs_that_names_no_program_stays_unreadable() {
    let controls = controls(github("enabled", None), false);
    // With no operand `xargs` runs `echo`, and with its program fed in from
    // somewhere else the command names nothing to own it.
    for command in [
        "xargs < list.txt",
        "xargs -I {} < list.txt",
        "xargs sh -c 'rm -rf \"$1\"' _ < list.txt",
        // A pipe carries arguments into the program `xargs` names, and
        // nothing else: into a shell it carries the program itself.
        "cat list.txt | sh",
        "cat list.txt | xargs sh -c 'rm -rf \"$1\"' _",
        // An assignment or `export` still hides the program that runs, even
        // when the pipe ends in an `xargs` that names one.
        "LD_PRELOAD=./x.so find . | xargs rm -f",
        "export PATH=./evil; ls | xargs rm",
        // The boundary this keeps: a substitution still runs whatever it
        // prints, so `eval \"$(curl ...)\"` cannot be read from the text.
        "eval \"$(direnv hook bash)\"",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}

#[test]
fn xargs_options_are_read_past_to_its_program() {
    for bounded in [
        "xargs rm",
        "xargs -0 rm -f",
        "xargs -n 20 rm",
        "xargs -n20 rm",
        "xargs -I{} cp {} /tmp",
        "xargs -i rm",
        "xargs -J rm evil",
        "xargs --replace mv",
        "xargs --max-args=3 rm",
        "xargs -- rm -f",
        "cat list.txt | xargs -P 4 -I {} mv {} archive/",
    ] {
        assert!(xargs_names_its_program(bounded), "{bounded}");
    }
    for unbounded in [
        "xargs",
        "xargs -0",
        // The value of `-I` is not the program.
        "xargs -I {}",
        // The program is the replacement token, so each input line names it.
        "xargs -I{} {}",
        "xargs -I X X",
        "xargs -I CMD CMD --flag",
        "cat list | xargs -I % %",
        // A clustered short option still carries `-I`, and `-J` takes the
        // replacement rather than the program.
        "xargs -0I{} {}",
        "xargs -tI X X",
        "xargs -0n 3 sh -c 'rm'",
        "xargs -J {} {}",
        "xargs -Z rm",
        // A non-ASCII short option is not a letter this reader knows, and
        // slicing it by bytes would panic inside the character.
        "xargs -é rm",
        "xargs --max-args 3",
        // A long option this does not know may take the next word.
        "xargs --future-option rm",
        // Programs this cannot read from the text.
        "xargs sh -c 'rm $0'",
        "xargs $tool",
        "xargs bin/*",
        // Every `xargs` in the text has to name its program.
        "cat list.txt | xargs rm -f && cat more.txt | xargs",
    ] {
        assert!(!xargs_names_its_program(unbounded), "{unbounded}");
    }
}
