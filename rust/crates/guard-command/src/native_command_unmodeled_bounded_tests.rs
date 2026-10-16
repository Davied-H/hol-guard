//! An `xargs` names the program it runs in the command text: standard input
//! supplies its arguments, not its program.
use super::tests::{controls, decision, github};
use super::xargs::{xargs_input_is_named, xargs_names_its_program};

const FAILED: &str = "native_command_extension_evaluation_failed";

#[test]
fn an_xargs_that_names_its_program_is_reviewable() {
    let controls = controls(github("enabled", None), false);
    // A redirect into `xargs` is judged by the redirect proof, which does not
    // yet read an input redirect from a literal path, so `xargs rm -f <
    // list.txt` keeps its evaluation failure for that reason instead.
    for command in [
        "cat list.txt | xargs -0 rm -f",
        "cat list.txt | xargs -n 20 rm -f",
    ] {
        let (action, code) = decision(&controls, command);
        assert_ne!(code, FAILED, "{command}");
        assert_eq!(action, "review", "{command}: {code}");
    }
}

/// Reading the program out of an `xargs` leaves the operands standard input
/// supplies unread. An extension that owns that program judges arguments this
/// text does not hold, so the read-through does not stand in for its rules.
#[test]
fn an_xargs_into_a_programs_own_extension_stays_unreadable() {
    // Every permission enabled is the softest the extension gets; a disabled
    // or default permission only holds the command higher.
    let controls = controls(github("enabled", None), false);
    for command in [
        "xargs gh pr merge 17 --squash < list.txt",
        "cat list.txt | xargs gh pr close",
        "xargs -n 1 gh pr close",
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
        // A bare `--replace` leaves it open whether the next word is its
        // token or the program.
        "xargs --replace mv",
        "xargs --max-args 1 --replace ITEM mv",
        // A long option this does not know may take the next word.
        "xargs --future-option rm",
        // Programs this cannot read from the text.
        "xargs sh -c 'rm $0'",
        "xargs $tool",
        "xargs bin/*",
        // The word is an argument of `echo`, not an `xargs` invocation.
        "echo xargs rm",
        // Every `xargs` in the text has to name its program.
        "cat list.txt | xargs rm -f && cat more.txt | xargs",
    ] {
        assert!(!xargs_names_its_program(unbounded), "{unbounded}");
    }
}

/// A bare `xargs` takes the caller's standard input, so the operands it hands
/// the program it names are not in the text. `xargs rm -rf BUILD` deletes
/// whatever that input holds, and the text proves nothing about it.
#[test]
fn an_xargs_without_a_named_input_stays_unreadable() {
    for named in [
        "cat list.txt | xargs -0 rm -f",
        "find . -name '*.log' | xargs rm",
        "xargs rm -f < list.txt",
        "xargs -a list.txt rm -f",
        "xargs --arg-file=list.txt rm -f",
    ] {
        assert!(xargs_input_is_named(named), "{named}");
    }
    for unnamed in [
        "xargs rm -rf BUILD",
        "xargs rm -rf '<tmp>'",
        "xargs rm -rf < /dev/stdin",
        "xargs rm -rf <&0",
        "xargs rm -rf < /dev/fd/0",
        "xargs rm -rf < /proc/self/fd/0",
        "xargs rm 2<list.txt",
        "xargs -a - rm",
        "xargs -a /dev/stdin rm",
        "xargs --arg-file=- rm",
        "xargs -0 rm -f",
        "xargs grep -a pattern",
        // The right side of a `||` follows no pipe.
        "test -f list.txt || xargs rm -f",
        // Every `xargs` in the text needs its own input.
        "cat list.txt | xargs rm -f && xargs rm -rf BUILD",
    ] {
        assert!(!xargs_input_is_named(unnamed), "{unnamed}");
    }
}
