//! A scheduling prefix names its programs the way the bare command does.
use super::tests::{controls, decision, github};

const FAILED: &str = "native_command_extension_evaluation_failed";

/// `timeout 30 npm test` models exactly. The same clock written with its
/// kill-after option left a wrapper the parser does not model, and so did
/// every `nice` and `stdbuf` spelling, which turned an ordinary long build
/// into an outright block with no approval left to give it.
#[test]
fn a_scheduling_prefix_reaches_its_owners_floor() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "nice cargo build",
        "nice -n 10 cargo build",
        "nice -n 19 npm run build",
        "stdbuf -oL npm test",
        "stdbuf -o0 -e0 cargo test",
        "setsid npm run dev",
        "timeout -k 5 30 npm test",
        "timeout -s KILL 30 cargo build",
        "timeout --preserve-status 5m npm run build",
    ] {
        let (action, code) = decision(&controls, command);
        assert_ne!(code, FAILED, "{command}");
        assert_eq!(action, "review", "{command}: {code}");
    }
}

/// The prefix opens no file, so the only thing it can stand in front of is an
/// interpreter, and that interpreter is a word in the same text. A prefix that
/// changes who runs the program, or what it inherits, is not one of these.
#[test]
fn a_prefix_hiding_an_interpreter_keeps_the_failure() {
    let controls = controls(github("enabled", None), false);
    for command in [
        "nice -n 10 sh -c 'npm run build'",
        "timeout -k 5 30 bash -lc 'pwd'",
        "stdbuf -oL python3 deploy.py",
        "setsid node server.js",
        "nice -n 10 xargs rm -f",
        "sudo -E npm install -g pnpm",
        "env FOO=1 npm run build",
        "sh -c 'npm run build'",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}

/// Reading the prefix does not read the command past it: a destructive program
/// the text names still reaches its own owner, whose floor blocks. Prefixing
/// `nice` must not be a way around that.
#[test]
fn a_prefix_does_not_soften_the_program_it_names() {
    let controls = controls(github("enabled", None), false);
    for command in ["nice -n 10 rm -rf /", "stdbuf -oL shred ~/.ssh/id_ed25519"] {
        assert_eq!(decision(&controls, command).0, "block", "{command}");
    }
}
