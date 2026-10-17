//! A pre-tool request that says where the command runs.
//!
//! The hook lane hands the harness's working directory and home directory to
//! the edge, and every rule that reads a path needs them: without them
//! `rg -n pattern ../service-api` cannot be resolved to anything, so it is
//! reviewed. A caller that asks the pre-tool entry point the same question —
//! `guard inspect`, the dashboard's console, a hook that goes through the
//! command-line lane — used to get the context-free answer, which reported a
//! review for work the enforced lane allows.
use crate::pretool_home_layout_reads::layout;
use guard_command::pretool::{evaluate_pre_tool, evaluate_pre_tool_in};
use guard_command::CommandModelRequestV1;

fn request(command: &str) -> CommandModelRequestV1 {
    CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    }
}

#[test]
fn a_sibling_search_reads_the_same_way_the_hook_lane_reads_it() {
    let layout = layout("pretool-request-context");
    let cwd = layout.org.join("app-portal");
    let command = request("rg -n fixture ../service-api");

    let without = evaluate_pre_tool(&command).unwrap();
    assert_eq!(
        without.minimum_action, "review",
        "a command that resolves nowhere is reviewed"
    );

    let with = evaluate_pre_tool_in(&command, layout.home.to_str(), cwd.to_str()).unwrap();
    assert_eq!(with.minimum_action, "allow", "{}", with.reason_code);
}

#[test]
fn a_sensitive_read_keeps_its_review_once_the_directories_are_known() {
    let layout = layout("pretool-request-context-secret");
    let cwd = layout.org.join("app-portal");
    for command in [
        "cat ~/.ssh/id_rsa",
        "rg -n token ~/.ssh",
        "cat ../service-api/.env",
    ] {
        let command = request(command);
        let decision = evaluate_pre_tool_in(&command, layout.home.to_str(), cwd.to_str()).unwrap();
        assert_ne!(decision.minimum_action, "allow", "{}", command.command);
    }
}
