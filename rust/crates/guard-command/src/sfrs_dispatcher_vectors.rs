//! Parity of `extract_sensitive_tool_action_request` against recorded Python
//! output. The fixture holds a directory tree plus the host facts each case
//! depended on: the executable identities it requested, `sys.executable`, the
//! environment and the reuse nonce. A case names the tool, the arguments, the
//! declared cwd and home, the text its canonical command was parsed from, and
//! the kind of synthetic native evaluation it carried. Paths carry a `{ROOT}`
//! token bound to a fresh tree.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::Path;

use serde_json::Value;

use crate::codex_output_env::{Ctx, GitCheck, GitRun, InspectionHost};
use crate::command_evaluation::CommandDecisionFloor;
use crate::command_model::parse_shell_command;
use crate::hook_adapter_value::OValue;
use crate::sfrs_dispatcher::{extract_sensitive_tool_action_request, ExtractInputs};
use crate::sfrs_dispatcher_request::NativeEvaluationView;
use crate::sfrs_pytest_vectors::{bind, build_tree_in, text};

type CallKey = (String, Option<String>, String);

/// Replays the host facts of one recorded case.
struct CaseHost {
    environment: Vec<(String, String)>,
    guard: String,
    nonce: String,
    calls: HashMap<CallKey, Value>,
}

impl InspectionHost for CaseHost {
    fn env(&self, name: &str) -> Option<String> {
        self.environment
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    }
    fn environment(&self) -> Vec<(String, String)> {
        self.environment.clone()
    }
    fn runtime_executable_identity(
        &self,
        command: &str,
        search_path: Option<&str>,
        cwd: &str,
    ) -> Option<Value> {
        self.calls
            .get(&(
                command.to_owned(),
                search_path.map(str::to_owned),
                cwd.to_owned(),
            ))
            .cloned()
    }
    fn reuse_nonce(&self) -> Option<String> {
        Some(self.nonce.clone())
    }
    fn guard_executable(&self) -> Option<String> {
        Some(self.guard.clone())
    }
    fn git_executable(&self) -> Option<String> {
        None
    }
    fn git_safety(&self, _: GitCheck, _: Option<&str>, _: &[String]) -> bool {
        false
    }
    fn git_binary_trusted(&self, _: &str, _: &str) -> bool {
        false
    }
    fn run_git(&self, _: &str, _: &[String], _: &str) -> GitRun {
        GitRun::Failed("vector host does not run git")
    }
}

fn fixture() -> Value {
    let bytes = include_bytes!("../tests/fixtures/sfrs/sfrs_dispatcher.json.gz");
    let mut text = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut text)
        .expect("gzip");
    serde_json::from_str(&text).expect("json")
}

fn case_host(document: &Value, root: &Path, case: &Value) -> CaseHost {
    let environment = bind(root, &document["env"])
        .as_object()
        .expect("env")
        .iter()
        .map(|(key, value)| (key.clone(), text(value).to_owned()))
        .collect();
    let mut calls = HashMap::new();
    for call in case["calls"].as_array().into_iter().flatten() {
        let call = bind(root, call);
        let key = (
            text(&call[0]).to_owned(),
            call[1].as_str().map(str::to_owned),
            text(&call[2]).to_owned(),
        );
        calls.insert(key, call[3].clone());
    }
    CaseHost {
        environment,
        guard: text(&bind(root, &document["guard"])).to_owned(),
        nonce: text(&document["nonce"]).to_owned(),
        calls,
    }
}

/// The synthetic native evaluation the recorder built for `kind`.
fn native_view(kind: &str, identity: &str, other: &str) -> NativeEvaluationView {
    let strings = |items: &[&str]| items.iter().map(|item| (*item).to_owned()).collect();
    let mut view = NativeEvaluationView {
        security_identity: identity.to_owned(),
        minimum_action: CommandDecisionFloor::Allow,
        match_default_modes: Vec::new(),
        reason_codes: Vec::new(),
        explicitly_enabled_permission_ids: Vec::new(),
        controlling_action_class: None,
        controlling_reason: None,
    };
    match kind {
        "benign" => view.reason_codes = strings(&["native.explicit-benign"]),
        "disabled_only" => view.match_default_modes = strings(&["disabled", "disabled"]),
        "interaction" => {
            view.minimum_action = CommandDecisionFloor::Review;
            view.match_default_modes = strings(&["review"]);
            view.controlling_action_class = Some("package install command".to_owned());
            view.controlling_reason = Some("A command extension requires review.".to_owned());
        }
        "enabled_allow" => {
            view.match_default_modes = strings(&["review"]);
            view.explicitly_enabled_permission_ids = strings(&["perm.x"]);
            view.controlling_action_class = Some("enabled extension action".to_owned());
            view.controlling_reason = Some("An enabled extension needs composition.".to_owned());
        }
        "monitor_no_class" => {
            view.minimum_action = CommandDecisionFloor::Monitor;
            view.match_default_modes = strings(&["review"]);
        }
        "classification_block" => {
            view.minimum_action = CommandDecisionFloor::Block;
            view.reason_codes = strings(&["native.classification-block"]);
        }
        "block_with_matches" => {
            view.minimum_action = CommandDecisionFloor::Block;
            view.match_default_modes = strings(&["block"]);
            view.reason_codes = strings(&["native.classification-block"]);
            view.controlling_action_class = Some("blocked extension action".to_owned());
            view.controlling_reason = Some("A command extension blocks this command.".to_owned());
        }
        "mismatch" => view.security_identity = other.to_owned(),
        other_kind => panic!("unknown native kind {other_kind}"),
    }
    view
}

fn declared(root: &Path, value: &Value) -> Option<std::path::PathBuf> {
    value.as_str().map(|relative| root.join(relative))
}

fn run_case(document: &Value, root: &Path, case: &Value) -> Value {
    let host = case_host(document, root, case);
    let ctx = Ctx::new(
        &host,
        &root.join("proj").to_string_lossy(),
        &root.join("home").to_string_lossy(),
    );
    let (cwd, home) = (declared(root, &case["cwd"]), declared(root, &case["home"]));
    let canonical = case["canonical"].as_str().map(|command| {
        parse_shell_command(
            command,
            cwd.as_deref(),
            home.as_deref(),
            "posix",
            "shell_string",
            "guard-shell",
            true,
        )
    });
    let native = match (&canonical, case["native"].as_str()) {
        (Some(command), Some(kind)) => {
            let other = parse_shell_command(
                "echo different",
                cwd.as_deref(),
                home.as_deref(),
                "posix",
                "shell_string",
                "guard-shell",
                true,
            );
            Some(native_view(
                kind,
                &command.security_identity(),
                &other.security_identity(),
            ))
        }
        _ => None,
    };
    let inputs = ExtractInputs {
        cwd: cwd.as_deref(),
        home_dir: home.as_deref(),
        canonical_command: canonical.as_ref(),
        native_evaluation: native.as_ref(),
        controls: None,
        ctx: &ctx,
    };
    let tool = OValue::from_wire(&tagged_wire(&case["tool"])).expect("tool");
    let arguments = bind(root, &case["arguments"]);
    match extract_sensitive_tool_action_request(&tool, &arguments, &inputs) {
        Ok(None) => Value::Null,
        Ok(Some(mut request)) => {
            if request.shell_execution_context_hash.is_some() {
                request.shell_execution_context_hash = Some("<hash>".to_owned());
            }
            serde_json::to_value(&request).expect("serialize")
        }
        Err(error) => serde_json::json!({ "error": error.0 }),
    }
}

/// The recorder writes plain JSON; the resident wire tags each list with `"l"`.
fn tagged_wire(value: &Value) -> Value {
    match value {
        Value::Array(items) => {
            let mut tagged = vec![Value::String("l".to_owned())];
            tagged.extend(items.iter().map(tagged_wire));
            Value::Array(tagged)
        }
        other => other.clone(),
    }
}

#[test]
fn dispatcher_matches_recorded_python() {
    let document = fixture();
    let scratch = build_tree_in(&document, "sfrs-dispatch");
    let root = scratch.0.clone();
    let mut failures = Vec::new();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let cases = document["cases"].as_array().expect("cases");
    for (position, case) in cases.iter().enumerate() {
        let expected = match case.get("error") {
            Some(error) => serde_json::json!({ "error": error }),
            None => bind(&root, &case["result"]),
        };
        let actual = run_case(&document, &root, case);
        let bucket = if actual == expected { "pass" } else { "fail" };
        *counts.entry(bucket).or_default() += 1;
        if actual != expected && failures.len() < 40 {
            failures.push(format!(
                "case {position}: tool {} args {} cwd {} home {} canonical {} native {}\n  expected {expected}\n  actual   {actual}",
                case["tool"], case["arguments"], case["cwd"], case["home"], case["canonical"], case["native"],
            ));
        }
    }
    assert!(cases.len() >= 800, "recorded {} cases", cases.len());
    assert!(
        counts.get("fail").is_none(),
        "{counts:?}\n{}",
        failures.join("\n")
    );
}
