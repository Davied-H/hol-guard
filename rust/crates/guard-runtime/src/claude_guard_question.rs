//! Claude `AskUserQuestion` answers to HOL Guard approval prompts.
//!
//! When Guard holds a sensitive Claude action it asks Claude to put one fixed
//! approval question to the user. The PostToolUse hook for that question
//! carries the question Claude actually asked and the user's answer. This
//! kind decides whether the asked question is exactly the pending prompt
//! (header, question text bound to the approval code, the three options) and
//! maps the chosen option to `allow` or `block`. Anything else is not an
//! approval: the caller persists nothing.

use guard_contracts::ClaudeGuardQuestionVerdictV1;
use serde_json::{Map, Value};

use crate::context_digest::{is_python_space, python_strip};

const HEADER: &str = "HOL Guard";
const DEFAULT_QUESTION: &str =
    "HOL Guard intercepted this sensitive action. What should Claude do?";
const OPTIONS: [&str; 3] = ["Allow once", "Allow during this session", "Keep blocked"];
const ANSWER_KEYS: [&str; 6] = [
    "answer",
    "selected_answer",
    "selected",
    "choice",
    "value",
    "label",
];

/// The hook fields the verdict reads, as the transport projected them.
pub(crate) struct Question<'a> {
    pub event: Option<&'a str>,
    pub tool_name: &'a Value,
    pub tool_input: &'a Value,
    pub tool_response: &'a Value,
    /// `tool_response.answers` as ordered `[question, answer]` pairs, so the
    /// first matching question wins as it did in hook order.
    pub response_answers: Option<&'a [Value]>,
    pub pending: &'a Value,
}

struct Contract {
    header: String,
    question: String,
    options: Vec<String>,
}

/// Case- and whitespace-insensitive form used for every comparison.
fn normalize(text: &str) -> String {
    python_strip(text)
        .to_lowercase()
        .split(is_python_space)
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn optional_string(value: Option<&Value>) -> Option<String> {
    let text = python_strip(value?.as_str()?);
    (!text.is_empty()).then(|| text.to_owned())
}

/// Option labels; any item without a label voids the whole list.
fn options(value: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    let mut labels = Vec::with_capacity(items.len());
    for item in items {
        let label = match item {
            Value::Object(object) => optional_string(object.get("label")),
            Value::String(text) => Some(python_strip(text).to_owned()),
            _ => None,
        };
        match label {
            Some(label) => labels.push(label),
            None => return Vec::new(),
        }
    }
    labels
}

fn normalized_options(options: &[impl AsRef<str>]) -> Vec<String> {
    options
        .iter()
        .map(|option| normalize(option.as_ref()))
        .collect()
}

/// The prompt Guard asked Claude to show for this pending approval.
fn pending_contract(pending: &Map<String, Value>) -> Option<Contract> {
    let header = optional_string(pending.get("approval_header"));
    let question = optional_string(pending.get("approval_question"));
    let options = options(pending.get("approval_options"));
    let expected_question = match optional_string(pending.get("approval_code")) {
        None if header.is_none() && question.is_none() && options.is_empty() => {
            return Some(Contract {
                header: HEADER.to_owned(),
                question: DEFAULT_QUESTION.to_owned(),
                options: OPTIONS.iter().map(|option| (*option).to_owned()).collect(),
            });
        }
        None => DEFAULT_QUESTION.to_owned(),
        Some(code) => format!(
            "HOL Guard intercepted this sensitive action (approval code: {code}). What should Claude do?"
        ),
    };
    let (Some(header), Some(question)) = (header, question) else {
        return None;
    };
    if options.is_empty()
        || normalize(&question) != normalize(&expected_question)
        || normalized_options(&options) != normalized_options(&OPTIONS)
    {
        return None;
    }
    Some(Contract {
        header,
        question,
        options,
    })
}

/// The single question in an `AskUserQuestion` input or response.
fn asked_contract(section: &Value) -> Option<Contract> {
    let Value::Array(questions) = section.as_object()?.get("questions")? else {
        return None;
    };
    let [Value::Object(first)] = questions.as_slice() else {
        return None;
    };
    let contract = Contract {
        header: optional_string(first.get("header"))?,
        question: optional_string(first.get("question"))?,
        options: options(first.get("options")),
    };
    (!contract.options.is_empty()).then_some(contract)
}

fn contracts_match(expected: &Contract, actual: &Contract) -> bool {
    normalize(&actual.header) == normalize(&expected.header)
        && normalize(&actual.question) == normalize(&expected.question)
        && normalized_options(&actual.options) == normalized_options(&expected.options)
}

fn is_question(request: &Question<'_>, pending: &Map<String, Value>) -> bool {
    if request.event != Some("PostToolUse") {
        return false;
    }
    let tool_name = optional_string(Some(request.tool_name));
    if tool_name.map(|name| name.to_lowercase()).as_deref() != Some("askuserquestion") {
        return false;
    }
    let Some(expected) = pending_contract(pending) else {
        return false;
    };
    let Some(input) = asked_contract(request.tool_input) else {
        return false;
    };
    contracts_match(&expected, &input)
        && asked_contract(request.tool_response)
            .is_none_or(|response| contracts_match(&expected, &response))
}

fn answer_text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(text) if !python_strip(text).is_empty() => Some(text.clone()),
        Value::Object(object) => optional_string(object.get("label")),
        _ => None,
    }
}

fn action_for_answer(text: &str) -> Option<&'static str> {
    match normalize(text).as_str() {
        "keep blocked" => Some("block"),
        "allow once" | "allow during this session" => Some("allow"),
        _ => None,
    }
}

/// The answer the user chose, read from the shapes Claude has reported.
fn chosen_answer(request: &Question<'_>, expected_question: Option<&str>) -> Option<String> {
    let response = match request.tool_response {
        Value::String(text) if !python_strip(text).is_empty() => return Some(text.clone()),
        Value::Object(object) => object,
        _ => return None,
    };
    if let Some(pairs) = request.response_answers {
        let pair = |item: &'_ Value| -> Option<(String, Value)> {
            let [Value::String(question), answer] = item.as_array()?.as_slice() else {
                return None;
            };
            Some((question.clone(), answer.clone()))
        };
        if let Some(expected) = expected_question.map(normalize) {
            let matched = pairs
                .iter()
                .filter_map(pair)
                .filter(|(question, _)| normalize(question) == expected)
                .find_map(|(_, answer)| answer_text(Some(&answer)));
            if matched.is_some() {
                return matched;
            }
        }
        if let [only] = pairs {
            if let Some(text) = pair(only).and_then(|(_, answer)| answer_text(Some(&answer))) {
                return Some(text);
            }
        }
    }
    if let Some(text) = ANSWER_KEYS
        .iter()
        .find_map(|key| answer_text(response.get(*key)))
    {
        return Some(text);
    }
    if response.contains_key("questions") || response.contains_key("options") {
        return None;
    }
    match response.get("content") {
        Some(Value::String(text)) if !python_strip(text).is_empty() => Some(text.clone()),
        _ => None,
    }
}

/// Whether the hook answers the pending HOL Guard prompt, and with what.
pub(crate) fn verdict(request: &Question<'_>) -> ClaudeGuardQuestionVerdictV1 {
    let Some(pending) = request.pending.as_object() else {
        return ClaudeGuardQuestionVerdictV1 {
            is_question: false,
            action: None,
        };
    };
    if !is_question(request, pending) {
        return ClaudeGuardQuestionVerdictV1 {
            is_question: false,
            action: None,
        };
    }
    let expected_question = optional_string(pending.get("approval_question"));
    let action = chosen_answer(request, expected_question.as_deref())
        .and_then(|text| action_for_answer(&text))
        .map(str::to_owned);
    ClaudeGuardQuestionVerdictV1 {
        is_question: true,
        action,
    }
}

#[cfg(test)]
#[path = "claude_guard_question_tests.rs"]
mod tests;
