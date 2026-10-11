//! Sensitivity authority uses the existing admitted, request-bound resident.

use guard_contracts::RequestContextContentSensitivityV1;
use serde_json::{json, Value};

use crate::request_context_op::Budget;

#[cfg(test)]
#[path = "content_sensitivity_op_tests.rs"]
mod tests;

pub(crate) fn evaluate(
    body: &RequestContextContentSensitivityV1,
    budget: &Budget,
    store: Option<&crate::policy_store::PolicySnapshotStore>,
) -> Result<Value, &'static str> {
    budget.check()?;
    let encoded = serde_json::to_vec(&body.input)
        .map_err(|_| "native_request_context_content_input_invalid")?;
    if encoded.len() > 262_144 || body.query.len() > 32 {
        return Err("native_request_context_content_input_invalid");
    }
    let result =
        guard_command::content_sensitivity::evaluate(&body.query, &body.input, budget.deadline())
            .map_err(|_| "native_request_context_content_unavailable")?;
    if result["ok"]["action"] == "forward" {
        // A Python-provided allow field is never a native forwarding grant.
        let store = store.ok_or("native_request_context_content_receipt_unavailable")?;
        let receipt: guard_contracts::NativeHookDecisionReceiptV1 =
            serde_json::from_value(body.input["validated_receipt"].clone())
                .map_err(|_| "native_request_context_content_receipt_invalid")?;
        crate::policy_store::native_review_origin::verify(store, &receipt)
            .map_err(|_| "native_request_context_content_receipt_invalid")?;
        let harness = body.input["binding"]["harness"]
            .as_str()
            .ok_or("native_request_context_content_receipt_invalid")?;
        if receipt.harness != harness
            || receipt.event_name != "PostToolUse"
            || receipt.decision != "allow"
            || receipt.model_output_action != "allow_original"
            || receipt.observe_mode && body.input["allow_observe_mode"] != Value::Bool(true)
        {
            return Err("native_request_context_content_receipt_invalid");
        }
    }
    budget.check()?;
    Ok(json!({"kind":"content_sensitivity","query":body.query,"result":result}))
}
