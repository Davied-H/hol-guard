from __future__ import annotations

from pathlib import Path

import pytest

from tests.pi_extension_response_callback_support import _run_generated_callback_payload
from tests.pi_extension_response_source_support import _generated_source


@pytest.mark.parametrize("harness", ["pi", "omp"])
@pytest.mark.parametrize(
    ("reason_code", "cause"),
    [
        ("output_secret_match", "credential-shaped text"),
        ("native_secret_exfiltration", "credential-shaped text"),
        ("native_prompt_injection_review", "instructions addressed to the agent"),
        ("native_post_tool_content", "HOL Guard recorded this as native_post_tool_content."),
    ],
)
def test_blocked_output_names_its_cause_without_quoting_the_output(
    tmp_path: Path, harness: str, reason_code: str, cause: str
) -> None:
    source = _generated_source(tmp_path, harness=harness)
    response = {
        "decision": "deny",
        "reason": "private fixture AKIAIOSFODNN7EXAMPLE in output",
        "reason_code": reason_code,
    }
    result = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": '{"note":"fixture"}'}],
        response,
        use_generated_blocked_reason=True,
    )
    text = result["result"]["content"][0]["text"]
    assert result["result"]["isError"] is True
    assert "blocked this tool output" in text
    assert cause in text
    assert "Do not retry the same tool call automatically" in text
    # The native reason can quote the blocked output; only the user notice carries it.
    assert "AKIAIOSFODNN7EXAMPLE" not in text
    assert "private fixture" not in text


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_blocked_output_omits_a_cause_for_an_unnamed_reason_code(tmp_path: Path, harness: str) -> None:
    source = _generated_source(tmp_path, harness=harness)
    response = {
        "decision": "deny",
        "reason": "Blocked by HOL Guard.",
        "reason_code": "Not A Code",
    }
    result = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": '{"note":"fixture"}'}],
        response,
        use_generated_blocked_reason=True,
    )
    text = result["result"]["content"][0]["text"]
    assert "blocked this tool output" in text
    assert "HOL Guard recorded this as" not in text
    assert "Not A Code" not in text
