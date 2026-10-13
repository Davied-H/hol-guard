#!/usr/bin/env python3
"""Record parity vectors for Guard's Claude Code prompt notice.

Usage: GUARD_PY_SNAPSHOT=<path to src dir of the reference snapshot> \
    python scripts/record_claude_prompt_notice_vectors.py [snapshot_src]

The reference snapshot must predate the move of the notice to the native
runtime (base commit ``BASE_COMMIT``). Each vector is one native prompt result,
the harness response the edge rendered for it, and the response the daemon
returns after adding its notice. Deterministic output.
"""

from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path

snapshot = os.environ.get("GUARD_PY_SNAPSHOT") or (sys.argv[1] if len(sys.argv) > 1 else "")
if not snapshot:
    sys.exit("set GUARD_PY_SNAPSHOT or pass the snapshot src directory")
sys.path.insert(0, snapshot)

from codex_plugin_scanner.guard.daemon import hook_worker_native as reference  # noqa: E402

BASE_COMMIT = "0c317c93f9"
OUT = Path(__file__).resolve().parent.parent / "rust/crates/guard-runtime/tests/fixtures"
ACTIONS = ("require-reapproval", "block", "sandbox-required")
CLASS_SETS: tuple[tuple[str, object], ...] = (
    ("no-classes", ...),
    ("empty", []),
    ("local-env", ["local_env_read"]),
    ("sensitive-material", ["sensitive_material"]),
    ("secret-read", ["secret_read"]),
    ("bypass", ["guard_bypass_intent"]),
    ("bypass-and-secret", ["local_env_read", "guard_bypass_intent"]),
    ("other", ["destructive_command"]),
    ("odd-items", ["", "  ", None, 3, {"class": "local_env_read"}, " local_env_read"]),
    ("not-a-list", "local_env_read"),
)
REASONS: tuple[tuple[str, object], ...] = (
    ("reason-plain", "Guard needs approval for this prompt"),
    ("reason-punctuated", "Guard blocked this prompt!"),
    ("reason-question", "  Should Claude read secrets?  "),
    ("reason-padded", "\t Guard flagged this prompt \n"),
    ("reason-blank", "   "),
    ("reason-empty", ""),
    ("reason-null", None),
    ("reason-missing", ...),
)
RESPONSES: tuple[tuple[str, dict[str, object]], ...] = (
    ("hook-output", {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}),
    (
        "hook-output-existing",
        {
            "systemMessage": "Edge message",
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": "Edge context"},
        },
    ),
    ("hook-output-not-object", {"hookSpecificOutput": "UserPromptSubmit", "continue": True}),
    ("no-hook-output", {"decision": "block", "reason": "Edge reason"}),
)


def result(action: object, classes: object, reason: object) -> dict[str, object]:
    fields: dict[str, object] = {"decision": "block", "minimum_action": action, "reason": reason}
    if classes is not ...:
        fields["prompt_risk_classes"] = classes
    return {key: value for key, value in fields.items() if value is not ...}


def cases() -> list[tuple[str, dict[str, object], dict[str, object]]]:
    collected = []
    for action in ACTIONS:
        for class_label, classes in CLASS_SETS:
            for reason_label, reason in REASONS:
                collected.append(
                    (f"{action}/{class_label}/{reason_label}", result(action, classes, reason), RESPONSES[0][1])
                )
        for response_label, response in RESPONSES[1:]:
            for class_label, classes in (CLASS_SETS[0], CLASS_SETS[2], CLASS_SETS[5]):
                collected.append(
                    (
                        f"{action}/{class_label}/{response_label}",
                        result(action, classes, "Guard needs approval"),
                        response,
                    )
                )
    for action in ("allow", "warn", "review", "", None, 3):
        collected.append((f"other-action/{action!r}", result(action, ["local_env_read"], "Reason"), RESPONSES[0][1]))
    return collected


def main() -> None:
    document = {
        "schema": "claude-prompt-notice-vectors.v1",
        "base_commit": BASE_COMMIT,
        "cases": [
            {
                "name": name,
                "result": native_result,
                "response": response,
                "expected": reference._claude_native_prompt_brand(copy.deepcopy(response), native_result),
            }
            for name, native_result, response in cases()
        ],
    }
    path = OUT / "claude_prompt_notice_vectors.json"
    path.write_text(json.dumps(document, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {len(document['cases'])} vectors to {path}")


if __name__ == "__main__":
    main()
