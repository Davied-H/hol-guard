"""Route contained-test receipts on the direct CLI hook path.

The daemon rewrites an eligible native containment receipt into the
contained sink before answering. Hook clients fall back to ``guard hook``
when the daemon is down, so this path must apply the same rewrite or the
harness sees a bare denial for ordinary test commands.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from ..adapters.zcode_contained_tests import route_zcode_containment
from ..daemon.hook_fail_closed import render_pre_tool

if TYPE_CHECKING:
    from ..adapters.base import HarnessContext


def emit_native_containment_route(
    edge: object,
    payload: dict[str, object],
    context: HarnessContext,
    workspace: Path | None,
    output_stream: TextIO | None,
) -> int | None:
    """Emit the contained-sink rewrite, or return ``None`` to keep the normal render."""

    if not isinstance(edge, Mapping) or edge.get("recording_only") or edge.get("event_name") != "PreToolUse":
        return None
    result = edge.get("result")
    if not isinstance(result, Mapping) or result.get("minimum_action") != "sandbox-required":
        return None
    harness = str(edge.get("harness") or "")
    receipt = render_pre_tool(harness, result, guard_home=context.guard_home)
    routed = route_zcode_containment(
        receipt,
        harness=harness,
        payload=payload,
        guard_home=context.guard_home,
        home_dir=context.home_dir,
        workspace=workspace,
    )
    if routed is receipt:
        return None
    stream = output_stream if output_stream is not None else sys.stdout
    stream.write(json.dumps(routed, ensure_ascii=False, separators=(",", ":")) + "\n")
    stream.flush()
    return 0


__all__ = ["emit_native_containment_route"]
