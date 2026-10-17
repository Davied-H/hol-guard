"""Read the inspected Composio meta-tool execution boundaries from the resident.

Tool roles describe routing, never authority. Hosted execution takes an array
of exact tool slugs, arguments and optional account selectors. Missing account
selectors cannot be interpreted as an account identity by Guard.

The native runtime owns the contract. These helpers only ask it and fall back
to the stricter answer when it cannot be reached: no role at all, and the
provider review a tool the contract cannot place would draw. Neither helper
recomputes a role in Python, so an absent resident can never route a call the
way a reachable one would have.
"""

from __future__ import annotations

from typing import Literal, cast

from ..native_composio_role import composio_role_native

ComposioToolRole = Literal["discovery", "batch", "workbench", "connections", "unknown"]


def composio_tool_role(tool_name: str) -> ComposioToolRole | None:
    """The wrapper a tool name routes to, or ``None`` for one the contract does not place.

    An unreachable resident also answers ``None``: callers gate discovery-only
    work on an exact ``"discovery"``, so no role refuses that work rather than
    admitting it.
    """
    native = composio_role_native(tool_name)
    if native is None:
        return None
    # The client admits only the contract's own roles, so the published
    # Literal holds without re-deriving it here.
    return cast("ComposioToolRole | None", native.role)


def composio_requires_action_review(tool_name: str) -> bool:
    """Whether a call to this tool is reviewed as a provider action.

    An unreachable resident answers ``True``: the call then draws the review a
    wrapper that could carry a provider action draws, never the quiet path.
    """
    native = composio_role_native(tool_name)
    return True if native is None else native.requires_action_review
