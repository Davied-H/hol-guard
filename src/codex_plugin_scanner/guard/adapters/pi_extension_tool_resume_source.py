"""Ask an Oh My Pi agent to re-run a call the user approved after a block.

In `safe-alternative` mode a reviewed tool call is blocked at once and queued
in the inbox, and the agent moves on. When the daemon says an approval can
release the identical retry (`approval_resume`), the active OMP extension
waits for that decision in the background, as it already does for a blocked
prompt. On an approval it starts a new turn that asks the model to run the
same call with the same arguments. This is a retry, not a continuation: the
one-time approval binding still rejects any call that is not identical.
"""

from __future__ import annotations

TOOL_APPROVAL_RESUME_SOURCE = (
    "  const TOOL_APPROVAL_RESUME_ARGUMENT_CHARS = 8_000;\n"
    "  function toolApprovalResumeMessage(toolName: string, toolInput: unknown): string {\n"
    "    let argumentsText: string | null = null;\n"
    "    try {\n"
    "      argumentsText = canonicalJson(toolInput);\n"
    "    } catch {\n"
    "      argumentsText = null;\n"
    "    }\n"
    "    const fence = '```';\n"
    "    const exact = argumentsText !== null && argumentsText.length <= TOOL_APPROVAL_RESUME_ARGUMENT_CHARS\n"
    "      ? `Run that ${toolName} call again now with exactly these arguments, unchanged:"
    "\\n\\n${fence}json\\n${argumentsText}\\n${fence}`\n"
    "      : `Run that ${toolName} call again now with exactly the same arguments, unchanged.`;\n"
    "    return [\n"
    "      `HOL Guard: the user approved the ${toolName} call that was blocked earlier in this session.`,\n"
    "      exact,\n"
    "      'The approval covers one identical call. A changed argument is a new action that needs a new approval.',\n"
    "    ].join('\\n\\n');\n"
    "  }\n"
    "  function scheduleToolApprovalResume(\n"
    "    response: GuardResponse,\n"
    "    ctx: { ui: { notify(message: string, kind?: 'info' | 'warning'): void } },\n"
    "    snapshot: { payload: Record<string, unknown> },\n"
    "  ): void {\n"
    "    const resume = (response as { approval_resume?: unknown }).approval_resume;\n"
    "    if (!resume || typeof resume !== 'object' || !ompInteractiveContext(ctx)) return;\n"
    "    const record = resume as { request_id?: unknown; poll_path?: unknown };\n"
    "    const requestId = typeof record.request_id === 'string' ? record.request_id.trim() : '';\n"
    "    if (!requestId || pendingApprovalResumes.has(requestId)) return;\n"
    "    const binding = captureInputApprovalResumeBinding(ctx);\n"
    "    if (binding === null) return;\n"
    "    const isActive = () => inputApprovalResumeBindingIsActive(ctx, binding);\n"
    "    const pollPath = typeof record.poll_path === 'string' && record.poll_path.startsWith('/v1/requests/')\n"
    "      ? record.poll_path\n"
    "      : `/v1/requests/${encodeURIComponent(requestId)}`;\n"
    "    const toolName = typeof snapshot.payload.tool_name === 'string' && snapshot.payload.tool_name\n"
    "      ? snapshot.payload.tool_name\n"
    "      : 'tool';\n"
    "    const content = toolApprovalResumeMessage(toolName, snapshot.payload.tool_input);\n"
    "    pendingApprovalResumes.set(requestId, binding);\n"
    "    void (async () => {\n"
    "      try {\n"
    "        const action = await pollApprovalResolution(requestId, pollPath, undefined, isActive);\n"
    "        if (action === 'allow' && isActive()) {\n"
    "          pi.sendMessage(\n"
    "            {\n"
    "              customType: 'hol_guard_approval_resume',\n"
    "              content,\n"
    "              display: false,\n"
    "              details: { requestId, toolName },\n"
    "              attribution: 'agent',\n"
    "            },\n"
    "            { triggerTurn: true, deliverAs: 'nextTurn' },\n"
    "          );\n"
    "          ctx.ui.notify('HOL Guard approved this request. Oh My Pi is running it again.', 'info');\n"
    "        } else if (action === 'block') {\n"
    "          ctx.ui.notify('HOL Guard kept this request blocked. Oh My Pi will not run it.', 'warning');\n"
    "        }\n"
    "      } finally {\n"
    "        if (pendingApprovalResumes.get(requestId) === binding) {\n"
    "          pendingApprovalResumes.delete(requestId);\n"
    "        }\n"
    "      }\n"
    "    })();\n"
    "  }\n"
)

_BLOCK_WITHOUT_REQUEST = (
    "      if (!requestId) {\n"
    '        ctx.ui.notify(reason, "warning");\n'
    "        return { block: true, reason };\n"
    "      }\n"
)
_BLOCK_WITH_RESUME = (
    "      if (!requestId) {\n"
    "        scheduleToolApprovalResume(response, ctx, snapshot);\n"
    '        ctx.ui.notify(reason, "warning");\n'
    "        return { block: true, reason };\n"
    "      }\n"
)


def with_tool_approval_resume(shared_source: str, *, harness: str) -> str:
    """Extend the active OMP variant, keeping the previous v1 text frozen."""
    if harness != "omp":
        return shared_source
    if shared_source.count(_BLOCK_WITHOUT_REQUEST) != 1:
        raise ValueError("OMP tool approval resume insertion point changed")
    return TOOL_APPROVAL_RESUME_SOURCE + shared_source.replace(_BLOCK_WITHOUT_REQUEST, _BLOCK_WITH_RESUME, 1)
