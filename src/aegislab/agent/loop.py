"""Intentionally weak agent loop, with an optional defense layer v1
wired in behind DEFENSE=on (see aegislab.defense).

When DEFENSE=off (the default), this is exactly the original broken
baseline: no allowlist, no human approval step, no output filtering.
That baseline must keep working as-is for attack demos.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from aegislab.agent.memory import SessionMemory
from aegislab.agent.prompts import SYSTEM_PROMPT
from aegislab.defense.allowlist import DEFAULT_ROLE
from aegislab.defense.approval import ApprovalCallback, cli_approval
from aegislab.defense.policy import PolicyBlocked, defense_enabled, enforce_tool_call, wrap_untrusted
from aegislab.defense.redact import redact_text
from aegislab.llm.client import LLMClient
from aegislab.rag.index import RagIndex
from aegislab.tools.registry import ToolRegistry

MAX_STEPS = 8


def _tools_schema(registry: ToolRegistry) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["args_schema"],
            },
        }
        for tool in registry.list_tools()
    ]


def run_turn(
    user_input: str,
    session: SessionMemory,
    llm: LLMClient,
    registry: ToolRegistry,
    max_steps: int = MAX_STEPS,
    rag_index: RagIndex | None = None,
    role: str = DEFAULT_ROLE,
    approval_callback: ApprovalCallback | None = None,
) -> str:
    """Run one user turn to completion, calling tools in a loop (up to max_steps).

    If rag_index is given, its top matches for user_input are pasted into
    context before the LLM is called.

    When DEFENSE=on: tool calls are checked against a per-role allowlist,
    tools in aegislab.defense.policy.TOOLS_REQUIRING_APPROVAL (send_email)
    also need approval_callback to return True, RAG chunks are wrapped as
    untrusted data, and assistant output is redacted for secrets/emails.
    When DEFENSE=off (default): none of that runs -- RAG chunks are
    pasted in with no isolation and output is never redacted, matching
    the original vulnerable baseline exactly.
    """
    defense_on = defense_enabled()
    approve = approval_callback or cli_approval

    if not session.messages:
        session.append({"role": "system", "content": SYSTEM_PROMPT})
    session.append({"role": "user", "content": user_input})

    if rag_index is not None:
        for retrieved in rag_index.search(user_input, top_k=2):
            text = wrap_untrusted(retrieved.text) if defense_on else retrieved.text
            session.append({"role": "system", "content": text})

    tools = _tools_schema(registry)

    for _ in range(max_steps):
        reply = llm.chat(session.messages, tools)
        reply_content = redact_text(reply.content) if defense_on else reply.content

        if reply.tool_calls:
            session.append(
                {
                    "role": "assistant",
                    "content": reply_content,
                    "tool_calls": [
                        {"id": tc.id, "name": tc.name, "arguments": tc.arguments}
                        for tc in reply.tool_calls
                    ],
                }
            )
            for tool_call in reply.tool_calls:
                if defense_on:
                    try:
                        enforce_tool_call(tool_call.name, tool_call.arguments, role, approve)
                    except PolicyBlocked as exc:
                        session.append(
                            {
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "name": tool_call.name,
                                "content": json.dumps(
                                    {"ok": False, "data": {"error": str(exc)}, "side_effects": []}
                                ),
                            }
                        )
                        continue

                tool = registry.get(tool_call.name)
                if tool is None:
                    result_payload = {
                        "ok": False,
                        "data": {"error": f"unknown tool: {tool_call.name}"},
                        "side_effects": [],
                    }
                else:
                    result_payload = asdict(tool.execute(tool_call.arguments))

                session.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "name": tool_call.name,
                        "content": json.dumps(result_payload),
                    }
                )
            continue

        session.append({"role": "assistant", "content": reply_content})
        return reply_content or ""

    return "[aegislab] step limit reached without a final answer."
