"""Intentionally weak agent loop: the vulnerable baseline.

Calls the LLM, and if it asks for a tool, runs that tool with whatever
arguments the LLM supplied. There is no allowlist, no human approval
step, and no output filtering anywhere in this loop. This is deliberately
unsafe; defenses are added in a later phase of the lab.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from aegislab.agent.memory import SessionMemory
from aegislab.agent.prompts import SYSTEM_PROMPT
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
) -> str:
    """Run one user turn to completion, calling tools in a loop (up to max_steps).

    If rag_index is given, its top matches for user_input are pasted
    directly into context as-is before the LLM is called -- no isolation,
    no "untrusted content" framing. This is the intended indirect prompt
    injection surface for this lab phase.
    """
    if not session.messages:
        session.append({"role": "system", "content": SYSTEM_PROMPT})
    session.append({"role": "user", "content": user_input})

    if rag_index is not None:
        for retrieved in rag_index.search(user_input, top_k=2):
            session.append({"role": "system", "content": retrieved.text})

    tools = _tools_schema(registry)

    for _ in range(max_steps):
        reply = llm.chat(session.messages, tools)

        if reply.tool_calls:
            session.append(
                {
                    "role": "assistant",
                    "content": reply.content,
                    "tool_calls": [
                        {"id": tc.id, "name": tc.name, "arguments": tc.arguments}
                        for tc in reply.tool_calls
                    ],
                }
            )
            for tool_call in reply.tool_calls:
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

        session.append({"role": "assistant", "content": reply.content})
        return reply.content or ""

    return "[aegislab] step limit reached without a final answer."
