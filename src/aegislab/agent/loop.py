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
from aegislab.context.firewall import scan_and_log
from aegislab.context.firewall import wrap_untrusted as firewall_wrap_untrusted
from aegislab.context.parts import ContextPart, Origin, Trust
from aegislab.defense.allowlist import DEFAULT_ROLE
from aegislab.defense.approval import ApprovalCallback, cli_approval
from aegislab.defense.policy import PolicyBlocked, defense_enabled, enforce_tool_call, wrap_untrusted
from aegislab.defense.redact import redact_text
from aegislab.identity.store import default_store
from aegislab.identity.tokens import LEAST_PRIVILEGE_SCOPES
from aegislab.llm.client import LLMClient
from aegislab.rag.index import RagIndex
from aegislab.tools.registry import ToolRegistry

MAX_STEPS = 8


def _render_for_llm(messages: list[dict[str, Any]], defense_on: bool) -> list[dict[str, Any]]:
    """Builds the message list actually sent to the LLM this call, without
    mutating the stored session history (session.messages stays plain
    JSON-able text for every other reader -- tests, attack scripts, the
    defense layer).

    DEFENSE=off: returned unchanged -- everything concatenated raw, the
    original vulnerable baseline. DEFENSE=on: tool-role message content
    is treated as untrusted (origin=tool), scanned for jailbreak markers
    (logging DET-02, never silently dropped -- see
    aegislab.context.firewall), and wrapped with the hard delimiter.
    """
    if not defense_on:
        return messages

    rendered = []
    for message in messages:
        if message.get("role") == "tool":
            part = ContextPart(origin=Origin.TOOL, trust=Trust.UNTRUSTED, text=message.get("content") or "")
            scan_and_log(part)
            rendered.append({**message, "content": firewall_wrap_untrusted(part)})
        else:
            rendered.append(message)
    return rendered


def _mint_turn_token(session_id: str, identity: str, registry: ToolRegistry, defense_on: bool) -> str:
    """Mints a capability token for this turn's tool calls.

    DEFENSE=off: always mints an all-powerful "admin" token, regardless
    of the requested identity -- this is the vulnerable baseline (a
    single over-privileged tool runner). DEFENSE=on: mints a
    least-agency token scoped to the identity (see
    aegislab.identity.tokens.LEAST_PRIVILEGE_SCOPES); "admin" gets
    whatever tools currently exist, since that identity is explicit
    full access rather than a fixed list.
    """
    all_tool_names = frozenset(tool["name"] for tool in registry.list_tools())

    if not defense_on:
        return default_store.mint(session_id, "admin", all_tool_names)

    scope = all_tool_names if identity == "admin" else LEAST_PRIVILEGE_SCOPES.get(identity, frozenset())
    return default_store.mint(session_id, identity, scope)


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
    identity: str | None = None,
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

    Independently of the above, every tool call in this turn is made
    with a capability token minted for `identity` (see
    aegislab.identity): least-privilege when DEFENSE=on, an all-powerful
    admin token when DEFENSE=off (same vulnerable-baseline framing). If
    `identity` is not given, it defaults to `role` (so existing callers
    that only pass `role` keep getting matching token scope) -- pass
    both explicitly to decouple them, e.g. to test the token gate on its
    own. See docs/controls/F01_agent_identity.md.

    Also independently: when DEFENSE=on, tool-result content is wrapped
    with the provenance-tagged context firewall (origin=tool, untrusted)
    right before each LLM call -- see _render_for_llm and
    docs/controls/F03_provenance.md. This only affects what the LLM is
    shown; session.messages itself is never mutated, so stored tool
    results remain plain JSON for every other reader.
    """
    defense_on = defense_enabled()
    approve = approval_callback or cli_approval
    effective_identity = identity if identity is not None else role
    token = _mint_turn_token(session.session_id, effective_identity, registry, defense_on)

    if not session.messages:
        session.append({"role": "system", "content": SYSTEM_PROMPT})
    session.append({"role": "user", "content": user_input})

    if rag_index is not None:
        for retrieved in rag_index.search(user_input, top_k=2):
            if defense_on:
                scan_and_log(ContextPart(origin=Origin.RETRIEVAL, trust=Trust.UNTRUSTED, text=retrieved.text))
                text = wrap_untrusted(retrieved.text)
            else:
                text = retrieved.text
            session.append({"role": "system", "content": text})

    tools = _tools_schema(registry)

    for _ in range(max_steps):
        reply = llm.chat(_render_for_llm(session.messages, defense_on), tools)
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
                    result_payload = asdict(
                        tool.execute(tool_call.arguments, token=token, session_id=session.session_id)
                    )

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
