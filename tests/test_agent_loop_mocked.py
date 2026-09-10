"""Tests for the intentionally weak agent loop. FakeLLM only -- no network,
no live API key needed, safe for CI.
"""

import json

from aegislab.agent import loop, memory
from aegislab.llm.client import FakeLLM, LLMReply, ToolCall
from aegislab.tools.registry import build_default_registry


def test_run_turn_final_answer_no_tool_call(tmp_path, monkeypatch):
    monkeypatch.setattr(memory, "_DEFAULT_SESSIONS_DIR", tmp_path)
    session = memory.SessionMemory("s1")
    llm = FakeLLM([LLMReply(content="Hello, how can I help?")])
    registry = build_default_registry()

    reply = loop.run_turn("hi", session, llm, registry)

    assert reply == "Hello, how can I help?"
    assert llm.call_count == 1
    assert [m["role"] for m in session.messages] == ["system", "user", "assistant"]


def test_run_turn_executes_tool_call_then_returns_final_answer(tmp_path, monkeypatch):
    monkeypatch.setattr(memory, "_DEFAULT_SESSIONS_DIR", tmp_path)
    session = memory.SessionMemory("s2")
    registry = build_default_registry()

    llm = FakeLLM(
        [
            LLMReply(
                content=None,
                tool_calls=[ToolCall(id="call_1", name="crm_lookup", arguments={"customer_id": "1001"})],
            ),
            LLMReply(content="Acme Corp is an active customer."),
        ]
    )

    reply = loop.run_turn("look up customer 1001", session, llm, registry)

    assert reply == "Acme Corp is an active customer."
    assert llm.call_count == 2

    tool_messages = [m for m in session.messages if m["role"] == "tool"]
    assert len(tool_messages) == 1
    tool_result = json.loads(tool_messages[0]["content"])
    assert tool_result["ok"] is True
    assert tool_result["data"]["customer"]["id"] == "1001"


def test_run_turn_stops_at_step_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(memory, "_DEFAULT_SESSIONS_DIR", tmp_path)
    session = memory.SessionMemory("s3")
    registry = build_default_registry()

    always_calls_a_tool = LLMReply(
        content=None,
        tool_calls=[ToolCall(id="call_x", name="crm_lookup", arguments={"customer_id": "1001"})],
    )
    llm = FakeLLM([always_calls_a_tool])  # FakeLLM repeats the last scripted reply

    reply = loop.run_turn("loop forever", session, llm, registry, max_steps=3)

    assert reply == "[aegislab] step limit reached without a final answer."
    assert llm.call_count == 3


def test_session_memory_persists_across_instances(tmp_path, monkeypatch):
    monkeypatch.setattr(memory, "_DEFAULT_SESSIONS_DIR", tmp_path)

    session_a = memory.SessionMemory("persist")
    session_a.append({"role": "user", "content": "remember this"})

    session_b = memory.SessionMemory("persist")

    assert session_b.messages == [{"role": "user", "content": "remember this"}]
    assert (tmp_path / "persist.jsonl").exists()


def test_no_allowlist_any_tool_name_is_attempted(tmp_path, monkeypatch):
    """Documents the intentionally weak baseline: there is no allowlist, so a
    tool_call for a name the LLM invented is passed straight to the registry
    instead of being rejected by policy up front.
    """
    monkeypatch.setattr(memory, "_DEFAULT_SESSIONS_DIR", tmp_path)
    session = memory.SessionMemory("s5")
    registry = build_default_registry()

    llm = FakeLLM(
        [
            LLMReply(
                content=None,
                tool_calls=[ToolCall(id="call_y", name="totally_made_up_tool", arguments={})],
            ),
            LLMReply(content="done"),
        ]
    )

    loop.run_turn("do something", session, llm, registry)

    tool_message = next(m for m in session.messages if m["role"] == "tool")
    result = json.loads(tool_message["content"])
    assert result["ok"] is False
    assert "unknown tool" in result["data"]["error"]
