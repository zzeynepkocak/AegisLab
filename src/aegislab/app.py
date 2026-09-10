"""Chat application wiring: LLM client + tool registry + session memory + agent loop.

Intentionally minimal and unsafe -- see aegislab.agent.loop. No approval
step, no allowlist, no output filtering.
"""

from __future__ import annotations

from aegislab.agent.loop import run_turn
from aegislab.agent.memory import SessionMemory
from aegislab.llm.client import OpenAILLMClient
from aegislab.tools.registry import build_default_registry


def run_repl(session_id: str) -> None:
    """Interactive stdin/stdout chat loop, used by `python -m aegislab chat`."""
    session = SessionMemory(session_id)
    llm = OpenAILLMClient()
    registry = build_default_registry()

    print(f"[aegislab] session={session_id} (Ctrl-D to exit)")
    while True:
        try:
            user_input = input("you> ")
        except EOFError:
            print()
            break
        if not user_input.strip():
            continue
        reply = run_turn(user_input, session, llm, registry)
        print(f"assistant> {reply}")
