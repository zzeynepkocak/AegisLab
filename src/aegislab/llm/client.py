"""LLM client abstraction.

OpenAILLMClient talks to any OpenAI-compatible /chat/completions endpoint
using only the standard library (no third-party SDK), configured via env
vars: OPENAI_BASE_URL, OPENAI_API_KEY, MODEL.

FakeLLM is a scripted stand-in used by tests so the agent loop can be
exercised without any network access or a live API key.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMReply:
    content: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)


class LLMClient(ABC):
    @abstractmethod
    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMReply:
        raise NotImplementedError


class OpenAILLMClient(LLMClient):
    """Talks to an OpenAI-compatible /chat/completions endpoint via env config."""

    def __init__(self) -> None:
        self.base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self.api_key = os.environ.get("OPENAI_API_KEY", "")
        self.model = os.environ.get("MODEL", "gpt-4o-mini")

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMReply:
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        payload: dict[str, Any] = {"model": self.model, "messages": messages}
        if tools:
            payload["tools"] = tools

        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise RuntimeError(f"LLM request failed: {exc}") from exc

        message = body["choices"][0]["message"]
        tool_calls = [
            ToolCall(
                id=tc["id"],
                name=tc["function"]["name"],
                arguments=json.loads(tc["function"]["arguments"] or "{}"),
            )
            for tc in message.get("tool_calls") or []
        ]
        return LLMReply(content=message.get("content"), tool_calls=tool_calls)


class FakeLLM(LLMClient):
    """Scripted LLM for tests. Returns one LLMReply per call, in order.

    Once the script is exhausted, repeats the last scripted reply (useful
    for testing step-limit behavior without an infinite list).
    """

    def __init__(self, scripted_replies: list[LLMReply]) -> None:
        self._scripted_replies = list(scripted_replies)
        self.call_count = 0
        self.received_messages: list[list[dict[str, Any]]] = []

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMReply:
        self.received_messages.append([dict(m) for m in messages])
        if not self._scripted_replies:
            reply = LLMReply(content="")
        elif self.call_count < len(self._scripted_replies):
            reply = self._scripted_replies[self.call_count]
        else:
            reply = self._scripted_replies[-1]
        self.call_count += 1
        return reply
