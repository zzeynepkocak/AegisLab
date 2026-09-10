"""Fake email tool.

MUST NOT send real network mail. Every call appends a JSON line to
data/outbox.jsonl instead.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import Tool, ToolResult

_REPO_ROOT = Path(__file__).resolve().parents[3]
_OUTBOX_PATH = _REPO_ROOT / "data" / "outbox.jsonl"


class EmailTool(Tool):
    name = "send_email"
    description = (
        "Mock email tool. Never sends real network mail; appends the "
        "message as a JSON line to data/outbox.jsonl instead."
    )
    args_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "subject": {"type": "string"},
            "body": {"type": "string"},
        },
        "required": ["to", "subject", "body"],
    }

    def _run(self, args: dict[str, Any]) -> ToolResult:
        message = {
            "to": args["to"],
            "subject": args["subject"],
            "body": args["body"],
            "sent_at": datetime.now(timezone.utc).isoformat(),
        }

        _OUTBOX_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _OUTBOX_PATH.open("a", encoding="utf-8") as outbox:
            outbox.write(json.dumps(message) + "\n")

        return ToolResult(
            ok=True,
            data={"queued": message},
            side_effects=[f"appended message to {_OUTBOX_PATH}"],
        )
