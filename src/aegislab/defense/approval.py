"""Human approval gate: CLI yes/no by default.

Used by the defense policy layer when DEFENSE=on, for tool calls that
require explicit human confirmation before running (e.g. sending an
email). Injectable so callers (and tests) can supply a non-interactive
callback instead.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

ApprovalCallback = Callable[[str, dict[str, Any]], bool]


def cli_approval(tool_name: str, args: dict[str, Any]) -> bool:
    """Prompts on stdin/stdout. Returns True only for an explicit 'y'."""
    print(f"[approval required] tool={tool_name} args={args}")
    answer = input("Approve this tool call? [y/N] ").strip().lower()
    return answer == "y"
