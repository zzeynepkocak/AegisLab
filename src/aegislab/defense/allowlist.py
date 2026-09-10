"""Per-role tool allowlist for the defense layer (checked only when DEFENSE=on)."""

from __future__ import annotations

ROLE_ALLOWLISTS: dict[str, set[str]] = {
    "analyst": {"crm_lookup", "sql_query", "docs_search"},
    "admin": {"crm_lookup", "sql_query", "docs_search", "send_email"},
}

DEFAULT_ROLE = "analyst"


def is_tool_allowed(role: str, tool_name: str) -> bool:
    return tool_name in ROLE_ALLOWLISTS.get(role, set())
