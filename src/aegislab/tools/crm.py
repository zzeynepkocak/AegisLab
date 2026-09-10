"""Fake CRM tool. In-memory mock data only, no network calls."""

from __future__ import annotations

from typing import Any

from .base import Tool, ToolResult

_CUSTOMERS: dict[str, dict[str, str]] = {
    "1001": {"id": "1001", "name": "Acme Corp", "owner": "Alice Example", "status": "active"},
    "1002": {"id": "1002", "name": "Globex Inc", "owner": "Bob Example", "status": "prospect"},
    "1003": {"id": "1003", "name": "Initech", "owner": "Carol Example", "status": "churned"},
}


class CRMTool(Tool):
    name = "crm_lookup"
    description = "Look up a fake CRM customer record by customer_id (mock in-memory data)."
    args_schema: dict[str, Any] = {
        "type": "object",
        "properties": {"customer_id": {"type": "string"}},
        "required": ["customer_id"],
    }

    def _run(self, args: dict[str, Any]) -> ToolResult:
        customer_id = args["customer_id"]
        record = _CUSTOMERS.get(customer_id)
        if record is None:
            return ToolResult(
                ok=False,
                data={"error": f"unknown customer_id: {customer_id}"},
                side_effects=[],
            )
        return ToolResult(ok=True, data={"customer": record}, side_effects=[])
