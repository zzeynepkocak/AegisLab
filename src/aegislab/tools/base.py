"""Base types for mock tools: ToolResult and the Tool interface.

Includes a minimal JSON-schema-style argument validator (required fields
and top-level type checks only) so each tool can reject invalid args
before running.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from aegislab.identity.store import default_store

_JSON_TYPE_MAP: dict[str, Any] = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "object": dict,
    "array": list,
}


@dataclass
class ToolResult:
    ok: bool
    data: dict[str, Any]
    side_effects: list[str] = field(default_factory=list)


class Tool(ABC):
    name: str
    description: str
    args_schema: dict[str, Any]

    def execute(
        self,
        args: dict[str, Any],
        *,
        token: str | None = None,
        session_id: str | None = None,
    ) -> ToolResult:
        """Runs the tool.

        token/session_id are optional for backward compatibility with
        direct/offline calls (the `tools call` CLI debug path and
        tool-level unit tests). Whenever a caller passes session_id, this
        is a session-scoped call from the agent loop, and a valid
        capability token covering this tool is required -- see
        aegislab.identity.store.
        """
        if session_id is not None and not default_store.validate(token, session_id, self.name):
            return ToolResult(
                ok=False,
                data={"error": f"tool {self.name!r} not permitted: missing or invalid capability token"},
                side_effects=[],
            )

        error = self._validate_args(args)
        if error is not None:
            return ToolResult(ok=False, data={"error": error}, side_effects=[])
        return self._run(args)

    @abstractmethod
    def _run(self, args: dict[str, Any]) -> ToolResult:
        raise NotImplementedError

    def _validate_args(self, args: dict[str, Any]) -> str | None:
        if not isinstance(args, dict):
            return "args must be a JSON object"

        properties: dict[str, Any] = self.args_schema.get("properties", {})
        required: list[str] = self.args_schema.get("required", [])

        for field_name in required:
            if field_name not in args:
                return f"missing required field: {field_name}"

        for field_name, value in args.items():
            spec = properties.get(field_name)
            if spec is None:
                return f"unexpected field: {field_name}"
            expected = _JSON_TYPE_MAP.get(spec.get("type"))
            if expected is not None and not isinstance(value, expected):
                return f"field {field_name!r} must be of type {spec['type']}"

        return None
