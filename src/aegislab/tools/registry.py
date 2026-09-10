"""Tool registry: name -> Tool lookup, used by the CLI (and later the agent)."""

from __future__ import annotations

from .base import Tool
from .crm import CRMTool
from .docs import DocsTool
from .email import EmailTool
from .sql import SQLTool


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def list_tools(self) -> list[dict]:
        return [
            {"name": tool.name, "description": tool.description, "args_schema": tool.args_schema}
            for tool in self._tools.values()
        ]


def build_default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    for tool_cls in (CRMTool, EmailTool, SQLTool, DocsTool):
        registry.register(tool_cls())
    return registry
