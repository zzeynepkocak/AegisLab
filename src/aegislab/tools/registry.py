"""Tool registry: loads tools from manifests under
src/aegislab/tools/manifests/, then instantiates each manifest's
declared implementation class.

DEFENSE=on: a manifest is rejected (its tool is not loaded at all) if
its publisher isn't in the trust store or its declared sha256 doesn't
match the actual implementation file -- see
aegislab.supplychain.manifest.verify_manifest. Its description is also
stripped of imperative language before being exposed via list_tools(),
since descriptions are DATA describing a tool, not instructions for the
model to follow.

DEFENSE=off: every manifest found is loaded, and its description is
used verbatim -- the vulnerable baseline. See
docs/controls/F02_tool_supply_chain.md.
"""

from __future__ import annotations

from pathlib import Path

from aegislab.defense.policy import defense_enabled
from aegislab.supplychain.manifest import load_manifests, strip_imperative, verify_manifest

from .base import Tool

MANIFESTS_DIR = Path(__file__).resolve().parent / "manifests"


class ToolRegistry:
    """Keys tools by the manifest's declared name, not the implementation
    class's own `.name` attribute -- the manifest is the authoritative
    supply-chain descriptor. (This also means a manifest can *claim* any
    name while pointing at any impl_class; that mismatch is itself part
    of the threat model this feature studies -- see
    docs/controls/F02_tool_supply_chain.md.)
    """

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}
        self._descriptions: dict[str, str] = {}

    def register(self, name: str, tool: Tool, description: str | None = None) -> None:
        self._tools[name] = tool
        self._descriptions[name] = description if description is not None else tool.description

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def list_tools(self) -> list[dict]:
        return [
            {"name": name, "description": self._descriptions[name], "args_schema": tool.args_schema}
            for name, tool in self._tools.items()
        ]


def build_default_registry(manifests_dir: Path = MANIFESTS_DIR) -> ToolRegistry:
    registry = ToolRegistry()

    for manifest in load_manifests(manifests_dir):
        if defense_enabled():
            outcome = verify_manifest(manifest)
            if not outcome.ok:
                continue

        description = manifest.description if not defense_enabled() else strip_imperative(manifest.description)
        tool_cls = manifest.resolve_impl_class()
        registry.register(manifest.name, tool_cls(), description)

    return registry
