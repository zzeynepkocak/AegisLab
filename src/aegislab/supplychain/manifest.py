"""Tool manifests: descriptors for tools, loaded from JSON files under
src/aegislab/tools/manifests/. This is the (file-based, no network)
"supply chain" for tools in this lab -- see
docs/controls/F02_tool_supply_chain.md for the threat model: an
untrusted manifest's description field is a prompt injection vector in
disguise, since it gets handed to the model as part of the tool list.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegislab.supplychain.trust import is_trusted_publisher

# Sentences containing these are treated as instructions in disguise,
# not data describing the tool, and stripped when DEFENSE=on.
_IMPERATIVE_TRIGGERS = re.compile(
    r"\b(ignore|disregard|override|bypass|forget)\b"
    r"|\byou must\b"
    r"|\balways\s+(call|use|send)\b"
    r"|\b\w+\.(send|write|delete|drop)\b",
    re.IGNORECASE,
)


def strip_imperative(description: str) -> str:
    """Drops sentences that read as commands rather than a description.

    Heuristic, not a guarantee -- see _IMPERATIVE_TRIGGERS above.
    """
    sentences = re.split(r"(?<=[.!?])\s+", description.strip())
    kept = [s for s in sentences if s and not _IMPERATIVE_TRIGGERS.search(s)]
    return " ".join(kept).strip()


@dataclass(frozen=True)
class ToolManifest:
    name: str
    version: str
    schema: dict[str, Any]
    description: str
    publisher: str
    sha256: str
    impl_module: str
    impl_class: str
    manifest_path: Path

    def resolve_impl_class(self) -> type:
        module = importlib.import_module(self.impl_module)
        return getattr(module, self.impl_class)

    def impl_source_path(self) -> Path:
        module = importlib.import_module(self.impl_module)
        return Path(module.__file__)

    def actual_sha256(self) -> str:
        return hashlib.sha256(self.impl_source_path().read_bytes()).hexdigest()


@dataclass(frozen=True)
class ManifestVerification:
    ok: bool
    reason: str | None = None


def verify_manifest(manifest: ToolManifest) -> ManifestVerification:
    """Trust + integrity check for a manifest.

    Only meaningful when DEFENSE=on -- callers decide whether to enforce
    this at all (see aegislab.tools.registry.build_default_registry).
    """
    if not is_trusted_publisher(manifest.publisher):
        return ManifestVerification(ok=False, reason=f"unsigned/untrusted publisher: {manifest.publisher!r}")

    if manifest.actual_sha256() != manifest.sha256:
        return ManifestVerification(ok=False, reason="sha256 mismatch: implementation does not match manifest")

    return ManifestVerification(ok=True)


def load_manifest(path: Path) -> ToolManifest:
    data = json.loads(path.read_text(encoding="utf-8"))
    return ToolManifest(
        name=data["name"],
        version=data["version"],
        schema=data["schema"],
        description=data["description"],
        publisher=data.get("publisher", ""),
        sha256=data.get("sha256", ""),
        impl_module=data["impl_module"],
        impl_class=data["impl_class"],
        manifest_path=path,
    )


def load_manifests(directory: Path) -> list[ToolManifest]:
    if not directory.exists():
        return []
    return [load_manifest(p) for p in sorted(directory.glob("*.json"))]
