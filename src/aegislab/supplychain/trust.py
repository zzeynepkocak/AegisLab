"""Publisher trust store for tool manifests.

Lab-scope: a flat JSON allowlist of publisher names, not a PKI or
certificate chain. See docs/controls/F02_tool_supply_chain.md.
"""

from __future__ import annotations

import json
from pathlib import Path

DEFAULT_TRUST_STORE_PATH = Path(__file__).resolve().parent / "publishers.json"


def load_allowed_publishers(path: Path = DEFAULT_TRUST_STORE_PATH) -> frozenset[str]:
    if not path.exists():
        return frozenset()
    data = json.loads(path.read_text(encoding="utf-8"))
    return frozenset(data.get("allowed_publishers", []))


def is_trusted_publisher(publisher: str, path: Path = DEFAULT_TRUST_STORE_PATH) -> bool:
    if not publisher:
        return False
    return publisher in load_allowed_publishers(path)
