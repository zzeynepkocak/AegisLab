"""Typed, provenance-tagged pieces of context.

Every ContextPart carries where it came from (origin) and whether it
should be trusted as instructions or treated as inert data (trust). See
firewall.py for how untrusted parts get wrapped before entering the
token stream, and docs/controls/F03_provenance.md for the threat model.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Origin(str, Enum):
    SYSTEM = "system"
    USER = "user"
    RETRIEVAL = "retrieval"
    TOOL = "tool"
    MEMORY = "memory"


class Trust(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class ContextPart:
    origin: Origin
    trust: Trust
    text: str


def classify_memory_part(text: str, source_session_id: str, current_session_id: str) -> ContextPart:
    """Memory pulled from another session ("foreign memory") is
    untrusted; the current session's own memory is trusted.

    Not currently wired into any live code path -- AegisLab has no
    cross-session memory retrieval feature yet -- but available for when
    that changes, and directly unit-tested here.
    """
    trust = Trust.TRUSTED if source_session_id == current_session_id else Trust.UNTRUSTED
    return ContextPart(origin=Origin.MEMORY, trust=trust, text=text)
