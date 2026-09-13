"""Scans text for canary tokens and attributes any verified match back
to the document/record that seeded it. See aegislab.canary.mint for how
canaries are minted; the HMAC key never leaves that module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aegislab.canary.mint import CANARY_PREFIX, parse_canary, verify_canary

# Shape-only match (no HMAC check) -- used both here (as a first pass,
# then verified) and by aegislab.defense.redact (which redacts anything
# canary-shaped, verified or not: safe-by-default output hygiene is a
# different job than precise attribution).
CANARY_TOKEN_RE = re.compile(rf"\b{CANARY_PREFIX}_\S+_\S+_[0-9a-f]{{16}}\b")


@dataclass(frozen=True)
class CanaryHit:
    token: str
    tenant: str
    doc_id: str


def find_canaries(text: str) -> list[CanaryHit]:
    """Finds every *verified* canary token in text, attributed to its
    source (tenant, doc_id).

    A canary-shaped substring that doesn't verify (wrong HMAC -- not
    actually minted by this process) is ignored, not reported: DET-04's
    attribution must be trustworthy, not just pattern-matched.
    """
    hits: list[CanaryHit] = []
    for match in CANARY_TOKEN_RE.finditer(text):
        token = match.group(0)
        if not verify_canary(token):
            continue
        parsed = parse_canary(token)
        if parsed is None:
            continue
        tenant, doc_id, _digest = parsed
        hits.append(CanaryHit(token=token, tenant=tenant, doc_id=doc_id))
    return hits
