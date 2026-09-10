"""Redacts secrets, API-key-shaped tokens, and email addresses from model
output text. Applied to assistant output only when DEFENSE=on.
"""

from __future__ import annotations

import re

_LAB_SECRET_RE = re.compile(r"\bLABSECRET_[A-Za-z0-9_-]+\b")
_API_KEY_RE = re.compile(r"\b(?:sk|pk|api[-_]?key|secret)[-_][A-Za-z0-9_-]{6,}\b", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")

_MASK = "[REDACTED]"


def redact_text(text: str | None) -> str | None:
    if text is None:
        return text

    redacted = _LAB_SECRET_RE.sub(_MASK, text)
    redacted = _API_KEY_RE.sub(_MASK, redacted)
    redacted = _EMAIL_RE.sub(_MASK, redacted)
    return redacted
