"""Redacts secrets, API-key-shaped tokens, email addresses, and canary
tokens from model output text. Applied to assistant output only when
DEFENSE=on.

Redaction here is deliberately permissive for canaries: it scrubs
anything canary-*shaped*, verified or not (aegislab.canary.detect.CANARY_TOKEN_RE),
because safe-by-default output hygiene doesn't need to be as precise as
attribution does. Redacting a canary and alerting on it are independent
-- see aegislab.detect.rules.det_04_canary_leak, which still attributes
and logs a leak even when the text shown to the user gets scrubbed here.
"""

from __future__ import annotations

import re

from aegislab.canary.detect import CANARY_TOKEN_RE

_LAB_SECRET_RE = re.compile(r"\bLABSECRET_[A-Za-z0-9_-]+\b")
_API_KEY_RE = re.compile(r"\b(?:sk|pk|api[-_]?key|secret)[-_][A-Za-z0-9_-]{6,}\b", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")

_MASK = "[REDACTED]"


def redact_text(text: str | None) -> str | None:
    if text is None:
        return text

    redacted = CANARY_TOKEN_RE.sub(_MASK, text)
    redacted = _LAB_SECRET_RE.sub(_MASK, redacted)
    redacted = _API_KEY_RE.sub(_MASK, redacted)
    redacted = _EMAIL_RE.sub(_MASK, redacted)
    return redacted
