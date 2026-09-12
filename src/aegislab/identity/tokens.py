"""Capability tokens: short-lived, opaque, scoped bearer tokens for agent
workload identities. These identify the *agent's* effective privilege for
a session -- not a human user, not SSO/OAuth. See identity/store.py for
the (in-memory, hashed) token store, and aegislab.agent.loop for how
tokens get minted and attached to tool calls.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass

IDENTITIES = {"analyst", "finance", "admin"}

DEFAULT_TTL_SECONDS = 15 * 60  # 15 minutes

# Least-privilege tool scopes per identity, used when DEFENSE=on. "admin"
# has no fixed entry here: it is granted whatever tools currently exist
# in the registry, decided in aegislab.agent.loop.
LEAST_PRIVILEGE_SCOPES: dict[str, frozenset[str]] = {
    "analyst": frozenset({"docs_search", "crm_lookup"}),
    "finance": frozenset({"send_email"}),
}


def new_raw_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CapabilityToken:
    """The record kept server-side -- never the raw bearer value itself."""

    token_hash: str
    session_id: str
    identity: str
    scope: frozenset[str]
    expires_at: float

    def is_expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires_at
