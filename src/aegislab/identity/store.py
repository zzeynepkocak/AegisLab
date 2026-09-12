"""In-memory capability token store.

Tokens are stored hashed; the raw opaque value is returned only once, at
mint time, to the caller that must attach it to tool calls. Lab-scope: a
single process-wide in-memory store, not a persistent/distributed token
service.
"""

from __future__ import annotations

import time

from aegislab.identity.tokens import (
    DEFAULT_TTL_SECONDS,
    IDENTITIES,
    CapabilityToken,
    hash_token,
    new_raw_token,
)


class TokenStore:
    def __init__(self) -> None:
        self._tokens: dict[str, CapabilityToken] = {}

    def mint(
        self,
        session_id: str,
        identity: str,
        scope: frozenset[str],
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
    ) -> str:
        if identity not in IDENTITIES:
            raise ValueError(f"unknown identity: {identity!r}")

        raw_token = new_raw_token()
        record = CapabilityToken(
            token_hash=hash_token(raw_token),
            session_id=session_id,
            identity=identity,
            scope=frozenset(scope),
            expires_at=time.time() + ttl_seconds,
        )
        self._tokens[record.token_hash] = record
        return raw_token

    def validate(self, raw_token: str | None, session_id: str, tool_name: str) -> bool:
        if not raw_token:
            return False
        record = self._tokens.get(hash_token(raw_token))
        if record is None:
            return False
        if record.session_id != session_id:
            return False
        if record.is_expired():
            return False
        return tool_name in record.scope


default_store = TokenStore()
