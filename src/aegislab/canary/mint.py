"""Canary tokens: per-document/per-record markers seeded into content
that might get exfiltrated, so a later leak can be attributed back to
its exact source.

The HMAC key lives only in this defense-side module (this process) --
it is never embedded in a minted token, never written to any document,
tool output, or model-visible text. Only the token itself (a one-way
HMAC output, not reversible to the key) ever leaves this module.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets

_ENV_KEY_VAR = "AEGISLAB_CANARY_KEY"
_PROCESS_KEY: bytes = secrets.token_bytes(32)

CANARY_PREFIX = "LABCANARY"
DIGEST_LENGTH = 16  # hex chars


def _key() -> bytes:
    """The HMAC key. Read from env if pinned (useful for a test wanting
    a stable key across processes); otherwise a random key generated
    once for this process's lifetime.
    """
    env_value = os.environ.get(_ENV_KEY_VAR)
    return env_value.encode("utf-8") if env_value else _PROCESS_KEY


def mint_canary(tenant: str, doc_id: str) -> str:
    """Mints a canary token bound to (tenant, doc_id).

    Deterministic for the same (tenant, doc_id) under the same process
    key, so re-minting the same document reproduces the same canary.
    Not reversible: the hmac suffix proves this process minted it (and
    that tenant/doc_id weren't tampered with) without revealing the key.

    Constraint: `tenant` must not contain an underscore (parse_canary
    below assumes the first underscore-delimited segment is the tenant).
    """
    digest = hmac.new(_key(), f"{tenant}:{doc_id}".encode("utf-8"), hashlib.sha256).hexdigest()[:DIGEST_LENGTH]
    return f"{CANARY_PREFIX}_{tenant}_{doc_id}_{digest}"


def parse_canary(token: str) -> tuple[str, str, str] | None:
    """Splits a canary-shaped token into (tenant, doc_id, digest)
    without verifying it. Returns None if the token isn't shaped like a
    canary at all.
    """
    prefix = f"{CANARY_PREFIX}_"
    if not token.startswith(prefix):
        return None

    remainder = token[len(prefix) :]
    if "_" not in remainder:
        return None
    tenant, rest = remainder.split("_", 1)

    if "_" not in rest:
        return None
    doc_id, digest = rest.rsplit("_", 1)

    if not tenant or not doc_id or len(digest) != DIGEST_LENGTH:
        return None
    return tenant, doc_id, digest


def verify_canary(token: str) -> bool:
    """Confirms a canary-shaped token was actually minted by this
    process's key -- not forged, guessed, or a coincidental look-alike.
    """
    parsed = parse_canary(token)
    if parsed is None:
        return False
    tenant, doc_id, _digest = parsed
    return hmac.compare_digest(mint_canary(tenant, doc_id), token)
