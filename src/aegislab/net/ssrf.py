"""SSRF policy for the fetch_url tool: allowed schemes, blocked IP
ranges, and a resolve+pin helper that prevents DNS rebinding between the
allowlist check and the actual connection.

One rule applies unconditionally, regardless of DEFENSE: this lab never
connects to a non-loopback address. See docs/controls/F04_ssrf.md.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}


@dataclass(frozen=True)
class Allowlist:
    """The DEFENSE=on target: exactly one lab fixture host+port, and the
    path prefixes allowed on it."""

    host: str
    port: int
    path_prefixes: frozenset[str]


@dataclass(frozen=True)
class SsrfCheckResult:
    ok: bool
    reason: str | None
    pinned_ip: str | None = None


def is_loopback_ip(ip: str) -> bool:
    return ipaddress.ip_address(ip).is_loopback


def is_blocked_ip(ip: str) -> bool:
    """Private ranges, link-local, reserved, and multicast -- the
    general policy a production SSRF guard would apply. Loopback is
    handled separately by is_loopback_ip: it is the one thing this lab
    always allows, not something to block.
    """
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback:
        return False
    return addr.is_private or addr.is_link_local or addr.is_reserved or addr.is_multicast


def resolve_and_pin(hostname: str) -> str:
    """Resolves hostname to a single IP once.

    Callers must use this exact IP for both the allowlist check and the
    actual connection -- never re-resolve, or a DNS-rebinding attacker
    (whose resolver answers differently on a second lookup) can swap the
    address out between check and connect.
    """
    return socket.gethostbyname(hostname)


def check_url(url: str, *, allowlist: Allowlist | None, defense_on: bool) -> SsrfCheckResult:
    """The full gate a fetch must pass before any socket is opened.

    The loopback-only rule below is enforced unconditionally, on both
    DEFENSE states. The allowlist (host+port+path prefix) is only
    enforced when defense_on.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        return SsrfCheckResult(ok=False, reason=f"scheme not allowed: {parsed.scheme!r}")

    if not parsed.hostname:
        return SsrfCheckResult(ok=False, reason="no hostname in URL")

    try:
        pinned_ip = resolve_and_pin(parsed.hostname)
    except OSError as exc:
        return SsrfCheckResult(ok=False, reason=f"DNS resolution failed: {exc}")

    if not is_loopback_ip(pinned_ip):
        if is_blocked_ip(pinned_ip):
            return SsrfCheckResult(ok=False, reason=f"blocked IP range: {pinned_ip}")
        return SsrfCheckResult(ok=False, reason=f"non-loopback address blocked (lab tool, loopback-only): {pinned_ip}")

    if defense_on:
        if allowlist is None:
            return SsrfCheckResult(ok=False, reason="no allowlist configured")

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.hostname != allowlist.host or port != allowlist.port:
            return SsrfCheckResult(ok=False, reason=f"host/port not on allowlist: {parsed.hostname}:{port}")

        if not any(parsed.path.startswith(prefix) for prefix in allowlist.path_prefixes):
            return SsrfCheckResult(ok=False, reason=f"path not on allowlist: {parsed.path!r}")

    return SsrfCheckResult(ok=True, reason=None, pinned_ip=pinned_ip)
