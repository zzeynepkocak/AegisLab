"""fetch_url tool: an HTTP(S) fetch tool with SSRF controls (see
aegislab.net.ssrf) and an intentionally weak mode.

Threat: an agent-controlled URL fetch could be aimed at
169.254.169.254 (cloud instance metadata), a file:// URI, or another
internal-only service. This tool never actually reaches any of that --
see the hard safety rule below -- but demonstrates the difference
between an allowlisted, redirect-safe, DNS-rebinding-safe fetch
(DEFENSE=on) and an unrestricted one (DEFENSE=off), both operating only
against this lab's own loopback HTTP fixture
(aegislab.fixtures.http_lab).

Hard safety rule, independent of DEFENSE: this tool NEVER opens a
socket to a non-loopback address and NEVER supports any scheme besides
http/https -- see aegislab.net.ssrf.check_url, which runs before every
connection attempt, including every redirect hop. There is no code path
in this file capable of reaching a real network host or a real cloud
metadata service.
"""

from __future__ import annotations

import http.client
from typing import Any
from urllib.parse import urljoin, urlparse

from aegislab.net.ssrf import Allowlist, check_url
from aegislab.tools.base import Tool, ToolResult

MAX_REDIRECTS = 5
MAX_RESPONSE_BYTES = 65536


class FetchUrlTool(Tool):
    name = "fetch_url"
    description = (
        "Fetch a URL over HTTP(S). Lab-only: can never reach anything but a "
        "loopback (127.0.0.1) HTTP fixture, never a real network host."
    )
    args_schema: dict[str, Any] = {
        "type": "object",
        "properties": {"url": {"type": "string"}},
        "required": ["url"],
    }

    def __init__(self, allowlist: Allowlist | None = None) -> None:
        self.allowlist = allowlist

    def _run(self, args: dict[str, Any]) -> ToolResult:
        from aegislab.defense.policy import defense_enabled

        return self._fetch(args["url"], defense_on=defense_enabled(), redirects_left=MAX_REDIRECTS)

    def _fetch(self, url: str, *, defense_on: bool, redirects_left: int) -> ToolResult:
        outcome = check_url(url, allowlist=self.allowlist, defense_on=defense_on)
        if not outcome.ok:
            return ToolResult(ok=False, data={"error": outcome.reason, "url": url}, side_effects=[])

        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        # Connect using the PINNED ip from check_url, never a fresh
        # resolution of parsed.hostname -- that is what prevents DNS
        # rebinding between the check above and this connection.
        conn = conn_cls(outcome.pinned_ip, port, timeout=5)
        try:
            try:
                conn.request("GET", path, headers={"Host": parsed.hostname})
                response = conn.getresponse()
                status = response.status
                body = response.read(MAX_RESPONSE_BYTES)
                location = response.getheader("Location")
            except OSError as exc:
                return ToolResult(ok=False, data={"error": f"connection failed: {exc}", "url": url}, side_effects=[])
        finally:
            conn.close()

        if status in (301, 302, 303, 307, 308) and location:
            if redirects_left <= 0:
                return ToolResult(ok=False, data={"error": "too many redirects", "url": url}, side_effects=[])
            next_url = urljoin(url, location)
            return self._fetch(next_url, defense_on=defense_on, redirects_left=redirects_left - 1)

        return ToolResult(
            ok=True,
            data={"url": url, "status": status, "body": body.decode("utf-8", errors="replace")},
            side_effects=[],
        )
