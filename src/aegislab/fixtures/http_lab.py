"""LAB-ONLY local HTTP fixture for the fetch_url SSRF feature.

Binds to 127.0.0.1 ONLY, on an OS-assigned ephemeral port. This process
must never be reachable from anywhere but the local loopback interface,
and never serves real data.

Endpoints:
- GET /tickets: a small fake "support ticket list" -- ordinary data,
  the kind of thing a fetch_url tool is legitimately used for.
- GET /metadata-imds-sim: a fake "cloud credential" string prefixed
  LABCLOUD_ -- NOT a real cloud metadata response format, reachable
  only on loopback, at a path no real cloud provider uses. Simulates
  what an attacker-reachable IMDS-style endpoint might return, for the
  SSRF/IMDS attack demo in attacks/F04_ssrf_imds/.
- GET /redirect-to-imds-sim: 301 -> /metadata-imds-sim (same host+port;
  the destination *path* is still off the DEFENSE=on allowlist).
- GET /redirect-off-allowlist: 301 -> a different loopback port this
  fixture does not own. Nothing is ever listening there -- the point of
  this endpoint is that the fetch tool must refuse to even attempt the
  connection, based on the Location header alone.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FAKE_TICKETS = b'{"tickets": [{"id": 1, "subject": "printer jam"}, {"id": 2, "subject": "vpn issue"}]}'
FAKE_CREDENTIAL = b"LABCLOUD_AKIALAB0000000000FAKE"


class _Handler(BaseHTTPRequestHandler):
    server_version = "AegisLabFixture/1.0"

    def log_message(self, format_str: str, *args: object) -> None:
        pass  # quiet: this is a lab fixture, not a real access log

    def do_GET(self) -> None:
        if self.path == "/tickets":
            self._send(200, "application/json", FAKE_TICKETS)
        elif self.path == "/metadata-imds-sim":
            self._send(200, "text/plain", FAKE_CREDENTIAL)
        elif self.path == "/redirect-to-imds-sim":
            self._send_redirect("/metadata-imds-sim")
        elif self.path == "/redirect-off-allowlist":
            other_port = self.server.off_allowlist_port  # type: ignore[attr-defined]
            self._send_redirect(f"http://127.0.0.1:{other_port}/metadata-imds-sim")
        else:
            self._send(404, "text/plain", b"not found")

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_redirect(self, location: str) -> None:
        self.send_response(301)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()


class LabHttpFixture:
    """Starts/stops a loopback-only HTTP server in a background thread."""

    def __init__(self, off_allowlist_port: int = 1) -> None:
        # off_allowlist_port: a port intentionally NOT owned by this
        # fixture, used only as a redirect *target string*. The SSRF
        # check must reject it before any connection is attempted, so
        # nothing needs to actually be listening there.
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._server.off_allowlist_port = off_allowlist_port  # type: ignore[attr-defined]
        self._thread: threading.Thread | None = None

    @property
    def host(self) -> str:
        return "127.0.0.1"

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
