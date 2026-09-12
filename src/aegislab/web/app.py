"""Minimal LAB-ONLY chat UI demonstrating output-handling / stored XSS.

Threat: model/tool output rendered as HTML in a chat UI is a stored-XSS
sink if not escaped. An attacker who gets attacker-controlled text into
a stored message (memory, a doc, a tool result) can have it execute as
script in whoever's browser later renders that message -- see
attacks/F05_xss_output/.

DEFENSE=off: message content is rendered into the page RAW (the
vulnerable sink), no Content-Security-Policy header is sent, and the
LABSESSION cookie is set WITHOUT HttpOnly (Secure is still set) -- so
injected script could read it, if a real browser were ever involved.
This app never runs one; see attacks/F05_xss_output/README.md for how
the "theft" is actually demonstrated.

DEFENSE=on: message content is HTML-escaped (aegislab.defense.output),
a strict CSP header is sent (default-src 'none'; script-src 'self', no
inline), and the cookie gets both HttpOnly and Secure.

Binds 127.0.0.1 ONLY, on an OS-assigned ephemeral port -- never a real
network-facing address, and no code path here talks to any other host.
See docs/controls/F05_output_handling.md.
"""

from __future__ import annotations

import html
import secrets
import threading
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from string import Template
from urllib.parse import parse_qs, urlparse

from aegislab.defense.output import CSP_HEADER_VALUE, escape_for_html
from aegislab.defense.policy import defense_enabled

TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "chat.html"
_TEMPLATE = Template(TEMPLATE_PATH.read_text(encoding="utf-8"))

COOKIE_NAME = "LABSESSION"


class _Handler(BaseHTTPRequestHandler):
    server_version = "AegisLabChat/1.0"

    def log_message(self, format_str: str, *args: object) -> None:
        pass  # quiet: this is a lab demo server, not a real access log

    def _session_id(self) -> str:
        jar = cookies.SimpleCookie()
        jar.load(self.headers.get("Cookie", ""))
        if COOKIE_NAME in jar:
            return jar[COOKIE_NAME].value
        return secrets.token_urlsafe(16)

    def _set_cookie_header(self, session_id: str, defense_on: bool) -> str:
        flags = "Path=/; Secure"
        if defense_on:
            flags += "; HttpOnly"
        return f"{COOKIE_NAME}={session_id}; {flags}"

    def do_GET(self) -> None:
        app: ChatApp = self.server.app  # type: ignore[attr-defined]
        if urlparse(self.path).path == "/chat":
            session_id = self._session_id()
            self._render_chat(app, session_id)
            return
        self._send(404, "text/plain", b"not found")

    def do_POST(self) -> None:
        app: ChatApp = self.server.app  # type: ignore[attr-defined]
        if urlparse(self.path).path == "/chat/messages":
            session_id = self._session_id()
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8")
            text = parse_qs(body).get("text", [""])[0]
            app.store_message(session_id, text)
            self._render_chat(app, session_id)
            return
        self._send(404, "text/plain", b"not found")

    def _render_chat(self, app: "ChatApp", session_id: str) -> None:
        defense_on = defense_enabled()
        rendered = [
            f'<div class="message">{escape_for_html(m) if defense_on else m}</div>' for m in app.history(session_id)
        ]
        page = _TEMPLATE.substitute(
            session_id=html.escape(session_id),
            messages_html="\n".join(rendered),
        )
        body = page.encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", self._set_cookie_header(session_id, defense_on))
        if defense_on:
            self.send_header("Content-Security-Policy", CSP_HEADER_VALUE)
        self.end_headers()
        self.wfile.write(body)

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ChatApp:
    """Starts/stops the loopback-only chat UI in a background thread.

    DEFENSE state is read live (aegislab.defense.policy.defense_enabled)
    on every request, not fixed at construction -- consistent with the
    rest of this lab, and so a test can flip DEFENSE without restarting
    the server.
    """

    def __init__(self) -> None:
        self._history: dict[str, list[str]] = {}
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._server.app = self  # type: ignore[attr-defined]
        self._thread: threading.Thread | None = None

    def history(self, session_id: str) -> list[str]:
        return self._history.setdefault(session_id, [])

    def store_message(self, session_id: str, text: str) -> None:
        self.history(session_id).append(text)

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
