"""LAB-ONLY: F05 stored XSS / output-handling attack scenario.

Plants payload.txt as a stored chat message in AegisLab's own minimal
chat UI (aegislab.web.app.ChatApp), then inspects the rendered /chat
response to determine whether the stored payload renders as executable
markup (weak mode) and whether the LABSESSION cookie lacks HttpOnly
(meaning a real browser's injected script could have read and
exfiltrated it).

This does NOT run a real browser and does NOT execute the payload's
JavaScript -- see README.md for why. The "cookie theft" recorded here is
a faithful simulation: it reads the exact Set-Cookie header a browser
would receive over the same HTTP response, and only counts the cookie as
"stolen" when both (a) the payload's <script> tag is present unescaped
in the page and (b) HttpOnly is absent -- the two conditions under which
injected script could actually read and exfiltrate document.cookie.

Never opens a socket off 127.0.0.1 -- see aegislab/web/app.py.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
from datetime import datetime, timezone
from http import cookies
from pathlib import Path
from urllib.parse import urlencode

from aegislab.web.app import ChatApp

_ATTACK_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _ATTACK_DIR.parents[1]
PAYLOAD_PATH = _ATTACK_DIR / "payload.txt"
EVIDENCE_PATH = _ATTACK_DIR / "evidence.json"


def _post_message(conn: http.client.HTTPConnection, text: str) -> str | None:
    body = urlencode({"text": text})
    conn.request(
        "POST",
        "/chat/messages",
        body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    response = conn.getresponse()
    response.read()
    return response.getheader("Set-Cookie")


def _get_chat(conn: http.client.HTTPConnection, cookie_header: str | None) -> tuple[bytes, str | None]:
    headers = {"Cookie": cookie_header} if cookie_header else {}
    conn.request("GET", "/chat", headers=headers)
    response = conn.getresponse()
    body = response.read()
    return body, response.getheader("Set-Cookie")


def _cookie_value_and_http_only(set_cookie_header: str | None) -> tuple[str | None, bool]:
    if not set_cookie_header:
        return None, False
    jar = cookies.SimpleCookie()
    jar.load(set_cookie_header)
    if "LABSESSION" not in jar:
        return None, False
    morsel = jar["LABSESSION"]
    return morsel.value, bool(morsel["httponly"])


def run_attack(defense: str) -> dict:
    os.environ["DEFENSE"] = defense
    payload = PAYLOAD_PATH.read_text(encoding="utf-8").strip()

    app = ChatApp()
    app.start()
    try:
        conn = http.client.HTTPConnection(app.host, app.port, timeout=5)
        try:
            set_cookie_1 = _post_message(conn, payload)
            body, set_cookie_2 = _get_chat(conn, set_cookie_1)
        finally:
            conn.close()

        html_body = body.decode("utf-8", errors="replace")
        xss_present = "<script>" in html_body  # raw, unescaped -- would execute in a real browser
        cookie_value, http_only = _cookie_value_and_http_only(set_cookie_2 or set_cookie_1)

        stolen_cookie = cookie_value if (xss_present and not http_only and cookie_value) else None

        evidence = {
            "attack_id": "F05_xss_output",
            "owasp": "LLM05:2026 Improper Output Handling",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload_file": str(PAYLOAD_PATH.relative_to(_REPO_ROOT)),
            "defense_state": defense,
            "xss_present_unescaped": xss_present,
            "cookie_http_only": http_only,
            "stolen_cookie": stolen_cookie,
            "leak_detected": stolen_cookie is not None,
        }
    finally:
        app.stop()

    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return evidence


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--defense",
        choices=["on", "off"],
        default="off",
        help="Set DEFENSE=on to run this scenario with output escaping + CSP + HttpOnly (default: off, broken baseline).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    evidence = run_attack(args.defense)
    status = "COOKIE STOLEN" if evidence["leak_detected"] else "no theft"
    print(f"[F05_xss_output] DEFENSE={args.defense}: {status}. Evidence written to {EVIDENCE_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
