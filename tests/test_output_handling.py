"""Tests for output-handling defenses (aegislab.defense.output) and the
LAB-ONLY chat UI (aegislab.web.app). Never opens a socket off 127.0.0.1.
"""

import http.client
import json
import subprocess
import sys
from http import cookies
from pathlib import Path
from urllib.parse import urlencode

import pytest

from aegislab.defense.output import CSP_HEADER_VALUE, escape_for_html
from aegislab.web.app import ChatApp

REPO_ROOT = Path(__file__).resolve().parents[1]
ATTACK_DIR = REPO_ROOT / "attacks" / "F05_xss_output"
PAYLOAD = (ATTACK_DIR / "payload.txt").read_text(encoding="utf-8").strip()


def _defense_off(monkeypatch):
    monkeypatch.delenv("DEFENSE", raising=False)


def _defense_on(monkeypatch):
    monkeypatch.setenv("DEFENSE", "on")


@pytest.fixture()
def chat_app():
    app = ChatApp()
    app.start()
    yield app
    app.stop()


def _post_and_get(app: ChatApp, text: str) -> tuple[bytes, dict[str, str]]:
    conn = http.client.HTTPConnection(app.host, app.port, timeout=5)
    try:
        conn.request(
            "POST",
            "/chat/messages",
            body=urlencode({"text": text}),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        post_response = conn.getresponse()
        post_response.read()
        set_cookie = post_response.getheader("Set-Cookie")

        conn.request("GET", "/chat", headers={"Cookie": set_cookie} if set_cookie else {})
        get_response = conn.getresponse()
        body = get_response.read()
        headers = dict(get_response.getheaders())
        return body, headers
    finally:
        conn.close()


# --- aegislab.defense.output -----------------------------------------------


def test_escape_for_html_neutralizes_script_tags():
    escaped = escape_for_html("<script>alert(1)</script>")
    assert "<script>" not in escaped
    assert "&lt;script&gt;" in escaped


def test_csp_header_value_has_no_unsafe_inline():
    assert "default-src 'none'" in CSP_HEADER_VALUE
    assert "script-src 'self'" in CSP_HEADER_VALUE
    assert "unsafe-inline" not in CSP_HEADER_VALUE


# --- ChatApp: DEFENSE=off (vulnerable sink) ---------------------------------


def test_defense_off_renders_payload_unescaped(chat_app, monkeypatch):
    _defense_off(monkeypatch)
    body, headers = _post_and_get(chat_app, PAYLOAD)

    assert b"<script>" in body
    assert "Content-Security-Policy" not in headers


def test_defense_off_cookie_lacks_httponly_but_has_secure(chat_app, monkeypatch):
    _defense_off(monkeypatch)
    _, headers = _post_and_get(chat_app, "hello")

    jar = cookies.SimpleCookie()
    jar.load(headers["Set-Cookie"])
    morsel = jar["LABSESSION"]
    assert bool(morsel["httponly"]) is False
    assert bool(morsel["secure"]) is True


# --- ChatApp: DEFENSE=on (escaped, CSP, HttpOnly) ---------------------------


def test_defense_on_escapes_payload(chat_app, monkeypatch):
    _defense_on(monkeypatch)
    body, headers = _post_and_get(chat_app, PAYLOAD)

    assert b"<script>" not in body
    assert b"&lt;script&gt;" in body
    assert headers["Content-Security-Policy"] == CSP_HEADER_VALUE


def test_defense_on_cookie_has_httponly_and_secure(chat_app, monkeypatch):
    _defense_on(monkeypatch)
    _, headers = _post_and_get(chat_app, "hello")

    jar = cookies.SimpleCookie()
    jar.load(headers["Set-Cookie"])
    morsel = jar["LABSESSION"]
    assert bool(morsel["httponly"]) is True
    assert bool(morsel["secure"]) is True


# --- session isolation -------------------------------------------------------


def test_sessions_are_isolated(chat_app, monkeypatch):
    _defense_off(monkeypatch)

    conn_a = http.client.HTTPConnection(chat_app.host, chat_app.port, timeout=5)
    conn_a.request(
        "POST",
        "/chat/messages",
        body=urlencode({"text": "secret for A"}),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp_a = conn_a.getresponse()
    resp_a.read()
    cookie_a = resp_a.getheader("Set-Cookie")
    conn_a.close()

    conn_b = http.client.HTTPConnection(chat_app.host, chat_app.port, timeout=5)
    conn_b.request("GET", "/chat")  # no cookie: fresh session B
    resp_b = conn_b.getresponse()
    body_b = resp_b.read()
    conn_b.close()

    assert b"secret for A" not in body_b
    assert cookie_a is not None


# --- full attack script, via subprocess (mirrors tests/test_attack_a01.py) --


def test_f05_run_off_writes_evidence_of_stolen_cookie():
    result = subprocess.run(
        [sys.executable, str(ATTACK_DIR / "run.py"), "--defense", "off"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr

    evidence = json.loads((ATTACK_DIR / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["attack_id"] == "F05_xss_output"
    assert evidence["owasp"].startswith("LLM05")
    assert evidence["xss_present_unescaped"] is True
    assert evidence["cookie_http_only"] is False
    assert evidence["leak_detected"] is True
    assert evidence["stolen_cookie"]


def test_f05_run_on_blocks_theft():
    result = subprocess.run(
        [sys.executable, str(ATTACK_DIR / "run.py"), "--defense", "on"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr

    evidence = json.loads((ATTACK_DIR / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["xss_present_unescaped"] is False
    assert evidence["cookie_http_only"] is True
    assert evidence["leak_detected"] is False
    assert evidence["stolen_cookie"] is None
