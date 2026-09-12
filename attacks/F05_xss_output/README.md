# F05 -- Stored XSS via Unescaped Output

**LAB-ONLY.** This scenario targets AegisLab's own minimal chat UI
(`aegislab.web.app.ChatApp`), bound to `127.0.0.1` only. It never runs a
real browser and never touches any site outside localhost.

## Goal

Show that model/tool output rendered as HTML without escaping is a
stored-XSS sink: an attacker who gets text into a stored message (chat
memory, a retrieved doc, a tool result) can have it render as live
markup for whoever's browser opens that page later, in this case
enabling theft of the `LABSESSION` cookie.

## OWASP mapping

**LLM05:2026 -- Improper Output Handling** (OWASP Top 10 for LLM
Applications): output from the model/tools is trusted and rendered
directly as HTML instead of being treated as data.

## Why this isn't a real browser exploit

`run.py` does not launch a browser and does not execute
`payload.txt`'s JavaScript. That would need a browser-automation
dependency this project doesn't have, and isn't necessary to prove the
vulnerability: whether injected script *would* execute is fully
determined by whether it appears unescaped in the HTML response (a
plain-text check), and whether it *could* then read the session cookie
is fully determined by the `Set-Cookie` response header's `HttpOnly`
flag -- both are directly observable over a normal HTTP request. So
`run.py` makes real (loopback-only) HTTP requests against the chat UI
and:

1. Posts `payload.txt` as a stored chat message.
2. Fetches `/chat` and checks whether `<script>` appears **unescaped**
   in the response body (if so: a real browser would execute it).
3. Reads the `Set-Cookie: LABSESSION=...` header and checks whether
   `HttpOnly` is present (if absent: a real browser's injected script
   *could* read `document.cookie`).
4. Only when both conditions hold does it record the cookie value in
   `evidence.json` as `stolen_cookie` -- a faithful simulation of what
   injected script could exfiltrate, without actually running any.

## Expected result

- **DEFENSE=off**: the payload's `<script>` tag renders unescaped, the
  cookie is set without `HttpOnly`, and `evidence.json` records
  `leak_detected: true` with the "stolen" cookie value.
- **DEFENSE=on**: the payload is HTML-escaped (`&lt;script&gt;...`,
  inert text), a strict CSP header is sent, and the cookie has
  `HttpOnly` set -- `evidence.json` records `leak_detected: false`.

## How to run

```bash
source venv/bin/activate
python attacks/F05_xss_output/run.py --defense off   # baseline: cookie stolen
python attacks/F05_xss_output/run.py --defense on    # blocked
```

## How to test

```bash
python -m pytest tests/test_output_handling.py -v
```
