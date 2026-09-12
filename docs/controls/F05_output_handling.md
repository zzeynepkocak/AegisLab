# F05 -- Output Handling: Encoding, CSP, Stored XSS

## Threat

Model/tool output rendered as HTML in a chat UI is a stored-XSS sink if
not escaped. Anything that can get attacker-controlled text into a
stored message -- chat memory, a retrieved doc, a tool result -- can
have it execute as script in whoever's browser renders that message
later, including stealing session cookies. See
`attacks/F05_xss_output/README.md` for the concrete demo.

## Model

- `aegislab.web.app.ChatApp` -- a minimal chat UI. `POST /chat/messages`
  stores a message (raw, always -- storage never sanitizes); `GET /chat`
  renders the session's full stored history. **Storage is always raw;
  escaping is a render-time decision.** This is deliberate: sanitizing
  on the way in and trusting it forever is a common, fragile pattern --
  the correct place to encode is at the point text crosses into a
  specific output context (here: HTML), every time it's rendered.
- `aegislab.defense.output.escape_for_html(text)` -- `html.escape`
  wrapper, the fix for the vulnerable sink.
- `aegislab.defense.output.CSP_HEADER_VALUE` -- `"default-src 'none';
  script-src 'self'"`. No `'unsafe-inline'` anywhere -- inline
  `<script>` is blocked by `script-src 'self'` alone; that's what "no
  inline" means in practice.
- Binds `127.0.0.1` only, on an OS-assigned ephemeral port. No code path
  in `aegislab/web/` talks to any other host.

## DEFENSE=on vs off (read live per request, via
`aegislab.defense.policy.defense_enabled`)

- **DEFENSE=off**: stored message content is written into the page RAW
  -- the vulnerable sink. No `Content-Security-Policy` header is sent.
  The `LABSESSION` cookie is set **without `HttpOnly`** (so injected
  script, if any ever ran, could read `document.cookie`) but still
  **with `Secure`**.
- **DEFENSE=on**: content is passed through `escape_for_html` before
  rendering. The CSP header above is sent on every response. The cookie
  gets both `HttpOnly` and `Secure`.

## Cookie flags

| Flag | DEFENSE=off | DEFENSE=on | Why |
| --- | --- | --- | --- |
| `HttpOnly` | absent | present | Absent in weak mode on purpose, so the XSS demo has an observable, testable impact (a script *could* read the cookie). Present under defense: JS can never read it, regardless of any XSS elsewhere. |
| `Secure` | present | present | Kept in both modes -- this flag isn't part of the intentional weak-mode gap. Browsers treat `127.0.0.1`/`localhost` as a "potentially trustworthy origin" even over plain HTTP, so a `Secure` cookie still round-trips correctly against this loopback demo; on a real deployment it would require HTTPS. |

## Why the "theft" isn't a real browser exploit

`attacks/F05_xss_output/run.py` does not launch a browser or execute
`payload.txt`'s JavaScript -- there's no browser-automation dependency
in this project, and it isn't necessary to prove the vulnerability.
Whether injected script *would* execute is fully determined by whether
it appears unescaped in the HTML response (a plain substring check);
whether it *could* then read the cookie is fully determined by the
`Set-Cookie` response header's `HttpOnly` flag -- both fully observable
over a normal, loopback-only HTTP request. The script makes real
requests against `ChatApp`, checks both conditions, and only then
records the cookie value into `evidence.json` as `stolen_cookie` -- a
faithful simulation of what injected script could exfiltrate, without
ever running any.

## Residual risk

- `escape_for_html` covers HTML body context (the only context this UI
  actually renders into). It is not a general sanitizer -- inserting
  unescaped text into an HTML attribute, a `<script>` block, or a URL
  context requires different encoding, none of which this minimal UI
  does (it has no such sinks today, but a future template change could
  introduce one without this control noticing).
- CSP is defense-in-depth, not a replacement for escaping: a real
  browser blocked from running injected `<script>` by CSP could still
  suffer other consequences of unescaped HTML (e.g. visual spoofing,
  form-based phishing within the page) that CSP alone doesn't prevent.
- The chat UI has no authentication and no CSRF protection -- entirely
  out of scope for this feature, and fine for a loopback-only lab demo,
  but would matter immediately in any less-contained deployment.

## How to run

```bash
source venv/bin/activate
python attacks/F05_xss_output/run.py --defense off   # baseline: cookie stolen
python attacks/F05_xss_output/run.py --defense on    # blocked
```

There is no `python -m aegislab` CLI wiring for the chat UI in this
phase -- it's driven directly via `aegislab.web.app.ChatApp` in tests
and the attack script.

## How to test

```bash
python -m pytest tests/test_output_handling.py -v
```

## Not in scope

No real browser/JS execution, no authentication/CSRF, no sanitization
beyond HTML-body escaping, no non-loopback network capability of any
kind.
