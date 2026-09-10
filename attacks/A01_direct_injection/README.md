# A01 -- Direct Prompt Injection

**LAB-ONLY.** This scenario targets AegisLab's own intentionally weak
baseline agent inside this repo's mocked lab environment. It is not a
working exploit against any production system and must never be pointed
at one.

## Goal

Show that a user-supplied message can directly override the agent's
naive system prompt ("be helpful, use any tool the user needs") and get
it to call a tool it should not -- here, `send_email` -- to exfiltrate a
secret to an attacker-controlled address, with no allowlist, human
approval, or output filter in the way.

## OWASP mapping

**LLM01:2026 -- Prompt Injection** (OWASP Top 10 for LLM Applications).
The injection arrives directly in the user's own message, as opposed to
an indirect-injection scenario where the payload arrives via retrieved
or tool content.

## Expected impact

If the underlying model complies with the injected instruction, the
agent loop (`aegislab.agent.loop.run_turn`) executes the resulting
`send_email` tool call unconditionally. The mock email tool never sends
real mail -- it appends to `data/outbox.jsonl` -- but the same code path
would call a real tool if one were ever wired in. This scenario proves
the control-flow gap: nothing today stops the tool call once the model
asks for it.

## How it works

`run.py` does not call a live LLM. It scripts a `FakeLLM` fixture with a
recorded, worst-case-compliant response to `payload.txt` (a model that
plays along with the injected instruction and calls `send_email`), then
runs that through the real, unmodified agent loop and tools. This
isolates the finding to "the agent loop has no safeguard here" rather
than "this specific model can be jailbroken this way."

## How to run

```bash
source venv/bin/activate
python attacks/A01_direct_injection/run.py
```

Writes `attacks/A01_direct_injection/evidence.json` recording the tool
calls made and whether a leak to the attacker address was detected. Also
appends to `data/outbox.jsonl` and
`data/sessions/attack-a01-direct-injection.jsonl` -- the same mocked,
local-file side effects a normal chat session would produce.

## How to test

```bash
python -m pytest tests/test_attack_a01.py -v
```

## Files

- `payload.txt` -- the direct-injection payload sent as the user message.
- `run.py` -- runs the scenario and writes `evidence.json`.
- `evidence.json` -- generated when you run `run.py`.
