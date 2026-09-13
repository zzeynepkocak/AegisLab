# F07 -- Canary Tokens + Leak Attribution

## Threat

Sensitive disclosure with no forensic trail: if confidential content
leaks through model output or a tool (e.g. an email body), there is
normally no way to know *which* document or record was the source.
Canary tokens close that gap -- a marker seeded into content at rest
that, if it ever surfaces in output, proves exactly where it came from.

## Model

- `aegislab.canary.mint.mint_canary(tenant, doc_id)` -- mints
  `LABCANARY_<tenant>_<doc_id>_<hmac>`. The `hmac` suffix (16 hex chars,
  HMAC-SHA256 truncated) is computed from an in-process key
  (`_key()` in `mint.py`) that **never leaves this module**: it isn't
  embedded in the token, isn't written to any document, tool output, or
  model-visible text, and callers only ever get the finished token
  string back. Deterministic per `(tenant, doc_id)`, so re-minting the
  same document reproduces the same canary.
  - Constraint: `tenant` must not contain an underscore -- parsing
    assumes the first `_`-delimited segment is the tenant, with
    everything up to the final `_<hmac>` being `doc_id` (which *can*
    contain underscores/dots, e.g. `secret_incident.md`, `crm_row_42`).
- `aegislab.canary.detect.find_canaries(text)` -- finds every
  canary-shaped substring (`CANARY_TOKEN_RE`) and **verifies** each one
  (`verify_canary`) before reporting it as a `CanaryHit(token, tenant,
  doc_id)`. An unverified look-alike (right shape, wrong HMAC -- not
  actually minted by this process) is silently ignored: attribution
  must be trustworthy, not just pattern-matched.
- `aegislab.detect.rules.det_04_canary_leak(text, log_path=...)` --
  runs `find_canaries` and, for every verified hit, logs a `DET-04`
  warning (stdlib `logging`, logger `aegislab.detect.rules`) and appends
  one JSONL line to `log_path` (default `data/audit/detections.jsonl`).
  Each `Detection` record carries `attributed_source` as `"tenant:doc_id"`.
  **Never phones home** -- the only I/O here is a local file append and
  a local log call.
- `aegislab.defense.redact.redact_text` (existing module, extended) --
  now also scrubs anything canary-*shaped* (not just verified hits) via
  the same `CANARY_TOKEN_RE` used for detection. This is deliberately
  more permissive than detection: output hygiene doesn't need proof of
  authenticity the way attribution does. Since `aegislab.agent.loop`
  already calls `redact_text` on assistant output whenever `DEFENSE=on`,
  this addition is live in the real agent loop without needing to touch
  `loop.py` at all.

## Alert != block

`DEFENSE=on` redacts canaries from what the user sees, **and** the
system still alerts on the raw text -- these are independent operations
on the same source text, not a single "handle it" step. Detection runs
on the pre-redaction text (a redacted canary can no longer be found, by
definition); redaction only affects what gets displayed. See
`tests/test_canary_attribution.py::test_redaction_does_not_suppress_det_04_alert_on_the_raw_text`.

## Seeded fixtures

"Seed canaries into `secret_incident.md` and one confidential CRM row"
is demonstrated with **lab-local fixtures inside the test file**
(`_seeded_secret_incident_md` / `_seeded_crm_row` in
`tests/test_canary_attribution.py`), not as committed repo files:
`src/aegislab/data/docs/` (the real docs corpus) and
`src/aegislab/tools/crm.py` (the real CRM tool data) were not in this
task's allowed files. Actually seeding a canary into the live docs
corpus and the live CRM tool's data, and wiring `det_04_canary_leak`
into the real agent loop's output path, are natural follow-up tasks.

## How to run

```bash
python3 -c "
from aegislab.canary.mint import mint_canary
from aegislab.detect.rules import det_04_canary_leak
canary = mint_canary('acme', 'secret_incident.md')
det_04_canary_leak(f'leaked content: {canary}')
"
cat data/audit/detections.jsonl
```

## How to test

```bash
python -m pytest tests/test_canary_attribution.py -v
```

## Not in scope

No real IdP/tenant system (tenants are lab strings), no live wiring
into `aegislab.agent.loop` or the real docs/CRM tool data (see "Seeded
fixtures" above), no outbound network calls of any kind -- detection is
local JSONL only, as required.
