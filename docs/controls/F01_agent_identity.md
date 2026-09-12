# F01 -- Agent Workload Identity + Capability Tokens

## Threat

A single over-privileged tool runner: before this control, every tool
call the agent loop made ran with the same, unrestricted access. After a
successful prompt injection, the model effectively inherits admin on
CRM, email, and SQL -- there was no per-call check of *what the agent is
currently allowed to touch*.

## Model

Three **workload identities** -- `analyst`, `finance`, `admin` -- not
human SSO/OAuth. They describe what the *agent* is allowed to do on
behalf of a session, not who the human operator is. See
`aegislab.identity.tokens.IDENTITIES`.

Each turn, the agent loop mints a **capability token**
(`aegislab.identity.store.TokenStore.mint`): opaque (a random
`secrets.token_urlsafe` string), stored server-side only as a SHA-256
hash, bound to `(session_id, identity, tool scope, expiry)`. The raw
token is handed to the caller once and attached to every tool call made
during that turn (`Tool.execute(args, token=..., session_id=...)`).
Every tool refuses to run for a session-scoped call unless the token is
valid, unexpired, bound to that same `session_id`, and its scope
includes that tool -- see `Tool.execute` in `aegislab/tools/base.py`.

Direct/offline calls that don't pass a `session_id` (the `tools call`
CLI debug path, and tool-level unit tests) are unaffected -- there's no
session to scope a token to, and no prompt-injection surface at that
call site.

## Minting policy

- **DEFENSE=off**: always mints an all-powerful `admin` token (scope =
  every tool currently registered), regardless of the requested
  identity. This is the vulnerable baseline this whole lab studies --
  the token layer exists, but grants everything, same as having none.
- **DEFENSE=on**: mints a least-agency token from
  `aegislab.identity.tokens.LEAST_PRIVILEGE_SCOPES`:
  - `analyst`: `docs_search`, `crm_lookup` (read-only lookups only).
  - `finance`: `send_email` only -- and actually sending still passes
    through the existing approval-callback gate
    (`aegislab.defense.policy.TOOLS_REQUIRING_APPROVAL`), so "email only
    after approval" is enforced by two independent layers.
  - `admin`: every currently registered tool (explicit, not a fixed
    list -- this identity means "no restriction").

## Relationship to the existing role/allowlist defense

`aegislab.agent.loop.run_turn` already had a `role` parameter
(`analyst`/`admin`) feeding `aegislab.defense.policy`'s per-role tool
allowlist, added in the defense-layer-v1 phase. This feature adds a
second, independent parameter, `identity`, for capability tokens.
They are **not unified** in this phase: touching
`aegislab.defense.allowlist` was out of scope for this change, and the
identity set here includes `finance`, which the allowlist doesn't know
about. A call now passes through both gates independently when
DEFENSE=on: the role-based allowlist (and approval callback) first, then
the token-scope check inside `Tool.execute`.

## How to run

```bash
source venv/bin/activate
DEFENSE=off python -m aegislab chat --session demo   # baseline: admin token, unrestricted
DEFENSE=on  python -m aegislab chat --session demo    # least-privilege token (identity defaults to "analyst")
```

`identity` is currently only reachable by calling
`aegislab.agent.loop.run_turn(..., identity=...)` directly (e.g. from
tests or future callers) -- the CLI chat command does not expose an
`--identity` flag in this phase.

## How to test

```bash
python -m pytest tests/test_identity_tokens.py -v
```

## Not in scope

No OAuth/OIDC provider, no persistent/distributed token store (the
store is a single in-memory process-wide dict), no `--identity` CLI
flag, no unification with the existing role allowlist.
