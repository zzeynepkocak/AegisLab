# F04 -- fetch_url SSRF Controls

## Threat

An agent-controlled URL fetch is a classic SSRF vector: point it at
`169.254.169.254` (cloud instance metadata) or `file://` and an agent
with no destination boundary can be tricked -- directly, or via a
redirect -- into reading internal-only data and handing it back to
whoever controls the input. See `attacks/F04_ssrf_imds/README.md` for
the credential-theft scenario this demonstrates.

## Hard safety rule (independent of DEFENSE)

**This lab never opens a socket to a non-loopback address, and never
supports any scheme besides http/https.** `aegislab.net.ssrf.check_url`
enforces this on every fetch attempt and every redirect hop, regardless
of the `DEFENSE` flag. There is no code path in `fetch.py` capable of
reaching a real network host or a real cloud metadata service --
verified in this session by confirming `socket.gethostbyname()` on a
literal IP performs no network I/O at all (it's a local parse), so even
the pure policy tests that check a real-looking address like
`169.254.169.254` never touch the network.

## Model

- `aegislab.net.ssrf.check_url(url, allowlist, defense_on)` -- the gate.
  Rejects disallowed schemes, resolves+pins the hostname
  (`resolve_and_pin`), rejects anything that doesn't resolve to loopback
  (unconditional), and -- only when `defense_on` -- also requires the
  host+port to match `allowlist` and the path to start with one of
  `allowlist.path_prefixes`.
- `aegislab.net.ssrf.is_blocked_ip(ip)` -- private/link-local/reserved/
  multicast classification via the stdlib `ipaddress` module. This is
  the general policy a production SSRF guard would apply; in this lab
  it's redundant with the loopback-only rule for anything actually
  reachable, but it's independently correct and unit-tested (e.g.
  `is_blocked_ip("169.254.169.254") is True`), which is where the "block
  private ranges, link-local" requirement is demonstrated directly.
- `aegislab.net.ssrf.resolve_and_pin(hostname)` -- resolves once.
  `FetchUrlTool` connects to exactly that IP, never re-resolving --
  see "DNS rebinding" below.
- `aegislab.tools.fetch.FetchUrlTool` -- the `fetch_url` tool. Not
  wired into the live tool registry/manifest system in this feature
  (`src/aegislab/tools/registry.py` and `.../tools/manifests/` weren't
  in this task's allowed files) -- it's tested by instantiating it
  directly, the same way `tests/test_tools.py` tests the other four
  tools before the registry gets involved.
- `aegislab.fixtures.http_lab.LabHttpFixture` -- the loopback-only test
  target. Binds `127.0.0.1:0` (OS-assigned ephemeral port), serves
  `/tickets` (ordinary data), `/metadata-imds-sim` (fake `LABCLOUD_...`
  credential string), and two redirect endpoints for testing redirect
  policy.

## DEFENSE=on vs off

- **DEFENSE=off**: no allowlist is enforced -- any path on the fixture
  is fetchable, including `/metadata-imds-sim` (the vulnerable
  baseline: an agent tricked into requesting that path gets the fake
  credential back). The loopback-only rule above still applies
  unconditionally, so this never reaches anywhere but the lab's own
  fixture.
- **DEFENSE=on**: `FetchUrlTool` must be constructed with an
  `Allowlist(host, port, path_prefixes)` covering only the intended
  path(s) (e.g. `/tickets`). A direct request to `/metadata-imds-sim`,
  or any redirect chain that ends up there, is rejected before any
  content is returned. Redirects are re-validated at every hop -- a
  same-host redirect to an off-allowlist path, or a redirect to a
  different host:port entirely, both fail closed. The off-allowlist
  redirect target is never even connection-attempted: nothing is
  listening there in the test fixture, and the test passes because
  `check_url` rejects it before any socket work.

## DNS rebinding

`resolve_and_pin` is called exactly once per fetch attempt; the
resulting IP is what `FetchUrlTool` actually connects to, never a fresh
resolution of the hostname. Tested by mocking the resolver for a
made-up hostname (`evil-rebind.lab.test`) that always answers with the
lab fixture's real loopback IP, and asserting the resolver is invoked
exactly once -- if the connection step re-resolved instead of using the
pinned IP, a rebinding attacker's second answer would be used instead.

## Residual risk

- `is_blocked_ip`'s private/link-local/reserved/multicast policy is
  demonstrated correctly but is not the operative gate in this lab --
  the loopback-only rule already rejects everything it would catch. A
  deployment that relaxed the loopback-only restriction (to allow real
  external fetches) would need `is_blocked_ip` to actually be load-
  bearing, and would need a real DNS resolver that can't be trivially
  tricked the way `resolve_and_pin`'s stdlib `socket.gethostbyname` can
  be (no DoH/DoT hardening, no resolver-response validation).
- Response size is capped (`MAX_RESPONSE_BYTES = 65536`) but there's no
  timeout tuning beyond a flat 5s connect/read timeout, and no protection
  against a slow-loris-style fixture -- irrelevant against this lab's own
  trusted fixture, but worth noting if this tool were ever pointed at
  anything less controlled.

## How to run

```bash
python -m pytest tests/test_ssrf_fetch.py -v
```

There is no CLI wiring for `fetch_url` in this phase (see "Model"
above) -- it's exercised directly in tests, not via `python -m aegislab`.

## Not in scope

No live registry/manifest wiring for `fetch_url`, no non-loopback
network capability of any kind, no real cloud metadata, no HTTPS
certificate handling beyond stdlib `http.client.HTTPSConnection`
defaults (moot here since the lab fixture is plain HTTP).
