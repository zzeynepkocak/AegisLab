"""Tests for fetch_url + SSRF controls (aegislab.net.ssrf) against a
LAB-ONLY loopback HTTP fixture. Never opens a socket off 127.0.0.1 --
see aegislab/tools/fetch.py and aegislab/net/ssrf.py for the hard rule.
"""

import pytest

from aegislab.fixtures.http_lab import LabHttpFixture
from aegislab.net import ssrf
from aegislab.tools.fetch import FetchUrlTool


@pytest.fixture()
def http_lab():
    fixture = LabHttpFixture()
    fixture.start()
    yield fixture
    fixture.stop()


def _defense_off(monkeypatch):
    monkeypatch.delenv("DEFENSE", raising=False)


def _defense_on(monkeypatch):
    monkeypatch.setenv("DEFENSE", "on")


# --- pure SSRF policy checks: no network at all ---------------------------


def test_is_loopback_ip():
    assert ssrf.is_loopback_ip("127.0.0.1") is True
    assert ssrf.is_loopback_ip("10.0.0.1") is False


def test_is_blocked_ip_covers_private_link_local_reserved_multicast():
    assert ssrf.is_blocked_ip("169.254.169.254") is True  # link-local / real cloud IMDS address
    assert ssrf.is_blocked_ip("10.0.0.1") is True
    assert ssrf.is_blocked_ip("192.168.1.1") is True
    assert ssrf.is_blocked_ip("172.16.0.1") is True
    assert ssrf.is_blocked_ip("224.0.0.1") is True  # multicast
    assert ssrf.is_blocked_ip("127.0.0.1") is False  # loopback is allowed, not "blocked"


def test_check_url_rejects_file_scheme():
    result = ssrf.check_url("file:///etc/passwd", allowlist=None, defense_on=True)
    assert result.ok is False
    assert "scheme" in result.reason


@pytest.mark.parametrize("scheme", ["gopher", "ftp"])
def test_check_url_rejects_gopher_and_ftp_schemes(scheme):
    result = ssrf.check_url(f"{scheme}://127.0.0.1/", allowlist=None, defense_on=True)
    assert result.ok is False
    assert "scheme" in result.reason


def test_check_url_rejects_real_imds_address_even_when_defense_off():
    """The absolute loopback-only rule is independent of DEFENSE -- pure
    string/IP check, never actually resolved or connected to.
    """
    result = ssrf.check_url("http://169.254.169.254/latest/meta-data/", allowlist=None, defense_on=False)
    assert result.ok is False


def test_check_url_rejects_private_range_even_when_defense_off():
    result = ssrf.check_url("http://10.0.0.5/", allowlist=None, defense_on=False)
    assert result.ok is False


# --- FetchUrlTool against the real loopback fixture ------------------------


def test_defense_off_can_fetch_tickets(http_lab, monkeypatch):
    _defense_off(monkeypatch)
    result = FetchUrlTool().execute({"url": f"{http_lab.base_url}/tickets"})

    assert result.ok is True
    assert result.data["status"] == 200
    assert "printer jam" in result.data["body"]


def test_defense_off_can_fetch_imds_sim_vulnerable_baseline(http_lab, monkeypatch):
    _defense_off(monkeypatch)
    result = FetchUrlTool().execute({"url": f"{http_lab.base_url}/metadata-imds-sim"})

    assert result.ok is True
    assert "LABCLOUD_" in result.data["body"]


def test_defense_on_can_fetch_allowlisted_tickets(http_lab, monkeypatch):
    _defense_on(monkeypatch)
    allowlist = ssrf.Allowlist(host=http_lab.host, port=http_lab.port, path_prefixes=frozenset({"/tickets"}))

    result = FetchUrlTool(allowlist=allowlist).execute({"url": f"{http_lab.base_url}/tickets"})

    assert result.ok is True
    assert "printer jam" in result.data["body"]


def test_defense_on_blocks_imds_sim_path(http_lab, monkeypatch):
    _defense_on(monkeypatch)
    allowlist = ssrf.Allowlist(host=http_lab.host, port=http_lab.port, path_prefixes=frozenset({"/tickets"}))

    result = FetchUrlTool(allowlist=allowlist).execute({"url": f"{http_lab.base_url}/metadata-imds-sim"})

    assert result.ok is False
    assert "LABCLOUD_" not in str(result.data)
    assert "allowlist" in result.data["error"]


def test_defense_on_blocks_redirect_to_imds_sim_path(http_lab, monkeypatch):
    """301 same-host redirect whose *destination path* is off the
    allowlist must still fail closed.
    """
    _defense_on(monkeypatch)
    allowlist = ssrf.Allowlist(
        host=http_lab.host, port=http_lab.port, path_prefixes=frozenset({"/tickets", "/redirect-to-imds-sim"})
    )

    result = FetchUrlTool(allowlist=allowlist).execute({"url": f"{http_lab.base_url}/redirect-to-imds-sim"})

    assert result.ok is False
    assert "LABCLOUD_" not in str(result.data)


def test_defense_on_blocks_redirect_off_allowlist_host_fails_closed(http_lab, monkeypatch):
    """301 redirect to a different host:port not on the allowlist must
    fail closed -- and must never attempt that connection at all
    (nothing is listening at the redirect target).
    """
    _defense_on(monkeypatch)
    allowlist = ssrf.Allowlist(
        host=http_lab.host, port=http_lab.port, path_prefixes=frozenset({"/tickets", "/redirect-off-allowlist"})
    )

    result = FetchUrlTool(allowlist=allowlist).execute({"url": f"{http_lab.base_url}/redirect-off-allowlist"})

    assert result.ok is False
    assert "allowlist" in result.data["error"]


def test_defense_on_requires_an_allowlist_to_be_configured(http_lab, monkeypatch):
    _defense_on(monkeypatch)
    result = FetchUrlTool(allowlist=None).execute({"url": f"{http_lab.base_url}/tickets"})

    assert result.ok is False


# --- DNS rebinding protection -----------------------------------------------


def test_dns_rebinding_uses_pinned_ip_not_a_fresh_resolution(http_lab, monkeypatch):
    """Simulates an attacker-controlled DNS name that could answer
    differently on a second lookup. resolve_and_pin must be called
    exactly once per fetch attempt, and that pinned IP is what actually
    gets connected to -- never re-resolved.
    """
    _defense_off(monkeypatch)
    call_count = {"n": 0}

    def fake_resolver(hostname: str) -> str:
        call_count["n"] += 1
        assert hostname == "evil-rebind.lab.test"
        return http_lab.host  # always resolves to our real loopback fixture

    monkeypatch.setattr(ssrf, "resolve_and_pin", fake_resolver)

    result = FetchUrlTool().execute({"url": f"http://evil-rebind.lab.test:{http_lab.port}/tickets"})

    assert result.ok is True
    assert call_count["n"] == 1
