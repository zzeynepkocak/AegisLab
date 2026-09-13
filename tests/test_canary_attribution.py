"""Tests for canary tokens (aegislab.canary), DET-04 leak attribution
(aegislab.detect.rules), and canary redaction (aegislab.defense.redact).
No network -- detection is local JSONL only.
"""

import json

from aegislab.canary.detect import find_canaries
from aegislab.canary.mint import mint_canary, parse_canary, verify_canary
from aegislab.defense.redact import redact_text
from aegislab.detect.rules import det_04_canary_leak

# --- lab-local fixtures: a "document" and a "CRM row" seeded with canaries.
# Not persisted as repo files -- src/aegislab/data/docs/ and
# src/aegislab/tools/crm.py weren't in this task's allowed files, so the
# actual seeding into the real docs corpus / CRM tool is a follow-up.

SECRET_INCIDENT_DOC_ID = "secret_incident.md"
CRM_ROW_DOC_ID = "crm_row_42"


def _seeded_secret_incident_md(tenant: str) -> str:
    canary = mint_canary(tenant, SECRET_INCIDENT_DOC_ID)
    return (
        "# Incident Report -- Confidential\n\n"
        "A security incident occurred affecting internal systems. "
        f"Reference: {canary}\n\n"
        "Do not distribute outside the response team.\n"
    )


def _seeded_crm_row(tenant: str) -> dict:
    canary = mint_canary(tenant, CRM_ROW_DOC_ID)
    return {
        "id": "42",
        "name": "Confidential Account",
        "notes": f"VIP customer, escalate directly. Internal ref {canary}.",
    }


# --- minting / verification -------------------------------------------------


def test_mint_canary_has_expected_shape():
    token = mint_canary("acme", "secret_incident.md")
    assert token.startswith("LABCANARY_acme_secret_incident.md_")
    assert verify_canary(token) is True


def test_parse_canary_handles_underscores_in_doc_id():
    token = mint_canary("acme", "crm_row_42")
    parsed = parse_canary(token)
    assert parsed == ("acme", "crm_row_42", parsed[2])


def test_mint_canary_is_deterministic_per_tenant_doc():
    assert mint_canary("acme", "x.md") == mint_canary("acme", "x.md")


def test_mint_canary_differs_across_tenants_and_docs():
    a = mint_canary("acme", "x.md")
    b = mint_canary("globex", "x.md")
    c = mint_canary("acme", "y.md")
    assert len({a, b, c}) == 3


def test_verify_canary_rejects_forged_lookalike():
    real = mint_canary("acme", "x.md")
    forged = real[:-1] + ("0" if real[-1] != "0" else "1")  # flip last hex char
    assert verify_canary(forged) is False


def test_verify_canary_rejects_non_canary_text():
    assert verify_canary("just some ordinary text") is False


# --- HMAC key never leaves the minting module -------------------------------


def test_hmac_key_not_embedded_in_token():
    import aegislab.canary.mint as mint_module

    token = mint_canary("acme", "x.md")
    key_bytes = mint_module._key()
    assert key_bytes.hex() not in token
    assert key_bytes not in token.encode("utf-8")


# --- detection + attribution ------------------------------------------------


def test_find_canaries_attributes_seeded_document_leak():
    doc_text = _seeded_secret_incident_md("acme")
    leaked_output = f"Sure, here's the incident summary: {doc_text}"

    hits = find_canaries(leaked_output)

    assert len(hits) == 1
    assert hits[0].tenant == "acme"
    assert hits[0].doc_id == SECRET_INCIDENT_DOC_ID


def test_find_canaries_attributes_seeded_crm_row_leak():
    row = _seeded_crm_row("globex")
    leaked_output = f"Customer notes: {row['notes']}"

    hits = find_canaries(leaked_output)

    assert len(hits) == 1
    assert hits[0].tenant == "globex"
    assert hits[0].doc_id == CRM_ROW_DOC_ID


def test_find_canaries_ignores_unverified_lookalike():
    fake = "LABCANARY_acme_totally_made_up_0000000000000000"
    assert find_canaries(f"leaked: {fake}") == []


# --- DET-04 ------------------------------------------------------------------


def test_det_04_logs_and_attributes(tmp_path, caplog):
    import logging

    log_path = tmp_path / "detections.jsonl"
    doc_text = _seeded_secret_incident_md("acme")

    with caplog.at_level(logging.WARNING, logger="aegislab.detect.rules"):
        detections = det_04_canary_leak(doc_text, log_path=log_path)

    assert len(detections) == 1
    assert detections[0].rule_id == "DET-04"
    assert detections[0].attributed_source == f"acme:{SECRET_INCIDENT_DOC_ID}"
    assert any("DET-04" in record.message for record in caplog.records)

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    logged = json.loads(lines[0])
    assert logged["attributed_source"] == f"acme:{SECRET_INCIDENT_DOC_ID}"


def test_det_04_writes_no_lines_for_clean_text(tmp_path):
    log_path = tmp_path / "detections.jsonl"
    detections = det_04_canary_leak("nothing sensitive here", log_path=log_path)

    assert detections == []
    assert not log_path.exists()


def test_evidence_style_output_includes_attributed_source(tmp_path):
    """Mirrors the evidence.json convention used by other attack
    scenarios in this repo (attack_id/owasp/... plus per-finding
    attribution) -- built here rather than as a committed attacks/
    fixture, since attacks/F07_.../ wasn't in this task's allowed files.
    """
    log_path = tmp_path / "detections.jsonl"
    doc_text = _seeded_secret_incident_md("acme")
    detections = det_04_canary_leak(f"leaked: {doc_text}", log_path=log_path)

    evidence = {
        "attack_id": "F07_canary_attribution",
        "detections": [d.__dict__ for d in detections],
    }
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")

    loaded = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert loaded["detections"][0]["attributed_source"] == f"acme:{SECRET_INCIDENT_DOC_ID}"


# --- redaction: alert != block ----------------------------------------------


def test_redact_text_scrubs_canary_from_output():
    doc_text = _seeded_secret_incident_md("acme")
    redacted = redact_text(doc_text)

    assert "LABCANARY_" not in redacted
    assert "[REDACTED]" in redacted


def test_redaction_does_not_suppress_det_04_alert_on_the_raw_text(tmp_path):
    """DEFENSE=on redacts what the user sees, but the raw text is still
    scanned and still alerts -- alert != block. Detection must run on
    the pre-redaction text (a redacted canary can no longer be found).
    """
    log_path = tmp_path / "detections.jsonl"
    doc_text = _seeded_secret_incident_md("acme")

    # what the system detects on (raw)
    detections = det_04_canary_leak(doc_text, log_path=log_path)
    # what the user actually sees (redacted)
    shown_to_user = redact_text(doc_text)

    assert len(detections) == 1
    assert "LABCANARY_" not in shown_to_user
