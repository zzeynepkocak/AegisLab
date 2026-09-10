import json
import sqlite3

from aegislab.tools import crm, docs, email, sql
from aegislab.tools.registry import build_default_registry


def test_registry_lists_all_four_tools():
    registry = build_default_registry()
    names = {t["name"] for t in registry.list_tools()}
    assert names == {"crm_lookup", "send_email", "sql_query", "docs_search"}


# --- crm ---------------------------------------------------------------


def test_crm_lookup_success():
    tool = crm.CRMTool()
    result = tool.execute({"customer_id": "1001"})
    assert result.ok
    assert result.data["customer"]["id"] == "1001"


def test_crm_lookup_unknown_customer():
    tool = crm.CRMTool()
    result = tool.execute({"customer_id": "does-not-exist"})
    assert not result.ok
    assert "error" in result.data


def test_crm_lookup_invalid_args_missing_field():
    tool = crm.CRMTool()
    result = tool.execute({})
    assert not result.ok
    assert "missing required field" in result.data["error"]


# --- email ---------------------------------------------------------------


def test_email_tool_appends_to_outbox_and_does_not_send_network_mail(tmp_path, monkeypatch):
    outbox = tmp_path / "outbox.jsonl"
    monkeypatch.setattr(email, "_OUTBOX_PATH", outbox)

    tool = email.EmailTool()
    result = tool.execute({"to": "a@b.lab", "subject": "hi", "body": "hello"})

    assert result.ok
    assert result.side_effects
    assert outbox.exists()

    lines = outbox.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["to"] == "a@b.lab"
    assert record["subject"] == "hi"


def test_email_tool_invalid_args_missing_body(tmp_path, monkeypatch):
    outbox = tmp_path / "outbox.jsonl"
    monkeypatch.setattr(email, "_OUTBOX_PATH", outbox)

    tool = email.EmailTool()
    result = tool.execute({"to": "a@b.lab", "subject": "hi"})

    assert not result.ok
    assert not outbox.exists()


# --- sql ---------------------------------------------------------------


def test_sql_query_success(tmp_path, monkeypatch):
    monkeypatch.setattr(sql, "_DB_PATH", tmp_path / "lab.db")

    tool = sql.SQLTool()
    result = tool.execute({"query": "SELECT * FROM employees"})

    assert result.ok
    assert len(result.data["rows"]) == 3


def test_sql_query_invalid_args_missing_query(tmp_path, monkeypatch):
    monkeypatch.setattr(sql, "_DB_PATH", tmp_path / "lab.db")

    tool = sql.SQLTool()
    result = tool.execute({})

    assert not result.ok


def test_sql_query_rejects_write(tmp_path, monkeypatch):
    db_path = tmp_path / "lab.db"
    monkeypatch.setattr(sql, "_DB_PATH", db_path)

    tool = sql.SQLTool()
    result = tool.execute({"query": "DELETE FROM employees"})

    assert not result.ok
    assert "error" in result.data

    # confirm no rows were touched
    sql._ensure_db()
    conn = sqlite3.connect(db_path)
    (count,) = conn.execute("SELECT COUNT(*) FROM employees").fetchone()
    conn.close()
    assert count == 3


def test_sql_query_rejects_injection_with_trailing_statement(tmp_path, monkeypatch):
    monkeypatch.setattr(sql, "_DB_PATH", tmp_path / "lab.db")

    tool = sql.SQLTool()
    result = tool.execute({"query": "SELECT * FROM employees; DROP TABLE employees"})

    assert not result.ok


# --- docs ---------------------------------------------------------------


def test_docs_search_finds_keyword_in_readme():
    tool = docs.DocsTool()
    result = tool.execute({"keyword": "AegisLab"})

    assert result.ok
    assert any(match["file"] == "README.md" for match in result.data["matches"])


def test_docs_search_invalid_args_empty_keyword():
    tool = docs.DocsTool()
    result = tool.execute({"keyword": ""})

    assert not result.ok
