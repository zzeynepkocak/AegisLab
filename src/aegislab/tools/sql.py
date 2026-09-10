"""Fake SQL tool.

Uses a SQLite file at data/lab.db. READ-ONLY in this phase: the table is
created and seeded from mock CRM/employee data automatically, and only
SELECT statements may be executed. Any write attempt is rejected before
touching the database, and the query connection itself is opened
read-only as a second layer of defense.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any

from .base import Tool, ToolResult

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DB_PATH = _REPO_ROOT / "data" / "lab.db"

_SEED_EMPLOYEES = [
    (1, "Alice Example", "alice@example.lab", "Sales"),
    (2, "Bob Example", "bob@example.lab", "Engineering"),
    (3, "Carol Example", "carol@example.lab", "Support"),
]

_WRITE_KEYWORDS = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|ATTACH|PRAGMA|VACUUM)\b",
    re.IGNORECASE,
)


def _ensure_db() -> None:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(_DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS employees (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                department TEXT NOT NULL
            )
            """
        )
        (count,) = conn.execute("SELECT COUNT(*) FROM employees").fetchone()
        if count == 0:
            conn.executemany(
                "INSERT INTO employees (id, name, email, department) VALUES (?, ?, ?, ?)",
                _SEED_EMPLOYEES,
            )
        conn.commit()
    finally:
        conn.close()


class SQLTool(Tool):
    name = "sql_query"
    description = (
        "Run a read-only SELECT query against the fake lab SQLite "
        "database (data/lab.db). Write statements are rejected."
    )
    args_schema: dict[str, Any] = {
        "type": "object",
        "properties": {"query": {"type": "string"}},
        "required": ["query"],
    }

    def _run(self, args: dict[str, Any]) -> ToolResult:
        raw_query = args["query"].strip()
        stripped = raw_query.rstrip(";").strip()

        if not stripped.upper().startswith("SELECT"):
            return ToolResult(
                ok=False,
                data={"error": "only SELECT statements are allowed in this phase"},
                side_effects=[],
            )
        if ";" in stripped:
            return ToolResult(
                ok=False,
                data={"error": "multiple statements are not allowed"},
                side_effects=[],
            )
        if _WRITE_KEYWORDS.search(stripped):
            return ToolResult(
                ok=False,
                data={"error": "write keyword detected; only SELECT is allowed"},
                side_effects=[],
            )

        _ensure_db()
        conn = sqlite3.connect(f"file:{_DB_PATH}?mode=ro", uri=True)
        try:
            conn.row_factory = sqlite3.Row
            rows = [dict(row) for row in conn.execute(stripped).fetchall()]
        except sqlite3.Error as exc:
            return ToolResult(ok=False, data={"error": str(exc)}, side_effects=[])
        finally:
            conn.close()

        return ToolResult(ok=True, data={"rows": rows}, side_effects=[])
