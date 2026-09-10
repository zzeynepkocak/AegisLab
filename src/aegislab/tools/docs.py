"""Fake docs search tool.

Searches project markdown files for a keyword using a simple
case-insensitive substring ("contains") match, and also surfaces the
naive RAG retriever's top matches from the knowledge-base corpus
(src/aegislab/data/docs/). RAG chunk text is included verbatim, with no
isolation or sanitization -- see aegislab.rag.index.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from aegislab.rag.index import build_index_from_dir

from .base import Tool, ToolResult

_REPO_ROOT = Path(__file__).resolve().parents[3]
_EXCLUDED_DIRS = {"venv", ".venv", "__pycache__", ".pytest_cache", "node_modules", "data"}


def _iter_markdown_files() -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(_REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDED_DIRS and not d.startswith(".")]
        for filename in filenames:
            if filename.endswith(".md"):
                found.append(Path(dirpath) / filename)
    return found


class DocsTool(Tool):
    name = "docs_search"
    description = "Search project markdown files for a keyword (case-insensitive substring match)."
    args_schema: dict[str, Any] = {
        "type": "object",
        "properties": {"keyword": {"type": "string"}},
        "required": ["keyword"],
    }

    def _run(self, args: dict[str, Any]) -> ToolResult:
        keyword = args["keyword"]
        if not keyword:
            return ToolResult(ok=False, data={"error": "keyword must not be empty"}, side_effects=[])

        needle = keyword.lower()
        matches = []
        for path in _iter_markdown_files():
            text = path.read_text(encoding="utf-8", errors="ignore")
            for lineno, line in enumerate(text.splitlines(), start=1):
                if needle in line.lower():
                    matches.append(
                        {
                            "file": str(path.relative_to(_REPO_ROOT)),
                            "line": lineno,
                            "text": line.strip(),
                        }
                    )

        rag_matches = [
            {"source": chunk.source, "text": chunk.text}
            for chunk in build_index_from_dir().search(keyword, top_k=3)
        ]

        return ToolResult(ok=True, data={"matches": matches, "rag_matches": rag_matches}, side_effects=[])
