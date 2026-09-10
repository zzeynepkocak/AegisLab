"""Append-only per-session message memory, persisted under data/sessions/."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_SESSIONS_DIR = _REPO_ROOT / "data" / "sessions"


class SessionMemory:
    def __init__(self, session_id: str, sessions_dir: Path | None = None) -> None:
        self.session_id = session_id
        self._path = (sessions_dir or _DEFAULT_SESSIONS_DIR) / f"{session_id}.jsonl"
        self._messages: list[dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        with self._path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    self._messages.append(json.loads(line))

    def append(self, message: dict[str, Any]) -> None:
        self._messages.append(message)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(message) + "\n")

    @property
    def messages(self) -> list[dict[str, Any]]:
        return list(self._messages)
