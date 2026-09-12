"""In-memory naive TF-IDF index over markdown chunks. No vector DB.

Retrieved chunk text is returned verbatim via search(). Callers
(aegislab.tools.docs, aegislab.agent.loop) may paste it directly into
LLM context with NO isolation or sanitization by default -- that is
intentional for this lab phase, which studies indirect prompt injection
via retrieved documents. Use search_as_context() / DocChunk.to_context_part()
to get provenance-tagged (origin=retrieval) parts instead -- see
aegislab.context.firewall for what a caller does with those when
DEFENSE=on.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path

from aegislab.context.parts import ContextPart, Origin, Trust
from aegislab.rag.chunk import chunk_markdown

_REPO_ROOT = Path(__file__).resolve().parents[3]
KNOWLEDGE_BASE_DIR = _REPO_ROOT / "src" / "aegislab" / "data" / "docs"

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


@dataclass
class DocChunk:
    source: str
    text: str

    def to_context_part(self, trust: Trust = Trust.UNTRUSTED) -> ContextPart:
        return ContextPart(origin=Origin.RETRIEVAL, trust=trust, text=self.text)


class RagIndex:
    def __init__(self, chunks: list[DocChunk]) -> None:
        self._chunks = chunks
        self._term_freqs = [self._term_freq(c.text) for c in chunks]
        self._idf = self._build_idf(self._term_freqs)

    @staticmethod
    def _term_freq(text: str) -> dict[str, int]:
        freq: dict[str, int] = {}
        for token in _tokenize(text):
            freq[token] = freq.get(token, 0) + 1
        return freq

    @staticmethod
    def _build_idf(term_freqs: list[dict[str, int]]) -> dict[str, float]:
        n_docs = len(term_freqs)
        doc_freq: dict[str, int] = {}
        for freq in term_freqs:
            for token in freq:
                doc_freq[token] = doc_freq.get(token, 0) + 1
        return {token: math.log((n_docs + 1) / (df + 1)) + 1 for token, df in doc_freq.items()}

    def search(self, query: str, top_k: int = 3) -> list[DocChunk]:
        query_tokens = _tokenize(query)
        if not query_tokens:
            return []

        scored: list[tuple[float, int]] = []
        for i, freq in enumerate(self._term_freqs):
            score = sum(freq.get(token, 0) * self._idf.get(token, 0.0) for token in query_tokens)
            if score > 0:
                scored.append((score, i))

        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [self._chunks[i] for _, i in scored[:top_k]]

    def search_as_context(self, query: str, top_k: int = 3, trust: Trust = Trust.UNTRUSTED) -> list[ContextPart]:
        """Same ranking as search(), but tagged origin=retrieval."""
        return [chunk.to_context_part(trust) for chunk in self.search(query, top_k)]


def build_index_from_dir(directory: Path = KNOWLEDGE_BASE_DIR) -> RagIndex:
    chunks: list[DocChunk] = []
    if directory.exists():
        for path in sorted(directory.glob("*.md")):
            text = path.read_text(encoding="utf-8", errors="ignore")
            for piece in chunk_markdown(text):
                chunks.append(DocChunk(source=path.name, text=piece))
    return RagIndex(chunks)
