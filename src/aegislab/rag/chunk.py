"""Naive markdown chunker: paragraph-aware, target size ~400 chars."""

from __future__ import annotations

DEFAULT_CHUNK_SIZE = 400


def chunk_markdown(text: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> list[str]:
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]

    chunks: list[str] = []
    current = ""

    for paragraph in paragraphs:
        candidate = f"{current}\n\n{paragraph}" if current else paragraph

        if len(candidate) <= chunk_size:
            current = candidate
            continue

        if current:
            chunks.append(current)
            current = ""

        if len(paragraph) <= chunk_size:
            current = paragraph
            continue

        # a single paragraph longer than chunk_size: split on word boundaries
        words = paragraph.split(" ")
        piece = ""
        for word in words:
            candidate_piece = f"{piece} {word}".strip()
            if len(candidate_piece) > chunk_size and piece:
                chunks.append(piece)
                piece = word
            else:
                piece = candidate_piece
        current = piece

    if current:
        chunks.append(current)

    return chunks
