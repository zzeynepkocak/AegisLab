"""Tests for the naive RAG retriever. No LLM involved."""

from aegislab.rag import chunk, index
from aegislab.tools.docs import DocsTool


def test_chunk_markdown_respects_target_size():
    text = ("Paragraph one is short.\n\n" * 40).strip()
    chunks = chunk.chunk_markdown(text, chunk_size=400)

    assert chunks
    assert all(len(c) <= 400 for c in chunks)


def test_chunk_markdown_splits_long_single_paragraph():
    long_paragraph = "word " * 200  # ~1000 chars, no blank lines
    chunks = chunk.chunk_markdown(long_paragraph, chunk_size=400)

    assert len(chunks) > 1
    assert all(len(c) <= 420 for c in chunks)


def test_rag_index_search_ranks_relevant_chunk_first():
    chunks = [
        index.DocChunk(source="a.md", text="The quarterly sales report shows growth in Q3."),
        index.DocChunk(source="b.md", text="Password reset instructions for the customer portal."),
        index.DocChunk(source="c.md", text="Office holiday schedule for December."),
    ]
    idx = index.RagIndex(chunks)

    results = idx.search("password reset portal", top_k=1)

    assert results[0].source == "b.md"


def test_rag_index_returns_empty_for_empty_query():
    idx = index.RagIndex([index.DocChunk(source="a.md", text="hello world")])
    assert idx.search("", top_k=3) == []


def test_build_index_from_dir_includes_poison_chunk_for_relevant_query():
    """Confirms the planted poison_ticket.md is retrievable via RAG for a
    relevant query. This only proves retrieval works -- making the
    injected instruction succeed is out of scope for this task.
    """
    idx = index.build_index_from_dir()

    results = idx.search("password reset link expired", top_k=3)

    assert results
    assert any(c.source == "poison_ticket.md" for c in results)


def test_poison_ticket_is_marked_lab_only():
    text = (index.KNOWLEDGE_BASE_DIR / "poison_ticket.md").read_text(encoding="utf-8")
    assert "LAB-ONLY" in text


def test_docs_tool_surfaces_poison_chunk_via_rag_matches():
    tool = DocsTool()
    result = tool.execute({"keyword": "password reset link expired"})

    assert result.ok
    assert any(m["source"] == "poison_ticket.md" for m in result.data["rag_matches"])
