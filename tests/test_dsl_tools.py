import asyncio

import pytest
from conftest import raised_by

from mcp_server_malcolm.errors import ToolInputError
from mcp_server_malcolm.server import create_server


def _tool_names():
    mcp = create_server()
    return [t.name for t in asyncio.run(mcp.list_tools())]


def test_dsl_core_tools_registered():
    names = _tool_names()
    for expected in ("search_dsl", "count", "list_indices", "index_mapping", "cluster_health"):
        assert expected in names, f"{expected} missing; have {names}"


@pytest.mark.asyncio
async def test_search_dsl_rejects_malformed_json():
    """It raises, so the call comes back with isError true rather than a
    success whose text happens to start with "Error:"."""
    raised = await raised_by(
        create_server(), "search_dsl", {"index": "arkime_sessions3-*", "query_dsl": "{not json"}
    )
    assert isinstance(raised, ToolInputError)
    assert "invalid JSON in query_dsl" in str(raised)


@pytest.mark.asyncio
async def test_search_dsl_rejects_bad_index_pattern():
    """index is LLM-controlled and lands in the URL path — no path metachars."""
    raised = await raised_by(
        create_server(), "search_dsl", {"index": "../_bulk", "query_dsl": "{}"}
    )
    assert isinstance(raised, ToolInputError)
    assert "invalid index pattern" in str(raised)
