import asyncio

from mcp_server_malcolm.server import create_server


def _tool_names():
    mcp = create_server()
    return [t.name for t in asyncio.run(mcp.list_tools())]


def test_dsl_core_tools_registered():
    names = _tool_names()
    for expected in ("search_dsl", "count", "list_indices", "index_mapping", "cluster_health"):
        assert expected in names, f"{expected} missing; have {names}"


def test_search_dsl_rejects_malformed_json():
    mcp = create_server()
    out = asyncio.run(
        mcp.call_tool("search_dsl", {"index": "arkime_sessions3-*", "query_dsl": "{not json"})
    )
    assert "Error: invalid JSON" in str(out)


def test_search_dsl_rejects_bad_index_pattern():
    """index is LLM-controlled and lands in the URL path — no path metachars."""
    mcp = create_server()
    out = asyncio.run(mcp.call_tool("search_dsl", {"index": "../_bulk", "query_dsl": "{}"}))
    assert "Error: invalid index" in str(out)
