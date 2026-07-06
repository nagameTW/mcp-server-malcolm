from mcp_server_malcolm.server import create_server


def test_no_write_tools_registered():
    """The server is read-only: no tool name hints at writing/posting/ingest."""
    import asyncio

    mcp = create_server()
    tools = asyncio.run(mcp.list_tools())
    names = [t.name for t in tools]
    banned = [
        n
        for n in names
        if any(w in n.lower() for w in ("post", "write", "ingest", "delete", "create", "update"))
    ]
    assert not banned, f"write-capable tools present: {banned}"
    assert "malcolm_event_post" not in names
