"""Tests for the read-only tools added from the API survey (issue #1):
arkime_session_detail, arkime_unique, malcolm_netbox_sites.
"""

import asyncio

import httpx
import pytest
from conftest import raised_by
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.errors import ToolInputError
from mcp_server_malcolm.server import create_server
from mcp_server_malcolm.tools.arkime import register_arkime_tools as _register_arkime_search
from mcp_server_malcolm.tools.arkime_content import register_arkime_content_tools
from mcp_server_malcolm.tools.netbox import register_netbox_tools


def register_arkime_tools(mcp, client) -> None:  # noqa: F811
    """Both halves of the Arkime read surface, so these tests keep asking the
    same questions after the module split: search/aggregation stayed in
    arkime.py, per-session content moved to arkime_content.py. The split is a
    module boundary, not a behaviour one."""
    _register_arkime_search(mcp, client)
    register_arkime_content_tools(mcp, client)


def _tool_names():
    mcp = create_server()
    return [t.name for t in asyncio.run(mcp.list_tools())]


def _mock_client(handler):
    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example",
        transport=httpx.MockTransport(handler),
    )
    return c


def test_new_read_tools_registered():
    names = _tool_names()
    assert "arkime_session_detail" in names
    assert "arkime_unique" in names
    assert "malcolm_netbox_sites" in names
    assert "arkime_spigraph" in names
    assert "arkime_spiview" in names
    assert "arkime_connections" in names


@pytest.mark.asyncio
async def test_session_detail_hits_endpoint_and_returns_fields():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        # /arkime/api/session/<id> answers the stored document itself, not a "data" array.
        return httpx.Response(200, json={"source": {"ip": "192.0.2.77"}, "tags": ["t"]})

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_session_detail", {"session_id": "240601-X"})
    assert seen["path"] == "/arkime/api/session/240601-X"
    assert "192.0.2.77" in str(out)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "session_id", ["3@240425:240425-IrHoGmqqp7SR6TWIWoG0Dw", "240425-IrHoGmqqp7SR6TWIWoG0Dw"]
)
async def test_session_detail_passes_either_id_form_through(session_id):
    """The route takes the node-prefixed id arkime_sessions hands out and the bare
    one alike: measured on Malcolm's training instance, both answered the same
    25-key document. (The old `id ==` expression matched only the bare form.)"""
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        return httpx.Response(200, json={"source": {"ip": "192.0.2.77"}})

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock_client(handler))
    await mcp.call_tool("arkime_session_detail", {"session_id": session_id})
    assert seen["path"] == f"/arkime/api/session/{session_id}"


@pytest.mark.asyncio
async def test_session_detail_reports_not_found():
    def handler(req):
        return httpx.Response(500, json={"success": False, "text": "Session not found"})

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_session_detail", {"session_id": "240601-X"})
    assert "no arkime session" in str(out).lower()


@pytest.mark.asyncio
async def test_session_detail_rejects_injection_session_id():
    def handler(req):
        raise AssertionError("must not fetch for a non-id session_id")

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock_client(handler))
    raised = await raised_by(mcp, "arkime_session_detail", {"session_id": "1||ip==0.0.0.0/0"})
    assert isinstance(raised, ToolInputError)
    assert "invalid session_id" in str(raised).lower()


@pytest.mark.asyncio
async def test_unique_returns_plain_text_lines():
    def handler(req):
        assert req.url.path == "/arkime/api/unique"
        assert req.url.params.get("exp") == "protocols"
        return httpx.Response(200, text="dns\ntls\nhttp\n")

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_unique", {"field": "protocols"})
    text = str(out)
    assert "dns" in text
    assert "tls" in text


@pytest.mark.asyncio
async def test_unique_passes_the_time_window():
    """Without a window Arkime answers from its default recent range, which is
    empty on a historical capture — verified live on 26.07.1."""
    seen = {}

    def handler(req):
        seen["start"] = req.url.params.get("startTime")
        seen["stop"] = req.url.params.get("stopTime")
        return httpx.Response(200, text="dns\n")

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock_client(handler))
    await mcp.call_tool(
        "arkime_unique",
        {"field": "protocols", "time_from": "1714003200", "time_to": "1714089600"},
    )
    assert seen["start"] == "1714003200"
    assert seen["stop"] == "1714089600"


@pytest.mark.asyncio
async def test_sessions_reports_matches_not_the_whole_index():
    """recordsFiltered is what the expression matched; recordsTotal is the size
    of the index. Reporting the latter said `protocols == ssh` matched 6,030,807
    sessions when it matched 134."""

    def handler(req):
        return httpx.Response(
            200,
            json={"data": [{"id": "240425-A"}], "recordsTotal": 6030807, "recordsFiltered": 134},
        )

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = str(await mcp.call_tool("arkime_sessions", {"expression": "protocols == ssh"}))
    assert "134" in out
    assert "6030807" not in out


@pytest.mark.asyncio
async def test_unique_requires_field():
    def handler(req):
        raise AssertionError("must not call the API without a field")

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock_client(handler))
    raised = await raised_by(mcp, "arkime_unique", {"field": "  "})
    assert isinstance(raised, ToolInputError)
    assert "field is required" in str(raised).lower()


@pytest.mark.asyncio
async def test_netbox_sites_hits_endpoint():
    def handler(req):
        assert req.url.path == "/mapi/netbox-sites"
        return httpx.Response(200, json={"sites": [{"id": 1, "name": "hq"}]})

    mcp = MCPServer("t")
    register_netbox_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("malcolm_netbox_sites", {})
    assert "hq" in str(out)


@pytest.mark.asyncio
async def test_spigraph_passes_field_and_scopes_time():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        seen["field"] = req.url.params.get("field")
        seen["start"] = req.url.params.get("startTime")
        return httpx.Response(200, json={"items": [{"name": "192.0.2.77", "count": 9}]})

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_spigraph", {"field": "ip.dst", "time_from": "1717200000"})
    assert seen["path"] == "/arkime/api/spigraph"
    assert seen["field"] == "ip.dst"
    assert seen["start"] == "1717200000"
    assert "192.0.2.77" in str(out)


@pytest.mark.asyncio
async def test_spigraph_requires_field():
    def handler(req):
        raise AssertionError("must not call the API without a field")

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock_client(handler))
    raised = await raised_by(mcp, "arkime_spigraph", {"field": " "})
    assert isinstance(raised, ToolInputError)
    assert "field is required" in str(raised).lower()


@pytest.mark.asyncio
async def test_spiview_passes_spi_list():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        seen["spi"] = req.url.params.get("spi")
        return httpx.Response(200, json={"spi": {"protocols": {"buckets": []}}})

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_spiview", {"spi": "protocols:10,ip.dst"})
    assert seen["path"] == "/arkime/api/spiview"
    assert seen["spi"] == "protocols:10,ip.dst"
    assert "protocols" in str(out)


@pytest.mark.asyncio
async def test_spiview_requires_spi():
    def handler(req):
        raise AssertionError("must not call the API without spi")

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock_client(handler))
    raised = await raised_by(mcp, "arkime_spiview", {"spi": ""})
    assert isinstance(raised, ToolInputError)
    assert "required" in str(raised).lower()


@pytest.mark.asyncio
async def test_connections_defaults_and_returns_graph():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        seen["src"] = req.url.params.get("srcField")
        seen["dst"] = req.url.params.get("dstField")
        return httpx.Response(
            200, json={"nodes": [{"id": "192.0.2.10"}], "links": [{"source": 0, "target": 1}]}
        )

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_connections", {})
    assert seen["path"] == "/arkime/api/connections"
    # Arkime db field names, not dotted ECS names — a dotted name errors in Arkime.
    assert seen["src"] == "srcIp"
    assert seen["dst"] == "dstIp"
    assert "nodes" in str(out)
