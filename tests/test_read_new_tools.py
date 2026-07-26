"""Tests for the read-only tools added from the API survey (issue #1):
arkime_session_detail, arkime_unique, malcolm_netbox_sites.
"""

import asyncio

import httpx
import pytest
from mcp.server.fastmcp import FastMCP

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.server import create_server
from mcp_server_malcolm.tools.arkime import register_arkime_tools
from mcp_server_malcolm.tools.netbox import register_netbox_tools


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
        return httpx.Response(200, json={"src.ip": "192.0.2.77", "protocols": ["dns"]})

    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_session_detail", {"session_id": "240601-X"})
    assert seen["path"] == "/arkime/api/session/240601-X"
    assert "192.0.2.77" in str(out)


@pytest.mark.asyncio
async def test_session_detail_rejects_injection_session_id():
    def handler(req):
        raise AssertionError("must not fetch for a non-id session_id")

    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_session_detail", {"session_id": "1||ip==0.0.0.0/0"})
    assert "invalid session_id" in str(out).lower()


@pytest.mark.asyncio
async def test_unique_returns_plain_text_lines():
    def handler(req):
        assert req.url.path == "/arkime/api/unique"
        assert req.url.params.get("exp") == "protocols"
        return httpx.Response(200, text="dns\ntls\nhttp\n")

    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_unique", {"field": "protocols"})
    text = str(out)
    assert "dns" in text
    assert "tls" in text


@pytest.mark.asyncio
async def test_unique_requires_field():
    def handler(req):
        raise AssertionError("must not call the API without a field")

    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_unique", {"field": "  "})
    assert "field is required" in str(out).lower()


@pytest.mark.asyncio
async def test_netbox_sites_hits_endpoint():
    def handler(req):
        assert req.url.path == "/mapi/netbox-sites"
        return httpx.Response(200, json={"sites": [{"id": 1, "name": "hq"}]})

    mcp = FastMCP("t")
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

    mcp = FastMCP("t")
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

    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_spigraph", {"field": " "})
    assert "field is required" in str(out).lower()


@pytest.mark.asyncio
async def test_spiview_passes_spi_list():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        seen["spi"] = req.url.params.get("spi")
        return httpx.Response(200, json={"spi": {"protocols": {"buckets": []}}})

    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_spiview", {"spi": "protocols:10,ip.dst"})
    assert seen["path"] == "/arkime/api/spiview"
    assert seen["spi"] == "protocols:10,ip.dst"
    assert "protocols" in str(out)


@pytest.mark.asyncio
async def test_spiview_requires_spi():
    def handler(req):
        raise AssertionError("must not call the API without spi")

    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_spiview", {"spi": ""})
    assert "required" in str(out).lower()


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

    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_connections", {})
    assert seen["path"] == "/arkime/api/connections"
    # Arkime db field names, not dotted ECS names — a dotted name errors in Arkime.
    assert seen["src"] == "srcIp"
    assert seen["dst"] == "dstIp"
    assert "nodes" in str(out)
