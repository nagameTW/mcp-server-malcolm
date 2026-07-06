import asyncio

import httpx
import pytest
from mcp.server.fastmcp import FastMCP

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.server import create_server


def _tool_names():
    mcp = create_server()
    return [t.name for t in asyncio.run(mcp.list_tools())]


def test_pcap_and_liveness_tools_registered():
    names = _tool_names()
    assert "arkime_session_pcap" in names
    assert "arkime_pcap_info" not in names  # dead-string tool removed
    assert "malcolm_ping" in names
    assert "malcolm_dashboard_export" in names


def _mock_client(handler):
    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example",
        transport=httpx.MockTransport(handler),
    )
    return c


@pytest.mark.asyncio
async def test_pcap_tool_validates_magic_no_disk_write():
    def handler(req):
        return httpx.Response(200, content=b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00rest-of-pcap")

    from mcp_server_malcolm.tools.arkime import register_arkime_tools

    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_session_pcap", {"session_id": "240601-X"})
    text = str(out)
    assert "valid_pcap" in text
    assert "true" in text.lower()
    assert "saved_to" not in text  # nothing is persisted to disk


@pytest.mark.asyncio
async def test_pcap_tool_rejects_injection_session_id():
    def handler(req):
        raise AssertionError("must not download for a non-id session_id")

    from mcp_server_malcolm.tools.arkime import register_arkime_tools

    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_session_pcap", {"session_id": "1||ip==0.0.0.0/0"})
    assert "invalid session_id" in str(out).lower()


@pytest.mark.asyncio
async def test_pcap_tool_flags_non_pcap_body(tmp_path, monkeypatch):
    monkeypatch.setenv("TMPDIR", str(tmp_path))

    def handler(req):
        return httpx.Response(200, content=b"<html>not a pcap</html>")

    from mcp_server_malcolm.tools.arkime import register_arkime_tools

    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_session_pcap", {"session_id": "240601-X"})
    assert "false" in str(out).lower()


@pytest.mark.asyncio
async def test_pcap_tool_url_only_skips_download():
    called = {"n": 0}

    def handler(req):
        called["n"] += 1
        return httpx.Response(200, content=b"\xa1\xb2\xc3\xd4")

    from mcp_server_malcolm.tools.arkime import register_arkime_tools

    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_session_pcap", {"session_id": "240601-X", "url_only": True})
    assert "pcap_url" in str(out)
    assert called["n"] == 0  # no download performed
