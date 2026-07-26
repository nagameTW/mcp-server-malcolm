"""Tests for the coverage additions from the upstream API audit:
- malcolm_search / malcolm_aggregate doctype selector
- malcolm_alerts category / action / sid (ECS-normalized fields)
- arkime_session_pcap multi-id support
- malcolm_netbox_query generic passthrough + path validation
"""

import httpx
import pytest
from mcp.server.fastmcp import FastMCP

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.tools.arkime import register_arkime_tools
from mcp_server_malcolm.tools.netbox import register_netbox_tools
from mcp_server_malcolm.tools.query import register_query_tools


def _mock_client(handler):
    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example",
        transport=httpx.MockTransport(handler),
    )
    return c


# -- doctype selector -------------------------------------------------------


@pytest.mark.asyncio
async def test_search_forwards_doctype():
    seen = {}

    def handler(req):
        seen["body"] = req.content.decode()
        return httpx.Response(200, json={"hits": []})

    mcp = FastMCP("t")
    register_query_tools(mcp, _mock_client(handler))
    await mcp.call_tool("malcolm_search", {"doctype": "arkime"})
    assert '"doctype"' in seen["body"]
    assert "arkime" in seen["body"]


@pytest.mark.asyncio
async def test_search_omits_doctype_when_empty():
    seen = {}

    def handler(req):
        seen["body"] = req.content.decode()
        return httpx.Response(200, json={"hits": []})

    mcp = FastMCP("t")
    register_query_tools(mcp, _mock_client(handler))
    await mcp.call_tool("malcolm_search", {})
    assert "doctype" not in seen["body"]


@pytest.mark.asyncio
async def test_aggregate_forwards_doctype():
    seen = {}

    def handler(req):
        seen["body"] = req.content.decode()
        return httpx.Response(200, json={})

    mcp = FastMCP("t")
    register_query_tools(mcp, _mock_client(handler))
    await mcp.call_tool("malcolm_aggregate", {"fields": "host.name", "doctype": "beat"})
    assert '"doctype"' in seen["body"]
    assert "beat" in seen["body"]


# -- malcolm_alerts ECS fields ---------------------------------------------


@pytest.mark.asyncio
async def test_alerts_category_action_sid_use_ecs_fields():
    seen = {}

    def handler(req):
        seen["body"] = req.content.decode()
        return httpx.Response(200, json={"hits": []})

    mcp = FastMCP("t")
    register_query_tools(mcp, _mock_client(handler))
    await mcp.call_tool(
        "malcolm_alerts",
        {"category": "Trojan", "action": "blocked", "sid": "2013028"},
    )
    body = seen["body"]
    # category and sid are normalized by Malcolm to ECS rule.* fields
    assert "rule.category" in body
    assert "rule.id" in body
    # action stays under the suricata namespace
    assert "suricata.alert.action" in body
    # the hallucinated non-ECS names must NOT be sent
    assert "suricata.alert.category" not in body
    assert "suricata.alert.signature_id" not in body


@pytest.mark.asyncio
async def test_alerts_multi_sid_becomes_list():
    seen = {}

    def handler(req):
        seen["body"] = req.content.decode()
        return httpx.Response(200, json={"hits": []})

    mcp = FastMCP("t")
    register_query_tools(mcp, _mock_client(handler))
    await mcp.call_tool("malcolm_alerts", {"sid": "111,222"})
    # two sids -> a list of ints, not a single value
    assert "111" in seen["body"] and "222" in seen["body"]
    assert "[" in seen["body"]


# -- arkime multi-id pcap ---------------------------------------------------


@pytest.mark.asyncio
async def test_pcap_accepts_comma_separated_ids():
    seen = {}

    def handler(req):
        seen["ids"] = req.url.params.get("ids")
        # minimal valid pcap-le magic
        return httpx.Response(200, content=b"\xd4\xc3\xb2\xa1rest")

    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_session_pcap", {"session_id": "240601-A,240601-B"})
    assert seen["ids"] == "240601-A,240601-B"
    assert "pcap-le" in str(out)


@pytest.mark.asyncio
async def test_pcap_rejects_injection_ids():
    def handler(req):
        raise AssertionError("must not download for an injecting id")

    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("arkime_session_pcap", {"session_id": "1 || ip==0.0.0.0/0"})
    assert "invalid session_id" in str(out).lower()


# -- netbox generic passthrough --------------------------------------------


@pytest.mark.asyncio
async def test_netbox_query_hits_path_and_forwards_params():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        seen["port"] = req.url.params.get("port")
        return httpx.Response(200, json={"results": [{"name": "https"}]})

    mcp = FastMCP("t")
    register_netbox_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool(
        "malcolm_netbox_query",
        {"path": "ipam/services/", "params": '{"port": "443"}'},
    )
    assert seen["path"] == "/mapi/netbox/ipam/services/"
    assert seen["port"] == "443"
    assert "https" in str(out)


@pytest.mark.asyncio
async def test_netbox_query_rejects_traversal_path():
    def handler(req):
        raise AssertionError("must not query for a traversal path")

    mcp = FastMCP("t")
    register_netbox_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("malcolm_netbox_query", {"path": "../../secret"})
    assert "invalid netbox path" in str(out).lower()


@pytest.mark.asyncio
async def test_netbox_query_rejects_absolute_url_path():
    def handler(req):
        raise AssertionError("must not query for an absolute url")

    mcp = FastMCP("t")
    register_netbox_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("malcolm_netbox_query", {"path": "http://evil.example/x"})
    assert "invalid netbox path" in str(out).lower()


@pytest.mark.asyncio
async def test_netbox_query_rejects_bad_params_json():
    def handler(req):
        raise AssertionError("must not query with unparseable params")

    mcp = FastMCP("t")
    register_netbox_tools(mcp, _mock_client(handler))
    out = await mcp.call_tool("malcolm_netbox_query", {"path": "ipam/vlans/", "params": "{bad"})
    assert "invalid json" in str(out).lower()
