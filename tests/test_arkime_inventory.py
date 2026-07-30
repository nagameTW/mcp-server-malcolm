"""Tests for the Arkime read-coverage tools (batch 2).

Endpoint shapes, parameter names and failure modes were measured against a live
Malcolm v26.07.1 / Arkime v6.6.0 before these were written.
"""

import asyncio
import json

import httpx
import pytest
from mcp.server.fastmcp import FastMCP

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.server import create_server
from mcp_server_malcolm.tools.arkime import register_arkime_tools
from mcp_server_malcolm.tools.arkime_inventory import register_arkime_inventory_tools


def _mock_client(handler):
    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example",
        transport=httpx.MockTransport(handler),
    )
    return c


def _tools(handler, register=register_arkime_inventory_tools):
    mcp = FastMCP("t")
    register(mcp, _mock_client(handler))
    return mcp


def payload(out):
    content = out[0] if isinstance(out, tuple) else out
    return content[0].text


def test_batch2_tools_registered():
    names = [t.name for t in asyncio.run(create_server().list_tools())]
    for name in (
        "arkime_views",
        "arkime_shortcuts",
        "arkime_reverse_dns",
        "arkime_pcap_files",
        "arkime_node_stats",
        "arkime_export_csv",
    ):
        assert name in names


# -- arkime_views / arkime_shortcuts ------------------------------------

_VIEW = {
    "name": "Arkime Sessions",
    "expression": "event.provider == arkime",
    "roles": ["arkimeUser"],
    "users": "",
    "user": "otex",
    "id": "WMGExBjWoxcIuZRPyq4_",
}


@pytest.mark.asyncio
async def test_views_lists_saved_searches():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        return httpx.Response(200, json={"data": [_VIEW], "recordsTotal": 1})

    out = json.loads(payload(await _tools(handler).call_tool("arkime_views", {})))

    assert seen["path"] == "/arkime/api/views"
    assert out["count"] == 1
    assert out["views"][0] == {
        "name": "Arkime Sessions",
        "expression": "event.provider == arkime",
        "owner": "otex",
        "roles": ["arkimeUser"],
        "id": "WMGExBjWoxcIuZRPyq4_",
    }


@pytest.mark.asyncio
async def test_views_reports_an_empty_list_plainly():
    def handler(req):
        return httpx.Response(200, json={"data": [], "recordsTotal": 0})

    out = payload(await _tools(handler).call_tool("arkime_views", {}))

    assert "no saved views" in out.lower()


@pytest.mark.asyncio
async def test_shortcuts_lists_value_lists_with_their_expression_reference():
    def handler(req):
        assert req.url.path == "/arkime/api/shortcuts"
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "name": "c2_ips",
                        "type": "ip",
                        "value": "192.0.2.1\n192.0.2.2",
                        "description": "known c2",
                        "userId": "otex",
                        "id": "abc",
                    }
                ],
                "recordsTotal": 1,
            },
        )

    out = json.loads(payload(await _tools(handler).call_tool("arkime_shortcuts", {})))
    row = out["shortcuts"][0]

    assert row["name"] == "c2_ips"
    assert row["type"] == "ip"
    assert row["values"] == ["192.0.2.1", "192.0.2.2"]
    # The whole point of a shortcut is being able to write $name in an expression.
    assert row["use_in_expression"] == "$c2_ips"


@pytest.mark.asyncio
async def test_shortcuts_says_where_they_come_from_when_empty():
    def handler(req):
        return httpx.Response(200, json={"data": [], "recordsTotal": 0})

    out = payload(await _tools(handler).call_tool("arkime_shortcuts", {}))

    assert "no shortcuts" in out.lower()


# -- arkime_reverse_dns -------------------------------------------------


@pytest.mark.asyncio
async def test_reverse_dns_returns_the_ptr_name():
    seen = {}

    def handler(req):
        seen["ip"] = req.url.params.get("ip")
        return httpx.Response(200, text="dns.google\n")

    out = json.loads(
        payload(await _tools(handler).call_tool("arkime_reverse_dns", {"ip": "8.8.8.8"}))
    )

    assert seen["ip"] == "8.8.8.8"
    assert out["hostname"] == "dns.google"
    assert out["resolved"] is True


@pytest.mark.asyncio
async def test_reverse_dns_translates_arkimes_error_text():
    """Arkime answers 200 with the body "reverse error" when there is no PTR —
    measured live for a private address. That must not read as a hostname."""

    def handler(req):
        return httpx.Response(200, text="reverse error")

    out = json.loads(
        payload(await _tools(handler).call_tool("arkime_reverse_dns", {"ip": "192.0.2.7"}))
    )

    assert out["resolved"] is False
    assert "reverse error" not in out.get("hostname", "")


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["", "  ", "not-an-ip", "1.2.3.4 && x"])
async def test_reverse_dns_rejects_a_non_ip(bad):
    def handler(req):
        raise AssertionError(f"must not query for {bad!r}")

    out = payload(await _tools(handler).call_tool("arkime_reverse_dns", {"ip": bad}))

    assert "error" in out.lower()


@pytest.mark.asyncio
async def test_reverse_dns_accepts_ipv6():
    def handler(req):
        return httpx.Response(200, text="localhost")

    out = payload(await _tools(handler).call_tool("arkime_reverse_dns", {"ip": "::1"}))

    assert "localhost" in out


# -- arkime_pcap_files --------------------------------------------------

_FILE = {
    "num": 101,
    "name": "/data/pcap/processed/CAPTURE-001.pcap",
    "node": "spark-0b7b-upload",
    "filesize": 15772997,
    "packets": 82217,
    "packetsSize": 15772997,
    "sessionsPresent": 6280,
    "sessionsStarted": 6301,
    "firstTimestamp": 1714049780727,
    "lastTimestamp": 1714053380515,
    "locked": 1,
    "packetPosEncoding": "gap0",
}


@pytest.mark.asyncio
async def test_pcap_files_lists_the_capture_inventory():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        seen["length"] = req.url.params.get("length")
        return httpx.Response(200, json={"data": [_FILE], "recordsTotal": 29})

    out = json.loads(payload(await _tools(handler).call_tool("arkime_pcap_files", {"limit": 5})))

    assert seen["path"] == "/arkime/api/files"
    assert seen["length"] == "5"
    assert out["total"] == 29
    row = out["files"][0]
    assert row["name"] == "/data/pcap/processed/CAPTURE-001.pcap"
    assert row["bytes"] == 15772997
    assert row["packets"] == 82217
    assert row["sessions"] == 6280
    assert row["node"] == "spark-0b7b-upload"
    # Timestamps are epoch MILLISECONDS here, unlike the epoch-seconds every
    # Arkime query parameter takes.
    assert row["first_packet"] == 1714049780727


@pytest.mark.asyncio
async def test_pcap_files_drops_the_internal_bookkeeping_fields():
    def handler(req):
        return httpx.Response(200, json={"data": [_FILE], "recordsTotal": 1})

    out = payload(await _tools(handler).call_tool("arkime_pcap_files", {}))

    assert "packetPosEncoding" not in out


# -- arkime_node_stats --------------------------------------------------

_NODE = {
    "nodeName": "spark-0b7b-upload",
    "hostname": "arkime",
    "ver": "6.6.0",
    "freeSpaceM": 1646362,
    "freeSpaceP": 40.83,
    "memoryP": 0.59,
    "cpu": 0,
    "totalPackets": 82217,
    "totalSessions": 6280,
    "totalDropped": 17,
    "deltaDroppedPerSec": 0,
    "deltaPacketsPerSec": 0,
    "esQueue": 4,
    "packetQueue": 0,
    "diskQueue": 0,
    "monitoring": 0,
    "runningTime": 999,
    "interval": 1,
    "id": "x",
}


@pytest.mark.asyncio
async def test_node_stats_surfaces_capture_health():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        return httpx.Response(200, json={"data": [_NODE], "recordsTotal": 1})

    out = json.loads(payload(await _tools(handler).call_tool("arkime_node_stats", {})))
    node = out["nodes"][0]

    assert seen["path"] == "/arkime/api/stats"
    assert node["node"] == "spark-0b7b-upload"
    assert node["arkime_version"] == "6.6.0"
    assert node["packets_dropped"] == 17
    assert node["disk_free_percent"] == 40.83


@pytest.mark.asyncio
async def test_node_stats_flags_a_node_that_is_dropping_packets():
    """A silently dropping capture node means the data is incomplete, which is
    the one thing an analyst must not miss."""
    dropping = {**_NODE, "deltaDroppedPerSec": 42}

    def handler(req):
        return httpx.Response(200, json={"data": [dropping], "recordsTotal": 1})

    out = payload(await _tools(handler).call_tool("arkime_node_stats", {}))

    assert "dropping" in out.lower()


@pytest.mark.asyncio
async def test_node_stats_filters_with_the_filter_param():
    """Measured live: nodeName= is ignored, filter= is what narrows the list."""
    seen = {}

    def handler(req):
        seen["params"] = dict(req.url.params)
        return httpx.Response(200, json={"data": [_NODE], "recordsTotal": 1})

    await _tools(handler).call_tool("arkime_node_stats", {"node": "spark"})

    assert seen["params"].get("filter") == "spark"
    assert "nodeName" not in seen["params"]


# -- arkime_export_csv --------------------------------------------------


@pytest.mark.asyncio
async def test_export_csv_sessions_hits_the_csv_route():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        seen["params"] = dict(req.url.params)
        return httpx.Response(200, text="IP Protocol, Src IP\nudp,192.0.2.7\n")

    out = payload(
        await _tools(handler, register_arkime_tools).call_tool(
            "arkime_export_csv",
            {"kind": "sessions", "expression": "protocols == dns", "time_from": "1714003200"},
        )
    )

    assert seen["path"] == "/arkime/api/sessions.csv"
    assert seen["params"]["expression"] == "protocols == dns"
    assert seen["params"]["startTime"] == "1714003200"
    assert "192.0.2.7" in out


@pytest.mark.asyncio
async def test_export_csv_connections_uses_db_field_names():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        seen["params"] = dict(req.url.params)
        return httpx.Response(200, text="Source, Destination\n192.0.2.7,192.0.2.8\n")

    await _tools(handler, register_arkime_tools).call_tool(
        "arkime_export_csv", {"kind": "connections"}
    )

    assert seen["path"] == "/arkime/api/connections.csv"
    # connections wants Arkime *db* names; the same 500 that bit arkime_connections.
    assert seen["params"]["srcField"] == "srcIp"
    assert seen["params"]["dstField"] == "dstIp"


@pytest.mark.asyncio
async def test_export_csv_rejects_an_unknown_kind():
    def handler(req):
        raise AssertionError("no request may leave for an unvalidated route")

    out = payload(
        await _tools(handler, register_arkime_tools).call_tool(
            "arkime_export_csv", {"kind": "everything"}
        )
    )

    assert "must be one of sessions, connections" in out


@pytest.mark.asyncio
async def test_export_csv_explains_a_timeout_as_a_bad_field_name():
    """Measured live: sessions.csv takes ECS dotted names in fields= and simply
    never answers on a db name like srcIp. A bare timeout tells the agent
    nothing, so name the likely cause."""

    def handler(req):
        raise httpx.ReadTimeout("timed out")

    out = payload(
        await _tools(handler, register_arkime_tools).call_tool(
            "arkime_export_csv", {"kind": "sessions", "fields": "srcIp,dstIp"}
        )
    )

    assert "fields" in out.lower()
    assert "source.ip" in out


@pytest.mark.asyncio
async def test_export_csv_passes_the_field_list_through():
    seen = {}

    def handler(req):
        seen["fields"] = req.url.params.get("fields")
        return httpx.Response(200, text="Src IP\n192.0.2.7\n")

    await _tools(handler, register_arkime_tools).call_tool(
        "arkime_export_csv", {"kind": "sessions", "fields": "source.ip, destination.ip"}
    )

    assert seen["fields"] == "source.ip,destination.ip"


# -- failure handling ---------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("arkime_views", {}),
        ("arkime_shortcuts", {}),
        ("arkime_reverse_dns", {"ip": "8.8.8.8"}),
        ("arkime_pcap_files", {}),
        ("arkime_node_stats", {}),
    ],
)
async def test_every_inventory_tool_reports_a_transport_failure(tool, args):
    """A tool must hand the agent a sentence, never raise into the MCP layer."""

    def handler(req):
        raise httpx.ConnectError("connection refused")

    out = payload(await _tools(handler).call_tool(tool, args))

    assert "failed" in out.lower()
    assert "connection refused" in out


@pytest.mark.asyncio
async def test_pcap_files_says_so_when_nothing_is_indexed():
    def handler(req):
        return httpx.Response(200, json={"data": [], "recordsTotal": 0})

    out = payload(await _tools(handler).call_tool("arkime_pcap_files", {}))

    assert "no indexed pcap" in out.lower()


@pytest.mark.asyncio
async def test_node_stats_says_so_when_no_node_matches():
    def handler(req):
        return httpx.Response(200, json={"data": [], "recordsTotal": 0})

    out = payload(await _tools(handler).call_tool("arkime_node_stats", {"node": "ghost"}))

    assert "ghost" in out


@pytest.mark.asyncio
async def test_node_stats_tolerates_counters_arriving_as_strings():
    """Arkime sends some counters as numbers and some as strings depending on
    the route; the drop check must not blow up on either."""
    stringy = {**_NODE, "deltaDroppedPerSec": "7"}

    def handler(req):
        return httpx.Response(200, json={"data": [stringy], "recordsTotal": 1})

    out = payload(await _tools(handler).call_tool("arkime_node_stats", {}))

    assert "dropping" in out.lower()
