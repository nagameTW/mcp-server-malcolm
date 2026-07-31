"""Tests for the Arkime read-coverage tools (batch 2).

Endpoint shapes, parameter names and failure modes were measured against a live
Malcolm v26.07.1 / Arkime v6.6.0 before these were written.
"""

import asyncio
import json

import httpx
import pytest
from conftest import raised_by, tool_text
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.errors import ToolInputError, UpstreamError
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
    mcp = MCPServer("t")
    register(mcp, _mock_client(handler))
    return mcp


def test_batch2_tools_registered():
    names = [t.name for t in asyncio.run(create_server().list_tools())]
    for name in (
        "arkime_views",
        "arkime_shortcuts",
        "arkime_reverse_dns",
        "arkime_pcap_files",
        "arkime_node_stats",
        "arkime_sessions_csv",
    ):
        assert name in names


# -- arkime_views / arkime_shortcuts ------------------------------------

_VIEW = {
    "name": "Arkime Sessions",
    "expression": "event.provider == arkime",
    "roles": ["arkimeUser"],
    "users": "",
    "user": "operator1",
    "id": "WMGExBjWoxcIuZRPyq4_",
}


@pytest.mark.asyncio
async def test_views_lists_saved_searches():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        return httpx.Response(200, json={"data": [_VIEW], "recordsTotal": 1})

    out = json.loads(tool_text(await _tools(handler).call_tool("arkime_views", {})))

    assert seen["path"] == "/arkime/api/views"
    assert out["count"] == 1
    assert out["views"][0] == {
        "name": "Arkime Sessions",
        "expression": "event.provider == arkime",
        "owner": "operator1",
        "roles": ["arkimeUser"],
        "id": "WMGExBjWoxcIuZRPyq4_",
    }


@pytest.mark.asyncio
async def test_views_reports_an_empty_list_plainly():
    def handler(req):
        return httpx.Response(200, json={"data": [], "recordsTotal": 0})

    out = tool_text(await _tools(handler).call_tool("arkime_views", {}))

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
                        "userId": "operator1",
                        "id": "abc",
                    }
                ],
                "recordsTotal": 1,
            },
        )

    out = json.loads(tool_text(await _tools(handler).call_tool("arkime_shortcuts", {})))
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

    out = tool_text(await _tools(handler).call_tool("arkime_shortcuts", {}))

    assert "no shortcuts" in out.lower()


# -- arkime_reverse_dns -------------------------------------------------


@pytest.mark.asyncio
async def test_reverse_dns_returns_the_ptr_name():
    seen = {}

    def handler(req):
        seen["ip"] = req.url.params.get("ip")
        return httpx.Response(200, text="dns.google\n")

    out = json.loads(
        tool_text(await _tools(handler).call_tool("arkime_reverse_dns", {"ip": "8.8.8.8"}))
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
        tool_text(await _tools(handler).call_tool("arkime_reverse_dns", {"ip": "192.0.2.7"}))
    )

    assert out["resolved"] is False
    assert "reverse error" not in out.get("hostname", "")


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["", "  ", "not-an-ip", "1.2.3.4 && x"])
async def test_reverse_dns_rejects_a_non_ip(bad):
    def handler(req):
        raise AssertionError(f"must not query for {bad!r}")

    raised = await raised_by(_tools(handler), "arkime_reverse_dns", {"ip": bad})

    assert isinstance(raised, ToolInputError)


@pytest.mark.asyncio
async def test_reverse_dns_accepts_ipv6():
    def handler(req):
        return httpx.Response(200, text="localhost")

    out = tool_text(await _tools(handler).call_tool("arkime_reverse_dns", {"ip": "::1"}))

    assert "localhost" in out


# -- arkime_pcap_files --------------------------------------------------

_FILE = {
    "num": 101,
    "name": "/data/pcap/processed/CAPTURE-001.pcap",
    "node": "capture-4f2a-node",
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

    out = json.loads(tool_text(await _tools(handler).call_tool("arkime_pcap_files", {"limit": 5})))

    assert seen["path"] == "/arkime/api/files"
    assert seen["length"] == "5"
    assert out["total"] == 29
    row = out["files"][0]
    assert row["name"] == "/data/pcap/processed/CAPTURE-001.pcap"
    assert row["bytes"] == 15772997
    assert row["packets"] == 82217
    assert row["sessions"] == 6280
    assert row["node"] == "capture-4f2a-node"
    # Timestamps are epoch MILLISECONDS here, unlike the epoch-seconds every
    # Arkime query parameter takes.
    assert row["first_packet"] == 1714049780727


@pytest.mark.asyncio
async def test_pcap_files_drops_the_internal_bookkeeping_fields():
    def handler(req):
        return httpx.Response(200, json={"data": [_FILE], "recordsTotal": 1})

    out = tool_text(await _tools(handler).call_tool("arkime_pcap_files", {}))

    assert "packetPosEncoding" not in out


# -- arkime_node_stats --------------------------------------------------

_NODE = {
    "nodeName": "capture-4f2a-node",
    "hostname": "arkime",
    "ver": "6.6.0",
    "freeSpaceM": 1646362,
    "freeSpaceP": 40.83,
    "memoryP": 0.59,
    "cpu": 134,
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

    out = json.loads(tool_text(await _tools(handler).call_tool("arkime_node_stats", {})))
    node = out["nodes"][0]

    assert seen["path"] == "/arkime/api/stats"
    assert node["node"] == "capture-4f2a-node"
    assert node["arkime_version"] == "6.6.0"
    assert node["packets_dropped"] == 17
    assert node["disk_free_percent"] == 40.83
    # Arkime stores cpu in hundredths of a percent; raw, 134 reads as 134% busy
    # on a node that is at 1.34%.
    assert node["cpu_percent"] == 1.34


@pytest.mark.asyncio
async def test_node_stats_flags_a_node_that_is_dropping_packets():
    """A silently dropping capture node means the data is incomplete, which is
    the one thing an analyst must not miss."""
    dropping = {**_NODE, "deltaDroppedPerSec": 42}

    def handler(req):
        return httpx.Response(200, json={"data": [dropping], "recordsTotal": 1})

    out = tool_text(await _tools(handler).call_tool("arkime_node_stats", {}))

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


# -- arkime_sessions_csv ------------------------------------------------


@pytest.mark.asyncio
async def test_sessions_csv_hits_the_csv_route_and_bounds_the_rows():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        seen["params"] = dict(req.url.params)
        return httpx.Response(200, text="IP Protocol, Src IP\nudp,192.0.2.7\n")

    out = tool_text(
        await _tools(handler, register_arkime_tools).call_tool(
            "arkime_sessions_csv",
            {
                "expression": "protocols == dns",
                "time_from": "1714003200",
                "time_to": "1714089600",
                "limit": 250,
            },
        )
    )

    assert seen["path"] == "/arkime/api/sessions.csv"
    assert seen["params"]["expression"] == "protocols == dns"
    assert seen["params"]["startTime"] == "1714003200"
    assert seen["params"]["stopTime"] == "1714089600"
    # length is what bounds the export; without it Arkime falls back to its own
    # default and the agent silently gets a different number of rows.
    assert seen["params"]["length"] == "250"
    assert "192.0.2.7" in out


@pytest.mark.asyncio
async def test_sessions_csv_clamps_the_limit_to_the_documented_ceiling():
    seen = {}

    def handler(req):
        seen["length"] = req.url.params.get("length")
        return httpx.Response(200, text="Src IP\n192.0.2.7\n")

    await _tools(handler, register_arkime_tools).call_tool("arkime_sessions_csv", {"limit": 10000})

    assert seen["length"] == "10000"


def test_no_connections_csv_tool_is_exposed():
    """Arkime 6.6.0's connections.csv emits a 9-column header over 7-column
    rows (apiConnections.js writes one header per fieldsMap entry sharing a
    dbField), so every column after "Sessions" is mislabeled. It is not wrapped;
    arkime_connections answers the same question correctly as JSON."""
    names = [t.name for t in asyncio.run(create_server().list_tools())]

    assert "arkime_connections" in names
    assert not [n for n in names if "connections" in n and "csv" in n]


@pytest.mark.asyncio
async def test_sessions_csv_explains_a_timeout_as_a_bad_field_name():
    """Measured live: sessions.csv takes ECS dotted names in fields= and simply
    never answers on a db name like srcIp. A bare timeout tells the agent
    nothing, so name the likely cause."""

    def handler(req):
        raise httpx.ReadTimeout("timed out")

    raised = await raised_by(
        _tools(handler, register_arkime_tools), "arkime_sessions_csv", {"fields": "srcIp,dstIp"}
    )

    assert isinstance(raised, UpstreamError)
    assert "fields" in str(raised).lower()
    assert "source.ip" in str(raised)


@pytest.mark.asyncio
async def test_sessions_csv_passes_the_field_list_through():
    seen = {}

    def handler(req):
        seen["fields"] = req.url.params.get("fields")
        return httpx.Response(200, text="Src IP\n192.0.2.7\n")

    await _tools(handler, register_arkime_tools).call_tool(
        "arkime_sessions_csv", {"fields": "source.ip, destination.ip"}
    )

    assert seen["fields"] == "source.ip,destination.ip"


@pytest.mark.asyncio
async def test_sessions_csv_reports_a_transport_failure():
    def handler(req):
        raise httpx.ConnectError("connection refused")

    raised = await raised_by(_tools(handler, register_arkime_tools), "arkime_sessions_csv", {})

    assert isinstance(raised, UpstreamError)
    assert "connection refused" in str(raised)


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
        ("arkime_crons", {}),
        ("arkime_hunt_status", {}),
    ],
)
async def test_every_inventory_tool_reports_a_transport_failure(tool, args):
    """A tool must RAISE on a transport failure, so the MCP layer reports
    isError: true -- a sentence would arrive as a successful answer."""

    def handler(req):
        raise httpx.ConnectError("connection refused")

    raised = await raised_by(_tools(handler), tool, args)

    assert isinstance(raised, UpstreamError)
    assert raised.status is None
    assert "connection refused" in str(raised)


@pytest.mark.asyncio
async def test_pcap_files_says_so_when_nothing_is_indexed():
    def handler(req):
        return httpx.Response(200, json={"data": [], "recordsTotal": 0})

    out = tool_text(await _tools(handler).call_tool("arkime_pcap_files", {}))

    assert "no indexed pcap" in out.lower()


@pytest.mark.asyncio
async def test_node_stats_says_so_when_no_node_matches():
    def handler(req):
        return httpx.Response(200, json={"data": [], "recordsTotal": 0})

    out = tool_text(await _tools(handler).call_tool("arkime_node_stats", {"node": "ghost"}))

    assert "ghost" in out


@pytest.mark.asyncio
async def test_node_stats_omits_cpu_when_arkime_sends_no_number():
    """A node that has not reported yet sends cpu as null; a bogus percent is
    worse than none at all in a block an analyst reads as health."""
    no_cpu = {**_NODE, "cpu": None}

    def handler(req):
        return httpx.Response(200, json={"data": [no_cpu], "recordsTotal": 1})

    out = tool_text(await _tools(handler).call_tool("arkime_node_stats", {}))

    assert "cpu_percent" not in out


@pytest.mark.asyncio
async def test_node_stats_tolerates_counters_arriving_as_strings():
    """Arkime sends some counters as numbers and some as strings depending on
    the route; the drop check must not blow up on either."""
    stringy = {**_NODE, "deltaDroppedPerSec": "7"}

    def handler(req):
        return httpx.Response(200, json={"data": [stringy], "recordsTotal": 1})

    out = tool_text(await _tools(handler).call_tool("arkime_node_stats", {}))

    assert "dropping" in out.lower()


# -- arkime_crons -------------------------------------------------------

# Field names follow Arkime's cron-query document (queries index). The lab has
# zero crons configured, so the EMPTY path below is the measured one and this
# populated row is not: it is the documented shape, kept deliberately
# defensive (see the tag-list and envelope tests).
_CRON = {
    "key": "cIfXsZ8Bao8axaN3ef1f",
    "name": "ot-write-commands",
    "query": "protocols == modbus",
    "tags": "ot-write,review-me",
    "enabled": True,
    "action": "tag",
    "creator": "operator1",
    "description": "flag OT writes for review",
    "lpValue": 1714089600,
    "count": 42,
}


@pytest.mark.asyncio
async def test_crons_lists_the_schedule_behind_a_tag():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        # Measured live on Arkime 6.6.0: this route answers with a BARE JSON
        # list, not the {"data": [...]} envelope /api/views uses.
        return httpx.Response(200, json=[_CRON])

    out = json.loads(tool_text(await _tools(handler).call_tool("arkime_crons", {})))

    assert seen["path"] == "/arkime/api/crons"
    assert out == {
        "count": 1,
        "crons": [
            {
                "name": "ot-write-commands",
                "expression": "protocols == modbus",
                "tags": ["ot-write", "review-me"],
                "enabled": True,
                "action": "tag",
                "owner": "operator1",
                "description": "flag OT writes for review",
                "last_run": 1714089600,
                "matched_sessions": 42,
                "id": "cIfXsZ8Bao8axaN3ef1f",
            }
        ],
    }


@pytest.mark.asyncio
async def test_crons_keeps_a_query_that_is_switched_off():
    """A disabled query still explains tags already sitting in the data, and
    `enabled` is the only field that tells the two apart — dropping the False
    as "empty" would read as still running."""

    def handler(req):
        return httpx.Response(200, json=[{**_CRON, "enabled": False}])

    out = json.loads(tool_text(await _tools(handler).call_tool("arkime_crons", {})))

    assert out["crons"][0]["enabled"] is False


@pytest.mark.asyncio
async def test_crons_answers_an_empty_deployment_in_prose():
    """Measured against the live lab: 200 with a bare []. "Nothing is tagging on
    a schedule" is an answer, so it must not raise."""

    def handler(req):
        return httpx.Response(200, json=[])

    out = tool_text(await _tools(handler).call_tool("arkime_crons", {}))

    assert "no cron queries" in out.lower()
    assert "arkime_add_tags" in out


@pytest.mark.asyncio
async def test_crons_reads_the_enveloped_shape_as_well():
    """Sibling Arkime routes wrap rows in {"data": [...]}. Reading a populated
    envelope as empty would answer "nothing is tagging" while a cron is
    stamping tags on sessions."""

    def handler(req):
        return httpx.Response(200, json={"data": [_CRON], "recordsTotal": 1})

    out = json.loads(tool_text(await _tools(handler).call_tool("arkime_crons", {})))

    assert out["count"] == 1


@pytest.mark.asyncio
async def test_crons_takes_tags_as_a_list_too():
    """Arkime stores them comma-separated; accepting the list form costs one
    branch, and the populated shape could not be measured here."""

    def handler(req):
        return httpx.Response(200, json=[{**_CRON, "tags": ["ot-write", " review-me "]}])

    out = json.loads(tool_text(await _tools(handler).call_tool("arkime_crons", {})))

    assert out["crons"][0]["tags"] == ["ot-write", "review-me"]


# -- arkime_hunt_status: moved out of the hunt-job write gate -----------


@pytest.mark.asyncio
async def test_hunt_status_lists_hunts_from_the_read_module():
    def handler(req):
        assert req.url.path == "/arkime/api/hunts"
        return httpx.Response(200, json={"data": [{"id": "H1", "status": "running"}]})

    out = tool_text(await _tools(handler).call_tool("arkime_hunt_status", {}))

    assert "running" in out


@pytest.mark.asyncio
async def test_hunt_status_asks_for_the_history_list_when_not_active_only():
    """The two halves are separate lists upstream: history=false hides every
    finished job, so the flag has to reach Arkime."""
    seen = {}

    def handler(req):
        seen.update(dict(req.url.params))
        return httpx.Response(200, json={"data": [], "recordsTotal": 0})

    await _tools(handler).call_tool("arkime_hunt_status", {"active_only": False, "limit": 5})

    assert seen["history"] == "true"
    assert seen["length"] == "5"


_WRITE_FLAGS = ("ALERTING", "ARKIME_TAGS", "HUNT_JOBS", "PCAP_UPLOAD", "ARKIME_VIEWS")


def _server_tool_names(monkeypatch, **flags) -> list[str]:
    for flag in _WRITE_FLAGS:
        monkeypatch.delenv(f"MALCOLM_MCP_ENABLE_{flag}", raising=False)
    for flag, value in flags.items():
        monkeypatch.setenv(f"MALCOLM_MCP_ENABLE_{flag}", value)
    return [t.name for t in asyncio.run(create_server().list_tools())]


def test_hunt_status_and_crons_are_there_with_every_write_class_off(monkeypatch):
    """The whole point of the move: /arkime/api/hunts is a plain GET, so a
    read-only deployment must still see the hunt jobs humans queued."""
    names = _server_tool_names(monkeypatch)

    assert "arkime_hunt_status" in names
    assert "arkime_crons" in names
    assert "arkime_create_hunt" not in names


def test_hunt_status_stays_registered_once_when_the_hunt_class_is_on(monkeypatch):
    """Enabling the write class must neither drop it nor register it twice."""
    names = _server_tool_names(monkeypatch, HUNT_JOBS="true")

    assert names.count("arkime_hunt_status") == 1
    assert "arkime_create_hunt" in names
