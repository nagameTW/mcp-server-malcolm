"""Results cut at a fixed cap must say so.

Measured on Malcolm's public training instance (2021 capture):
- /arkime/api/connections builds its graph from `length` sessions, default 100.
  "protocols == modbus" matched 41,768 sessions; length 100 gave 8 nodes and
  5 links, length 50,000 gave 39 nodes and 34 links. The tool never sent length.
- /arkime/api/spigraphhierarchy kept exactly 20 first-level values, and several
  branches exactly 20 children.
- /arkime/api/multiunique on ip.src,ip.dst returned 6,378 lines, 183,248 chars.
"""

from __future__ import annotations

import json

import httpx
from mcp.client import Client
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.tools.arkime import register_arkime_tools
from mcp_server_malcolm.tools.netbox import register_netbox_tools

_FIELDS = [
    {"exp": "ip.src", "dbField2": "source.ip", "type": "ip"},
    {"exp": "ip.dst", "dbField2": "destination.ip", "type": "ip"},
    {"exp": "port.dst", "dbField2": "destination.port", "type": "integer"},
]


def _client(responder, seen: list[httpx.Request] | None = None) -> MalcolmClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        if request.url.path == "/arkime/api/fields":
            return httpx.Response(200, json=_FIELDS)
        return responder(request)

    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example", transport=httpx.MockTransport(handler)
    )
    return c


async def _call(register, client, tool, args) -> str:
    mcp = MCPServer("t")
    register(mcp, client)
    async with Client(mcp) as session:
        result = await session.call_tool(tool, args)
    assert not result.is_error, result.content
    return "".join(getattr(c, "text", "") for c in result.content)


# -- arkime_connections --------------------------------------------------------

_GRAPH = {
    "nodes": [{"id": "10.0.0.1"}, {"id": "10.0.0.2"}],
    "links": [{}],
    "recordsFiltered": 41768,
}


async def test_connections_sends_a_session_count_and_says_when_it_used_fewer():
    seen: list[httpx.Request] = []
    out = await _call(
        register_arkime_tools,
        _client(lambda r: httpx.Response(200, json=_GRAPH), seen),
        "arkime_connections",
        {"expression": "protocols == modbus", "sessions": 5000},
    )
    request = next(r for r in seen if r.url.path == "/arkime/api/connections")
    assert request.url.params["length"] == "5000"
    assert out.startswith("Note:")
    assert "5,000" in out and "41,768" in out


async def test_connections_adds_no_note_when_every_session_was_used():
    graph = {**_GRAPH, "recordsFiltered": 300}
    out = await _call(
        register_arkime_tools,
        _client(lambda r: httpx.Response(200, json=graph)),
        "arkime_connections",
        {"expression": "protocols == modbus"},
    )
    assert json.loads(out)["recordsFiltered"] == 300


# -- arkime_spigraphhierarchy --------------------------------------------------


def _node(name, children=0):
    return {"name": name, "size": 1, "children": [_node(f"{name}.{i}") for i in range(children)]}


async def test_hierarchy_flags_branches_cut_at_twenty():
    tree = {
        "name": "root",
        "children": [_node(f"10.0.0.{i}", 20 if i < 3 else 2) for i in range(20)],
    }
    body = {"success": True, "tableResults": [], "hierarchicalResults": tree}
    out = await _call(
        register_arkime_tools,
        _client(lambda r: httpx.Response(200, json=body)),
        "arkime_spigraphhierarchy",
        {"fields": "ip.src,ip.dst"},
    )
    first = out.splitlines()[0]
    assert first.startswith("Note:")
    assert "4 nodes" in first


async def test_hierarchy_below_the_cap_has_no_note():
    tree = {"name": "root", "children": [_node("10.0.0.1", 3)]}
    body = {"success": True, "tableResults": [], "hierarchicalResults": tree}
    out = await _call(
        register_arkime_tools,
        _client(lambda r: httpx.Response(200, json=body)),
        "arkime_spigraphhierarchy",
        {"fields": "ip.src,ip.dst"},
    )
    assert json.loads(out)["success"] is True


# -- arkime_unique -------------------------------------------------------------


async def test_unique_flags_a_list_that_reached_arkimes_ceiling():
    text = "\n".join(str(p) for p in range(10000)) + "\n"
    out = await _call(
        register_arkime_tools,
        _client(lambda r: httpx.Response(200, text=text)),
        "arkime_unique",
        {"field": "port.dst"},
    )
    assert out.startswith("Note:")
    assert out.count("\n") >= 10000


async def test_unique_below_the_ceiling_is_unchanged():
    out = await _call(
        register_arkime_tools,
        _client(lambda r: httpx.Response(200, text="80\n443\n")),
        "arkime_unique",
        {"field": "port.dst"},
    )
    assert out == "80\n443\n"


# -- arkime_multiunique --------------------------------------------------------


async def test_multiunique_stops_at_limit_and_counts_the_rest():
    text = "".join(f"10.0.0.{i}, 10.0.1.{i}\n" for i in range(250))
    out = await _call(
        register_arkime_tools,
        _client(lambda r: httpx.Response(200, text=text)),
        "arkime_multiunique",
        {"fields": "ip.src,ip.dst", "limit": 100},
    )
    lines = out.splitlines()
    assert len(lines) == 101
    assert "150 more" in lines[-1]


async def test_multiunique_under_limit_is_unchanged():
    text = "10.0.0.1, 10.0.1.1\n"
    out = await _call(
        register_arkime_tools,
        _client(lambda r: httpx.Response(200, text=text)),
        "arkime_multiunique",
        {"fields": "ip.src,ip.dst"},
    )
    assert out == text


# -- malcolm_netbox_lookup -----------------------------------------------------


async def test_netbox_lookup_reports_netboxs_count_when_it_shows_fewer():
    entries = [{"address": f"192.0.2.{i}/24"} for i in range(12)]
    out = await _call(
        register_netbox_tools,
        _client(lambda r: httpx.Response(200, json={"count": 12, "results": entries})),
        "malcolm_netbox_lookup",
        {"ip": "192.0.2.1"},
    )
    lookup = json.loads(out)["ip_lookup"]
    assert len(lookup["results"]) == 5
    assert lookup["matched"] == 12


async def test_netbox_lookup_omits_matched_when_everything_is_shown():
    out = await _call(
        register_netbox_tools,
        _client(lambda r: httpx.Response(200, json={"count": 1, "results": [{"address": "x"}]})),
        "malcolm_netbox_lookup",
        {"ip": "192.0.2.1"},
    )
    assert "matched" not in json.loads(out)["ip_lookup"]
