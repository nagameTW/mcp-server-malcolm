"""Every tool that advertises an outputSchema must satisfy it, through a real client.

Why this file exists at all. The rest of the suite reads a tool's TEXT block --
tool_text() in conftest -- and never looks at structured_content, so 572 green
tests said nothing about the half of the answer a spec-compliant client
actually validates. Two tools shipped returning a bare TypedDict, which the SDK
turns into a schema whose optional keys are typed string/array with
"default": null and then dumps as literal nulls; the official client rejected
the call outright ("None is not of type 'array'") and the caller got no value
back. Both looked perfectly healthy through tool_text().

The 2026-07-28 spec is the standard being held to here: given an outputSchema,
"Servers MUST provide structured results that conform to this schema" and
"Clients SHOULD validate structured results against this schema". So the check
is not "does the tool return something sensible" -- the other modules cover that
-- it is "would a client that does what the spec tells it to do get an answer".

Three layers, deliberately general rather than per-tool, because a per-tool
patch would not have stopped this and will not stop the next one:

1. test_no_output_schema_forces_a_null_default -- static, needs no upstream.
   Catches the exact defect signature in the schema itself: a property whose
   type excludes null carrying "default": null. Any such tool is impossible to
   answer conformantly, so this fails at registration time, for every tool that
   exists now or later.
2. test_every_typed_tool_validates -- drives all of them through the official
   SDK client (mcp.client.Client, which calls validate_tool_result on every
   result) against two mock upstreams: one populated, one degraded. A schema
   violation surfaces as the client's own RuntimeError.
3. The two detail tools, against controlled upstreams the lab cannot produce --
   notably an ENABLED, TRIGGERED monitor, whose `note` key is absent exactly
   where this lab's single disabled monitor populates it, which is what hid the
   defect in malcolm_alerting_monitor_detail.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from mcp.client import Client
from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.tools import register_all_tools

# One body answering every route. Not a semantically coherent Malcolm response
# -- it is the union of every key any client method reaches for, so each tool
# picks out the few it knows and leaves the rest of its row unpopulated. That
# partial fill is the point: a fully-empty upstream makes most tools return
# their "nothing found" sentence and never build a row at all, and a per-tool
# ideal fixture would populate every key and hide precisely the unset-key bug
# this file is about.
_POPULATED: dict[str, Any] = {
    "hits": {
        "total": {"value": 3, "relation": "eq"},
        "hits": [
            {
                "_id": "NYUZsZ8Bao8axaN3ef1f",
                "_index": "arkime_sessions3-260731",
                "_source": {
                    "name": "row",
                    "enabled": True,
                    "indices": ["arkime_sessions3-*"],
                    "detector_type": "SINGLE_ENTITY",
                    "detection_interval": {"period": {"interval": 10, "unit": "MINUTES"}},
                    "feature_attributes": [{"feature_name": "bytes"}],
                    "event": {"dataset": "conn"},
                    "source": {"ip": "192.0.2.10"},
                    "destination": {"ip": "192.0.2.20"},
                },
            }
        ],
    },
    "aggregations": {"field": {"buckets": [{"key": "192.0.2.10", "doc_count": 7}]}},
    "buckets": [{"key": "192.0.2.10", "doc_count": 7, "max_anomaly_grade": 0.8}],
    "total": 1,
    "totalAlerts": 1,
    "alerts": [{"id": "a1", "monitor_name": "m", "state": "ACTIVE", "severity": "1"}],
    "monitor": {
        "name": "row",
        "monitor_type": "query_level_monitor",
        "enabled": True,
        "schedule": {"period": {"interval": 10, "unit": "MINUTES"}},
        "inputs": [{"search": {"indices": ["arkime_sessions3-*"], "query": {"size": 0}}}],
        "triggers": [
            {
                "query_level_trigger": {
                    "name": "t",
                    "severity": "1",
                    "condition": {"script": {"source": "ctx.results[0].hits.total.value > 0"}},
                    "actions": [{"name": "notify"}],
                }
            }
        ],
    },
    "_id": "NYUZsZ8Bao8axaN3ef1f",
    "saved_objects": [
        {
            "type": "search",
            "id": "abd55c60-06a5-11ec-8c6b-353266ade330",
            "updated_at": "2026-07-30T03:34:17.701Z",
            "attributes": {"title": "row", "description": "d"},
        }
    ],
    "type": "search",
    "id": "abd55c60-06a5-11ec-8c6b-353266ade330",
    "updated_at": "2026-07-30T03:34:17.701Z",
    "attributes": {
        "title": "row",
        "description": "d",
        "columns": ["source.ip"],
        "sort": [["firstPacket", "desc"]],
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps(
                {
                    "query": {"query": "event.dataset:conn", "language": "lucene"},
                    "filter": [],
                    "indexRefName": "ref_0",
                }
            )
        },
    },
    "references": [{"name": "ref_0", "id": "arkime_sessions3-*", "type": "index-pattern"}],
    "objects": [{"type": "search", "id": "s1", "attributes": {"title": "row"}}],
    # Arkime list routes.
    "data": [
        {
            "id": "3@260731-abcdef",
            "name": "row",
            "node": "malcolm",
            "num": 1,
            "ip": "192.0.2.10",
            "hosts": ["host-001"],
            "firstPacket": 1714003200000,
            "lastPacket": 1714089600000,
            "totDataBytes": 1234,
            "totBytes": 2345,
            "totPackets": 12,
            "packetsSrc": 6,
            "packetsDst": 6,
            "source": {"ip": "192.0.2.10", "port": 1234, "bytes": 1},
            "destination": {"ip": "192.0.2.20", "port": 53, "bytes": 2},
            "network": {"protocol": ["dns"], "bytes": 3, "packets": 4},
            "expression": "ip == 192.0.2.10",
            "users": ["operator1"],
            "query": "ip == 192.0.2.10",
            "value": "192.0.2.10",
            "type": "string",
            "userId": "operator1",
            "enabled": True,
            "since": 0,
            "cronQueries": True,
            "filesize": 1024,
            "first": 1714003200,
            "locked": 1,
            "packetsWritten": 12,
            "monitoring": 1,
            "freeSpaceM": 100,
            "deltaBytes": 1,
            "deltaPackets": 2,
            "deltaSessions": 3,
            "deltaDropped": 0,
            "deltaMS": 1000,
            "memory": 1,
            "memoryP": 2,
            "cpu": 3,
            "diskQueue": 0,
            "esQueue": 0,
        }
    ],
    "recordsTotal": 1,
    "recordsFiltered": 1,
    "graph": {"xmin": 1714003200000, "xmax": 1714089600000},
    "map": {},
    "items": [{"name": "192.0.2.10", "count": 1}],
    "hierarchicalResults": {"name": "root", "children": []},
    "nodes": [{"id": "192.0.2.10", "cnt": 1}],
    "links": [{"source": 0, "target": 0, "value": 1}],
    "spi": {"source.ip": {"buckets": [{"key": "192.0.2.10", "doc_count": 1}]}},
    "files": [{"name": "f", "node": "malcolm"}],
    "hunts": [{"id": "h1", "name": "hunt", "status": "running", "userId": "operator1"}],
    "shortcuts": [{"id": "s1", "name": "sc", "type": "ip"}],
    "views": [{"name": "v", "expression": "ip == 192.0.2.10"}],
    "success": True,
    "text": "ok",
    # arkime_build_query reads the compiled query out of `esquery`; a 200
    # without it is how Arkime reports a parse error, so the tool raises.
    "esquery": {"query": {"bool": {"filter": [{"term": {"source.ip": "192.0.2.10"}}]}}},
    # Malcolm /mapi shapes.
    "fields": {"source.ip": {"type": "ip", "description": "source address"}},
    "indices": {"arkime_sessions3-260731": {"health": "green", "docs.count": "10"}},
    "version": "26.07.1",
    "sha": "abcdef",
    "mode": "standard",
    "built": "2026-07-01",
    "status": "green",
    "cluster_name": "malcolm",
    "number_of_nodes": 1,
    "active_shards": 10,
    "results": [{"key": "conn", "doc_count": 5}],
    "values": [{"key": "conn", "doc_count": 5}],
    "doc_count": 5,
    "count": 5,
    "ingest": {"pipelines": {}},
    "sites": [{"id": 1, "name": "SITE-A", "slug": "site-a"}],
    "state": "DISABLED",
    "arkime_sessions3-260731": {"mappings": {"properties": {"source": {"type": "object"}}}},
}

# The same routes with nothing in them. Every list is empty and every lookup
# misses, which is the shape a fresh Malcolm and a pruned index both produce.
_DEGRADED: dict[str, Any] = {
    "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
    "aggregations": {},
    "buckets": [],
    "total": 0,
    "totalAlerts": 0,
    "alerts": [],
    "monitor": {},
    "saved_objects": [],
    "attributes": {},
    "references": [],
    "objects": [],
    "data": [],
    "recordsTotal": 0,
    "items": [],
    "nodes": [],
    "links": [],
    "spi": {},
    "files": [],
    "hunts": [],
    "shortcuts": [],
    "views": [],
    "fields": {},
    "indices": {},
    "results": [],
    "values": [],
    "sites": [],
}

# One argument set per tool, keyed by the parameter name rather than the tool,
# because several arguments are shape-checked before any request goes out
# (OpenSearch doc ids, epoch milliseconds, hashes) and a generic filler would
# be rejected by the guard instead of reaching the tool body. A new required
# parameter name fails _args() loudly rather than silently skipping a tool.
_ARG_VALUES: dict[str, Any] = {
    "index": "arkime_sessions3-*",
    "query_dsl": '{"match_all": {}}',
    "fields": "source.ip",
    "field": "source.ip",
    "spi": "source.ip",
    "expression": "ip == 192.0.2.10",
    "session_id": "3@260731-abcdef",
    "file_hash": "d" * 64,
    "object_id": "abd55c60-06a5-11ec-8c6b-353266ade330",
    "monitor_id": "NYUZsZ8Bao8axaN3ef1f",
    "detector_id": "NYUZsZ8Bao8axaN3ef1f",
    "dashboard_id": "abd55c60-06a5-11ec-8c6b-353266ade330",
    "uid": "CabcdefGHIJKLMNop",
    "filename": "extracted.txt",
    "ip": "192.0.2.10",
    "path": "dcim/devices/",
    "start_time_ms": 1714003200000,
    "end_time_ms": 1714089600000,
}

# Tools whose parameters are all optional in the schema but which refuse to run
# without one of them -- an "at least one of" guard the schema cannot express.
_EXTRA_ARGS: dict[str, dict[str, Any]] = {
    "malcolm_netbox_lookup": {"ip": "192.0.2.10"},
}


def _handler(body: dict[str, Any]):
    """Answer every route with the same body, in the content type it expects."""

    def respond(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith(".pcap"):
            # libpcap magic + a truncated header: enough that the reader does
            # not reject it before the tool builds its row.
            return httpx.Response(200, content=b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
        if path.endswith(".csv"):
            return httpx.Response(200, text="id,ip.src\n1,192.0.2.10\n")
        if path == "/arkime/api/fields":
            return httpx.Response(
                200,
                json=[{"exp": "ip.src", "dbField2": "source.ip", "type": "ip"}]
                if body is _POPULATED
                else [],
            )
        return httpx.Response(200, json=body)

    return respond


def _server(body: dict[str, Any]) -> MCPServer:
    client = MalcolmClient(base_url="https://malcolm.example")
    client._http = httpx.AsyncClient(
        base_url="https://malcolm.example",
        transport=httpx.MockTransport(_handler(body)),
    )
    mcp = MCPServer("structured-output")
    register_all_tools(mcp, client)
    return mcp


def _args(schema: dict[str, Any], tool: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name in schema.get("required", []):
        assert name in _ARG_VALUES, (
            f"{tool} requires {name!r}, which _ARG_VALUES does not cover — add a "
            "value shaped the way the tool's own guard expects, or this tool is "
            "silently exempt from the structured-output check."
        )
        value = _ARG_VALUES[name]
        if schema.get("properties", {}).get(name, {}).get("type") == "array":
            value = [value]
        out[name] = value
    return {**out, **_EXTRA_ARGS.get(tool, {})}


# -- 1. static: the schema shape that makes conformance impossible ------


def _null_defaulted(schema: dict[str, Any]) -> list[str]:
    """Properties typed to exclude null that nonetheless default to null.

    The signature of the defect. `"default": null` is not itself validated by a
    client, but the SDK only writes it for a key it will also dump as a literal
    null when unset, and a null is not a string or an array.
    """
    bad = []
    for name, prop in (schema.get("properties") or {}).items():
        if "default" not in prop or prop["default"] is not None:
            continue
        declared = prop.get("type")
        allows_null = declared == "null" or (isinstance(declared, list) and "null" in declared)
        if declared is not None and not allows_null:
            bad.append(name)
    return bad


@pytest.mark.asyncio
async def test_no_output_schema_forces_a_null_default():
    mcp = _server(_POPULATED)
    offenders = {
        tool.name: _null_defaulted(tool.output_schema or {})
        for tool in await mcp.list_tools()
        if tool.output_schema and _null_defaulted(tool.output_schema)
    }
    assert not offenders, (
        f"outputSchema declares a non-nullable property defaulting to null: {offenders}. "
        "A bare TypedDict return does this: the SDK gives every total=False key "
        "default=None without widening its type, then dumps the null. Return "
        "`X | str` so pydantic keeps the key NotRequired instead."
    )


# -- 2. every typed tool, through the official SDK client ---------------


async def _drive(mcp: MCPServer) -> dict[str, str]:
    """Call every outputSchema tool through the SDK client; report what came back.

    Client.call_tool runs validate_tool_result on every non-error result, which
    is the same jsonschema check a spec-following client performs, so a
    violation raises here rather than being asserted for.
    """
    outcome: dict[str, str] = {}
    async with Client(mcp) as client:
        typed = [t for t in (await client.list_tools()).tools if t.output_schema]
        assert len(typed) >= 50, f"only {len(typed)} typed tools found; registration changed"
        for tool in typed:
            result: CallToolResult = await client.call_tool(
                tool.name, _args(tool.input_schema, tool.name)
            )
            if result.is_error:
                outcome[tool.name] = "error"
            elif result.structured_content is None:
                outcome[tool.name] = "unstructured"
            else:
                outcome[tool.name] = "validated"
    return outcome


@pytest.mark.asyncio
async def test_every_typed_tool_validates():
    """The sweep. A schema violation raises out of _drive; nothing to assert for it.

    The second assertion is what keeps the sweep from passing vacuously: a tool
    that errors under both upstreams was never actually checked, so it has to
    reach its structured branch at least once or the fixture is missing a route
    that tool reads.
    """
    populated = await _drive(_server(_POPULATED))
    degraded = await _drive(_server(_DEGRADED))

    never = sorted(
        name
        for name in populated
        if populated[name] != "validated" and degraded.get(name) != "validated"
    )
    assert not never, (
        f"these tools never produced structured content under either upstream, so "
        f"the sweep does not cover them: {never}"
    )


# -- 3. the two detail tools, on upstreams the lab cannot produce -------

_ENABLED_TRIGGERED_MONITOR = {
    "_id": "NYUZsZ8Bao8axaN3ef1f",
    "monitor": {
        "name": "Exfil watch",
        "monitor_type": "query_level_monitor",
        "enabled": True,
        "schedule": {"period": {"interval": 5, "unit": "MINUTES"}},
        "inputs": [
            {
                "search": {
                    "indices": ["arkime_sessions3-*"],
                    "query": {"size": 0, "query": {"range": {"totDataBytes": {"gt": 1000000}}}},
                }
            }
        ],
        "triggers": [
            {
                "query_level_trigger": {
                    "name": "Large transfer",
                    "severity": "1",
                    "condition": {"script": {"source": "ctx.results[0].hits.total.value > 0"}},
                    "actions": [{"name": "page the analyst"}],
                }
            }
        ],
    },
}


@pytest.mark.asyncio
async def test_monitor_detail_validates_for_an_enabled_triggered_monitor():
    """The case this lab cannot produce, and the reason the defect looked absent.

    `note` is populated only when a monitor cannot fire. The lab's one monitor
    is disabled, so it always carried a note and the row happened to fill every
    declared key. An enabled monitor with triggers -- the normal production
    shape -- leaves `note` unset, which is where the bare TypedDict put
    "note": null on the wire and the client raised "None is not of type
    'string'".
    """
    mcp = _server(_ENABLED_TRIGGERED_MONITOR)
    async with Client(mcp) as client:
        result = await client.call_tool(
            "malcolm_alerting_monitor_detail", {"monitor_id": "NYUZsZ8Bao8axaN3ef1f"}
        )
        assert not result.is_error, result.content
        row = (result.structured_content or {})["result"]
        assert row["enabled"] is True
        assert row["triggers"][0]["condition"] == "ctx.results[0].hits.total.value > 0"
        assert "note" not in row, "an enabled, triggered monitor must not claim it cannot fire"
        assert None not in row.values()


@pytest.mark.asyncio
async def test_saved_object_detail_validates_when_most_keys_are_unset():
    """An index pattern populates the fewest keys of any type this tool accepts."""
    mcp = _server(
        {
            "type": "index-pattern",
            "id": "arkime_sessions3-*",
            "updated_at": "2026-07-31T05:35:07.419Z",
            "attributes": {"title": "arkime_sessions3-*"},
            "references": [],
        }
    )
    async with Client(mcp) as client:
        result = await client.call_tool(
            "malcolm_saved_object_detail",
            {"object_id": "arkime_sessions3-*", "object_type": "index-pattern"},
        )
        assert not result.is_error, result.content
        row = (result.structured_content or {})["result"]
        assert row["title"] == "arkime_sessions3-*"
        assert "an index pattern holds no query" in row["note"]
        assert None not in row.values()
        for absent in ("query", "language", "filters", "sort", "columns", "based_on_search"):
            assert absent not in row, f"{absent} should be absent, not null"


@pytest.mark.asyncio
async def test_saved_object_detail_unwraps_a_query_string_object():
    """Some saved searches store the pre-7.x query_string shape, not a string.

    Declared `query: str`, that dict made the tool raise ("Input should be a
    valid string") rather than degrade -- the union does not fall back to the
    str branch for a dict that fails the TypedDict.
    """
    mcp = _server(
        {
            "type": "search",
            "id": "858102a3-eec0-4ab3-82bb-a791e4eb364b",
            "updated_at": "2026-07-30T03:34:17.701Z",
            "attributes": {
                "title": "X.509 - Logs",
                "columns": ["source.ip"],
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps(
                        {
                            "query": {
                                "query": {
                                    "query_string": {
                                        "query": "event.dataset:x509",
                                        "analyze_wildcard": True,
                                    }
                                },
                                "language": "lucene",
                            },
                            "filter": [],
                            "indexRefName": "ref_0",
                        }
                    )
                },
            },
            "references": [{"name": "ref_0", "id": "arkime_sessions3-*", "type": "index-pattern"}],
        }
    )
    async with Client(mcp) as client:
        result = await client.call_tool(
            "malcolm_saved_object_detail",
            {"object_id": "858102a3-eec0-4ab3-82bb-a791e4eb364b", "object_type": "search"},
        )
        assert not result.is_error, result.content
        row = (result.structured_content or {})["result"]
        assert row["query"] == "event.dataset:x509"
        assert row["language"] == "lucene"
        assert "note" not in row, "the query was recovered, so there is nothing to explain"


@pytest.mark.asyncio
async def test_saved_object_detail_keeps_an_unrecognised_query_shape():
    """Degrade to text rather than raise: an unknown dict is still evidence."""
    mcp = _server(
        {
            "type": "search",
            "id": "abd55c60-06a5-11ec-8c6b-353266ade330",
            "attributes": {
                "title": "odd",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps(
                        {"query": {"query": {"bool": {"must": []}}, "language": "kuery"}}
                    )
                },
            },
        }
    )
    async with Client(mcp) as client:
        result = await client.call_tool(
            "malcolm_saved_object_detail",
            {"object_id": "abd55c60-06a5-11ec-8c6b-353266ade330"},
        )
        assert not result.is_error, result.content
        assert (result.structured_content or {})["result"]["query"] == '{"bool": {"must": []}}'
