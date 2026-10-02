"""Value lists built on /mapi/agg must not read as complete when they are not.

The fixtures use the response shape Malcolm actually returns, measured on its
public training instance: the buckets sit under the field name, next to
sum_other_doc_count, and an unknown field comes back as one "-" bucket holding
every document rather than as an empty list.
"""

from __future__ import annotations

import json

import httpx
from mcp.client import Client
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.tools.fields import register_field_tools
from mcp_server_malcolm.tools.health import register_health_tools
from mcp_server_malcolm.tools.query import register_query_tools

_FIELDS = {"destination.ip": "ip", "http.useragent": "string", "rule.name": "string"}


def _agg(field: str, buckets: list[tuple[str, int]], other: int = 0) -> dict:
    return {
        "fields": [field],
        "filter": None,
        field: {
            "buckets": [{"key": k, "doc_count": n} for k, n in buckets],
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": other,
        },
        "range": [1609459200, 1790928527],
        "urls": [],
    }


def _client(agg_reply, seen: list[httpx.Request] | None = None) -> MalcolmClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        if request.url.path == "/mapi/fields":
            return httpx.Response(
                200, json={"fields": {k: {"type": v} for k, v in _FIELDS.items()}}
            )
        if request.url.path.startswith("/mapi/agg/"):
            return httpx.Response(200, json=agg_reply(request))
        if request.url.path == "/mapi/document":
            return httpx.Response(200, json={"results": [{"_id": "1"}]})
        return httpx.Response(200, json={})

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
    return "".join(getattr(c, "text", "") for c in result.content)


# -- malcolm_field_values ------------------------------------------------------


async def test_field_values_says_when_the_list_is_cut():
    # Measured: destination.ip at limit 30 left 813,785 documents in values not listed.
    reply = _agg("destination.ip", [(f"10.0.0.{i}", 100 - i) for i in range(30)], other=813785)
    out = await _call(
        register_field_tools,
        _client(lambda r: reply),
        "malcolm_field_values",
        {"field": "destination.ip", "time_from": "2021-01-01"},
    )
    assert "30 distinct" not in out
    assert "813,785" in out


async def test_field_values_keeps_distinct_wording_when_the_list_is_complete():
    reply = _agg("destination.ip", [("10.0.0.1", 5), ("10.0.0.2", 3)])
    out = await _call(
        register_field_tools,
        _client(lambda r: reply),
        "malcolm_field_values",
        {"field": "destination.ip"},
    )
    assert "(2 distinct)" in out


async def test_field_values_explains_an_unknown_field_behind_the_placeholder_bucket():
    # Measured: http.user_agent answered "(1 distinct): - (7,718,258 docs)" and no hint.
    reply = _agg("http.user_agent", [("-", 7718258)])
    out = await _call(
        register_field_tools,
        _client(lambda r: reply),
        "malcolm_field_values",
        {"field": "http.user_agent", "time_from": "2021-01-01"},
    )
    assert "http.useragent" in out
    assert "distinct" not in out


async def test_field_values_does_not_claim_a_field_exists_it_could_not_check():
    seen: list[httpx.Request] = []

    def reply(request):
        return _agg("destination.ip", [])

    client = _client(reply, seen)
    real_get = client.get

    async def get_without_fields(path, params=None):
        if path == "/mapi/fields":
            raise RuntimeError("field list unreachable")
        return await real_get(path, params)

    client.get = get_without_fields
    out = await _call(
        register_field_tools, client, "malcolm_field_values", {"field": "destination.ip"}
    )
    assert "exists" not in out


# -- malcolm_data_coverage -----------------------------------------------------


async def test_data_coverage_lists_every_dataset_and_counts_the_rest():
    # Measured: 174 datasets; the tool listed 50 and summed only those.
    seen: list[httpx.Request] = []
    reply = _agg("event.dataset", [("conn", 10), ("dns", 5)], other=7)
    out = await _call(
        register_health_tools, _client(lambda r: reply, seen), "malcolm_data_coverage", {}
    )
    data = json.loads(out)
    agg = next(r for r in seen if r.url.path.startswith("/mapi/agg/"))
    assert json.loads(agg.content)["limit"] == 500
    assert data["total_documents"] == 22
    assert data["documents_in_unlisted_datasets"] == 7


# -- malcolm_alerts signature pre-scan ----------------------------------------


async def test_alert_prescan_covers_all_history_when_no_window_is_given():
    # Measured: signature="Modbus" with no time_from answered "No alert signature
    # contains 'Modbus'" while 5,037 Modbus alerts exist in a 2021 capture.
    seen: list[httpx.Request] = []
    reply = _agg("rule.name", [("SURICATA Modbus Data mismatch", 5037)])
    await _call(
        register_query_tools,
        _client(lambda r: reply, seen),
        "malcolm_alerts",
        {"signature": "modbus"},
    )
    agg = next(r for r in seen if r.url.path.startswith("/mapi/agg/"))
    assert json.loads(agg.content)["from"] == "0"


async def test_alert_prescan_does_not_assert_absence_when_the_scan_was_cut():
    reply = _agg("rule.name", [("ET POLICY something", 9)], other=1234)
    out = await _call(
        register_query_tools,
        _client(lambda r: reply),
        "malcolm_alerts",
        {"signature": "log4shell"},
    )
    assert "No alert signature contains" not in out
    assert "1,234" in out


async def test_alert_prescan_still_says_no_when_the_scan_was_complete():
    reply = _agg("rule.name", [("ET POLICY something", 9)])
    out = await _call(
        register_query_tools,
        _client(lambda r: reply),
        "malcolm_alerts",
        {"signature": "log4shell", "time_from": "2021-01-01"},
    )
    assert "No alert signature contains" in out


# -- malcolm_aggregate ---------------------------------------------------------


async def test_aggregate_skips_the_field_lookup_when_buckets_came_back():
    seen: list[httpx.Request] = []
    reply = _agg("destination.ip", [("10.0.0.1", 5)])
    out = await _call(
        register_query_tools,
        _client(lambda r: reply, seen),
        "malcolm_aggregate",
        {"fields": "destination.ip"},
    )
    assert "not indexed" not in out
    assert not any(r.url.path == "/mapi/fields" for r in seen)


async def test_aggregate_explains_an_unknown_field_behind_the_placeholder_bucket():
    reply = _agg("http.user_agent", [("-", 7718258)])
    out = await _call(
        register_query_tools,
        _client(lambda r: reply),
        "malcolm_aggregate",
        {"fields": "http.user_agent"},
    )
    assert "http.useragent" in out


async def test_alert_prescan_flags_a_match_list_that_may_miss_rarer_values():
    # Measured: over all history the top 500 rule.name values left 327 alert
    # documents unscanned, and "Modbus Request flood detected" (1 alert) was one.
    reply = _agg("rule.name", [("SURICATA Modbus Data mismatch", 12479)], other=327)
    out = await _call(
        register_query_tools,
        _client(lambda r: reply),
        "malcolm_alerts",
        {"signature": "modbus"},
    )
    assert out.startswith("Note:")
    assert "327" in out


async def test_alert_prescan_adds_no_note_when_the_scan_was_complete():
    reply = _agg("rule.name", [("SURICATA Modbus Data mismatch", 12479)])
    out = await _call(
        register_query_tools,
        _client(lambda r: reply),
        "malcolm_alerts",
        {"signature": "modbus"},
    )
    assert out.startswith("{")
