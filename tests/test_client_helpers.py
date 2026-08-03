"""Unit tests for client.py extraction/resolution helpers and query parsing —
the read-layer logic the review flagged as untested (M5)."""

from __future__ import annotations

import json
from typing import Any, Callable

import httpx
import pytest

from mcp_server_malcolm import client as client_mod
from mcp_server_malcolm.client import (
    MalcolmClient,
    _arkime_query_params,
    _decode_search_source,
    _extract_buckets,
    _packets_to_text,
)
from mcp_server_malcolm.errors import ToolInputError, UpstreamError
from mcp_server_malcolm.tools.query import _parse_filters

# -- _extract_buckets: all fallback strategies -------------------------------


def test_extract_buckets_results_list():
    data = {"results": [{"key": "conn", "doc_count": 5}]}
    assert _extract_buckets(data, "event.dataset") == [{"key": "conn", "doc_count": 5}]


def test_extract_buckets_results_nested_dict_with_buckets():
    data = {"results": {"agg": {"buckets": [{"key": "dns", "doc_count": 3}]}}}
    assert _extract_buckets(data, "event.dataset") == [{"key": "dns", "doc_count": 3}]


def test_extract_buckets_results_nested_dict_with_list():
    data = {"results": {"agg": [{"key": "ssl", "doc_count": 1}]}}
    assert _extract_buckets(data, "event.dataset") == [{"key": "ssl", "doc_count": 1}]


def test_extract_buckets_top_level_buckets():
    data = {"buckets": [{"key": "http", "doc_count": 9}]}
    assert _extract_buckets(data, "event.dataset") == [{"key": "http", "doc_count": 9}]


def test_extract_buckets_field_keyed_with_dots():
    data = {"event.dataset": {"buckets": [{"key": "alert", "doc_count": 2}]}}
    assert _extract_buckets(data, "event.dataset") == [{"key": "alert", "doc_count": 2}]


def test_extract_buckets_field_keyed_underscore_fallback():
    data = {"event_dataset": {"buckets": [{"key": "conn", "doc_count": 4}]}}
    assert _extract_buckets(data, "event.dataset") == [{"key": "conn", "doc_count": 4}]


def test_extract_buckets_values_last_resort():
    data = {"values": [{"key": "x", "doc_count": 1}]}
    assert _extract_buckets(data, "event.dataset") == [{"key": "x", "doc_count": 1}]


def test_extract_buckets_no_match_returns_empty():
    assert _extract_buckets({"unexpected": 1}, "event.dataset") == []


# -- _arkime_query_params ----------------------------------------------------


def test_arkime_query_params_omits_empty():
    assert _arkime_query_params("", "", "") == {}


def test_arkime_query_params_full():
    assert _arkime_query_params("ip==1.2.3.4", "100", "200") == {
        "expression": "ip==1.2.3.4",
        "startTime": "100",
        "stopTime": "200",
    }


# -- _parse_filters ----------------------------------------------------------


def test_parse_filters_empty_variants_are_none():
    for raw in ("", "  ", "{}", "null", "none", "NULL"):
        assert _parse_filters(raw) is None


def test_parse_filters_valid_dict():
    assert _parse_filters('{"event.dataset": "conn"}') == {"event.dataset": "conn"}


def test_parse_filters_malformed_json_raises():
    """It used to return None, which malcolm_search read as "no filter" and
    answered with the whole index — presented as the answer to a filtered
    question. The single-quoted Python dict is the spelling that hit it."""
    for raw in ("{not json", "{'event.dataset': 'conn'}"):
        with pytest.raises(ToolInputError):
            _parse_filters(raw)


def test_parse_filters_non_dict_raises():
    for raw in ("[1, 2, 3]", '"a string"'):
        with pytest.raises(ToolInputError):
            _parse_filters(raw)


# -- resolve_field: exact / normalized / fuzzy suggestion strategies ---------


def _client_with_fields(fields: dict[str, str]) -> MalcolmClient:
    c = MalcolmClient(base_url="https://malcolm.example")

    def handler(req):
        payload = {"fields": {name: {"type": t} for name, t in fields.items()}}
        return httpx.Response(200, json=payload)

    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example", transport=httpx.MockTransport(handler)
    )
    return c


@pytest.mark.asyncio
async def test_resolve_field_exact_hit():
    c = _client_with_fields({"source.ip": "ip"})
    res = await c.resolve_field("source.ip")
    assert res == {"exists": True, "field": "source.ip", "type": "ip"}


@pytest.mark.asyncio
async def test_resolve_field_normalized_suggestion():
    # "source_ip" normalizes to "sourceip" == "source.ip" normalized.
    c = _client_with_fields({"source.ip": "ip"})
    res = await c.resolve_field("source_ip")
    assert res["exists"] is False
    assert res["suggestion"] == "source.ip"
    assert res["type"] == "ip"


@pytest.mark.asyncio
async def test_resolve_field_fuzzy_substring_suggestions():
    c = _client_with_fields(
        {"http.useragent": "keyword", "http.host": "keyword", "dns.query": "keyword"}
    )
    res = await c.resolve_field("useragent")
    assert res["exists"] is False
    assert "http.useragent" in res["suggestions"]


# ===========================================================================
# Payload, summary and plugin routes (the coverage-gap client methods).
#
# Every fixture below is a body this lab actually returned (Malcolm v26.07.1,
# 2024-04-25 OT capture), copied from the raw HTTP response rather than
# invented: a mock agrees with whatever the method under test believes, so a
# fabricated shape would prove only that the method is self-consistent.
# ===========================================================================


def _recorded(
    responder: Callable[[httpx.Request], httpx.Response] | None = None,
) -> tuple[MalcolmClient, list[httpx.Request]]:
    """A client whose transport records every request instead of sending one."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return responder(request) if responder is not None else httpx.Response(200, json={})

    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example", transport=httpx.MockTransport(handler)
    )
    return c, seen


def _html(body: str) -> Callable[[httpx.Request], httpx.Response]:
    return lambda _req: httpx.Response(200, text=body, headers={"content-type": "text/html"})


_NODE = "capture-4f2a-node"
_SESSION = "240425--QT0FcV5EldCsYVF9qw2nmDb"

# GET /arkime/api/session/capture-4f2a-node/240425--QT0FcV5EldCsYVF9qw2nmDb
#     /packets?base=hex&packets=4 -- LDAP over TCP/389, one src block and one
# dst block, each <pre> trimmed to its first two dump lines.
_PACKETS_FRAGMENT = (
    '<div class="row" id="textpacket"><div class="col-md-6"><h4><span class="srccol">'
    '<span class="str"></span><span class="small">&nbsp;(203.0.113.32:50642)</span>'
    '<span class="src-col-tip"></span></span></h4></div><div class="col-md-6"><h4>'
    '<span class="dstcol"><span class="str"></span><span class="small">'
    '&nbsp;(203.0.113.10:389)</span><span class="dst-col-tip"></span></span></h4></div>'
    '</div><div class="row"><div class="col-md-6 sessionsrc">'
    '<div class="session-detail-ts" value="1714060786953">'
    '<em class="ts-value">1714060786953</em><span class="pull-right">350&nbsp;'
    '<span class="bytes"></span></span></div>'
    "<pre>3084 0000 0158 0201 0163 8400 0001 4f04 0....X...c....O.\n"
    "000a 0100 0a01 0002 0100 0201 7801 0100 ............x...\n"
    '</pre></div><div class="col-md-6"></div></div><div class="row">'
    '<div class="col-md-6 offset-md-6 sessiondst">'
    '<div class="session-detail-ts" value="1714060786953">'
    '<em class="ts-value">1714060786953</em><span class="pull-right">2770&nbsp;'
    '<span class="bytes"></span></span></div>'
    "<pre>3084 0000 0ab6 0201 0164 8400 000a ad04 0........d......\n"
    "0030 8400 000a a530 8400 0000 b204 1573 .0.....0.......s\n"
    "</pre></div></div>"
)

# GET .../packets on a session with no fileId. HTTP 200, 128 bytes.
_NO_PCAP_FRAGMENT = (
    '<div class="alert alert-danger"><span class="fa fa-exclamation-triangle"></span>'
    "<strong>&nbsp; No pcap data found</strong></div>"
)


# -- _packets_to_text --------------------------------------------------------


def test_packets_to_text_keeps_the_direction_the_css_class_carries():
    """The column class is the only record of which way a packet went.

    A plain tag strip renders the two halves of a conversation identically,
    which is how a client-sent payload gets read as a server response.
    """
    text = _packets_to_text(_PACKETS_FRAGMENT)
    assert "[src]" in text and "[dst]" in text
    assert text.index("[src]") < text.index("[dst]")
    # The src block's bytes stay under the src marker, not the dst one.
    assert "0201 0163" in text.split("[dst]")[0]
    assert "0201 0164" in text.split("[dst]")[1]


def test_packets_to_text_keeps_the_hex_gutter_intact():
    text = _packets_to_text(_PACKETS_FRAGMENT)
    assert "3084 0000 0158 0201 0163 8400 0001 4f04 0....X...c....O." in text
    assert "203.0.113.32:50642" in text and "203.0.113.10:389" in text
    assert "<" not in text and ">" not in text


def test_packets_to_text_unescapes_payload_bytes_after_the_tags_are_gone():
    """Payload is entity-escaped by Arkime, so the order of the two passes matters.

    This is a real gutter line from session 240425-yATE05tK50pD37H4n83ww_-M.
    Unescaping before the tag strip turns escaped payload into markup, and the
    strip then deletes the bytes it was asked to show.
    """
    line = "8628 6622 64bc f910 08df 26d9 db1f c480 .(f&quot;d.....&amp;...."
    assert '.(f"d.....&....' in _packets_to_text(f"<pre>{line}\n</pre>")
    # The pathological case: payload that spells out a tag.
    assert "<a>hi</a>" in _packets_to_text("<pre>&lt;a&gt;hi&lt;/a&gt;\n</pre>")


def test_packets_to_text_turns_nbsp_into_a_plain_space():
    assert "\xa0" not in _packets_to_text(_PACKETS_FRAGMENT)


def test_packets_to_text_passes_the_empty_answer_through_as_prose():
    """No payload is an answer, not a failure -- it must survive as readable text."""
    assert _packets_to_text(_NO_PCAP_FRAGMENT) == "No pcap data found"


# -- arkime_session_packets --------------------------------------------------


@pytest.mark.asyncio
async def test_session_packets_builds_the_route_and_decodes_the_fragment():
    c, seen = _recorded(_html(_PACKETS_FRAGMENT))
    text = await c.arkime_session_packets(_NODE, _SESSION, base="hex", packets=4)
    assert seen[0].url.path == f"/arkime/api/session/{_NODE}/{_SESSION}/packets"
    assert dict(seen[0].url.params) == {"base": "hex", "packets": "4"}
    assert "[src]" in text and "0201 0163" in text


@pytest.mark.asyncio
async def test_session_packets_defaults_cap_the_render():
    """No cap upstream renders the whole session -- 1,066,665 bytes, measured."""
    c, seen = _recorded(_html(_PACKETS_FRAGMENT))
    await c.arkime_session_packets(_NODE, _SESSION)
    assert dict(seen[0].url.params) == {"base": "hex", "packets": "10"}


@pytest.mark.asyncio
async def test_session_packets_accepts_the_node_prefixed_id_its_sibling_hands_out():
    c, seen = _recorded(_html(_PACKETS_FRAGMENT))
    await c.arkime_session_packets(_NODE, f"3@240425:{_SESSION}")
    assert seen[0].url.path.endswith(f"3@240425:{_SESSION}/packets")


@pytest.mark.asyncio
async def test_session_packets_returns_no_pcap_data_rather_than_raising():
    c, _ = _recorded(_html(_NO_PCAP_FRAGMENT))
    assert await c.arkime_session_packets(_NODE, _SESSION) == "No pcap data found"


@pytest.mark.asyncio
async def test_session_packets_returns_the_not_found_text_rather_than_raising():
    """Arkime answers a bogus id with HTTP 200 and 79 bytes of plain text."""
    body = "Problem loading packets for 240425-000 Error: Not found"
    c, _ = _recorded(_html(body))
    assert await c.arkime_session_packets(_NODE, _SESSION) == body


# -- arkime_session_bodyhash -------------------------------------------------


@pytest.mark.asyncio
async def test_session_bodyhash_reports_a_400_as_an_empty_answer():
    """Arkime answers a hash it does not hold with 400 "No match" -- the
    session simply carried no such body, which is not a fault."""
    c, seen = _recorded(lambda _r: httpx.Response(400, content=b"No match"))
    digest = "0123456789abcdef0123456789abcdef"
    status, body = await c.arkime_session_bodyhash(_NODE, _SESSION, digest)
    assert seen[0].url.path == f"/arkime/api/session/{_NODE}/{_SESSION}/bodyhash/{digest}"
    assert (status, body) == (400, b"")


# -- arkime_sessions_summary -------------------------------------------------

# POST /arkime/api/sessions/summary with fields="source.ip" over
# protocols == modbus, 1714003200-1714089600. Trailing {} is upstream's own
# sentinel; the totals block is verbatim apart from the trimmed graph.
_SUMMARY_BODY: list[dict[str, Any]] = [
    {
        "firstPacket": 1714049780275,
        "lastPacket": 1714071819668,
        "sessions": 4377209,
        "bytes": 491951510,
        "dataBytes": 79151902,
        "packets": 7938454,
    },
    {
        "field": "source.ip",
        "viewMode": "bar",
        "metricType": "sessions",
        "data": [{"item": "198.51.100.10", "sessions": 2055216}],
    },
    {},
]


@pytest.mark.asyncio
async def test_sessions_summary_posts_the_window_and_reshapes_the_list():
    c, seen = _recorded(lambda _r: httpx.Response(200, json=_SUMMARY_BODY))
    out = await c.arkime_sessions_summary(
        "source.ip", expression="protocols == modbus", time_from="1714003200", time_to="1714089600"
    )
    req = seen[0]
    assert req.method == "POST"
    assert req.url.path == "/arkime/api/sessions/summary"
    assert json.loads(req.content) == {
        "fields": "source.ip",
        "expression": "protocols == modbus",
        "startTime": "1714003200",
        "stopTime": "1714089600",
    }
    assert out["totals"]["sessions"] == 4377209
    # The sentinel is dropped; a real breakdown is not.
    assert [b["field"] for b in out["breakdowns"]] == ["source.ip"]


@pytest.mark.asyncio
async def test_sessions_summary_drops_the_breakdown_arkime_silently_refused():
    """fields="srcIp" (a db name) comes back as totals plus the bare sentinel.

    Keeping the {} would read as "this field had no values"; dropping it lets
    the caller notice that nothing came back for the name it asked about.
    """
    c, _ = _recorded(lambda _r: httpx.Response(200, json=[{"sessions": 4377209}, {}]))
    out = await c.arkime_sessions_summary("srcIp")
    assert out["breakdowns"] == []
    assert out["totals"]["sessions"] == 4377209


@pytest.mark.asyncio
async def test_sessions_summary_keeps_the_empty_breakdown_a_no_match_still_answers():
    """Measured on 26.07.1 with expression "ip == 203.0.113.99" over
    1714003200-1714089600: a window nothing matches still carries one breakdown
    per field, each with an empty `data` list. Only a field Arkime refused
    (a db name) collapses to the bare {} sentinel, which is why the two cases
    have to stay distinguishable here."""
    empty = [
        {"firstPacket": None, "sessions": 0, "bytes": 0},
        {"field": "source.ip", "viewMode": "bar", "metricType": "sessions", "data": []},
        {},
    ]
    c, _ = _recorded(lambda _r: httpx.Response(200, json=empty))
    out = await c.arkime_sessions_summary("source.ip")
    assert out["totals"] == {"firstPacket": None, "sessions": 0, "bytes": 0}
    assert [(b["field"], b["data"]) for b in out["breakdowns"]] == [("source.ip", [])]


# -- arkime_buildquery / arkime_crons ----------------------------------------


@pytest.mark.asyncio
async def test_buildquery_posts_expression_and_window():
    built = {
        "esquery": {"query": {"bool": {"filter": [{"term": {"protocol": "modbus"}}]}}},
        "indices": "arkime_sessions3-240425",
    }
    c, seen = _recorded(lambda _r: httpx.Response(200, json=built))
    out = await c.arkime_buildquery("protocols == modbus", "1714003200", "1714089600")
    assert seen[0].method == "POST"
    assert seen[0].url.path == "/arkime/api/buildquery"
    assert json.loads(seen[0].content) == {
        "expression": "protocols == modbus",
        "startTime": "1714003200",
        "stopTime": "1714089600",
    }
    assert out["indices"] == "arkime_sessions3-240425"


@pytest.mark.asyncio
async def test_crons_returns_the_empty_list_as_an_answer():
    c, seen = _recorded(lambda _r: httpx.Response(200, json=[]))
    assert await c.arkime_crons() == []
    assert seen[0].url.path == "/arkime/api/crons"


# -- _write_arkime_hunt_cancel -----------------------------------------------


def _cancel_transport(status: int, body: dict[str, Any]) -> Callable[..., httpx.Response]:
    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/arkime/api/hunts":
            return httpx.Response(
                200,
                json={"data": []},
                headers={"set-cookie": "ARKIME-COOKIE=tok-123; Path=/"},
            )
        return httpx.Response(status, json=body)

    return responder


@pytest.mark.asyncio
async def test_hunt_cancel_primes_the_cookie_and_replays_it_as_the_header():
    """Without the replay Arkime answers 500 {"text": "Missing token"}."""
    c, seen = _recorded(_cancel_transport(200, {"success": True, "text": "Canceled"}))
    out = await c._write_arkime_hunt_cancel("NYUZsZ8Bao8axaN3ef1f")
    assert [(r.method, r.url.path) for r in seen] == [
        ("GET", "/arkime/api/hunts"),
        ("PUT", "/arkime/api/hunt/NYUZsZ8Bao8axaN3ef1f/cancel"),
    ]
    assert seen[1].headers["x-arkime-cookie"] == "tok-123"
    assert out["success"] is True


@pytest.mark.asyncio
async def test_hunt_cancel_raises_with_arkimes_own_reason_attached():
    """The two 500s mean opposite things: "Missing token" is the plumbing,
    "Error canceling hunt" is the id. httpx's message carries neither."""
    c, _ = _recorded(_cancel_transport(500, {"success": False, "text": "Error canceling hunt"}))
    with pytest.raises(UpstreamError) as err:
        await c._write_arkime_hunt_cancel("doesnotexist123")
    assert err.value.status == 500
    assert "Error canceling hunt" in str(err.value)


# -- Alerting ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_alerting_monitor_fetches_one_monitor_by_id():
    c, seen = _recorded(lambda _r: httpx.Response(200, json={"_id": "x", "monitor": {}}))
    await c.alerting_monitor("NYUZsZ8Bao8axaN3ef1f")
    assert seen[0].url.path == ("/mapi/opensearch/_plugins/_alerting/monitors/NYUZsZ8Bao8axaN3ef1f")


@pytest.mark.asyncio
async def test_alerting_alerts_still_pins_active_by_default():
    """Upstream defaults to ALL, which mixes resolved history into "firing now"."""
    c, seen = _recorded(lambda _r: httpx.Response(200, json={"alerts": [], "totalAlerts": 0}))
    await c.alerting_alerts()
    assert dict(seen[0].url.params) == {"alertState": "ACTIVE"}


@pytest.mark.asyncio
async def test_alerting_alerts_passes_the_filters_through_with_the_singular_name():
    """monitorIds is a 400; OpenSearch itself suggests monitorId."""
    c, seen = _recorded(lambda _r: httpx.Response(200, json={"alerts": []}))
    await c.alerting_alerts(
        alert_state="ALL", monitor_id="NYUZsZ8Bao8axaN3ef1f", severity="1", search="modbus"
    )
    assert dict(seen[0].url.params) == {
        "alertState": "ALL",
        "monitorId": "NYUZsZ8Bao8axaN3ef1f",
        "severityLevel": "1",
        "searchString": "modbus",
    }


# -- Anomaly detection -------------------------------------------------------


@pytest.mark.asyncio
async def test_detector_profile_reports_the_run_state():
    c, seen = _recorded(lambda _r: httpx.Response(200, json={"state": "DISABLED"}))
    out = await c.anomaly_detector_profile("9YUZsZ8Bao8axaN3EPxa")
    assert seen[0].url.path.endswith("/detectors/9YUZsZ8Bao8axaN3EPxa/_profile")
    assert out["state"] == "DISABLED"


@pytest.mark.asyncio
async def test_top_anomalies_sends_milliseconds_and_a_lowercase_order():
    """Seconds land in 1970 and answer empty; "SEVERITY" is a 400."""
    c, seen = _recorded(lambda _r: httpx.Response(200, json={"buckets": []}))
    await c.anomaly_top_results(
        "9YUZsZ8Bao8axaN3EPxa",
        start_time_ms=1714003200000,
        end_time_ms=1714089600000,
        category_fields=["network.protocol"],
    )
    body = json.loads(seen[0].content)
    assert body["start_time_ms"] == 1714003200000
    assert body["end_time_ms"] == 1714089600000
    assert body["order"] == "severity"
    assert body["category_field"] == ["network.protocol"]


@pytest.mark.asyncio
async def test_top_anomalies_puts_historical_in_the_query_string_not_the_body():
    """In the body it is silently ignored: the real-time results come back 200,
    so a caller who asked for history is answered a different question."""
    c, seen = _recorded(lambda _r: httpx.Response(200, json={"buckets": []}))
    await c.anomaly_top_results("9YUZsZ8Bao8axaN3EPxa", 1714003200000, 1714089600000)
    assert dict(seen[0].url.params) == {"historical": "false"}
    assert "historical" not in json.loads(seen[0].content)
    assert "category_field" not in json.loads(seen[0].content)

    await c.anomaly_top_results("9YUZsZ8Bao8axaN3EPxa", 1, 2, historical=True)
    assert dict(seen[1].url.params) == {"historical": "true"}


# -- Saved objects -----------------------------------------------------------

# GET /dashboards/api/saved_objects/search/abd55c60-06a5-11ec-8c6b-353266ade330
_SAVED_SEARCH = {
    "id": "abd55c60-06a5-11ec-8c6b-353266ade330",
    "type": "search",
    "attributes": {
        "title": "Severity-Scored Logs",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": (
                '{"highlightAll":false,"version":true,'
                '"query":{"query":"event.severity:*","language":"kuery"},'
                '"filter":[],"indexRefName":"kibanaSavedObjectMeta.searchSourceJSON.index"}'
            )
        },
    },
    "references": [
        {
            "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
            "type": "index-pattern",
            "id": "arkime_sessions3-*",
        }
    ],
}

# A visualization carries no indexRefName -- its index arrives via the saved
# search it references.
_SAVED_VISUALIZATION = {
    "id": "bcfa8900-06ac-11ec-8c6b-353266ade330",
    "type": "visualization",
    "attributes": {
        "title": "Severity by dataset",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": '{"query":{"query":"","language":"kuery"},"filter":[]}'
        },
    },
    "references": [
        {"name": "search_0", "type": "search", "id": "abd55c60-06a5-11ec-8c6b-353266ade330"}
    ],
}


def test_decode_search_source_resolves_the_index_through_references():
    assert _decode_search_source(_SAVED_SEARCH) == {
        "query": "event.severity:*",
        "language": "kuery",
        "filters": [],
        "index_pattern": "arkime_sessions3-*",
    }


def test_decode_search_source_leaves_the_index_blank_when_there_is_no_ref_name():
    decoded = _decode_search_source(_SAVED_VISUALIZATION)
    assert decoded["index_pattern"] == ""
    assert decoded["language"] == "kuery"


def test_decode_search_source_is_empty_when_the_object_carries_no_query():
    assert _decode_search_source({"id": "x", "attributes": {"title": "t"}}) == {}
    broken = {"id": "x", "attributes": {"kibanaSavedObjectMeta": {"searchSourceJSON": "{not json"}}}
    assert _decode_search_source(broken) == {}


@pytest.mark.asyncio
async def test_saved_object_returns_the_object_plus_the_decoded_query():
    c, seen = _recorded(lambda _r: httpx.Response(200, json=_SAVED_SEARCH))
    out = await c.saved_object("search", "abd55c60-06a5-11ec-8c6b-353266ade330")
    assert seen[0].url.path == (
        "/dashboards/api/saved_objects/search/abd55c60-06a5-11ec-8c6b-353266ade330"
    )
    assert out["attributes"]["title"] == "Severity-Scored Logs"
    assert out["search_source"]["query"] == "event.severity:*"
    # The upstream object is not mutated on the way through.
    assert "search_source" not in _SAVED_SEARCH


@pytest.mark.asyncio
async def test_saved_object_accepts_an_index_pattern_id_that_is_the_pattern():
    """Resolving a saved search's references[] lands on exactly these ids."""
    c, seen = _recorded(lambda _r: httpx.Response(200, json={"id": "arkime_sessions3-*"}))
    await c.saved_object("index-pattern", "arkime_sessions3-*")
    assert seen[0].url.path == "/dashboards/api/saved_objects/index-pattern/arkime_sessions3-*"


# -- Guards: the character class has to be what rejects these ----------------
#
# None of the values below contains a ".." segment, so _DOT_SEGMENT cannot
# answer first and the allow-list is the only thing left that can reject them.
# Each is a working escape once the class stops matching: every one of these
# routes is built by f-string, so "/" adds a segment of somebody else's
# endpoint, "?" starts a query, "#" truncates what httpx sends, "%2f" is a
# separator a server may decode after routing, and a space or backslash lands
# in a path a proxy may normalise differently from Arkime.

_NO_DOT_SEGMENT_ATTACKS = ("a/b", "x?a=b", "x#frag", "..%2f..%2fhunts", "x y", "x\\y")


def _assert_class_is_load_bearing(value: str) -> None:
    assert not client_mod._DOT_SEGMENT.search(value), f"{value!r} is caught by the wrong guard"


@pytest.mark.asyncio
async def test_node_and_session_id_guards_reject_values_with_no_dot_segment():
    c, seen = _recorded()
    for bad in _NO_DOT_SEGMENT_ATTACKS:
        _assert_class_is_load_bearing(bad)
        for call in (
            lambda b=bad: c.arkime_session_packets(b, _SESSION),
            lambda b=bad: c.arkime_session_packets(_NODE, b),
            lambda b=bad: c.arkime_session_bodyhash(b, _SESSION, "a" * 32),
            lambda b=bad: c.arkime_session_bodyhash(_NODE, b, "a" * 32),
        ):
            with pytest.raises(ToolInputError):
                await call()
    assert seen == []


@pytest.mark.asyncio
async def test_node_and_session_id_guards_accept_what_the_lab_hands_out():
    c, seen = _recorded(_html(_PACKETS_FRAGMENT))
    for node in ("arkime", _NODE, "capture_node.example"):
        await c.arkime_session_packets(node, _SESSION)
    for sid in (_SESSION, "240425-yATE05tK50pD37H4n83ww_-M", f"3@240425:{_SESSION}"):
        await c.arkime_session_packets(_NODE, sid)
    assert len(seen) == 6


@pytest.mark.asyncio
async def test_opensearch_id_guard_rejects_values_with_no_dot_segment():
    """ "a.b" is the one only the class can stop: an OpenSearch auto-id is
    base64url, so a dot means the value came from somewhere else."""
    c, seen = _recorded()
    for bad in (*_NO_DOT_SEGMENT_ATTACKS, "a.b"):
        _assert_class_is_load_bearing(bad)
        for call in (
            lambda b=bad: c.alerting_monitor(b),
            lambda b=bad: c.anomaly_detector_profile(b),
            lambda b=bad: c.anomaly_top_results(b, 1, 2),
            lambda b=bad: c._write_arkime_hunt_cancel(b),
        ):
            with pytest.raises(ToolInputError):
                await call()
    assert seen == []


@pytest.mark.asyncio
async def test_saved_object_type_and_id_guards_reject_values_with_no_dot_segment():
    c, seen = _recorded()
    for bad in _NO_DOT_SEGMENT_ATTACKS:
        _assert_class_is_load_bearing(bad)
        with pytest.raises(ToolInputError):
            await c.saved_object(bad, "abd55c60-06a5-11ec-8c6b-353266ade330")
        with pytest.raises(ToolInputError):
            await c.saved_object("search", bad)
    # A type is a lowercase word: anything else came from the caller's guess,
    # not from the saved-objects API.
    for bad_type in ("Search", "search_v2", "search."):
        _assert_class_is_load_bearing(bad_type)
        with pytest.raises(ToolInputError):
            await c.saved_object(bad_type, "abd55c60-06a5-11ec-8c6b-353266ade330")
    assert seen == []


@pytest.mark.asyncio
async def test_saved_object_guards_accept_every_id_shape_the_lab_holds():
    c, seen = _recorded(lambda _r: httpx.Response(200, json={"id": "x"}))
    for obj_type, obj_id in (
        ("search", "abd55c60-06a5-11ec-8c6b-353266ade330"),
        ("visualization", "AWDG9Qx0xQT5EBNmq3_2"),
        ("dashboard", "Metricbeat-system-overview"),
        ("index-pattern", "arkime_sessions3-*"),
    ):
        await c.saved_object(obj_type, obj_id)
    assert len(seen) == 4


# -- Arkime's cookie-dependent CSRF gate -------------------------------------


def _cookie_aware_client() -> tuple[MalcolmClient, list[httpx.Request]]:
    """A client whose transport sets ARKIME-COOKIE the way a session GET does.

    An ordinary MockTransport never sets a cookie, so the jar stays empty and
    every Arkime POST looks fine -- which is exactly why this defect shipped.
    The state that breaks it lives ACROSS calls, so the fixture has to hold it.
    """
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/arkime/api/sessions":
            # What Arkime really answers: Set-Cookie ARKIME-COOKIE; Path=/arkime/
            return httpx.Response(
                200,
                json={"data": []},
                headers={"set-cookie": "ARKIME-COOKIE=t0ken; Path=/arkime/"},
            )
        if "x-arkime-cookie" not in request.headers and "cookie" in request.headers:
            # Arkime switches to checkCookieToken once a cookie rides along.
            return httpx.Response(500, json={"success": False, "text": "Missing token"})
        return httpx.Response(200, json=[{"sessions": 1}])

    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example", transport=httpx.MockTransport(handler)
    )
    return c, seen


async def test_summary_still_answers_after_a_session_search_set_the_cookie():
    """arkime_sessions is the centre of the documented hunt flow.

    Before the fix, the first search poisoned the shared jar and every later
    arkime_sessions_summary answered 500 for the life of the process.
    """
    c, seen = _cookie_aware_client()
    await c.arkime_sessions(expression="protocols == modbus")
    assert c._http is not None and c._http.cookies.get("ARKIME-COOKIE") == "t0ken"

    out = await c.arkime_sessions_summary(fields="source.ip")

    assert out["totals"] == {"sessions": 1}
    assert seen[-1].headers["x-arkime-cookie"] == "t0ken"


async def test_summary_sends_no_token_when_no_cookie_was_ever_issued():
    """Arkime accepts an untokened POST only while the request carries none."""
    c, seen = _cookie_aware_client()
    await c.arkime_sessions_summary(fields="source.ip")
    assert "x-arkime-cookie" not in seen[-1].headers


async def test_tagging_shares_the_one_cookie_replay_path():
    """The idiom lived in three places; a fourth Arkime POST must not re-add it."""
    c, seen = _cookie_aware_client()
    await c.arkime_sessions(expression="protocols == modbus")
    await c._write_arkime_tags(ids="a", tags="b")
    assert seen[-1].headers["x-arkime-cookie"] == "t0ken"


# -- the arkimeAdmin `all` gate on the three inventory listings ---------------


def _param_capturing_client() -> tuple[MalcolmClient, dict[str, dict[str, str]]]:
    seen: dict[str, dict[str, str]] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen[req.url.path] = dict(req.url.params)
        return httpx.Response(200, json={"data": [], "recordsTotal": 0})

    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example",
        transport=httpx.MockTransport(handler),
    )
    return c, seen


@pytest.mark.parametrize(
    "call,path",
    [
        ("arkime_views", "/arkime/api/views"),
        ("arkime_shortcuts", "/arkime/api/shortcuts"),
        ("arkime_crons", "/arkime/api/crons"),
    ],
)
async def test_inventory_listings_ask_for_every_owner_not_just_this_account(call, path):
    """Arkime filters these three to owner+roles unless the request says all=true.

    Measured in the shipped viewer at Arkime 6.6.0: apiViews.js:31 and
    apiShortcuts.js:137 both read `all: req.query.all && roles.includes(
    'arkimeAdmin')`, and apiCrons.js:150 gates on the same pair. Without the
    parameter an arkimeAdmin account still sees only its own, so an empty list
    could never be trusted to mean the deployment has none.
    """
    c, seen = _param_capturing_client()

    await getattr(c, call)()

    assert seen[path].get("all") == "true"
