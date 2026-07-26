"""Unit tests for client.py extraction/resolution helpers and query parsing —
the read-layer logic the review flagged as untested (M5)."""

import httpx
import pytest

from mcp_server_malcolm.client import MalcolmClient, _arkime_query_params, _extract_buckets
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


def test_parse_filters_malformed_json_is_none():
    assert _parse_filters("{not json") is None


def test_parse_filters_non_dict_is_none():
    assert _parse_filters("[1, 2, 3]") is None
    assert _parse_filters('"a string"') is None


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
