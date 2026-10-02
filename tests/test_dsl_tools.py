import asyncio
import json

import httpx
import pytest
from conftest import raised_by
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.errors import ToolInputError
from mcp_server_malcolm.server import create_server
from mcp_server_malcolm.tools import dsl


def _tool_names():
    mcp = create_server()
    return [t.name for t in asyncio.run(mcp.list_tools())]


def test_dsl_core_tools_registered():
    names = _tool_names()
    for expected in ("search_dsl", "count", "list_indices", "index_mapping", "cluster_health"):
        assert expected in names, f"{expected} missing; have {names}"


@pytest.mark.asyncio
async def test_search_dsl_rejects_malformed_json():
    """It raises, so the call comes back with isError true rather than a
    success whose text happens to start with "Error:"."""
    raised = await raised_by(
        create_server(), "search_dsl", {"index": "arkime_sessions3-*", "query_dsl": "{not json"}
    )
    assert isinstance(raised, ToolInputError)
    assert "invalid JSON in query_dsl" in str(raised)


@pytest.mark.asyncio
async def test_search_dsl_rejects_bad_index_pattern():
    """index is LLM-controlled and lands in the URL path — no path metachars."""
    raised = await raised_by(
        create_server(), "search_dsl", {"index": "../_bulk", "query_dsl": "{}"}
    )
    assert isinstance(raised, ToolInputError)
    assert "invalid index pattern" in str(raised)


# -- the tool-layer index guard admits the same comma form the client does --
#
# _INDEX_RE here used to be `[A-Za-z0-9_.*-]+`, no comma. OpenSearch's
# multi-index form ("idx1,idx2") is ordinary, and MalcolmClient's own
# _INDEX_RE (client.py) already accepted it -- the stricter tool-layer copy
# made that form unreachable through these four tools even though the client
# underneath them would have honoured it end to end.


def _dsl_server(handler) -> tuple[MCPServer, list[httpx.Request]]:
    """A server carrying only the DSL tools, transport mocked and recorded."""
    seen: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    mcp = MCPServer("t")
    client = MalcolmClient(base_url="https://malcolm.example")
    client._http = httpx.AsyncClient(
        base_url="https://malcolm.example", transport=httpx.MockTransport(recording)
    )
    dsl.register_dsl_tools(mcp, client)
    return mcp, seen


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "extra_args", "index_arg", "expect_path"),
    [
        (
            "search_dsl",
            {"query_dsl": "{}"},
            "index",
            "/mapi/opensearch/idx1,idx2/_search",
        ),
        ("count", {}, "index", "/mapi/opensearch/idx1,idx2/_count"),
        ("list_indices", {}, "pattern", "/mapi/opensearch/_cat/indices/idx1,idx2"),
        ("index_mapping", {}, "index", "/mapi/opensearch/idx1,idx2/_mapping"),
    ],
)
async def test_comma_joined_index_is_accepted_and_reaches_the_client(
    tool, extra_args, index_arg, expect_path
):
    mcp, seen = _dsl_server(lambda _req: httpx.Response(200, json={}))
    result = await mcp.call_tool(tool, {index_arg: "idx1,idx2", **extra_args})
    assert result.is_error is False, f"{tool} rejected a comma-joined index"
    assert seen[0].url.path == expect_path


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "extra_args", "index_arg"),
    [
        ("search_dsl", {"query_dsl": "{}"}, "index"),
        ("count", {}, "index"),
        ("list_indices", {}, "pattern"),
        ("index_mapping", {}, "index"),
    ],
)
@pytest.mark.parametrize("bad", ["a/b", "a?b", "../x", "a#b"])
async def test_path_metachars_are_still_rejected_on_every_dsl_tool(
    tool, extra_args, index_arg, bad
):
    def _refuse(_req: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("the index guard let a request through")

    mcp, seen = _dsl_server(_refuse)
    raised = await raised_by(mcp, tool, {index_arg: bad, **extra_args})
    assert isinstance(raised, ToolInputError), f"{tool} let {bad!r} through"
    assert seen == []


# -- aggregation bucket sizes are capped like malcolm_aggregate's limit --
#
# The top-level size was always clamped; a size inside aggs went to OpenSearch
# as written, so one terms agg could return tens of thousands of buckets into
# the caller's context. Refused rather than clamped: 500 silently-truncated
# buckets would read as the complete answer.


def _refusing_server():
    def _refuse(_req: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("the bucket-size guard let a request through")

    return _dsl_server(_refuse)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("body", "path"),
    [
        (
            {"aggs": {"by_src": {"terms": {"field": "source.ip", "size": 50000}}}},
            "aggs.by_src.terms.size",
        ),
        (
            {"aggregations": {"x": {"composite": {"size": 501, "sources": []}}}},
            "aggregations.x.composite.size",
        ),
        (
            {
                "aggs": {
                    "outer": {
                        "terms": {"field": "a", "size": 10},
                        "aggs": {"inner": {"multi_terms": {"terms": [], "size": 9999}}},
                    }
                }
            },
            "aggs.outer.aggs.inner.multi_terms.size",
        ),
        (
            {"aggs": {"s": {"significant_terms": {"field": "a", "size": "600"}}}},
            "aggs.s.significant_terms.size",
        ),
    ],
)
async def test_search_dsl_refuses_oversized_bucket_aggregations(body, path):
    mcp, seen = _refusing_server()
    body = {"query": {"match_all": {}}, **body}
    raised = await raised_by(
        mcp, "search_dsl", {"index": "arkime_sessions3-*", "query_dsl": json.dumps(body)}
    )
    assert isinstance(raised, ToolInputError)
    assert path in str(raised)
    assert "500" in str(raised)
    assert seen == []


@pytest.mark.asyncio
async def test_search_dsl_passes_bucket_aggregations_at_the_limit():
    mcp, seen = _dsl_server(lambda _req: httpx.Response(200, json={}))
    body = {
        "query": {"match_all": {}},
        "aggs": {
            "t": {
                "terms": {"field": "a", "size": 500},
                "aggs": {
                    "h": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1m"}},
                    "top": {"top_hits": {"size": 3}},
                },
            }
        },
    }
    result = await mcp.call_tool(
        "search_dsl", {"index": "arkime_sessions3-*", "query_dsl": json.dumps(body), "size": 0}
    )
    assert result.is_error is False
    assert len(seen) == 1


# -- only a bare query clause is wrapped in {"query": ...} --
#
# The wrap used to fire on any body without a "query" key, so an
# aggregation-only body ({"size": 0, "aggs": {...}}) went upstream as
# {"query": {"size": 0, "aggs": {...}}}, which OpenSearch rejects as an
# unknown query -- and its aggs sat where the bucket-size guard never looked.


def _sent_body(seen: list[httpx.Request]) -> dict:
    return json.loads(seen[0].content)


@pytest.mark.asyncio
async def test_search_dsl_wraps_a_bare_query_clause():
    mcp, seen = _dsl_server(lambda _req: httpx.Response(200, json={}))
    clause = {"term": {"event.dataset": "conn"}}
    await mcp.call_tool("search_dsl", {"index": "i", "query_dsl": json.dumps(clause)})
    assert _sent_body(seen)["query"] == clause


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        {"size": 0, "aggs": {"t": {"terms": {"field": "a"}}}},
        {"aggregations": {"t": {"terms": {"field": "a"}}}},
        {"sort": [{"@timestamp": "desc"}]},
    ],
)
async def test_search_dsl_sends_a_query_less_body_as_a_body(body):
    mcp, seen = _dsl_server(lambda _req: httpx.Response(200, json={}))
    await mcp.call_tool("search_dsl", {"index": "i", "query_dsl": json.dumps(body)})
    sent = _sent_body(seen)
    assert "query" not in sent
    assert {k: v for k, v in sent.items() if k != "size"} == {
        k: v for k, v in body.items() if k != "size"
    }


@pytest.mark.asyncio
async def test_search_dsl_bucket_guard_sees_aggs_in_a_query_less_body():
    mcp, seen = _refusing_server()
    body = {"size": 0, "aggs": {"t": {"terms": {"field": "a", "size": 50000}}}}
    raised = await raised_by(mcp, "search_dsl", {"index": "i", "query_dsl": json.dumps(body)})
    assert isinstance(raised, ToolInputError)
    assert "aggs.t.terms.size" in str(raised)
    assert seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize("query_dsl", ["[1, 2]", '"text"', "5"])
async def test_search_dsl_refuses_a_non_object_body(query_dsl):
    mcp, seen = _refusing_server()
    raised = await raised_by(mcp, "search_dsl", {"index": "i", "query_dsl": query_dsl})
    assert isinstance(raised, ToolInputError)
    assert "must be a JSON object" in str(raised)
    assert seen == []
