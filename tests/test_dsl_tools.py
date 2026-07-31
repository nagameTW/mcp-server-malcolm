import asyncio

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
