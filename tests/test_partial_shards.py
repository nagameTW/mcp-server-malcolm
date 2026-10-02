"""search_dsl and count say up front when OpenSearch answered only in part.

OpenSearch answers HTTP 200 when some shards fail or the search times out; the
shortfall is only in `_shards` and `timed_out`, near the top of a long reply
that a model reads for `hits` and `aggregations`.
"""

from __future__ import annotations

import json

import httpx
from mcp.client import Client
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.tools.dsl import register_dsl_tools

_PARTIAL = {
    "took": 31,
    "timed_out": False,
    "_shards": {"total": 12, "successful": 9, "skipped": 0, "failed": 3},
    "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
}


def _client(body) -> MalcolmClient:
    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example",
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json=body)),
    )
    return c


async def _call(body, tool, args) -> str:
    mcp = MCPServer("t")
    register_dsl_tools(mcp, _client(body))
    async with Client(mcp) as session:
        result = await session.call_tool(tool, args)
    assert not result.is_error
    return "".join(getattr(c, "text", "") for c in result.content)


async def test_search_dsl_flags_failed_shards_above_the_unchanged_json():
    out = await _call(
        _PARTIAL, "search_dsl", {"index": "arkime_sessions3-*", "query_dsl": '{"match_all": {}}'}
    )
    first, rest = out.split("\n", 1)
    assert first.startswith("INCOMPLETE: 3 of 12 shards failed")
    assert json.loads(rest) == _PARTIAL


async def test_count_flags_a_timeout():
    body = {"count": 0, "timed_out": True, "_shards": {"total": 4, "successful": 4, "failed": 0}}
    out = await _call(body, "count", {})
    assert out.startswith("INCOMPLETE: the search timed out")


async def test_a_complete_reply_is_byte_for_byte_unchanged():
    body = {**_PARTIAL, "_shards": {"total": 12, "successful": 12, "skipped": 0, "failed": 0}}
    out = await _call(
        body, "search_dsl", {"index": "arkime_sessions3-*", "query_dsl": '{"match_all": {}}'}
    )
    assert out == json.dumps(body, ensure_ascii=False)
