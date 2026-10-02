"""malcolm_related_sessions: what the "related" side adds, and failed sides.

Malcolm copies every Zeek record's zeek.uid into rootId (1200_zeek_mutate.conf),
so {"rootId": uid} alone returns the direct hits again. The records it adds
carry a different zeek.uid: a conn record inside a tunnel gets the tunnel's uid
as rootId (1015_zeek_conn.conf). Measured on Malcolm's training instance:
tunnel uid CaUqUb4EBFHPWSsOVi had 2 direct records and 46 rootId records, 44
of them the connections inside the tunnel; {"rootId": uid, "!zeek.uid": uid}
returned exactly those 44.
"""

from __future__ import annotations

import json

import httpx
import pytest
from conftest import tool_text
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.tools.correlation import register_correlation_tools

_UID = "CaUqUb4EBFHPWSsOVi"


def _tools(handler):
    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example", transport=httpx.MockTransport(handler)
    )
    mcp = MCPServer("t")
    register_correlation_tools(mcp, c)
    return mcp


async def test_related_side_excludes_records_that_carry_the_uid_themselves():
    filters = []

    def handler(req):
        filters.append(json.loads(req.content)["filter"])
        return httpx.Response(200, json={"results": []})

    await _tools(handler).call_tool("malcolm_related_sessions", {"uid": _UID})

    assert {"zeek.uid": _UID} in filters
    assert {"rootId": _UID, "!zeek.uid": _UID} in filters


async def test_a_failed_side_is_not_counted_as_zero():
    def handler(req):
        if "rootId" in json.loads(req.content)["filter"]:
            return httpx.Response(504, text="gateway timeout")
        return httpx.Response(200, json={"results": [{"_id": "a"}, {"_id": "b"}]})

    out = json.loads(
        tool_text(await _tools(handler).call_tool("malcolm_related_sessions", {"uid": _UID}))
    )

    assert "related_error" in out
    assert "related" not in out
    assert "0 related" not in out["summary"]
    assert out["summary"].startswith("2 direct")


async def test_limit_is_capped_like_the_other_search_tools():
    mcp = _tools(lambda req: httpx.Response(200, json={"results": []}))
    with pytest.raises(Exception):
        await mcp.call_tool("malcolm_related_sessions", {"uid": _UID, "limit": 501})


async def test_a_side_that_filled_limit_says_more_may_exist():
    def handler(req):
        if "rootId" in json.loads(req.content)["filter"]:
            return httpx.Response(200, json={"results": [{"_id": "r"}]})
        return httpx.Response(200, json={"results": [{"_id": "a"}, {"_id": "b"}]})

    text = tool_text(
        await _tools(handler).call_tool("malcolm_related_sessions", {"uid": _UID, "limit": 2})
    )
    summary = json.loads(text)["summary"]

    assert summary.startswith("2 direct (the limit; more may exist)")
    assert "1 related sessions" in summary


async def test_output_is_not_indented():
    mcp = _tools(lambda req: httpx.Response(200, json={"results": [{"_id": "a"}]}))
    text = tool_text(await mcp.call_tool("malcolm_related_sessions", {"uid": _UID}))
    assert "\n" not in text
