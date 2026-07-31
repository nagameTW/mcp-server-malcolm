"""Tests for the two content tools: session payload and session-scoped file fetch.

These are the tools that reach past metadata to the bytes, so what they must
get right is what a mock cannot teach: which HTML survives the strip, which
non-200-looking answer is really an empty result, and that raw bytes never
reach the caller. The fixtures below are trimmed copies of what Malcolm
v26.07.1 actually served -- the HTML fragment shape, the "No pcap data found"
alert, Arkime's 400 "No match" -- so a change in this repo's reading of those
answers fails here rather than in production.

The last section tests a promise of the same kind: arkime_build_query tells the
caller how to hand its output to search_dsl, and an instruction that does not
survive being followed literally is a defect in the tool, not in the caller.
"""

import hashlib
import json

import httpx
import pytest
from conftest import raised_by, tool_text
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.errors import ToolInputError
from mcp_server_malcolm.tools.arkime import register_arkime_tools as _register_arkime_search
from mcp_server_malcolm.tools.arkime_content import register_arkime_content_tools
from mcp_server_malcolm.tools.dsl import register_dsl_tools


def register_arkime_tools(mcp, client) -> None:  # noqa: F811
    """Both halves of the Arkime read surface, so these tests keep asking the
    same questions after the module split: search/aggregation stayed in
    arkime.py, per-session content moved to arkime_content.py. The split is a
    module boundary, not a behaviour one."""
    _register_arkime_search(mcp, client)
    register_arkime_content_tools(mcp, client)


_NODE = "capture-node-a"
_SID = "240425-yATE05tK50pD37H4n83ww_-M"
_MD5 = "a" * 32

# What /api/session/<node>/<id>/packets serves: an HTML fragment, two columns,
# direction recorded only in the sessionsrc/sessiondst class. The payload here
# spells out "<a>hi</a>" as entities, which is the case that decides the order
# of the strip and the unescape.
_PACKETS_HTML = (
    '<div class="row" id="textpacket">'
    '<div class="col-md-6"><h4><span class="srccol">&nbsp;(192.0.2.1:1234)</span></h4></div>'
    '<div class="col-md-6"><h4><span class="dstcol">&nbsp;(192.0.2.2:80)</span></h4></div></div>'
    '<div class="row"><div class="col-md-6 sessionsrc">'
    '<div class="session-detail-ts" value="1714060940561"></div>'
    "<pre>GET &#47;a HTTP&#47;1.1\nX-Note: &lt;a&gt;hi&lt;/a&gt;</pre></div></div>"
    '<div class="row"><div class="col-md-6 sessiondst">'
    "<pre>HTTP&#47;1.1 200 OK</pre></div></div>"
)
_NO_PCAP = (
    '<div class="alert alert-danger"><span class="fa fa-exclamation-triangle"></span>'
    "<strong>&nbsp; No pcap data found</strong></div>"
)


def _mock(handler):
    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example", transport=httpx.MockTransport(handler)
    )
    return c


def _session_lookup(req, node=_NODE):
    """Answer the node-resolution lookup arkime_session_detail makes."""
    return httpx.Response(200, json={"data": [{"id": _SID, "node": node}]})


def _server(handler):
    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock(handler))
    return mcp


# -- arkime_session_payload -------------------------------------------------


@pytest.mark.asyncio
async def test_payload_returns_decoded_bytes_with_direction_markers():
    seen = {}

    def handler(req):
        if req.url.path == "/arkime/api/sessions":
            return _session_lookup(req)
        seen["path"] = req.url.path
        seen["base"] = req.url.params.get("base")
        seen["packets"] = req.url.params.get("packets")
        return httpx.Response(200, text=_PACKETS_HTML)

    out = tool_text(
        await _server(handler).call_tool(
            "arkime_session_payload", {"session_id": _SID, "base": "ascii", "packets": 6}
        )
    )
    assert seen["path"] == f"/arkime/api/session/{_NODE}/{_SID}/packets"
    assert seen["base"] == "ascii" and seen["packets"] == "6"
    # the payload itself, not a description of it
    assert "GET /a HTTP/1.1" in out and "HTTP/1.1 200 OK" in out
    # direction survives even though it lived only in the CSS class
    assert "[src]" in out and "[dst]" in out
    assert "<div" not in out and "sessionsrc" not in out


@pytest.mark.asyncio
async def test_payload_unescapes_entities_without_manufacturing_markup():
    """Payload bytes that spell out a tag must arrive as text, not be eaten.

    Unescaping before the tag strip would turn &lt;a&gt; into <a> and the strip
    would then remove it, silently rewriting the evidence.
    """

    def handler(req):
        if req.url.path == "/arkime/api/sessions":
            return _session_lookup(req)
        return httpx.Response(200, text=_PACKETS_HTML)

    out = tool_text(
        await _server(handler).call_tool("arkime_session_payload", {"session_id": _SID})
    )
    assert "X-Note: <a>hi</a>" in out


@pytest.mark.asyncio
async def test_payload_resolves_the_node_and_an_explicit_one_skips_the_lookup():
    calls = []

    def handler(req):
        calls.append(req.url.path)
        if req.url.path == "/arkime/api/sessions":
            return _session_lookup(req)
        return httpx.Response(200, text=_PACKETS_HTML)

    mcp = _server(handler)
    await mcp.call_tool("arkime_session_payload", {"session_id": _SID})
    assert calls == ["/arkime/api/sessions", f"/arkime/api/session/{_NODE}/{_SID}/packets"]

    calls.clear()
    await mcp.call_tool("arkime_session_payload", {"session_id": _SID, "node": "other-node"})
    assert calls == [f"/arkime/api/session/other-node/{_SID}/packets"]


@pytest.mark.asyncio
async def test_payload_session_without_stored_packets_is_an_answer_not_a_failure():
    def handler(req):
        if req.url.path == "/arkime/api/sessions":
            return _session_lookup(req)
        return httpx.Response(200, text=_NO_PCAP)

    out = tool_text(
        await _server(handler).call_tool("arkime_session_payload", {"session_id": _SID})
    )
    assert "no stored packets" in out
    assert "arkime_session_detail" in out  # points somewhere useful


@pytest.mark.asyncio
async def test_payload_unknown_session_is_an_answer_not_a_failure():
    def handler(req):
        assert req.url.path == "/arkime/api/sessions", "must not fetch packets for a missing id"
        return httpx.Response(200, json={"data": []})

    out = tool_text(
        await _server(handler).call_tool("arkime_session_payload", {"session_id": _SID})
    )
    assert "No Arkime session found" in out


@pytest.mark.asyncio
async def test_payload_arkime_not_found_text_is_an_answer_not_a_failure():
    """Arkime answers an unknown id on the packets route with 200 and prose."""

    def handler(req):
        if req.url.path == "/arkime/api/sessions":
            return _session_lookup(req)
        return httpx.Response(200, text=f"Problem loading packets for {_SID} Error: Not found")

    out = tool_text(
        await _server(handler).call_tool(
            "arkime_session_payload", {"session_id": _SID, "node": _NODE}
        )
    )
    assert "No session with id" in out


@pytest.mark.asyncio
async def test_payload_refuses_an_oversized_render():
    def handler(req):
        if req.url.path == "/arkime/api/sessions":
            return _session_lookup(req)
        return httpx.Response(200, text="<pre>" + ("A" * 250_000) + "</pre>")

    raised = await raised_by(
        _server(handler), "arkime_session_payload", {"session_id": _SID, "packets": 100}
    )
    assert isinstance(raised, ToolInputError)
    assert "fewer packets" in str(raised)


@pytest.mark.asyncio
async def test_payload_rejects_a_base_arkime_would_silently_replace():
    def handler(req):
        raise AssertionError("must not reach Arkime with an unknown base")

    raised = await raised_by(
        _server(handler), "arkime_session_payload", {"session_id": _SID, "base": "utf-16"}
    )
    assert isinstance(raised, ToolInputError)
    assert "invalid base" in str(raised)


@pytest.mark.asyncio
async def test_payload_base_advertises_its_closed_set_without_delegating_the_check():
    """`base` carries its enum in the schema (a client can offer the three, and
    Glama's scorer counts it) while validation stays in the handler above --
    declaring it as a Literal would move rejection into Pydantic and replace
    this repo's message, which names the silent-ASCII trap, with a generic one."""
    tools = {t.name: t for t in await _server(lambda req: None).list_tools()}
    base = tools["arkime_session_payload"].input_schema["properties"]["base"]
    assert sorted(base["enum"]) == ["ascii", "hex", "utf8"]


@pytest.mark.asyncio
async def test_payload_rejects_a_traversing_session_id():
    def handler(req):
        raise AssertionError("must not reach Arkime")

    raised = await raised_by(
        _server(handler), "arkime_session_payload", {"session_id": "../../etc/passwd"}
    )
    assert isinstance(raised, ToolInputError)
    assert "invalid session_id" in str(raised)


@pytest.mark.asyncio
async def test_payload_rejects_a_node_that_is_not_a_capture_node():
    """Arkime answers 200 with a viewer-lookup message, which reads like payload."""

    def handler(req):
        return httpx.Response(200, text="Can't find view url for 'nope' check viewer logs")

    raised = await raised_by(
        _server(handler), "arkime_session_payload", {"session_id": _SID, "node": "nope"}
    )
    assert isinstance(raised, ToolInputError)
    assert "capture node" in str(raised)


# -- arkime_session_file_by_hash -------------------------------------------


@pytest.mark.asyncio
async def test_session_file_returns_metadata_and_hashes_of_the_served_bytes():
    body = b"MZ\x90\x00this-is-the-file"

    def handler(req):
        if req.url.path == "/arkime/api/sessions":
            return _session_lookup(req)
        assert req.url.path == f"/arkime/api/session/{_NODE}/{_SID}/bodyhash/{_MD5}"
        return httpx.Response(200, content=body)

    out = json.loads(
        tool_text(
            await _server(handler).call_tool(
                "arkime_session_file_by_hash", {"session_id": _SID, "file_hash": _MD5}
            )
        )
    )
    assert out["found"] is True
    assert out["size_bytes"] == len(body)
    assert out["magic"] == body[:4].hex()
    # the digests are over what was served, so they can be compared with the ask
    assert out["md5"] == hashlib.md5(body).hexdigest()
    assert out["sha256"] == hashlib.sha256(body).hexdigest()
    assert "this-is-the-file" not in json.dumps(out)  # bytes never leave


@pytest.mark.asyncio
async def test_session_file_no_match_in_this_session_is_an_answer_not_a_failure():
    """Arkime's 400 "No match" means this session carried no such body."""

    def handler(req):
        if req.url.path == "/arkime/api/sessions":
            return _session_lookup(req)
        return httpx.Response(400, content=b"No match")

    out = json.loads(
        tool_text(
            await _server(handler).call_tool(
                "arkime_session_file_by_hash", {"session_id": _SID, "file_hash": _MD5}
            )
        )
    )
    assert out["found"] is False
    assert "arkime_file_by_hash" in out["note"]  # names the tool that searches them all


@pytest.mark.asyncio
async def test_session_file_unknown_session_is_an_answer_not_a_failure():
    def handler(req):
        assert req.url.path == "/arkime/api/sessions"
        return httpx.Response(200, json={"data": []})

    out = tool_text(
        await _server(handler).call_tool(
            "arkime_session_file_by_hash", {"session_id": _SID, "file_hash": _MD5}
        )
    )
    assert "No Arkime session found" in out


@pytest.mark.asyncio
async def test_session_file_url_only_skips_the_download_but_still_names_the_session():
    def handler(req):
        if req.url.path == "/arkime/api/sessions":
            return _session_lookup(req)
        raise AssertionError("no download expected")

    out = json.loads(
        tool_text(
            await _server(handler).call_tool(
                "arkime_session_file_by_hash",
                {"session_id": _SID, "file_hash": _MD5, "url_only": True},
            )
        )
    )
    assert out["download_url"].endswith(f"/session/{_NODE}/{_SID}/bodyhash/{_MD5}")


@pytest.mark.asyncio
async def test_session_file_refuses_an_oversized_body():
    def handler(req):
        if req.url.path == "/arkime/api/sessions":
            return _session_lookup(req)
        return httpx.Response(200, content=b"x", headers={"content-length": str(200 * 1024 * 1024)})

    raised = await raised_by(
        _server(handler),
        "arkime_session_file_by_hash",
        {"session_id": _SID, "file_hash": _MD5},
    )
    assert isinstance(raised, ToolInputError)
    assert "url_only" in str(raised)


@pytest.mark.asyncio
async def test_session_file_rejects_a_non_hex_hash():
    def handler(req):
        raise AssertionError("must not reach Arkime")

    raised = await raised_by(
        _server(handler),
        "arkime_session_file_by_hash",
        {"session_id": _SID, "file_hash": "../../etc/passwd"},
    )
    assert isinstance(raised, ToolInputError)
    assert "invalid file_hash" in str(raised)


# -- arkime_build_query -> search_dsl handoff --------------------------------

_ESQUERY = {
    "size": 100,
    "query": {"bool": {"filter": [{"term": {"protocols": "modbus"}}]}},
    "sort": [{"firstPacket": {"order": "asc"}}],
}


@pytest.mark.asyncio
async def test_build_query_handoff_works_when_its_note_is_followed_literally():
    """The compiled query reaches OpenSearch when query_dsl is serialised.

    query_dsl comes back as an object so it can be edited, but search_dsl
    declares that argument a string: the object verbatim never reaches the tool
    body, it is refused at the schema with "Input should be a valid string".
    Both halves are asserted, because the note is only correct if the
    serialising step it names is the one that works.
    """
    searched = {}

    def handler(req):
        if req.url.path == "/arkime/api/buildquery":
            return httpx.Response(
                200, json={"esquery": _ESQUERY, "indices": "arkime_sessions3-240425"}
            )
        if req.url.path.endswith("/_search"):
            searched["index"] = req.url.path.split("/")[-2]
            searched["body"] = json.loads(req.content)
            return httpx.Response(200, json={"hits": {"total": {"value": 3}, "hits": []}})
        raise AssertionError(f"unexpected {req.method} {req.url.path}")

    mcp = _server(handler)
    register_dsl_tools(mcp, _mock(handler))

    built = json.loads(
        tool_text(await mcp.call_tool("arkime_build_query", {"expression": "protocols == modbus"}))
    )
    assert "JSON string" in built["note"]

    out = json.loads(
        tool_text(
            await mcp.call_tool(
                "search_dsl",
                {"index": built["index"], "query_dsl": json.dumps(built["query_dsl"]), "size": 2},
            )
        )
    )
    assert out["hits"]["total"]["value"] == 3
    assert searched["index"] == "arkime_sessions3-240425"
    assert searched["body"]["query"] == _ESQUERY["query"]
    assert searched["body"]["size"] == 2  # search_dsl's own size wins, as the note says

    with pytest.raises(Exception) as info:  # noqa: PT011 - SDK validation type is not the point
        await mcp.call_tool(
            "search_dsl", {"index": built["index"], "query_dsl": built["query_dsl"]}
        )
    assert "valid string" in str(info.value)
