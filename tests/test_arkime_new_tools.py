"""Tests for the API-coverage additions: multiunique, spigraphhierarchy,
file-by-hash, sessions-summary, buildquery (read) and view/shortcut create
(write)."""

import json

import httpx
import pytest
from conftest import raised_by, tool_text
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.errors import ToolInputError
from mcp_server_malcolm.tools.arkime import register_arkime_tools as _register_arkime_search
from mcp_server_malcolm.tools.arkime_content import register_arkime_content_tools
from mcp_server_malcolm.tools.write.arkime_views import register_arkime_view_tools


def register_arkime_tools(mcp, client) -> None:  # noqa: F811
    """Both halves of the Arkime read surface, so these tests keep asking the
    same questions after the module split: search/aggregation stayed in
    arkime.py, per-session content moved to arkime_content.py. The split is a
    module boundary, not a behaviour one."""
    _register_arkime_search(mcp, client)
    register_arkime_content_tools(mcp, client)


def _mock(handler):
    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example", transport=httpx.MockTransport(handler)
    )
    return c


# -- read: multiunique / spigraphhierarchy / file_by_hash --------------------


@pytest.mark.asyncio
async def test_multiunique_sends_exp_and_returns_text():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        seen["exp"] = req.url.params.get("exp")
        seen["counts"] = req.url.params.get("counts")
        return httpx.Response(200, text="1.2.3.4, 443\n5.6.7.8, 80\n")

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock(handler))
    out = await mcp.call_tool("arkime_multiunique", {"fields": "source.ip,destination.port"})
    assert seen["path"] == "/arkime/api/multiunique"
    assert seen["exp"] == "source.ip,destination.port"
    assert seen["counts"] == "1"
    assert "1.2.3.4" in str(out)


@pytest.mark.asyncio
async def test_multiunique_requires_fields():
    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock(lambda r: httpx.Response(200, text="")))
    raised = await raised_by(mcp, "arkime_multiunique", {"fields": "  "})
    assert isinstance(raised, ToolInputError)
    assert "required" in str(raised).lower()


@pytest.mark.asyncio
async def test_spigraphhierarchy_sends_exp_and_returns_json():
    def handler(req):
        assert req.url.path == "/arkime/api/spigraphhierarchy"
        assert req.url.params.get("exp") == "source.ip,destination.ip"
        return httpx.Response(200, json={"hierarchicalResults": {"name": "root"}})

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock(handler))
    out = await mcp.call_tool("arkime_spigraphhierarchy", {"fields": "source.ip,destination.ip"})
    assert "hierarchicalResults" in str(out)


@pytest.mark.asyncio
async def test_file_by_hash_rejects_non_hex():
    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock(lambda r: httpx.Response(200)))
    raised = await raised_by(mcp, "arkime_file_by_hash", {"file_hash": "../etc/passwd"})
    assert isinstance(raised, ToolInputError)
    assert "invalid" in str(raised).lower()


@pytest.mark.asyncio
async def test_file_by_hash_returns_metadata_not_bytes():
    md5 = "a" * 32

    def handler(req):
        assert req.url.path == f"/arkime/api/sessions/bodyhash/{md5}"
        return httpx.Response(200, content=b"MZ\x90\x00some-exe-bytes")

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock(handler))
    out = await mcp.call_tool("arkime_file_by_hash", {"file_hash": md5})
    text = str(out)
    assert "found" in text and '"size_bytes"' in text
    assert "MZ" not in text  # raw bytes must not be in the response


@pytest.mark.asyncio
async def test_file_by_hash_no_match_reports_not_found():
    def handler(req):
        return httpx.Response(400, text="No Match Found")

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock(handler))
    out = await mcp.call_tool("arkime_file_by_hash", {"file_hash": "b" * 64})
    assert '"found": false' in str(out).lower() or "no match" in str(out).lower()


@pytest.mark.asyncio
async def test_file_by_hash_url_only_skips_download():
    def handler(req):
        raise AssertionError("no download expected")

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock(handler))
    out = await mcp.call_tool("arkime_file_by_hash", {"file_hash": "c" * 32, "url_only": True})
    assert "download_url" in str(out) and "bodyhash" in str(out)


# -- read: sessions summary --------------------------------------------------

# What POST /api/sessions/summary serves: totals, then one entry per field it
# accepted, then a bare {} sentinel. The graph/map scaffolding in the totals is
# empty on this route and is dropped before the caller sees it.
_SUMMARY_TOTALS = {
    "firstPacket": 1714049780275,
    "lastPacket": 1714071818600,
    "sessions": 424262,
    "bytes": 590664497,
    "dataBytes": 734530783,
    "packets": 1799906,
    "map": {},
    "graph": {"xmin": 1714003200000, "sessionsHisto": []},
    "downloadBytes": 619463017,
}
_SUMMARY_BREAKDOWN = {
    "field": "protocols",
    "viewMode": "pie",
    "metricType": "sessions",
    "data": [{"item": "http", "sessions": 424262, "bytes": 590664497, "packets": 1799906}],
}


def _summary_mock(body_capture, entries=None):
    def handler(req):
        assert req.method == "POST" and req.url.path == "/arkime/api/sessions/summary"
        body_capture.update(json.loads(req.content))
        return httpx.Response(
            200, json=entries if entries is not None else [_SUMMARY_TOTALS, _SUMMARY_BREAKDOWN, {}]
        )

    return _mock(handler)


@pytest.mark.asyncio
async def test_summary_sizes_the_set_and_drops_the_empty_scaffolding():
    cap = {}
    mcp = MCPServer("t")
    register_arkime_tools(mcp, _summary_mock(cap))
    out = json.loads(
        tool_text(
            await mcp.call_tool(
                "arkime_sessions_summary",
                {
                    "expression": "protocols == http",
                    "time_from": "1714003200",
                    "time_to": "1714089600",
                },
            )
        )
    )
    # the window travels in the JSON body -- as query params Arkime 400s, and a
    # GET silently substitutes its own recent window
    assert cap == {
        "fields": "protocols",
        "expression": "protocols == http",
        "startTime": "1714003200",
        "stopTime": "1714089600",
    }
    assert out["totals"]["sessions"] == 424262
    assert out["totals"]["packets"] == 1799906
    assert "graph" not in out["totals"] and "map" not in out["totals"]
    assert out["breakdowns"][0]["field"] == "protocols"
    assert "ignored_fields" not in out


@pytest.mark.asyncio
async def test_summary_reports_a_field_arkime_silently_dropped():
    """A db name comes back as no breakdown at all, which upstream cannot be
    told apart from a field with no values -- so the tool names it."""
    cap = {}
    mcp = MCPServer("t")
    register_arkime_tools(mcp, _summary_mock(cap))
    out = json.loads(
        tool_text(await mcp.call_tool("arkime_sessions_summary", {"fields": "protocols, srcIp"}))
    )
    assert cap["fields"] == "protocols,srcIp"  # whitespace normalised, nothing dropped
    assert out["ignored_fields"] == ["srcIp"]
    assert "arkime_field_search" in out["ignored_note"]


@pytest.mark.asyncio
async def test_summary_empty_result_is_an_answer_not_a_failure():
    cap = {}
    zero = {**_SUMMARY_TOTALS, "sessions": 0, "bytes": 0, "packets": 0}
    mcp = MCPServer("t")
    register_arkime_tools(mcp, _summary_mock(cap, entries=[zero, {}]))
    out = json.loads(
        tool_text(
            await mcp.call_tool("arkime_sessions_summary", {"expression": "ip == 203.0.113.99"})
        )
    )
    assert out["totals"]["sessions"] == 0
    assert out["breakdowns"] == []


@pytest.mark.asyncio
async def test_summary_empty_fields_falls_back_rather_than_400ing():
    cap = {}
    mcp = MCPServer("t")
    register_arkime_tools(mcp, _summary_mock(cap))
    await mcp.call_tool("arkime_sessions_summary", {"fields": "  "})
    assert cap["fields"] == "protocols"


# -- read: build query -------------------------------------------------------

_ESQUERY = {
    "size": 100,
    "timeout": "300s",
    "query": {"bool": {"filter": [{"term": {"protocol": "http"}}]}},
    "sort": [{"firstPacket": {"order": "asc"}}],
}


@pytest.mark.asyncio
async def test_build_query_returns_the_two_arguments_search_dsl_takes():
    seen = {}

    def handler(req):
        assert req.method == "POST" and req.url.path == "/arkime/api/buildquery"
        seen.update(json.loads(req.content))
        return httpx.Response(200, json={"esquery": _ESQUERY, "indices": "arkime_sessions3-240425"})

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock(handler))
    out = json.loads(
        tool_text(
            await mcp.call_tool(
                "arkime_build_query",
                {
                    "expression": "protocols == http",
                    "time_from": "1714003200",
                    "time_to": "1714089600",
                },
            )
        )
    )
    assert seen == {
        "expression": "protocols == http",
        "startTime": "1714003200",
        "stopTime": "1714089600",
    }
    assert out["index"] == "arkime_sessions3-240425"
    assert out["query_dsl"] == _ESQUERY
    assert "search_dsl" in out["note"]


@pytest.mark.asyncio
async def test_build_query_empty_expression_compiles_the_window_alone():
    def handler(req):
        assert json.loads(req.content) == {"startTime": "1714003200", "stopTime": "1714089600"}
        return httpx.Response(200, json={"esquery": _ESQUERY, "indices": "arkime_sessions3-*"})

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock(handler))
    out = json.loads(
        tool_text(
            await mcp.call_tool(
                "arkime_build_query", {"time_from": "1714003200", "time_to": "1714089600"}
            )
        )
    )
    assert out["query_dsl"] == _ESQUERY


@pytest.mark.asyncio
async def test_build_query_raises_on_an_expression_arkime_answered_200_for():
    """A parse error is HTTP 200 with an error field and no query, so nothing
    upstream raised on the way here -- returning it would read as success."""

    def handler(req):
        return httpx.Response(
            200,
            json={
                "recordsTotal": 0,
                "recordsFiltered": 0,
                "error": "Error: Parse error on line 1:\nnot a valid ===",
            },
        )

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock(handler))
    raised = await raised_by(mcp, "arkime_build_query", {"expression": "not a valid ==="})
    assert isinstance(raised, ToolInputError)
    assert "Parse error" in str(raised)
    assert "arkime_field_search" in str(raised)


@pytest.mark.asyncio
async def test_build_query_raises_on_an_unknown_field():
    def handler(req):
        return httpx.Response(200, json={"recordsTotal": 0, "error": "Unknown field bogusfield"})

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock(handler))
    raised = await raised_by(mcp, "arkime_build_query", {"expression": "bogusfield == 1"})
    assert isinstance(raised, ToolInputError)
    assert "Unknown field bogusfield" in str(raised)


@pytest.mark.asyncio
async def test_summary_survives_a_primed_arkime_cookie():
    """The order every hunt actually uses: find sessions, then size them.

    Was marked xfail while client.arkime_sessions_summary POSTed without the
    token: once any GET /arkime/api/sessions plants an ARKIME-COOKIE in the
    shared jar, Arkime switches to checkCookieToken and the route answers 500
    {'text': 'Missing token'} for the life of the process. _arkime_post now
    replays the cookie, so this is a live regression test rather than a
    recorded defect.
    """

    def handler(req):
        if req.method == "GET" and req.url.path == "/arkime/api/sessions":
            return httpx.Response(
                200,
                json={"data": [], "recordsFiltered": 0},
                headers={"set-cookie": "ARKIME-COOKIE=tok123; Path=/"},
            )
        if req.method == "GET" and req.url.path == "/arkime/api/hunts":
            return httpx.Response(
                200, json={"data": []}, headers={"set-cookie": "ARKIME-COOKIE=tok123; Path=/"}
            )
        if req.url.path == "/arkime/api/sessions/summary":
            if req.headers.get("cookie") and not req.headers.get("x-arkime-cookie"):
                return httpx.Response(500, json={"success": False, "text": "Missing token"})
            return httpx.Response(200, json=[_SUMMARY_TOTALS, _SUMMARY_BREAKDOWN, {}])
        raise AssertionError(f"unexpected {req.method} {req.url.path}")

    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock(handler))
    await mcp.call_tool("arkime_sessions", {"expression": "protocols == http"})
    out = json.loads(tool_text(await mcp.call_tool("arkime_sessions_summary", {})))
    assert out["totals"]["sessions"] == 424262


# -- write: view / shortcut (with the cookie-token dance) --------------------


def _mock_with_cookie(post_capture):
    """Mock that issues an ARKIME-COOKIE on the prime GET and captures the POST."""

    def handler(req):
        if req.method == "GET" and req.url.path == "/arkime/api/hunts":
            return httpx.Response(
                200, json={"data": []}, headers={"set-cookie": "ARKIME-COOKIE=tok123; Path=/"}
            )
        if req.method == "POST":
            post_capture["path"] = req.url.path
            post_capture["x_arkime_cookie"] = req.headers.get("x-arkime-cookie")
            post_capture["body"] = json.loads(req.content)
            return httpx.Response(200, json={"success": True})
        raise AssertionError(f"unexpected {req.method} {req.url.path}")

    return _mock(handler)


@pytest.mark.asyncio
async def test_create_view_primes_cookie_and_posts(tmp_path):
    cap = {}
    mcp = MCPServer("t")
    register_arkime_view_tools(mcp, _mock_with_cookie(cap), None)
    out = await mcp.call_tool(
        "arkime_create_view", {"name": "hunt_c2", "expression": "ip==1.2.3.4"}
    )
    assert cap["path"] == "/arkime/api/view"
    assert cap["x_arkime_cookie"] == "tok123"  # replayed primed cookie
    assert cap["body"] == {"name": "hunt_c2", "expression": "ip==1.2.3.4"}
    assert "success" in str(out).lower()


@pytest.mark.asyncio
async def test_create_view_requires_name_and_expression():
    mcp = MCPServer("t")
    register_arkime_view_tools(mcp, _mock_with_cookie({}), None)
    raised = await raised_by(mcp, "arkime_create_view", {"name": "", "expression": "x"})
    assert isinstance(raised, ToolInputError)
    assert "required" in str(raised).lower()


@pytest.mark.asyncio
async def test_create_shortcut_validates_type_and_posts():
    cap = {}
    mcp = MCPServer("t")
    register_arkime_view_tools(mcp, _mock_with_cookie(cap), None)
    out = await mcp.call_tool(
        "arkime_create_shortcut",
        {"name": "c2_ips", "value": "1.2.3.4\n5.6.7.8", "shortcut_type": "ip"},
    )
    assert cap["path"] == "/arkime/api/shortcut"
    assert cap["body"]["type"] == "ip"
    assert cap["body"]["value"] == "1.2.3.4\n5.6.7.8"
    assert "success" in str(out).lower()


@pytest.mark.asyncio
async def test_create_shortcut_rejects_bad_type():
    mcp = MCPServer("t")
    register_arkime_view_tools(mcp, _mock_with_cookie({}), None)
    raised = await raised_by(
        mcp, "arkime_create_shortcut", {"name": "x", "value": "y", "shortcut_type": "regex"}
    )
    assert isinstance(raised, ToolInputError)
    assert "shortcut_type" in str(raised) and "must be one of" in str(raised)


@pytest.mark.asyncio
async def test_create_shortcut_audits(tmp_path):
    audit = tmp_path / "a.jsonl"
    cap = {}
    mcp = MCPServer("t")
    register_arkime_view_tools(mcp, _mock_with_cookie(cap), str(audit))
    await mcp.call_tool(
        "arkime_create_shortcut", {"name": "c2", "value": "1.2.3.4", "shortcut_type": "ip"}
    )
    row = json.loads(audit.read_text().splitlines()[-1])
    assert row["class"] == "arkime-view" and row["outcome"] == "ok"
