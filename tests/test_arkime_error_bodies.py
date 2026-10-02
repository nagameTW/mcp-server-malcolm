"""Arkime failures that arrive inside an HTTP 200, and the one-session route.

Measured on Malcolm's public training instance: /arkime/api/sessions answers
the expression "ip.src==[[[" with 200 {"data": [], "recordsFiltered": 0,
"error": "Parse error on line 1: ..."}, which arkime_sessions reported as
matched: 0. Arkime's viewer source gives /api/spiview the same "error" key and
/api/sessions/summary a streamed [{"bsqErr": ...}].
"""

from __future__ import annotations

import httpx
from mcp.client import Client
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.tools.arkime import register_arkime_tools
from mcp_server_malcolm.tools.arkime_content import register_arkime_content_tools

_PARSE_ERROR = "Parse error on line 1:\nip.src==[[[\n--------^\nExpecting 'STR', got 'INVALID'"


def _client(responder, seen: list[httpx.Request] | None = None) -> MalcolmClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        if request.url.path == "/arkime/api/fields":
            return httpx.Response(
                200, json=[{"exp": "ip.src", "dbField2": "source.ip", "type": "ip"}]
            )
        return responder(request)

    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example", transport=httpx.MockTransport(handler)
    )
    return c


async def _call(register, client, tool, args):
    mcp = MCPServer("t")
    register(mcp, client)
    async with Client(mcp) as session:
        result = await session.call_tool(tool, args)
    return result.is_error, "".join(getattr(c, "text", "") for c in result.content)


async def test_sessions_reports_arkimes_error_instead_of_zero_matches():
    body = {"data": [], "recordsTotal": 0, "recordsFiltered": 0, "error": _PARSE_ERROR}
    is_error, text = await _call(
        register_arkime_tools,
        _client(lambda r: httpx.Response(200, json=body)),
        "arkime_sessions",
        {"expression": "ip.src==[[[", "time_from": "1609459200"},
    )
    assert is_error
    assert "Parse error" in text
    assert '"matched"' not in text


async def test_spiview_reports_arkimes_error():
    body = {"spi": {}, "error": "Unknown field nosuch.field"}
    is_error, text = await _call(
        register_arkime_tools,
        _client(lambda r: httpx.Response(200, json=body)),
        "arkime_spiview",
        {"spi": "protocol:10", "expression": "nosuch.field==1"},
    )
    assert is_error
    assert "Unknown field nosuch.field" in text


async def test_summary_reports_a_streamed_bsqerr():
    is_error, text = await _call(
        register_arkime_tools,
        _client(lambda r: httpx.Response(200, json=[{"bsqErr": "Unknown field nosuch.field"}])),
        "arkime_sessions_summary",
        {"fields": "ip.src", "expression": "nosuch.field==1"},
    )
    assert is_error
    assert "Unknown field nosuch.field" in text


async def test_sessions_without_an_error_key_still_return_rows():
    body = {"data": [{"id": "3@x:abc", "node": "n"}], "recordsFiltered": 1}
    is_error, text = await _call(
        register_arkime_tools,
        _client(lambda r: httpx.Response(200, json=body)),
        "arkime_sessions",
        {"expression": "ip.src == 10.0.0.1"},
    )
    assert not is_error
    assert '"matched": 1' in text


# -- arkime_session_detail --------------------------------------------------

_SID = "3@26w39:260928--x0yJQXq-m1nSq8hFiBQyg"
_FULL = {"id": _SID, "node": "n", "@timestamp": 1, "event": {"dataset": "conn"}, "tags": ["x"]}


async def test_session_detail_reads_the_one_session_route():
    seen: list[httpx.Request] = []
    is_error, text = await _call(
        register_arkime_content_tools,
        _client(lambda r: httpx.Response(200, json=_FULL), seen),
        "arkime_session_detail",
        {"session_id": _SID},
    )
    assert not is_error
    request = seen[-1]
    assert request.url.path.startswith("/arkime/api/session/")
    assert request.url.path != "/arkime/api/sessions"
    assert '"tags"' in text and '"event"' in text


async def test_session_detail_answers_an_unknown_id_with_a_sentence():
    # Measured: an unknown id is 500 {"success":false,"text":"Session not found"}.
    body = {"success": False, "text": "Session not found", "i18n": "api.sessions.sessionNotFound"}
    is_error, text = await _call(
        register_arkime_content_tools,
        _client(lambda r: httpx.Response(500, json=body)),
        "arkime_session_detail",
        {"session_id": _SID},
    )
    assert not is_error
    assert "No Arkime session found" in text


async def test_session_detail_still_fails_on_any_other_500():
    is_error, _ = await _call(
        register_arkime_content_tools,
        _client(lambda r: httpx.Response(500, json={"success": False, "text": "boom"})),
        "arkime_session_detail",
        {"session_id": _SID},
    )
    assert is_error
