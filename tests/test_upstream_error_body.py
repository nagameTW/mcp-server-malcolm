"""An upstream refusal carries its reason in the body; the error must keep it.

Measured on Malcolm's training instance: /arkime/api/connections answers a bad
expression with 403 {"success":false,"text":"Error: Parse error on line 1: ..."},
and the tool reported only "Client error '403 Forbidden' for url ...". Malcolm's
/mapi/opensearch/ is a plain nginx proxy_pass (nginx/nginx_opensearch_mapi.conf),
so OpenSearch's own 400 body reaches the client the same way.
"""

from __future__ import annotations

import httpx
import pytest

from mcp_server_malcolm.client import MalcolmClient, _body_excerpt
from mcp_server_malcolm.errors import UpstreamError

_OPENSEARCH_400 = {
    "error": {
        "root_cause": [{"type": "parsing_exception", "reason": "unknown query [bogus_query_type]"}],
        "type": "parsing_exception",
        "reason": "unknown query [bogus_query_type]",
    },
    "status": 400,
}


def _client(response: httpx.Response) -> MalcolmClient:
    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example",
        transport=httpx.MockTransport(lambda request: response),
    )
    return c


async def _error(response: httpx.Response) -> UpstreamError:
    with pytest.raises(UpstreamError) as info:
        await _client(response).post("/mapi/opensearch/arkime_sessions3-*/_search", {})
    return info.value


async def test_opensearch_reason_reaches_the_caller():
    err = await _error(httpx.Response(400, json=_OPENSEARCH_400))
    assert err.status == 400
    assert "unknown query [bogus_query_type]" in str(err)


async def test_arkime_reason_reaches_the_caller():
    body = {"success": False, "text": "Error: Parse error on line 1:\nip.src==[[["}
    err = await _error(httpx.Response(403, json=body))
    assert "Parse error on line 1" in str(err)


async def test_an_html_error_page_adds_nothing():
    page = "<html><head><title>401 Authorization Required</title></head></html>"
    err = await _error(httpx.Response(401, text=page, headers={"content-type": "text/html"}))
    assert "<html" not in str(err)
    assert "401" in str(err)


async def test_the_excerpt_is_capped_and_redacted():
    body = "token=abc123 " + "x" * 5000
    err = await _error(httpx.Response(500, text=body))
    assert "abc123" not in str(err)
    assert len(str(err)) < 1000


def test_an_unread_streamed_body_adds_nothing():
    response = httpx.Response(500, stream=httpx.ByteStream(b"not read yet"))
    assert _body_excerpt(response) == ""
