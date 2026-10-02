"""search() and aggregate() retry as GET when a deployment refuses POST.

Malcolm documents /mapi/document and /mapi/agg as GET or POST. Its public
training instance (training.malcolm.fyi) answers 403 to every POST and serves
the same request as GET, so without the retry the core query tools fail there.
"""

from __future__ import annotations

import json

import httpx
import pytest

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.errors import UpstreamError

_BASE = "https://malcolm.example"


def _client(post_status: int, get_status: int = 200) -> tuple[MalcolmClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.method == "POST":
            return httpx.Response(post_status, json={"via": "POST"})
        return httpx.Response(get_status, json={"via": "GET"})

    c = MalcolmClient(base_url=_BASE)
    c._http = httpx.AsyncClient(base_url=_BASE, transport=httpx.MockTransport(handler))
    return c, seen


@pytest.mark.parametrize("status", [403, 405])
async def test_search_retries_as_get_when_post_is_refused(status):
    c, seen = _client(post_status=status)

    out = await c.search({"event.dataset": "alert"}, limit=5, time_from="0")

    assert out == {"via": "GET"}
    assert [r.method for r in seen] == ["POST", "GET"]
    get = seen[1]
    assert get.url.path == "/mapi/document"
    assert get.url.params["limit"] == "5"
    assert get.url.params["from"] == "0"
    assert json.loads(get.url.params["filter"]) == {"event.dataset": "alert"}


async def test_aggregate_retries_as_get_on_the_same_path():
    c, seen = _client(post_status=403)

    out = await c.aggregate("rule.name", {"!rule.name": None}, limit=10)

    assert out == {"via": "GET"}
    get = seen[1]
    assert get.method == "GET"
    assert get.url.path == "/mapi/agg/rule.name"
    assert get.url.params["limit"] == "10"
    assert json.loads(get.url.params["filter"]) == {"!rule.name": None}


async def test_post_that_works_sends_no_get():
    c, seen = _client(post_status=200)

    assert await c.search() == {"via": "POST"}
    assert [r.method for r in seen] == ["POST"]


async def test_other_post_failures_propagate_without_a_retry():
    c, seen = _client(post_status=500)

    with pytest.raises(UpstreamError) as err:
        await c.search()

    assert err.value.status == 500
    assert [r.method for r in seen] == ["POST"]


async def test_a_refused_get_reports_the_get_failure():
    c, seen = _client(post_status=403, get_status=401)

    with pytest.raises(UpstreamError) as err:
        await c.aggregate("rule.name")

    assert err.value.status == 401
    assert [r.method for r in seen] == ["POST", "GET"]
