import asyncio
import json

import httpx
import pytest
from conftest import raised_by
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.errors import ToolInputError, UpstreamError
from mcp_server_malcolm.server import create_server
from mcp_server_malcolm.tools.write.hunt_jobs import register_hunt_job_tools


def _mock(handler):
    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example", transport=httpx.MockTransport(handler)
    )
    return c


@pytest.mark.asyncio
async def test_create_hunt_builds_body_and_primes_cookie(tmp_path):
    audit = tmp_path / "audit.jsonl"
    calls = []

    def handler(req):
        calls.append((req.method, req.url.path))
        if req.url.path == "/arkime/api/hunts":
            return httpx.Response(
                200,
                json={"data": [], "recordsTotal": 0},
                headers={"set-cookie": "ARKIME-COOKIE=tok; Path=/"},
            )
        body = json.loads(req.content)
        assert body["searchType"] == "ascii"
        assert body["type"] == "raw"
        assert body["src"] is True and body["dst"] is True
        assert body["query"]["startTime"] == 1717200000
        assert body["query"]["stopTime"] == 1717203600
        return httpx.Response(200, json={"success": True, "hunt": {"id": "H1"}})

    mcp = MCPServer("t")
    register_hunt_job_tools(mcp, _mock(handler), str(audit))
    out = await mcp.call_tool(
        "arkime_create_hunt",
        {
            "name": "beacon-bytes",
            "search": "deadbeef",
            "search_type": "ascii",
            "total_sessions": 12,
            "start_time": 1717200000,
            "stop_time": 1717203600,
            "expression": "ip==192.0.2.77",
        },
    )
    assert ("GET", "/arkime/api/hunts") in calls
    assert ("POST", "/arkime/api/hunt") in calls
    assert "H1" in str(out)
    row = json.loads(audit.read_text().splitlines()[-1])
    assert row["class"] == "hunt-job" and row["outcome"] == "ok"


@pytest.mark.asyncio
async def test_create_hunt_rejects_bad_search_type(tmp_path):
    def handler(req):
        return httpx.Response(200, json={"data": []}, headers={"set-cookie": "ARKIME-COOKIE=t"})

    mcp = MCPServer("t")
    register_hunt_job_tools(mcp, _mock(handler), None)
    raised = await raised_by(
        mcp,
        "arkime_create_hunt",
        {
            "name": "x",
            "search": "y",
            "search_type": "bogus",
            "total_sessions": 1,
            "start_time": 1,
            "stop_time": 2,
            "expression": "ip==192.0.2.1",
        },
    )
    assert isinstance(raised, ToolInputError)
    assert "search_type" in str(raised).lower()


def test_hunt_status_is_no_longer_gated_by_this_class():
    """It moved to tools/arkime_inventory.py — a plain GET the write gate had no
    reason to hide. Registered here as well it would be a duplicate name; absent
    from both, hunt jobs would be invisible (tests/test_arkime_inventory.py
    covers the other half)."""
    mcp = MCPServer("t")
    register_hunt_job_tools(mcp, _mock(lambda req: httpx.Response(200, json={})), None)

    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert names == {"arkime_create_hunt", "arkime_cancel_hunt"}


# -- arkime_cancel_hunt -------------------------------------------------


def _cancel_handler(status: int, body: dict, calls: list) -> object:
    def handler(req):
        calls.append((req.method, req.url.path, req.headers.get("x-arkime-cookie")))
        if req.url.path == "/arkime/api/hunts":
            return httpx.Response(
                200,
                json={"data": [], "recordsTotal": 0},
                headers={"set-cookie": "ARKIME-COOKIE=tok; Path=/"},
            )
        return httpx.Response(status, json=body)

    return handler


@pytest.mark.asyncio
async def test_cancel_primes_the_csrf_cookie_and_audits_the_stop(tmp_path):
    """Without the primed cookie replayed as x-arkime-cookie, Arkime answers
    500 "Missing token" — measured live on 26.07.1."""
    audit = tmp_path / "audit.jsonl"
    calls = []

    mcp = MCPServer("t")
    register_hunt_job_tools(
        mcp,
        _mock(_cancel_handler(200, {"success": True, "text": "Canceled"}, calls)),
        str(audit),
    )
    out = await mcp.call_tool("arkime_cancel_hunt", {"hunt_id": "NYUZsZ8Bao8axaN3ef1f"})

    assert ("GET", "/arkime/api/hunts", None) in calls
    assert ("PUT", "/arkime/api/hunt/NYUZsZ8Bao8axaN3ef1f/cancel", "tok") in calls
    assert "Canceled" in str(out)
    row = json.loads(audit.read_text().splitlines()[-1])
    assert row["tool"] == "arkime_cancel_hunt"
    assert row["class"] == "hunt-job"
    assert row["target"] == "hunt_id=NYUZsZ8Bao8axaN3ef1f"
    assert row["outcome"] == "ok"


@pytest.mark.asyncio
async def test_cancel_raises_and_still_audits_when_arkime_refuses(tmp_path):
    """Measured live with an id that does not exist: 500 {"success":false,
    "text":"Error canceling hunt"}. The attempt is audited either way, and the
    failure must reach the caller as isError rather than as prose."""
    audit = tmp_path / "audit.jsonl"

    mcp = MCPServer("t")
    register_hunt_job_tools(
        mcp,
        _mock(_cancel_handler(500, {"success": False, "text": "Error canceling hunt"}, [])),
        str(audit),
    )
    raised = await raised_by(mcp, "arkime_cancel_hunt", {"hunt_id": "ThisHuntIdDoesNotExist"})

    assert isinstance(raised, UpstreamError)
    assert raised.status == 500
    assert "Error canceling hunt" in str(raised)
    row = json.loads(audit.read_text().splitlines()[-1])
    assert row["tool"] == "arkime_cancel_hunt" and row["outcome"] == "http_5xx"


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["", "   ", "hunt/../../api", "H1 && x"])
async def test_cancel_rejects_an_id_that_is_not_a_hunt_id(bad):
    def handler(req):  # pragma: no cover - the guard must stop this first
        raise AssertionError(f"a cancel went out for {bad!r}")

    mcp = MCPServer("t")
    register_hunt_job_tools(mcp, _mock(handler), None)
    raised = await raised_by(mcp, "arkime_cancel_hunt", {"hunt_id": bad})

    assert isinstance(raised, ToolInputError)


def test_cancel_is_absent_unless_the_hunt_class_is_enabled(monkeypatch):
    for flag in ("ALERTING", "ARKIME_TAGS", "HUNT_JOBS", "PCAP_UPLOAD", "ARKIME_VIEWS"):
        monkeypatch.delenv(f"MALCOLM_MCP_ENABLE_{flag}", raising=False)
    assert "arkime_cancel_hunt" not in _server_names()

    monkeypatch.setenv("MALCOLM_MCP_ENABLE_HUNT_JOBS", "true")
    assert "arkime_cancel_hunt" in _server_names()


def _server_names() -> set[str]:
    return {t.name for t in asyncio.run(create_server().list_tools())}
