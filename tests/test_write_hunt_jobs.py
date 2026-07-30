import json

import httpx
import pytest
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
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
    out = await mcp.call_tool(
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
    assert "search_type" in str(out).lower()


@pytest.mark.asyncio
async def test_hunt_status_is_read_and_unaudited(tmp_path):
    audit = tmp_path / "audit.jsonl"

    def handler(req):
        return httpx.Response(
            200, json={"data": [{"id": "H1", "status": "running"}], "recordsTotal": 1}
        )

    mcp = MCPServer("t")
    register_hunt_job_tools(mcp, _mock(handler), str(audit))
    out = await mcp.call_tool("arkime_hunt_status", {})
    assert "running" in str(out)
    assert not audit.exists()  # reads are never audited
