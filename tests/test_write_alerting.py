import json

import httpx
import pytest
from mcp.server.fastmcp import FastMCP

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.tools.write.alerting import register_alerting_tools


def _mock(handler):
    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example", transport=httpx.MockTransport(handler)
    )
    return c


@pytest.mark.asyncio
async def test_create_alert_posts_event_and_audits(tmp_path):
    audit = tmp_path / "audit.jsonl"
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        seen["body"] = json.loads(req.content)
        return httpx.Response(200, json={"result": {"_id": "260706-x"}})

    mcp = FastMCP("t")
    register_alerting_tools(mcp, _mock(handler), str(audit))
    out = await mcp.call_tool(
        "malcolm_create_alert",
        {"title": "Suspicious beacon", "severity": 2, "description": "periodic C2"},
    )
    assert seen["path"] == "/mapi/event"
    alert = seen["body"]["alert"]
    assert alert["trigger"]["name"] == "Suspicious beacon"
    assert alert["trigger"]["severity"] == 2
    assert "260706-x" in str(out)
    row = json.loads(audit.read_text().splitlines()[-1])
    assert row["tool"] == "malcolm_create_alert"
    assert row["class"] == "alerting"
    assert row["outcome"] == "ok"


@pytest.mark.asyncio
async def test_create_alert_audits_http_error(tmp_path):
    audit = tmp_path / "audit.jsonl"

    def handler(req):
        return httpx.Response(500, json={"error": "boom"})

    mcp = FastMCP("t")
    register_alerting_tools(mcp, _mock(handler), str(audit))
    out = await mcp.call_tool("malcolm_create_alert", {"title": "x", "severity": 3})
    assert "failed" in str(out).lower() or "error" in str(out).lower()
    row = json.loads(audit.read_text().splitlines()[-1])
    assert row["outcome"] == "http_5xx"


@pytest.mark.asyncio
async def test_create_alert_rejects_bad_severity(tmp_path):
    def handler(req):
        raise AssertionError("should not POST on validation failure")

    mcp = FastMCP("t")
    register_alerting_tools(mcp, _mock(handler), None)
    out = await mcp.call_tool("malcolm_create_alert", {"title": "x", "severity": 9})
    assert "severity" in str(out).lower()
