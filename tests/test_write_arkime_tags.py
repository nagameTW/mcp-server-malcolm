import json

import httpx
import pytest
from mcp.server.fastmcp import FastMCP

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.tools.write.arkime_tags import register_arkime_tag_tools


def _mock(handler):
    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example", transport=httpx.MockTransport(handler)
    )
    return c


@pytest.mark.asyncio
async def test_add_tags_posts_and_audits(tmp_path):
    audit = tmp_path / "audit.jsonl"
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        seen["body"] = json.loads(req.content)
        return httpx.Response(200, json={"success": True, "text": "Tags added successfully"})

    mcp = FastMCP("t")
    register_arkime_tag_tools(mcp, _mock(handler), str(audit))
    out = await mcp.call_tool(
        "arkime_add_tags", {"session_ids": "id1,id2", "tags": "malicious,review"}
    )
    assert seen["path"] == "/arkime/api/sessions/addtags"
    assert seen["body"]["ids"] == "id1,id2"
    assert seen["body"]["tags"] == "malicious,review"
    assert "true" in str(out).lower()
    row = json.loads(audit.read_text().splitlines()[-1])
    assert row["class"] == "arkime-tag" and row["outcome"] == "ok"


@pytest.mark.asyncio
async def test_add_tags_requires_both_args(tmp_path):
    def handler(req):
        raise AssertionError("no POST expected")

    mcp = FastMCP("t")
    register_arkime_tag_tools(mcp, _mock(handler), None)
    assert (
        "required"
        in str(await mcp.call_tool("arkime_add_tags", {"session_ids": "", "tags": "x"})).lower()
    )
    assert (
        "required"
        in str(await mcp.call_tool("arkime_add_tags", {"session_ids": "id1", "tags": ""})).lower()
    )


@pytest.mark.asyncio
async def test_add_tags_audits_http_error(tmp_path):
    audit = tmp_path / "audit.jsonl"

    def handler(req):
        return httpx.Response(403, json={"text": "forbidden"})

    mcp = FastMCP("t")
    register_arkime_tag_tools(mcp, _mock(handler), str(audit))
    await mcp.call_tool("arkime_add_tags", {"session_ids": "id1", "tags": "x"})
    row = json.loads(audit.read_text().splitlines()[-1])
    assert row["outcome"] == "http_4xx"
