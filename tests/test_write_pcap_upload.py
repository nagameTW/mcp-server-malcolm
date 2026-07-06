import json

import httpx
import pytest
from mcp.server.fastmcp import FastMCP

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.tools.write.pcap_upload import register_pcap_upload_tools


def _mock(handler):
    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example", transport=httpx.MockTransport(handler)
    )
    return c


@pytest.mark.asyncio
async def test_upload_reads_file_and_posts_multipart(tmp_path):
    audit = tmp_path / "audit.jsonl"
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\xa1\xb2\xc3\xd4" + b"x" * 100)
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        seen["body"] = req.content
        return httpx.Response(200, text="ok")

    mcp = FastMCP("t")
    register_pcap_upload_tools(mcp, _mock(handler), str(audit))
    out = await mcp.call_tool("malcolm_upload_pcap", {"file_path": str(pcap), "tags": "hunt7"})
    assert seen["path"] == "/server/php/submit.php"
    assert b'name="filepond"' in seen["body"]
    assert b'name="tags"' in seen["body"]
    assert "uploaded" in str(out).lower()
    row = json.loads(audit.read_text().splitlines()[-1])
    assert row["class"] == "pcap-upload" and row["outcome"] == "ok"


@pytest.mark.asyncio
async def test_upload_missing_file(tmp_path):
    def handler(req):
        raise AssertionError("no POST expected")

    mcp = FastMCP("t")
    register_pcap_upload_tools(mcp, _mock(handler), None)
    out = await mcp.call_tool("malcolm_upload_pcap", {"file_path": str(tmp_path / "nope.pcap")})
    assert "not found" in str(out).lower()


@pytest.mark.asyncio
async def test_upload_rejects_oversize(tmp_path):
    pcap = tmp_path / "big.pcap"
    pcap.write_bytes(b"\x00" * (2 * 1024 * 1024))  # 2 MB

    def handler(req):
        raise AssertionError("no POST expected")

    mcp = FastMCP("t")
    register_pcap_upload_tools(mcp, _mock(handler), None)
    out = await mcp.call_tool("malcolm_upload_pcap", {"file_path": str(pcap), "max_mb": 1})
    assert "exceeds" in str(out).lower() or "too large" in str(out).lower()
