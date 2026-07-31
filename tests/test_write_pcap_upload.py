import json

import httpx
import pytest
from conftest import raised_by
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.errors import ToolInputError
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

    mcp = MCPServer("t")
    register_pcap_upload_tools(mcp, _mock(handler), str(audit), str(tmp_path))
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

    mcp = MCPServer("t")
    register_pcap_upload_tools(mcp, _mock(handler), None, str(tmp_path))
    raised = await raised_by(mcp, "malcolm_upload_pcap", {"file_path": str(tmp_path / "nope.pcap")})
    assert isinstance(raised, ToolInputError)
    assert "not found" in str(raised).lower()


@pytest.mark.asyncio
async def test_upload_rejects_oversize(tmp_path):
    pcap = tmp_path / "big.pcap"
    pcap.write_bytes(b"\x00" * (2 * 1024 * 1024))  # 2 MB

    def handler(req):
        raise AssertionError("no POST expected")

    mcp = MCPServer("t")
    register_pcap_upload_tools(mcp, _mock(handler), None, str(tmp_path))
    raised = await raised_by(mcp, "malcolm_upload_pcap", {"file_path": str(pcap), "max_mb": 1})
    assert isinstance(raised, ToolInputError)
    assert "exceeds" in str(raised).lower()


@pytest.mark.asyncio
async def test_upload_disabled_without_upload_dir(tmp_path):
    """With no MALCOLM_MCP_UPLOAD_DIR, uploads are refused (H1: no arbitrary read)."""
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\xa1\xb2\xc3\xd4" + b"x" * 100)

    def handler(req):
        raise AssertionError("no POST expected")

    mcp = MCPServer("t")
    register_pcap_upload_tools(mcp, _mock(handler), None, None)
    raised = await raised_by(mcp, "malcolm_upload_pcap", {"file_path": str(pcap)})
    assert isinstance(raised, ToolInputError)
    assert "disabled" in str(raised).lower() and "MALCOLM_MCP_UPLOAD_DIR" in str(raised)


@pytest.mark.asyncio
async def test_upload_rejects_path_outside_upload_dir(tmp_path):
    """A path outside the staging dir (../secret) is rejected, not read (H1)."""
    staging = tmp_path / "staging"
    staging.mkdir()
    secret = tmp_path / "secret.key"
    secret.write_bytes(b"\xa1\xb2\xc3\xd4" + b"TOPSECRET")

    def handler(req):
        raise AssertionError("no POST expected")

    mcp = MCPServer("t")
    register_pcap_upload_tools(mcp, _mock(handler), None, str(staging))
    # Traversal out of the staging dir.
    raised = await raised_by(
        mcp, "malcolm_upload_pcap", {"file_path": str(staging / ".." / "secret.key")}
    )
    assert isinstance(raised, ToolInputError)
    assert "inside" in str(raised).lower() and "MALCOLM_MCP_UPLOAD_DIR" in str(raised)


@pytest.mark.asyncio
async def test_upload_rejects_symlink_escape(tmp_path):
    """A symlink inside the staging dir pointing outside it is rejected (H1)."""
    staging = tmp_path / "staging"
    staging.mkdir()
    secret = tmp_path / "secret.key"
    secret.write_bytes(b"\xa1\xb2\xc3\xd4" + b"TOPSECRET")
    link = staging / "innocent.pcap"
    link.symlink_to(secret)

    def handler(req):
        raise AssertionError("no POST expected")

    mcp = MCPServer("t")
    register_pcap_upload_tools(mcp, _mock(handler), None, str(staging))
    raised = await raised_by(mcp, "malcolm_upload_pcap", {"file_path": str(link)})
    assert isinstance(raised, ToolInputError)
    assert "inside" in str(raised).lower()


def test_resolve_in_dir_clamp_is_independent_of_containment(tmp_path):
    """The 2048 MB hard ceiling in the tool is a plain min(); its correctness is
    covered by test_upload_rejects_oversize. Here we lock the containment helper:
    a file inside the dir resolves, and the three refusals raise — the H1
    branches, unit-tested without the MCP layer."""
    from mcp_server_malcolm.tools.write.pcap_upload import _resolve_in_dir

    inside = tmp_path / "a.pcap"
    inside.write_bytes(b"x")
    assert _resolve_in_dir(str(inside), str(tmp_path)) == inside.resolve()

    for args, wanted in (
        ((str(tmp_path / ".." / "x.pcap"), str(tmp_path)), "inside"),
        ((str(inside), None), "disabled"),
        (("", str(tmp_path)), "required"),
    ):
        with pytest.raises(ToolInputError) as info:
            _resolve_in_dir(*args)
        assert wanted in str(info.value).lower()
