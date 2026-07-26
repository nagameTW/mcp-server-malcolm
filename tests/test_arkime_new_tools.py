"""Tests for the API-coverage additions: multiunique, spigraphhierarchy,
file-by-hash (read) and view/shortcut create (write)."""

import json

import httpx
import pytest
from mcp.server.fastmcp import FastMCP

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.tools.arkime import register_arkime_tools
from mcp_server_malcolm.tools.write.arkime_views import register_arkime_view_tools


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

    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock(handler))
    out = await mcp.call_tool("arkime_multiunique", {"fields": "source.ip,destination.port"})
    assert seen["path"] == "/arkime/api/multiunique"
    assert seen["exp"] == "source.ip,destination.port"
    assert seen["counts"] == "1"
    assert "1.2.3.4" in str(out)


@pytest.mark.asyncio
async def test_multiunique_requires_fields():
    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock(lambda r: httpx.Response(200, text="")))
    out = await mcp.call_tool("arkime_multiunique", {"fields": "  "})
    assert "required" in str(out).lower()


@pytest.mark.asyncio
async def test_spigraphhierarchy_sends_exp_and_returns_json():
    def handler(req):
        assert req.url.path == "/arkime/api/spigraphhierarchy"
        assert req.url.params.get("exp") == "source.ip,destination.ip"
        return httpx.Response(200, json={"hierarchicalResults": {"name": "root"}})

    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock(handler))
    out = await mcp.call_tool("arkime_spigraphhierarchy", {"fields": "source.ip,destination.ip"})
    assert "hierarchicalResults" in str(out)


@pytest.mark.asyncio
async def test_file_by_hash_rejects_non_hex():
    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock(lambda r: httpx.Response(200)))
    out = await mcp.call_tool("arkime_file_by_hash", {"file_hash": "../etc/passwd"})
    assert "invalid" in str(out).lower()


@pytest.mark.asyncio
async def test_file_by_hash_returns_metadata_not_bytes():
    md5 = "a" * 32

    def handler(req):
        assert req.url.path == f"/arkime/api/sessions/bodyhash/{md5}"
        return httpx.Response(200, content=b"MZ\x90\x00some-exe-bytes")

    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock(handler))
    out = await mcp.call_tool("arkime_file_by_hash", {"file_hash": md5})
    text = str(out)
    assert "found" in text and '"size_bytes"' in text
    assert "MZ" not in text  # raw bytes must not be in the response


@pytest.mark.asyncio
async def test_file_by_hash_no_match_reports_not_found():
    def handler(req):
        return httpx.Response(400, text="No Match Found")

    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock(handler))
    out = await mcp.call_tool("arkime_file_by_hash", {"file_hash": "b" * 64})
    assert '"found": false' in str(out).lower() or "no match" in str(out).lower()


@pytest.mark.asyncio
async def test_file_by_hash_url_only_skips_download():
    def handler(req):
        raise AssertionError("no download expected")

    mcp = FastMCP("t")
    register_arkime_tools(mcp, _mock(handler))
    out = await mcp.call_tool("arkime_file_by_hash", {"file_hash": "c" * 32, "url_only": True})
    assert "download_url" in str(out) and "bodyhash" in str(out)


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
    mcp = FastMCP("t")
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
    mcp = FastMCP("t")
    register_arkime_view_tools(mcp, _mock_with_cookie({}), None)
    assert (
        "required"
        in str(await mcp.call_tool("arkime_create_view", {"name": "", "expression": "x"})).lower()
    )


@pytest.mark.asyncio
async def test_create_shortcut_validates_type_and_posts():
    cap = {}
    mcp = FastMCP("t")
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
    mcp = FastMCP("t")
    register_arkime_view_tools(mcp, _mock_with_cookie({}), None)
    out = await mcp.call_tool(
        "arkime_create_shortcut",
        {"name": "x", "value": "y", "shortcut_type": "regex"},
    )
    assert "shortcut_type" in str(out) or "must be one of" in str(out)


@pytest.mark.asyncio
async def test_create_shortcut_audits(tmp_path):
    audit = tmp_path / "a.jsonl"
    cap = {}
    mcp = FastMCP("t")
    register_arkime_view_tools(mcp, _mock_with_cookie(cap), str(audit))
    await mcp.call_tool(
        "arkime_create_shortcut", {"name": "c2", "value": "1.2.3.4", "shortcut_type": "ip"}
    )
    row = json.loads(audit.read_text().splitlines()[-1])
    assert row["class"] == "arkime-view" and row["outcome"] == "ok"
