import json

import httpx
import pytest

from mcp_server_malcolm.client import MalcolmClient


def _mock_client(handler):
    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example",
        transport=httpx.MockTransport(handler),
    )
    return c


@pytest.mark.asyncio
async def test_write_event_posts_alert_envelope():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["url"] = str(req.url)
        seen["body"] = json.loads(req.content)
        return httpx.Response(200, json={"result": {"_id": "260706-abc"}})

    c = _mock_client(handler)
    out = await c._write_event({"trigger": {"name": "t", "severity": 2}})
    assert seen["url"].endswith("/mapi/event")
    assert seen["body"] == {"alert": {"trigger": {"name": "t", "severity": 2}}}
    assert out["result"]["_id"] == "260706-abc"


@pytest.mark.asyncio
async def test_write_arkime_tags_posts_ids_and_tags():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["url"] = str(req.url)
        seen["body"] = json.loads(req.content)
        return httpx.Response(200, json={"success": True, "text": "Tags added successfully"})

    c = _mock_client(handler)
    out = await c._write_arkime_tags(ids="id1,id2", tags="suspicious,review")
    assert seen["url"].endswith("/arkime/api/sessions/addtags")
    assert seen["body"] == {"ids": "id1,id2", "tags": "suspicious,review", "segments": "no"}
    assert out["success"] is True


@pytest.mark.asyncio
async def test_write_arkime_hunt_primes_cookie_then_posts():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, req.url.path, req.headers.get("x-arkime-cookie")))
        if req.url.path == "/arkime/api/hunts":
            return httpx.Response(
                200,
                json={"data": [], "recordsTotal": 0},
                headers={"set-cookie": "ARKIME-COOKIE=primed-token; Path=/"},
            )
        return httpx.Response(200, json={"success": True, "hunt": {"id": "H1"}})

    c = _mock_client(handler)
    out = await c._write_arkime_hunt({"name": "h", "totalSessions": 5})
    # first call primes (GET /hunts), second is the POST carrying the cookie header
    assert calls[0][0] == "GET" and calls[0][1] == "/arkime/api/hunts"
    assert calls[1][0] == "POST" and calls[1][1] == "/arkime/api/hunt"
    assert calls[1][2] == "primed-token"
    assert out["hunt"]["id"] == "H1"


@pytest.mark.asyncio
async def test_write_upload_pcap_multipart_field_name():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["url"] = str(req.url)
        seen["ctype"] = req.headers.get("content-type", "")
        seen["body"] = req.content
        return httpx.Response(200, text="ok")

    c = _mock_client(handler)
    resp = await c._write_upload_pcap("capture.pcap", b"\xa1\xb2\xc3\xd4rest", tags="hunt7")
    assert seen["url"].endswith("/upload")
    assert "multipart/form-data" in seen["ctype"]
    assert b'name="filepond"' in seen["body"]
    assert b'name="tags"' in seen["body"]
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_arkime_session_pcap_uses_sessions_dot_pcap_expression():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["path"] = req.url.path
        seen["query"] = dict(req.url.params)
        return httpx.Response(200, content=b"\xd4\xc3\xb2\xa1pcapbytes")

    c = _mock_client(handler)
    data = await c.arkime_session_pcap("240601-SESSIONID")
    assert seen["path"] == "/arkime/api/sessions.pcap"
    assert seen["query"]["expression"] == "id==240601-SESSIONID"
    assert data.startswith(b"\xd4\xc3\xb2\xa1")


@pytest.mark.asyncio
async def test_arkime_hunts_read_status():
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/arkime/api/hunts"
        return httpx.Response(
            200, json={"data": [{"id": "H1", "status": "running"}], "recordsTotal": 1}
        )

    c = _mock_client(handler)
    out = await c.arkime_hunts(length=5)
    assert out["recordsTotal"] == 1


@pytest.mark.asyncio
async def test_arkime_tags_replays_primed_cookie():
    """A prior hunt-prime leaves ARKIME-COOKIE in the shared jar; tagging must
    then replay it as x-arkime-cookie or Arkime's checkCookieToken 500s."""
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["x-arkime-cookie"] = req.headers.get("x-arkime-cookie")
        return httpx.Response(200, json={"success": True})

    c = _mock_client(handler)
    c._http.cookies.set("ARKIME-COOKIE", "primed", domain="malcolm.example")
    await c._write_arkime_tags(ids="id1", tags="x")
    assert seen["x-arkime-cookie"] == "primed"


def test_parse_ssl_verify_accepts_true_false_or_ca_path(monkeypatch):
    monkeypatch.setenv("MALCOLM_SSL_VERIFY", "true")
    assert MalcolmClient.from_env()._ssl_verify is True
    monkeypatch.setenv("MALCOLM_SSL_VERIFY", "FALSE")
    assert MalcolmClient.from_env()._ssl_verify is False
    monkeypatch.setenv("MALCOLM_SSL_VERIFY", "/etc/ssl/ca.pem")
    assert MalcolmClient.from_env()._ssl_verify == "/etc/ssl/ca.pem"
