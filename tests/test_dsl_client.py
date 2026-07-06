import pytest

from mcp_server_malcolm.client import MalcolmClient


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _FakeHttp:
    def __init__(self):
        self.calls = []

    async def post(self, path, json=None):
        self.calls.append(("POST", path, json))
        return _FakeResp({"hits": {"total": {"value": 3}}, "aggregations": {}})

    async def get(self, path, params=None):
        self.calls.append(("GET", path, params))
        return _FakeResp({"ok": True})

    @property
    def is_closed(self):
        return False


@pytest.mark.asyncio
async def test_opensearch_dsl_posts_body_to_mapi_proxy():
    c = MalcolmClient(base_url="https://malcolm.example.internal")
    c._http = _FakeHttp()
    body = {"query": {"match_all": {}}, "size": 1}
    out = await c.opensearch_dsl("arkime_sessions3-*", body)
    assert out["hits"]["total"]["value"] == 3
    method, path, sent = c._http.calls[-1]
    assert method == "POST"
    assert path == "/mapi/opensearch/arkime_sessions3-*/_search"
    assert sent == body


@pytest.mark.asyncio
async def test_opensearch_count_and_health_paths():
    c = MalcolmClient(base_url="https://malcolm.example.internal")
    c._http = _FakeHttp()
    await c.opensearch_count("arkime_sessions3-*", {"match_all": {}})
    await c.opensearch_cluster_health()
    paths = [p for _, p, _ in c._http.calls]
    assert "/mapi/opensearch/arkime_sessions3-*/_count" in paths
    assert "/mapi/opensearch/_cluster/health" in paths
