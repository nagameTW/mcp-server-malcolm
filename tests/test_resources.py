"""The two field catalogues as MCP resources, and the server's cache hints.

The catalogues are this server's anti-hallucination layer, so the thing worth
pinning is not that a resource exists but that it agrees with the tool an agent
would otherwise have to spend a call on: a resource that drifted from
malcolm_field_search would be a second, quieter source of wrong field names.
"""

from __future__ import annotations

import json

import httpx
import pytest
from conftest import tool_text
from mcp.server.caching import CacheHint
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ResourceError

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.resources import (
    ARKIME_FIELDS_URI,
    MALCOLM_FIELDS_URI,
    register_resources,
)
from mcp_server_malcolm.server import create_server
from mcp_server_malcolm.tools.arkime import register_arkime_tools
from mcp_server_malcolm.tools.fields import register_field_tools

# Two shapes, deliberately different: /mapi/fields is a name -> {"type": ...}
# map, /arkime/api/fields?array=true is a list of entries keyed by "exp".
_MAPI_FIELDS = {
    "fields": {
        "http.useragent": {"type": "keyword"},
        "source.ip": {"type": "ip"},
        "event.dataset": {"type": "keyword"},
    }
}
_ARKIME_FIELDS = [
    {
        "exp": "ip.src",
        "dbField2": "source.ip",
        "type": "ip",
        "group": "general",
        "help": "Source IP",
    },
    {
        "exp": "protocols",
        "dbField2": "network.protocol",
        "type": "termfield",
        "group": "general",
        "help": "Protocols set for session",
    },
]


def _mock_client(handler) -> MalcolmClient:
    client = MalcolmClient(base_url="https://malcolm.example")
    client._http = httpx.AsyncClient(
        base_url="https://malcolm.example",
        transport=httpx.MockTransport(handler),
    )
    return client


def _catalogue_handler(counter: dict[str, int] | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if counter is not None:
            counter[request.url.path] = counter.get(request.url.path, 0) + 1
        if request.url.path == "/mapi/fields":
            return httpx.Response(200, json=_MAPI_FIELDS)
        if request.url.path == "/arkime/api/fields":
            return httpx.Response(200, json=_ARKIME_FIELDS)
        return httpx.Response(404, json={"error": "unexpected path"})

    return handler


async def _read(mcp: MCPServer, uri: str) -> tuple[str, str | None]:
    """The single content block a catalogue resource returns, with its type."""
    blocks = list(await mcp.read_resource(uri))
    assert len(blocks) == 1
    return blocks[0].content, blocks[0].mime_type


async def test_both_catalogues_are_listed_with_a_usable_description():
    """The capability is advertised unconditionally by the SDK; these two make
    it true rather than empty."""
    resources = {str(r.uri): r for r in await create_server().list_resources()}

    assert set(resources) == {MALCOLM_FIELDS_URI, ARKIME_FIELDS_URI}
    for resource in resources.values():
        assert resource.name
        assert resource.description
        assert resource.mime_type == "application/json"

    # The description has to keep the two vocabularies apart, or a client picks
    # the wrong one and every field name it produces is rejected downstream.
    assert "arkime" in resources[ARKIME_FIELDS_URI].description.lower()
    assert "expression" in resources[ARKIME_FIELDS_URI].description.lower()


async def test_malcolm_catalogue_matches_what_the_field_search_tool_returns():
    mcp = MCPServer("t")
    client = _mock_client(_catalogue_handler())
    register_resources(mcp, client)
    register_field_tools(mcp, client)

    content, mime_type = await _read(mcp, MALCOLM_FIELDS_URI)
    assert mime_type == "application/json"
    catalogue = json.loads(content)

    listed = tool_text(await mcp.call_tool("malcolm_field_search", {}))
    from_tool = {
        line.strip().split(" (")[0]: line.strip().split(" (")[1].rstrip(")")
        for line in listed.splitlines()[1:]
    }
    assert len(catalogue) == len(_MAPI_FIELDS["fields"])  # never compare two empties
    assert from_tool == catalogue


async def test_arkime_catalogue_matches_what_the_arkime_field_search_tool_returns():
    mcp = MCPServer("t")
    client = _mock_client(_catalogue_handler())
    register_resources(mcp, client)
    register_arkime_tools(mcp, client)

    content, mime_type = await _read(mcp, ARKIME_FIELDS_URI)
    assert mime_type == "application/json"
    catalogue = json.loads(content)

    listed = tool_text(await mcp.call_tool("arkime_field_search", {}))
    for entry in catalogue:
        assert f"  {entry['exp']} | {entry['db']} | {entry['type']} | {entry['group']}" in listed
    # Both dialects carry a "source.ip", under different names: the resource
    # must expose Arkime's expression name, not the db name shared with
    # /mapi/fields, or it feeds an expression Arkime rejects.
    assert [entry["exp"] for entry in catalogue] == ["ip.src", "protocols"]


async def test_reads_reuse_the_client_field_cache():
    """Two reads, one upstream fetch each — the resources add no cache of their
    own and pay nothing for a re-read."""
    counter: dict[str, int] = {}
    mcp = MCPServer("t")
    register_resources(mcp, _mock_client(_catalogue_handler(counter)))

    for _ in range(2):
        await _read(mcp, MALCOLM_FIELDS_URI)
        await _read(mcp, ARKIME_FIELDS_URI)

    assert counter == {"/mapi/fields": 1, "/arkime/api/fields": 1}


async def test_an_upstream_failure_raises_instead_of_returning_a_message():
    """A resource body that returned "Error: ..." would be a successful read of
    a document claiming to be the field catalogue."""
    mcp = MCPServer("t")
    register_resources(mcp, _mock_client(lambda request: httpx.Response(503, text="down")))

    with pytest.raises(ResourceError):
        await mcp.read_resource(MALCOLM_FIELDS_URI)


def test_cache_hints_are_declared_for_the_frozen_methods():
    """Pins both the TTLs and the deliberate omissions. `cache_hints` has no
    public accessor on MCPServer, so this reaches through to the lowlevel
    server the way conftest owns the CallToolResult shape."""
    hints = create_server()._lowlevel_server.cache_hints

    assert hints == {
        "tools/list": CacheHint(ttl_ms=3_600_000, scope="public"),
        "prompts/list": CacheHint(ttl_ms=3_600_000, scope="public"),
        "resources/list": CacheHint(ttl_ms=3_600_000, scope="public"),
        "resources/read": CacheHint(ttl_ms=3_600_000, scope="private"),
    }
