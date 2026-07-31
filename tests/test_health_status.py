"""Pins malcolm_service_status's three-way split between failure, empty
success, and partial success.

Was: `if not result: raise UpstreamError("; ".join(errors))`. That keyed the
raise off *empty data*, not off *both probes having failed* -- so a request
where both `ready()` and `version()` succeeded but each answered `{}` also
hit `not result` and raised, with the joined message empty because `errors`
itself was empty. A successful-but-empty answer became an unnamed failure.
Fixed to key off `len(errors) == 2`: raise only when there is genuinely no
status to report because both probes came back as exceptions.
"""

from __future__ import annotations

import httpx
import pytest
from conftest import raised_by, tool_text
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.errors import UpstreamError
from mcp_server_malcolm.tools import health


def _server(handler) -> MCPServer:
    mcp = MCPServer("t")
    client = MalcolmClient(base_url="https://malcolm.example")
    client._http = httpx.AsyncClient(
        base_url="https://malcolm.example", transport=httpx.MockTransport(handler)
    )
    health.register_health_tools(mcp, client)
    return mcp


@pytest.mark.asyncio
async def test_both_probes_raising_raises_naming_both_failures():
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    raised = await raised_by(_server(handler), "malcolm_service_status", {})
    assert isinstance(raised, UpstreamError)
    assert "ready check failed" in str(raised)
    assert "version check failed" in str(raised)


@pytest.mark.asyncio
async def test_both_probes_succeeding_empty_returns_prose_not_a_raise():
    """The exact bug: no exception anywhere, both bodies are `{}`, so `result`
    stays empty -- `not result` used to be mistaken for "both failed"."""

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    result = await _server(handler).call_tool("malcolm_service_status", {})
    assert result.is_error is False
    assert "no version or service data" in tool_text(result).lower()


@pytest.mark.asyncio
async def test_one_probe_failing_one_succeeding_empty_still_returns_with_errors_key():
    """version() succeeds but answers `{}` (contributes nothing to `result`),
    ready() raises. Only one error, so this is NOT the "both failed" case --
    but `result` is still empty before the errors key is added, which is
    exactly the second way `not result` used to misfire: one real failure plus
    one empty-but-successful probe used to raise too, dropping the "not both
    failed" half of the contract."""

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/mapi/version":
            return httpx.Response(200, json={})
        raise httpx.ConnectError("connection refused")

    result = await _server(handler).call_tool("malcolm_service_status", {})
    assert result.is_error is False
    text = tool_text(result)
    assert '"errors"' in text
    assert "ready check failed" in text
