"""Shared test helpers.

The one place that knows the shape of an MCP call result. SDK 2.0 changed it
from a (content, structured) tuple to a CallToolResult object, and renamed
Tool.inputSchema to input_schema; keeping that knowledge here means the next
such change touches one file rather than every test module.
"""

from __future__ import annotations

from typing import Any

import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult


def tool_text(result: CallToolResult) -> str:
    """The text a tool returned, unwrapped from the SDK's result envelope.

    Always use this rather than str(result). The 2.0 envelope reprs as
    `... structured_content={...} is_error=False result_type='complete'`, so a
    substring assertion against str(result) can be satisfied by the envelope
    rather than by the tool — which silently emptied two guards during the 2.0
    port before this helper existed.
    """
    return "".join(block.text for block in result.content if getattr(block, "type", None) == "text")


async def raised_by(mcp: MCPServer, tool: str, args: dict[str, Any]) -> BaseException:
    """The exception a tool raised, unwrapped from the SDK's ToolError.

    MCPServer.call_tool re-raises anything a tool body raises as ToolError with
    the original as __cause__ (mcp/server/mcpserver/tools/base.py). Only the
    request handler one level further out turns that into a CallToolResult with
    is_error true, which is why a unit test asserts on the cause and the
    end-to-end tests in test_failures_raise.py assert on the flag.
    """
    with pytest.raises(ToolError) as info:
        await mcp.call_tool(tool, args)
    cause = info.value.__cause__
    assert cause is not None, f"{tool} raised ToolError with no cause"
    return cause
