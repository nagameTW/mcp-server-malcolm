"""Shared test helpers.

The one place that knows the shape of an MCP call result. SDK 2.0 changed it
from a (content, structured) tuple to a CallToolResult object, and renamed
Tool.inputSchema to input_schema; keeping that knowledge here means the next
such change touches one file rather than every test module.
"""

from __future__ import annotations

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
