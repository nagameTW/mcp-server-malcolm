"""Shared test helpers.

The one place that knows the shape of an MCP call result. SDK 2.0 changed it
from a (content, structured) tuple to a CallToolResult object, and renamed
Tool.inputSchema to input_schema; keeping that knowledge here means the next
such change touches one file rather than every test module.
"""

from __future__ import annotations

from typing import Any


def tool_text(result: Any) -> str:
    """The text a tool returned, whatever envelope the SDK wrapped it in."""
    content = getattr(result, "content", None)
    if content is None:
        # SDK 1.x handed back (content, structured_output).
        content = result[0] if isinstance(result, tuple) else result
    return "".join(block.text for block in content if getattr(block, "type", None) == "text")
