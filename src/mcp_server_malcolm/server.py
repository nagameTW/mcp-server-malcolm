"""MCP server setup -- creates FastMCP instance with all tools registered."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.tools import register_all_tools


def create_server() -> FastMCP:
    """Build and return a fully configured MCP server."""
    mcp = FastMCP(
        "mcp-server-malcolm",
        instructions=(
            "Malcolm network traffic analysis server. "
            "Provides search, aggregation, field discovery, Suricata alerts, "
            "Arkime sessions, NetBox asset lookup, and system health tools. "
            "All network data lives in a unified index (arkime_sessions3-*). "
            "Use event.dataset to distinguish data types: conn, dns, ssl, http, alert, etc."
        ),
    )
    client = MalcolmClient.from_env()
    register_all_tools(mcp, client)
    return mcp
