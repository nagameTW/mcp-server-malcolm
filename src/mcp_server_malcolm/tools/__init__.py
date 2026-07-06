"""Tool registration -- collects all tool modules."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient


def register_all_tools(mcp: FastMCP, client: MalcolmClient) -> None:
    """Register every tool module with the MCP server."""
    from mcp_server_malcolm.tools.arkime import register_arkime_tools
    from mcp_server_malcolm.tools.correlation import register_correlation_tools
    from mcp_server_malcolm.tools.dsl import register_dsl_tools
    from mcp_server_malcolm.tools.fields import register_field_tools
    from mcp_server_malcolm.tools.health import register_health_tools
    from mcp_server_malcolm.tools.netbox import register_netbox_tools
    from mcp_server_malcolm.tools.query import register_query_tools

    register_dsl_tools(mcp, client)
    register_query_tools(mcp, client)
    register_field_tools(mcp, client)
    register_health_tools(mcp, client)
    register_netbox_tools(mcp, client)
    register_arkime_tools(mcp, client)
    register_correlation_tools(mcp, client)
