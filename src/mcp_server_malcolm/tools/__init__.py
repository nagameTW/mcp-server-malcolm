"""Tool registration -- collects all tool modules."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient
    from mcp_server_malcolm.config import WriteConfig


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


def register_write_tools(mcp: FastMCP, client: MalcolmClient, cfg: WriteConfig) -> None:
    """Register write tools for enabled classes only (disabled = not registered)."""
    if cfg.alerting:
        from mcp_server_malcolm.tools.write.alerting import register_alerting_tools

        register_alerting_tools(mcp, client, cfg.audit_file)
    if cfg.arkime_tags:
        from mcp_server_malcolm.tools.write.arkime_tags import register_arkime_tag_tools

        register_arkime_tag_tools(mcp, client, cfg.audit_file)
    if cfg.hunt_jobs:
        from mcp_server_malcolm.tools.write.hunt_jobs import register_hunt_job_tools

        register_hunt_job_tools(mcp, client, cfg.audit_file)
    if cfg.pcap_upload:
        from mcp_server_malcolm.tools.write.pcap_upload import register_pcap_upload_tools

        register_pcap_upload_tools(mcp, client, cfg.audit_file, cfg.upload_dir)
    if cfg.arkime_views:
        from mcp_server_malcolm.tools.write.arkime_views import register_arkime_view_tools

        register_arkime_view_tools(mcp, client, cfg.audit_file)
