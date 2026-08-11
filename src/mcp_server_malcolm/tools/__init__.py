"""Tool registration -- collects all tool modules."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from mcp.server.mcpserver import MCPServer

    from mcp_server_malcolm.client import MalcolmClient
    from mcp_server_malcolm.config import WriteConfig

# Comma-separated read groups to leave unregistered. Every group ships on;
# this exists because the full read surface costs ~34k tokens of tool schema
# before a model has asked anything, which a small-context deployment may not
# be able to spend on subsystems it does not run (no NetBox, no OpenSearch
# alerting) or does not want the agent touching.
DISABLE_READ_GROUPS_ENV = "MALCOLM_MCP_DISABLE_READ_GROUPS"


def _read_groups() -> dict[str, Callable[[MCPServer, MalcolmClient], None]]:
    """Map each read group name to its registrar, in registration order."""
    from mcp_server_malcolm.tools.arkime import register_arkime_tools
    from mcp_server_malcolm.tools.arkime_content import register_arkime_content_tools
    from mcp_server_malcolm.tools.arkime_inventory import register_arkime_inventory_tools
    from mcp_server_malcolm.tools.correlation import register_correlation_tools
    from mcp_server_malcolm.tools.dashboards import register_dashboard_tools
    from mcp_server_malcolm.tools.detections import register_detection_tools
    from mcp_server_malcolm.tools.dsl import register_dsl_tools
    from mcp_server_malcolm.tools.fields import register_field_tools
    from mcp_server_malcolm.tools.files import register_file_tools
    from mcp_server_malcolm.tools.health import register_health_tools
    from mcp_server_malcolm.tools.netbox import register_netbox_tools
    from mcp_server_malcolm.tools.query import register_query_tools

    # Insertion order is the registration order, so with nothing disabled the
    # tool list is byte-identical to what it was before groups existed.
    return {
        "dsl": register_dsl_tools,
        "query": register_query_tools,
        "fields": register_field_tools,
        "health": register_health_tools,
        "netbox": register_netbox_tools,
        "arkime": register_arkime_tools,
        "arkime-content": register_arkime_content_tools,
        "correlation": register_correlation_tools,
        "files": register_file_tools,
        "arkime-inventory": register_arkime_inventory_tools,
        "dashboards": register_dashboard_tools,
        "detections": register_detection_tools,
    }


def _disabled_read_groups(valid: frozenset[str]) -> frozenset[str]:
    """Parse the disable list, rejecting names that match no group.

    A typo has to fail loudly: silently keeping a group the operator meant to
    drop is the one outcome nobody would notice until the schema bill or an
    unwanted tool call showed up.
    """
    raw = os.environ.get(DISABLE_READ_GROUPS_ENV, "")
    names = frozenset(part.strip() for part in raw.split(",") if part.strip())
    unknown = names - valid
    if unknown:
        raise ValueError(
            f"{DISABLE_READ_GROUPS_ENV}: unknown read group(s) "
            f"{', '.join(sorted(unknown))}. Valid names: {', '.join(sorted(valid))}."
        )
    return names


def register_all_tools(mcp: MCPServer, client: MalcolmClient) -> frozenset[str]:
    """Register every read group except those named in the disable list.

    Returns the disabled group names so the caller can report the posture. A
    disabled group is not registered rather than hidden, so its tools are
    absent from tools/list and calling one fails as unregistered.
    """
    groups = _read_groups()
    disabled = _disabled_read_groups(frozenset(groups))
    for name, register in groups.items():
        if name not in disabled:
            register(mcp, client)
    return disabled


def register_write_tools(mcp: MCPServer, client: MalcolmClient, cfg: WriteConfig) -> None:
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
