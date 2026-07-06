"""MCP server setup — read tools always, write tools per enabled class."""

from __future__ import annotations

import logging
import sys

from mcp.server.fastmcp import FastMCP

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.config import WriteConfig
from mcp_server_malcolm.tools import register_all_tools, register_write_tools

logger = logging.getLogger(__name__)


def create_server() -> FastMCP:
    """Build and return a fully configured MCP server.

    Read tools are always registered. Write tools are registered only for the
    classes enabled via MALCOLM_MCP_ENABLE_* — a disabled class's tools are not
    registered at all (an unregistered tool cannot be called).
    """
    mcp = FastMCP(
        "mcp-server-malcolm",
        instructions=(
            "Malcolm network traffic analysis server. "
            "Provides search, aggregation, field discovery, Suricata alerts, "
            "Arkime sessions, NetBox asset lookup, and system health tools. "
            "All network data lives in a unified index (arkime_sessions3-*). "
            "Use event.dataset to distinguish data types: conn, dns, ssl, http, alert, etc. "
            "Write tools (alert creation, session tagging, hunts, PCAP upload) are "
            "opt-in per class and off by default."
        ),
    )
    client = MalcolmClient.from_env()
    cfg = WriteConfig.from_env()

    register_all_tools(mcp, client)
    register_write_tools(mcp, client, cfg)

    # Operators must be able to see the write posture instantly.
    print(
        f"[mcp-server-malcolm] write classes: {cfg.enabled_summary()}", file=sys.stderr, flush=True
    )
    return mcp
