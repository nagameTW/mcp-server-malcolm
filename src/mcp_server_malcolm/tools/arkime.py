"""Arkime session search and PCAP tools."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient


def register_arkime_tools(mcp: FastMCP, client: MalcolmClient) -> None:
    """Register Arkime session search and PCAP info tools."""

    @mcp.tool()
    async def arkime_sessions(
        expression: str,
        limit: int = 10,
        time_from: str = "",
        time_to: str = "",
    ) -> str:
        """Search Arkime sessions using Arkime expression syntax.

        Arkime expressions are simpler than OpenSearch DSL.

        Expression examples:
          ip==192.0.2.77
          ip.src==192.0.2.77 && ip.dst==198.51.100.1
          protocols==dns
          port.dst==443
          http.uri==/login*
          ip==192.0.2.77 && protocols==ssh
          country.dst==CN

        Args:
            expression: Arkime search expression (required).
            limit: Maximum sessions to return (1-100).
            time_from: Start time, epoch seconds. Omit = recent-only; pass a range
                for historical data.
            time_to: End time, epoch seconds.
        """
        if not expression.strip():
            return "Error: expression is required."

        try:
            data = await client.arkime_sessions(
                expression=expression.strip(),
                limit=min(max(1, limit), 100),
                time_from=time_from,
                time_to=time_to,
            )
        except Exception as exc:
            return f"Arkime search failed: {exc}"

        sessions = data.get("data", [])
        total = data.get("recordsTotal", 0)

        result = {
            "total": total,
            "showing": len(sessions),
            "sessions": sessions,
        }
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)

    @mcp.tool()
    async def arkime_pcap_info(
        session_id: str,
    ) -> str:
        """Get PCAP download info for an Arkime session.

        Returns the download URL for the session's PCAP. The actual download
        must be performed by the host system (e.g. curl with authentication).

        Args:
            session_id: Arkime session ID (from arkime_sessions results).
        """
        if not session_id.strip():
            return "Error: session_id is required."

        # Build the download URL (client can use it with auth)
        base = client._base_url
        url = f"{base}/arkime/api/session/{session_id.strip()}/pcap"

        return json.dumps(
            {
                "session_id": session_id.strip(),
                "pcap_url": url,
                "note": "Download requires Malcolm authentication (Basic auth).",
            },
            indent=2,
        )
