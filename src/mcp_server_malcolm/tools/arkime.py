"""Arkime session search and PCAP tools."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient

# session_id is spliced into an Arkime expression (id==<sid>); keep it to
# Arkime's id charset so it can't inject operators/spaces that widen the query.
_SESSION_ID_RE = re.compile(r"[A-Za-z0-9:@._-]+")


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

    @mcp.tool(
        annotations={"readOnlyHint": True, "destructiveHint": False},
    )
    async def arkime_session_pcap(
        session_id: str,
        url_only: bool = False,
    ) -> str:
        """Download and validate the PCAP for one Arkime session.

        Fetches the raw PCAP bytes, checks the file-magic (pcap/pcapng), and
        returns metadata only — nothing is persisted to disk, and the MCP
        response carries metadata rather than raw bytes. Set url_only=True to
        get just the download URL for very large sessions (no download).

        Args:
            session_id: Arkime session id (from arkime_sessions results).
            url_only: If true, return the URL only and skip the download.
        """
        sid = session_id.strip()
        if not sid:
            return "Error: session_id is required."
        if not _SESSION_ID_RE.fullmatch(sid):
            return "Error: invalid session_id (expected an Arkime session id)."

        url = f"{client.base_url}/arkime/api/sessions.pcap?ids={sid}"
        if url_only:
            return json.dumps(
                {
                    "session_id": sid,
                    "pcap_url": url,
                    "note": "Download requires Malcolm authentication (Basic auth).",
                },
                indent=2,
            )

        try:
            content = await client.arkime_session_pcap(sid)
        except Exception as exc:
            return f"PCAP download failed: {exc}"

        magic = content[:4]
        pcap_magics = {
            b"\xa1\xb2\xc3\xd4": "pcap-be",
            b"\xd4\xc3\xb2\xa1": "pcap-le",
            b"\xa1\xb2\x3c\x4d": "pcap-ns-be",
            b"\x4d\x3c\xb2\xa1": "pcap-ns-le",
            b"\x0a\x0d\x0d\x0a": "pcapng",
        }
        kind = pcap_magics.get(magic)

        return json.dumps(
            {
                "session_id": sid,
                "magic": magic.hex(),
                "format": kind or "unknown",
                "valid_pcap": kind is not None,
                "size_bytes": len(content),
                "pcap_url": url,
            },
            indent=2,
        )
