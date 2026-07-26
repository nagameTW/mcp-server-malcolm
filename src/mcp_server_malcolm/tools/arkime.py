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
# sessions.pcap takes a comma-separated ids= query param, so allow commas here
# (never used for a path segment or expression, so a comma is safe).
_SESSION_IDS_RE = re.compile(r"[A-Za-z0-9:@._,-]+")


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

        Arkime expressions are simpler than OpenSearch DSL. Unlike
        malcolm_search (Malcolm filter dict, dateparser times), this uses
        Arkime expressions and epoch-second times, and is the ONLY search that
        returns a session id usable with arkime_session_pcap / arkime_add_tags.

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
            time_from: Start time, epoch seconds (NOT a dateparser string like
                "7 days ago"). Omit = recent-only; pass a range for historical
                data.
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
        """Download and validate the PCAP for one or more Arkime sessions.

        Fetches the raw PCAP bytes, checks the file-magic (pcap/pcapng), and
        returns metadata only — nothing is persisted to disk, and the MCP
        response carries metadata rather than raw bytes. Set url_only=True to
        get just the download URL for very large sessions (no download).

        Args:
            session_id: One Arkime session id, or several comma-separated
                (from arkime_sessions results). Multiple ids are merged into a
                single combined PCAP.
            url_only: If true, return the URL only and skip the download.
        """
        sid = session_id.strip()
        if not sid:
            return "Error: session_id is required."
        if not _SESSION_IDS_RE.fullmatch(sid):
            return "Error: invalid session_id (expected Arkime session id(s))."

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

    @mcp.tool(
        annotations={"readOnlyHint": True, "destructiveHint": False},
    )
    async def arkime_session_detail(session_id: str) -> str:
        """Fetch all fields (full SPI document) for one Arkime session.

        arkime_sessions returns a trimmed row per session; this returns the
        complete field set for a single session id.

        Args:
            session_id: Arkime session id (from arkime_sessions results).
        """
        sid = session_id.strip()
        if not sid:
            return "Error: session_id is required."
        if not _SESSION_ID_RE.fullmatch(sid):
            return "Error: invalid session_id (expected an Arkime session id)."

        try:
            data = await client.arkime_session_detail(sid)
        except Exception as exc:
            return f"Arkime session detail failed: {exc}"

        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(
        annotations={"readOnlyHint": True, "destructiveHint": False},
    )
    async def arkime_unique(
        field: str,
        expression: str = "",
        counts: bool = True,
    ) -> str:
        """List distinct values of one Arkime field, with optional counts.

        Lighter than a full aggregation when you only need to see what values
        a field holds. Returns one value per line (Arkime streams plain text).

        Args:
            field: Arkime field expression, e.g. "ip.dst", "protocols".
            expression: Optional Arkime filter to scope the values.
            counts: Include a per-value count (default true).
        """
        if not field.strip():
            return "Error: field is required."

        try:
            text = await client.arkime_unique(
                expression=expression.strip(),
                field=field.strip(),
                counts=counts,
            )
        except Exception as exc:
            return f"Arkime unique failed: {exc}"

        return text or "(no values)"

    @mcp.tool(
        annotations={"readOnlyHint": True, "destructiveHint": False},
    )
    async def arkime_spigraph(
        field: str,
        expression: str = "",
        size: int = 20,
        time_from: str = "",
        time_to: str = "",
    ) -> str:
        """Top values of one Arkime field, with a time-series graph.

        Good for finding top talkers or spotting a value that spikes over time.

        Args:
            field: Arkime field, e.g. "ip.dst", "protocols", "http.host".
            expression: Optional Arkime filter to scope the data.
            size: Number of top values to return (1-100).
            time_from: Start time, epoch seconds (NOT a dateparser string).
                Omit = recent-only.
            time_to: End time, epoch seconds.
        """
        if not field.strip():
            return "Error: field is required."

        try:
            data = await client.arkime_spigraph(
                field=field.strip(),
                expression=expression.strip(),
                size=min(max(1, size), 100),
                time_from=time_from,
                time_to=time_to,
            )
        except Exception as exc:
            return f"Arkime spigraph failed: {exc}"

        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(
        annotations={"readOnlyHint": True, "destructiveHint": False},
    )
    async def arkime_spiview(
        spi: str,
        expression: str = "",
        time_from: str = "",
        time_to: str = "",
    ) -> str:
        """Value profile across several Arkime fields at once.

        Returns per-field top values with counts, in a single call — lighter
        than running one aggregation per field.

        Args:
            spi: Comma-separated fields, each optionally ":<count>", e.g.
                "protocols:10,ip.dst:20,http.host".
            expression: Optional Arkime filter to scope the data.
            time_from: Start time, epoch seconds (NOT a dateparser string).
                Omit = recent-only.
            time_to: End time, epoch seconds.
        """
        if not spi.strip():
            return "Error: spi (field list) is required."

        try:
            data = await client.arkime_spiview(
                spi=spi.strip(),
                expression=expression.strip(),
                time_from=time_from,
                time_to=time_to,
            )
        except Exception as exc:
            return f"Arkime spiview failed: {exc}"

        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(
        annotations={"readOnlyHint": True, "destructiveHint": False},
    )
    async def arkime_connections(
        src_field: str = "ip.src",
        dst_field: str = "ip.dst:port",
        expression: str = "",
        time_from: str = "",
        time_to: str = "",
    ) -> str:
        """Build a source/destination connection graph (who talked to whom).

        Returns nodes and links — useful for tracing lateral movement or
        mapping which hosts a suspect IP communicated with.

        Args:
            src_field: Source field (default "ip.src").
            dst_field: Destination field (default "ip.dst:port").
            expression: Optional Arkime filter to scope the graph.
            time_from: Start time, epoch seconds (NOT a dateparser string).
                Omit = recent-only.
            time_to: End time, epoch seconds.
        """
        try:
            data = await client.arkime_connections(
                src_field=src_field.strip() or "ip.src",
                dst_field=dst_field.strip() or "ip.dst:port",
                expression=expression.strip(),
                time_from=time_from,
                time_to=time_to,
            )
        except Exception as exc:
            return f"Arkime connections failed: {exc}"

        return json.dumps(data, indent=2, ensure_ascii=False, default=str)
