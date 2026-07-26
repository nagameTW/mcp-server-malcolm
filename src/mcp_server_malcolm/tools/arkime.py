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
# The charset admits "." for real ids (3@240425-x.123); callers also reject
# ".." so a bare "session/.." can't traverse up out of the API prefix.
_SESSION_ID_RE = re.compile(r"[A-Za-z0-9:@._-]+")
# sessions.pcap takes a comma-separated ids= query param, so allow commas here
# (never used for a path segment or expression, so a comma is safe).
_SESSION_IDS_RE = re.compile(r"[A-Za-z0-9:@._,-]+")

# Cap the in-memory PCAP download: the whole body is read into RAM, so a huge
# (or many-session) fetch could OOM. Refuse before reading when the server
# declares an oversized Content-Length.
_PCAP_MAX_MB = 500

# file_hash lands in the URL path (/sessions/bodyhash/<hash>); a body hash is
# hex only (md5 = 32, sha256 = 64), so restrict to hex and reject anything that
# could add a path segment or query.
_HASH_RE = re.compile(r"[A-Fa-f0-9]{16,128}")
# Extracted-file guard: bodyhash streams the file into memory, same OOM concern
# as the PCAP download.
_FILE_MAX_MB = 100


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
        except Exception as exc:  # noqa: BLE001
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
        if not _SESSION_IDS_RE.fullmatch(sid) or ".." in sid:
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
            content = await client.arkime_session_pcap(sid, max_bytes=_PCAP_MAX_MB * 1024 * 1024)
        except Exception as exc:  # noqa: BLE001
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
        if not _SESSION_ID_RE.fullmatch(sid) or ".." in sid:
            return "Error: invalid session_id (expected an Arkime session id)."

        try:
            data = await client.arkime_session_detail(sid)
        except Exception as exc:  # noqa: BLE001
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
        except Exception as exc:  # noqa: BLE001
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
        except Exception as exc:  # noqa: BLE001
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
        except Exception as exc:  # noqa: BLE001
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
        except Exception as exc:  # noqa: BLE001
            return f"Arkime connections failed: {exc}"

        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(
        annotations={"readOnlyHint": True, "destructiveHint": False},
    )
    async def arkime_multiunique(
        fields: str,
        expression: str = "",
        counts: bool = True,
        time_from: str = "",
        time_to: str = "",
    ) -> str:
        """Unique value combinations across several Arkime fields at once.

        Like arkime_unique but for a tuple of fields — e.g. every distinct
        (source.ip, destination.port) pair. Good for spotting a host scanning
        many ports, or a small set of talkers behind a lot of traffic.

        Args:
            fields: Comma-separated Arkime field names, e.g.
                "source.ip,destination.port".
            expression: Optional Arkime filter to scope the data.
            counts: Include a per-combination count (default true).
            time_from: Start time, epoch seconds (NOT a dateparser string).
                Omit = recent-only.
            time_to: End time, epoch seconds.
        """
        if not fields.strip():
            return "Error: fields is required."

        try:
            text = await client.arkime_multiunique(
                fields=fields.strip(),
                expression=expression.strip(),
                counts=counts,
                time_from=time_from,
                time_to=time_to,
            )
        except Exception as exc:  # noqa: BLE001
            return f"Arkime multiunique failed: {exc}"

        return text or "(no values)"

    @mcp.tool(
        annotations={"readOnlyHint": True, "destructiveHint": False},
    )
    async def arkime_spigraphhierarchy(
        fields: str,
        expression: str = "",
        time_from: str = "",
        time_to: str = "",
    ) -> str:
        """Hierarchical top-N breakdown across fields (a treemap/drill-down).

        Unlike malcolm_aggregate's flat multi-field buckets, this returns a
        nested hierarchy (level 1 -> its top level-2 values -> ...), matching
        Arkime's SPI-graph hierarchy view.

        Args:
            fields: Comma-separated fields defining the hierarchy levels, e.g.
                "source.ip,destination.ip,destination.port".
            expression: Optional Arkime filter to scope the data.
            time_from: Start time, epoch seconds (NOT a dateparser string).
                Omit = recent-only.
            time_to: End time, epoch seconds.
        """
        if not fields.strip():
            return "Error: fields is required."

        try:
            data = await client.arkime_spigraphhierarchy(
                fields=fields.strip(),
                expression=expression.strip(),
                time_from=time_from,
                time_to=time_to,
            )
        except Exception as exc:  # noqa: BLE001
            return f"Arkime spigraphhierarchy failed: {exc}"

        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(
        annotations={"readOnlyHint": True, "destructiveHint": False},
    )
    async def arkime_file_by_hash(file_hash: str, url_only: bool = False) -> str:
        """Extract the transferred file whose content hash matches, across sessions.

        Pivots from one file IOC to the actual bytes: Arkime finds the most
        recent session carrying a body with this hash, resolves the capture node
        itself, and returns the file. This tool checks the file-magic and
        returns metadata only — the raw bytes are never put in the MCP response.
        The hash comes from a session's http.md5 / http.sha256 field.

        Args:
            file_hash: The file's content hash, md5 (32 hex) or sha256 (64 hex).
            url_only: If true, return just the download URL, skip the download.
        """
        h = file_hash.strip()
        if not h:
            return "Error: file_hash is required."
        if not _HASH_RE.fullmatch(h):
            return "Error: invalid file_hash (expected md5/sha256 hex)."

        url = f"{client.base_url}/arkime/api/sessions/bodyhash/{h}"
        if url_only:
            return json.dumps(
                {
                    "file_hash": h,
                    "download_url": url,
                    "note": "Download requires Malcolm authentication (Basic auth).",
                },
                indent=2,
            )

        try:
            resp = await client.arkime_file_by_hash(h)
        except Exception as exc:  # noqa: BLE001
            return f"File extraction failed: {exc}"

        if resp.status_code == 400:
            return json.dumps({"file_hash": h, "found": False, "note": "No match found."}, indent=2)
        try:
            resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            return f"File extraction failed: {exc}"

        content = resp.content
        if len(content) > _FILE_MAX_MB * 1024 * 1024:
            return (
                f"Error: extracted file exceeds {_FILE_MAX_MB} MB "
                f"({len(content) / 1024 / 1024:.1f} MB); use url_only to fetch it directly."
            )
        return json.dumps(
            {
                "file_hash": h,
                "found": True,
                "size_bytes": len(content),
                "magic": content[:4].hex(),
                "download_url": url,
            },
            indent=2,
        )
