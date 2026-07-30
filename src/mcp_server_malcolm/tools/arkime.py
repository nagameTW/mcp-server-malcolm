"""Arkime session search and PCAP tools."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Annotated

import httpx
from pydantic import Field

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

# Shared: every Arkime tool here reads from the external Arkime (via Malcolm)
# server, never mutates it.
_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}


def register_arkime_tools(mcp: FastMCP, client: MalcolmClient) -> None:
    """Register Arkime session search and PCAP info tools."""

    @mcp.tool(title="Search Arkime expression fields", annotations=_READ)
    async def arkime_field_search(
        keyword: Annotated[
            str,
            Field(
                description="Substring matched against the expression name, db name and "
                'help text, e.g. "user", "cert", "ja3". Empty = no keyword filter.'
            ),
        ] = "",
        group: Annotated[
            str,
            Field(
                description='Exact Arkime field group to restrict to, e.g. "http", "dns", '
                '"tls", "general". Empty = any group.'
            ),
        ] = "",
        limit: Annotated[int, Field(description="Max fields to return.", ge=1, le=200)] = 50,
    ) -> str:
        """Discover the field names Arkime expressions accept — call before writing one.

        Arkime's expression parser has its own vocabulary (ip.src, port.dst,
        protocols, country) and rejects the dotted ECS names malcolm_field_search
        reports (source.ip, destination.port). That makes this the field-discovery
        tool for every arkime_* tool, exactly as malcolm_field_search is for the
        malcolm_* ones. Each row gives both names: use "exp" inside an `expression`
        argument, and "db" where a tool asks for an Arkime db field (arkime_connections,
        arkime_multiunique). Returns "exp | db | type | group" lines with the help text.
        """
        try:
            results = await client.search_arkime_fields(keyword=keyword, group=group)
        except Exception as exc:  # noqa: BLE001
            return f"Arkime field lookup failed: {exc}"

        if not results:
            return "No Arkime fields matched. Try a shorter keyword, or drop the group filter."

        lines = [f"Found {len(results)} Arkime fields (exp | db | type | group):"]
        for field in results[:limit]:
            help_text = f"  — {field['help']}" if field["help"] else ""
            lines.append(
                f"  {field['exp']} | {field['db']} | {field['type']} | {field['group']}{help_text}"
            )
        if len(results) > limit:
            lines.append(f"  ... and {len(results) - limit} more")

        return "\n".join(lines)

    @mcp.tool(title="Search Arkime sessions", annotations=_READ)
    async def arkime_sessions(
        expression: Annotated[
            str,
            Field(
                description="Arkime expression syntax (NOT OpenSearch DSL, NOT a "
                'Malcolm filter dict). Examples: "ip==192.0.2.77"; '
                '"ip.src==192.0.2.77 && ip.dst==198.51.100.1"; "protocols==dns"; '
                '"port.dst==443"; "http.uri==/login*"; "country.dst==CN". '
                "Every clause must be field-operator-value — there is no free-text "
                "search. Field existence is the literal token EXISTS!, as in "
                '"zeek.ftp.password == EXISTS!". A list is an OR: "port == [80,443]". '
                "Field names are Arkime's own, NOT the ECS names malcolm_field_search "
                "returns — look them up with arkime_field_search."
            ),
        ],
        limit: Annotated[int, Field(description="Max sessions to return.", ge=1, le=100)] = 10,
        time_from: Annotated[
            str,
            Field(
                description="Start time as EPOCH SECONDS (NOT a dateparser string "
                'like "7 days ago"). Empty = Arkime\'s recent-only default; pass a '
                "range for historical data."
            ),
        ] = "",
        time_to: Annotated[
            str,
            Field(description="End time as EPOCH SECONDS (NOT a dateparser string). Empty = now."),
        ] = "",
    ) -> str:
        """Search Arkime sessions by expression; returns trimmed rows each carrying a session id.

        This is the ONLY search returning a session id usable by
        arkime_session_pcap, arkime_session_detail, arkime_file_by_hash, and
        arkime_add_tags. For the complete field set of one session use
        arkime_session_detail; for its PCAP bytes/metadata use
        arkime_session_pcap. To search with Malcolm filter dicts and dateparser
        times instead of Arkime expressions and epoch seconds, use
        malcolm_search. Returns `matched` (how many sessions the expression
        found, which is usually far more than are returned), `showing`, and the
        session rows. Each row's `id` is what the drill-down tools take.
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
        # recordsFiltered is how many sessions the expression matched;
        # recordsTotal is how many exist in the index at all. Reporting the
        # latter as "total" told an agent that `protocols == ssh` matched
        # 6,030,807 sessions when it matched 134 (measured on 26.07.1).
        result = {
            "matched": data.get("recordsFiltered", 0),
            "showing": len(sessions),
            "sessions": sessions,
        }
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(title="Download session PCAP", annotations=_READ)
    async def arkime_session_pcap(
        session_id: Annotated[
            str,
            Field(
                description="One Arkime session id, or several comma-separated, "
                "each taken from arkime_sessions results (arkime_sessions is the "
                "only source of these ids). Multiple ids are merged into a single "
                "combined PCAP."
            ),
        ],
        url_only: Annotated[
            bool,
            Field(
                description="If true, return only the download URL and skip the "
                "download (use for very large sessions)."
            ),
        ] = False,
    ) -> str:
        """Fetch and validate the PCAP for one or more Arkime sessions; returns METADATA ONLY.

        Downloads the raw PCAP bytes, checks the file-magic (pcap/pcapng), and
        returns metadata (magic, format, size) only — never the raw bytes, and
        nothing is persisted to disk. Enforces a size cap and refuses oversized
        downloads before reading. Set url_only=True to get just the download URL
        with no download. Needs a session id, which only arkime_sessions
        produces. For a session's parsed fields (not its packets) use
        arkime_session_detail; to extract a specific transferred file by its
        content hash use arkime_file_by_hash.
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

    @mcp.tool(title="Get full session detail", annotations=_READ)
    async def arkime_session_detail(
        session_id: Annotated[
            str,
            Field(
                description="One Arkime session id from arkime_sessions results "
                "(arkime_sessions is the only source of these ids)."
            ),
        ],
    ) -> str:
        """Fetch every field (the full SPI document) for one Arkime session by id.

        arkime_sessions returns only a trimmed row per session; this returns the
        complete parsed field set for a single id. Use arkime_sessions to search
        and obtain the id first. For the session's raw packets use
        arkime_session_pcap; for distinct values across many sessions use
        arkime_unique / arkime_spiview. Returns the raw Arkime session document.
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

        if not data:
            return f"No Arkime session found with id {sid}."

        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(title="List unique values of one field", annotations=_READ)
    async def arkime_unique(
        field: Annotated[
            str,
            Field(
                description='One Arkime field expression, e.g. "ip.dst", "protocols", "http.host".'
            ),
        ],
        expression: Annotated[
            str,
            Field(
                description="Optional Arkime expression syntax to scope the "
                'values, e.g. "protocols==dns". Empty = all sessions.'
            ),
        ] = "",
        counts: Annotated[
            bool,
            Field(description="Include a per-value occurrence count (default true)."),
        ] = True,
        time_from: Annotated[
            str,
            Field(
                description="Start time as EPOCH SECONDS (NOT a dateparser string). "
                "Empty = Arkime's default recent window, which finds nothing in a "
                "capture older than it — pass a range to reach historical data."
            ),
        ] = "",
        time_to: Annotated[
            str,
            Field(description="End time as EPOCH SECONDS (NOT a dateparser string). Empty = now."),
        ] = "",
    ) -> str:
        """List distinct values of ONE Arkime field as plain text, optionally with counts.

        For distinct value COMBINATIONS across a tuple of fields use
        arkime_multiunique; for top values of one field plus a time-series graph
        use arkime_spigraph; to profile many fields in one call use
        arkime_spiview. Lighter than a full aggregation when you only need to see
        what values a field holds.

        Returns plain TEXT (one value per line, not JSON) — Arkime streams it
        directly. "(no values)" with no time range usually means the data is
        older than Arkime's default window rather than absent: pass time_from.
        """
        if not field.strip():
            return "Error: field is required."

        try:
            text = await client.arkime_unique(
                expression=expression.strip(),
                field=field.strip(),
                counts=counts,
                time_from=time_from.strip(),
                time_to=time_to.strip(),
            )
        except Exception as exc:  # noqa: BLE001
            return f"Arkime unique failed: {exc}"

        return text or "(no values)"

    @mcp.tool(title="Graph top values over time", annotations=_READ)
    async def arkime_spigraph(
        field: Annotated[
            str,
            Field(description='One Arkime field, e.g. "ip.dst", "protocols", "http.host".'),
        ],
        expression: Annotated[
            str,
            Field(
                description="Optional Arkime expression syntax to scope the data. "
                "Empty = all sessions."
            ),
        ] = "",
        size: Annotated[
            int, Field(description="Number of top values to return.", ge=1, le=100)
        ] = 20,
        time_from: Annotated[
            str,
            Field(
                description="Start time as EPOCH SECONDS (NOT a dateparser string). "
                "Empty = Arkime's recent-only default."
            ),
        ] = "",
        time_to: Annotated[
            str,
            Field(description="End time as EPOCH SECONDS (NOT a dateparser string). Empty = now."),
        ] = "",
    ) -> str:
        """Return top values of ONE Arkime field plus a per-value time-series graph.

        Use for top talkers or spotting a value that spikes over time. For
        distinct values of one field without the graph use arkime_unique; for a
        nested multi-level hierarchy use arkime_spigraphhierarchy; for many
        fields profiled at once use arkime_spiview. Returns the raw Arkime
        spigraph response (top values with time-bucketed counts).
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

    @mcp.tool(title="Profile many fields at once", annotations=_READ)
    async def arkime_spiview(
        spi: Annotated[
            str,
            Field(
                description="Comma-separated Arkime fields, each optionally "
                'suffixed ":<count>" to cap its values, e.g. '
                '"protocols:10,ip.dst:20,http.host".'
            ),
        ],
        expression: Annotated[
            str,
            Field(
                description="Optional Arkime expression syntax to scope the data. "
                "Empty = all sessions."
            ),
        ] = "",
        time_from: Annotated[
            str,
            Field(
                description="Start time as EPOCH SECONDS (NOT a dateparser string). "
                "Empty = Arkime's recent-only default."
            ),
        ] = "",
        time_to: Annotated[
            str,
            Field(description="End time as EPOCH SECONDS (NOT a dateparser string). Empty = now."),
        ] = "",
    ) -> str:
        """Profile top values across SEVERAL Arkime fields at once, each with counts.

        One call covers many fields — lighter than running one aggregation per
        field. For a single field use arkime_unique (plain text) or
        arkime_spigraph (adds a time graph); for distinct field-tuple
        combinations use arkime_multiunique; for a nested drill-down hierarchy
        use arkime_spigraphhierarchy. Returns the raw Arkime spiview response
        (per-field top values with counts).
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

    @mcp.tool(title="Build connection graph", annotations=_READ)
    async def arkime_connections(
        src_field: Annotated[
            str,
            Field(
                description="Arkime DB field for source nodes (default srcIp). Use an Arkime db "
                "name (srcIp, dstIp, dstPort, node) — NOT a dotted ECS name like ip.src."
            ),
        ] = "srcIp",
        dst_field: Annotated[
            str,
            Field(
                description="Arkime DB field for destination nodes (default dstIp; use dstPort to "
                "graph by port). Arkime db name only, NOT a dotted ECS name."
            ),
        ] = "dstIp",
        expression: Annotated[
            str,
            Field(
                description="Optional Arkime expression syntax to scope the graph. "
                "Empty = all sessions."
            ),
        ] = "",
        time_from: Annotated[
            str,
            Field(
                description="Start time as EPOCH SECONDS (NOT a dateparser string). "
                "Empty = Arkime's recent-only default."
            ),
        ] = "",
        time_to: Annotated[
            str,
            Field(description="End time as EPOCH SECONDS (NOT a dateparser string). Empty = now."),
        ] = "",
    ) -> str:
        """Build a source/destination connection graph of who talked to whom.

        Returns nodes and links between two fields — useful for tracing lateral
        movement or mapping which hosts a suspect IP communicated with. NOTE the
        src/dst fields take Arkime *db* names (srcIp, dstIp, dstPort, node), not
        the dotted ECS names the other tools use — a dotted name errors inside
        Arkime. For distinct field-tuple pairs as text rather than a graph use
        arkime_multiunique; for a nested top-N hierarchy use
        arkime_spigraphhierarchy. Returns the raw Arkime connections response
        (nodes and links).
        """
        try:
            data = await client.arkime_connections(
                src_field=src_field.strip() or "srcIp",
                dst_field=dst_field.strip() or "dstIp",
                expression=expression.strip(),
                time_from=time_from,
                time_to=time_to,
            )
        except Exception as exc:  # noqa: BLE001
            return f"Arkime connections failed: {exc}"

        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(title="List unique field combinations", annotations=_READ)
    async def arkime_multiunique(
        fields: Annotated[
            str,
            Field(
                description="Comma-separated Arkime field names forming the tuple, "
                'e.g. "source.ip,destination.port".'
            ),
        ],
        expression: Annotated[
            str,
            Field(
                description="Optional Arkime expression syntax to scope the data. "
                "Empty = all sessions."
            ),
        ] = "",
        counts: Annotated[
            bool,
            Field(description="Include a per-combination occurrence count (default true)."),
        ] = True,
        time_from: Annotated[
            str,
            Field(
                description="Start time as EPOCH SECONDS (NOT a dateparser string). "
                "Empty = Arkime's recent-only default."
            ),
        ] = "",
        time_to: Annotated[
            str,
            Field(description="End time as EPOCH SECONDS (NOT a dateparser string). Empty = now."),
        ] = "",
    ) -> str:
        """List distinct value COMBINATIONS across a tuple of Arkime fields as plain text.

        Like arkime_unique but for a field tuple — e.g. every distinct
        (source.ip, destination.port) pair. Good for spotting a host scanning
        many ports, or a few talkers behind a lot of traffic. For a single field
        use arkime_unique; for a source/destination graph use arkime_connections;
        for a nested hierarchy use arkime_spigraphhierarchy. Returns plain TEXT
        (one combination per line, not JSON).
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

    @mcp.tool(title="Build nested field hierarchy", annotations=_READ)
    async def arkime_spigraphhierarchy(
        fields: Annotated[
            str,
            Field(
                description="Comma-separated Arkime fields defining the hierarchy "
                "levels in order, e.g. "
                '"source.ip,destination.ip,destination.port".'
            ),
        ],
        expression: Annotated[
            str,
            Field(
                description="Optional Arkime expression syntax to scope the data. "
                "Empty = all sessions."
            ),
        ] = "",
        time_from: Annotated[
            str,
            Field(
                description="Start time as EPOCH SECONDS (NOT a dateparser string). "
                "Empty = Arkime's recent-only default."
            ),
        ] = "",
        time_to: Annotated[
            str,
            Field(description="End time as EPOCH SECONDS (NOT a dateparser string). Empty = now."),
        ] = "",
    ) -> str:
        """Build a nested top-N hierarchy across Arkime fields (a treemap / drill-down).

        Returns a nested hierarchy (level 1 -> its top level-2 values -> ...),
        matching Arkime's SPI-graph hierarchy view. Unlike malcolm_aggregate's
        flat multi-field buckets and arkime_multiunique's flat tuple list, the
        result is nested. For a single field plus a time graph use
        arkime_spigraph; for a source/destination graph use arkime_connections.
        Returns the raw Arkime spigraph-hierarchy response (nested value tree).
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

    @mcp.tool(title="Extract file by hash", annotations=_READ)
    async def arkime_file_by_hash(
        file_hash: Annotated[
            str,
            Field(
                description="The transferred file's content hash: md5 (32 hex "
                "chars) or sha256 (64 hex chars). Taken from a session's "
                "http.md5 / http.sha256 field (see arkime_session_detail)."
            ),
        ],
        url_only: Annotated[
            bool,
            Field(description="If true, return only the download URL and skip the download."),
        ] = False,
    ) -> str:
        """Extract the transferred file matching a content hash across sessions; returns METADATA ONLY.

        Pivots from a file-hash IOC to the actual bytes: Arkime finds the most
        recent session carrying a body with this hash, resolves the capture node,
        and fetches the file. Checks the file-magic and returns metadata (magic,
        size) only — the raw bytes are never put in the MCP response — and
        enforces a size cap, refusing oversized files (use url_only then). Get
        the hash from arkime_session_detail (http.md5 / http.sha256). For the
        whole session's packets rather than one carried file use
        arkime_session_pcap. Returns whether a match was found plus its metadata.
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

    @mcp.tool(title="Export sessions as CSV", annotations=_READ)
    async def arkime_sessions_csv(
        expression: Annotated[
            str,
            Field(
                description="Arkime expression syntax to scope the rows, "
                'e.g. "ip == 192.0.2.7 && protocols == dns". Empty = all sessions.'
            ),
        ] = "",
        fields: Annotated[
            str,
            Field(
                description="Comma-separated columns, as ECS DOTTED names "
                '("source.ip,destination.port") — the names malcolm_field_search '
                "returns, NOT Arkime db names (srcIp) or expression names "
                "(ip.src). A name Arkime does not accept is never reported as an "
                "error: measured on 6.6.0 it either comes back as an empty column "
                "or the request hangs until it times out. Leave empty for "
                "Arkime's default columns, which always work."
            ),
        ] = "",
        limit: Annotated[int, Field(description="Max rows to export.", ge=1, le=10000)] = 100,
        time_from: Annotated[
            str,
            Field(
                description="Start time as EPOCH SECONDS (NOT a dateparser string). "
                "Empty = Arkime's default recent window."
            ),
        ] = "",
        time_to: Annotated[
            str,
            Field(description="End time as EPOCH SECONDS (NOT a dateparser string). Empty = now."),
        ] = "",
    ) -> str:
        """Export many sessions as a compact CSV table, one row each.

        Use this when you want a lot of sessions cheaply: CSV costs roughly half
        the tokens of the same rows as JSON, so it suits "show me every DNS
        session this host made" when you intend to read the result as a table.
        Use arkime_sessions instead when you need a session id to drill into
        (this returns none), and arkime_connections for a who-talked-to-whom
        summary — Arkime's connections.csv is not wrapped here because on 6.6.0
        it emits nine header columns over seven-column rows, so every column
        after the second is mislabeled.

        Returns raw CSV TEXT with a header row, not JSON. `limit` bounds the
        rows exactly. A request naming a column Arkime does not accept hangs
        rather than failing, so a timeout is reported as a probable `fields`
        problem.
        """
        wanted = ",".join(f.strip() for f in fields.split(",") if f.strip())
        try:
            text = await client.arkime_sessions_csv(
                expression=expression.strip(),
                limit=min(max(1, limit), 10000),
                fields=wanted,
                time_from=time_from.strip(),
                time_to=time_to.strip(),
            )
        except httpx.TimeoutException:
            return (
                "Arkime CSV export timed out. When `fields` is set this almost "
                "always means a column name Arkime does not accept: it takes ECS "
                "dotted names such as source.ip and destination.port, and never "
                "answers for a db name (srcIp) or an expression name (ip.src). "
                "Retry with no fields to get the default columns."
            )
        except Exception as exc:  # noqa: BLE001
            return f"Arkime CSV export failed: {exc}"

        return text or "(no rows)"
