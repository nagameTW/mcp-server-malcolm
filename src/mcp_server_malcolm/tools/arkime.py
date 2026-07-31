"""Arkime session search and aggregation: find sessions, then profile them.

The per-session content reads (detail, PCAP, payload, carried files) moved to
arkime_content.py when this file crossed 1200 lines.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated, Any

import httpx
from pydantic import Field

from mcp_server_malcolm.errors import ToolInputError, UpstreamError

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from mcp_server_malcolm.client import MalcolmClient

# Arkime's sessions/summary is a 400 without a `fields` list, so the tool sends
# one. protocols is present on every session and its breakdown is short.
_SUMMARY_DEFAULT_FIELDS = "protocols"

# Shared: every Arkime tool here reads from the external Arkime (via Malcolm)
# server, never mutates it.
_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}


def register_arkime_tools(mcp: MCPServer, client: MalcolmClient) -> None:
    """Register Arkime session search, aggregation and export tools."""

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
        """Discover the field names Arkime's routes accept — call before writing one.

        Arkime names the same field more than once, and which spelling a
        parameter wants is decided per PARAMETER, not per tool. This is the
        field-discovery tool for every arkime_* tool, as malcolm_field_search
        is for the malcolm_* ones. Returns "exp | db | type | group" lines with
        the help text. Route the two columns like this — every number measured
        on Malcolm v26.07.1 over one 24-hour window:

        - "exp" (ip.src, port.dst, protocols): every `expression` argument, and
          the field lists of arkime_unique, arkime_multiunique and
          arkime_spigraphhierarchy. exp=ip.src,ip.dst returned 692 multiunique
          rows and 140 spigraphhierarchy table rows; exp=srcIp,dstIp returned
          the body "Unknown expression srcIp" under HTTP 200 from multiunique
          and HTTP 403 from spigraphhierarchy, so those three parameters reject
          a db name before the request rather than pass it on.
        - "db" (srcIp, dstPort, node): arkime_connections' src_field and
          dst_field, and nothing else. srcIp/dstIp returned a 10-node graph;
          ip.src/dstIp returned HTTP 403 and srcIp/port.dst HTTP 500.
        - A THIRD spelling, the storage path, is what arkime_spigraph's field
          and arkime_spiview's spi take. It is the same string as the db column
          for 4,034 of the 4,051 fields here; the other seventeen print a
          camelCase db alias and store under a dotted name instead — srcIp is
          source.ip, dstPort is destination.port, totBytes is network.bytes,
          dstGEO is destination.geo.country_iso_code — and the dotted one is
          what those two parameters want.

        A dotted storage path is also accepted wherever the exp column is:
        exp=destination.port returned the same 10,000 unique lines as
        exp=port.dst and exp=network.bytes 5,544, while exp=dstPort returned
        none. It is the one spelling that answers on every route.

        The catalogue is far bigger than a keyword suggests — measured on
        v26.07.1: 4,051 fields, of which 942 match "ip" and 114 match "http" —
        so the list usually stops at `limit` and says "... and N more". Read a
        field you cannot see as "not on this page" rather than absent, and
        narrow with group, of which this deployment has 192, instead of raising
        limit.
        """
        results = await client.search_arkime_fields(keyword=keyword, group=group)

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
                "returns — look them up with arkime_field_search. A name Arkime "
                "cannot resolve is not an error: measured on Malcolm v26.07.1, "
                '"nosuch.field==1" over a window holding 6M sessions answered '
                "matched:0 with no marker, indistinguishable from a query that "
                "genuinely found nothing."
            ),
        ],
        limit: Annotated[
            int,
            Field(
                description="Max sessions to return. Each row is a JSON object "
                "carrying its own keys, which is why this stops at 100; when you "
                "want thousands of rows and no session id, arkime_sessions_csv "
                "takes up to 10,000.",
                ge=1,
                le=100,
            ),
        ] = 10,
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

        This is the ONLY search returning a session id, and every
        session-scoped tool needs one: arkime_session_detail,
        arkime_session_pcap, arkime_session_payload,
        arkime_session_file_by_hash and arkime_add_tags. For one session's own
        row use arkime_session_detail; for its PCAP bytes/metadata use
        arkime_session_pcap. To search with Malcolm filter dicts and dateparser
        times instead of Arkime expressions and epoch seconds, use
        malcolm_search. Returns `matched` (how many sessions the expression
        found, which is usually far more than are returned), `showing`, and the
        session rows. Each row's `id` is what the drill-down tools take.
        """
        if not expression.strip():
            raise ToolInputError(
                'expression is required — Arkime expression syntax, e.g. "ip==192.0.2.77" '
                'or "protocols==dns". Look field names up with arkime_field_search.'
            )

        data = await client.arkime_sessions(
            expression=expression.strip(),
            limit=min(max(1, limit), 100),
            time_from=time_from,
            time_to=time_to,
        )

        sessions = data.get("data", [])
        # recordsFiltered is how many sessions the expression matched;
        # recordsTotal is how many exist in the index at all. Reporting the
        # latter as "total" told an agent that `protocols == ssh` matched
        # 6,030,807 sessions when it matched 134 (measured on Malcolm v26.07.1).
        result = {
            "matched": data.get("recordsFiltered", 0),
            "showing": len(sessions),
            "sessions": sessions,
        }
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)

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
            Field(
                description="Include a per-value occurrence count (default true). "
                "Turning it off cuts about a third of the characters (measured on "
                "v26.07.1: 91,033 down to 59,931 for one field over a 24-hour "
                "window) and is the right choice when you only need the value set "
                "itself — to paste into arkime_create_shortcut, for instance."
            ),
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
        directly. "(no values)" has TWO causes and this route cannot tell them
        apart: the window holds nothing, or the field name does not resolve.
        Measured on Malcolm v26.07.1, field="nosuch.field" over a window with
        6M sessions answers HTTP 200 with a zero-byte body, exactly like a
        genuinely empty result — where every sibling is loud (arkime_multiunique
        says "Unknown expression", arkime_spigraphhierarchy answers 403,
        arkime_sessions_summary lists the name in ignored_fields). So check the
        spelling against arkime_field_search's exp column before assuming the
        window is wrong; only then pass time_from.

        A wide field is truncated silently at Arkime's aggregation ceiling of
        10,000 values, with no marker and no error: measured on Malcolm v26.07.1, one
        port field returned exactly 10,000 lines over a window that held 16,005
        distinct values. Treat a round 10,000 as "there are more", and scope
        with expression rather than reading it as the whole value set.
        """
        if not field.strip():
            raise ToolInputError(
                'field is required — one Arkime field expression, e.g. "ip.dst" or '
                '"protocols". Look it up with arkime_field_search.'
            )

        text = await client.arkime_unique(
            expression=expression.strip(),
            field=field.strip(),
            counts=counts,
            time_from=time_from.strip(),
            time_to=time_to.strip(),
        )

        return text or "(no values)"

    @mcp.tool(title="Graph top values over time", annotations=_READ)
    async def arkime_spigraph(
        field: Annotated[
            str,
            Field(
                description="One Arkime field named by its STORAGE PATH, e.g. "
                '"destination.ip", "protocol", "http.host" — arkime_field_search\'s '
                "db column. NOT the exp column: measured on Malcolm v26.07.1 over one "
                "24-hour window, field=destination.ip, field=protocol and "
                "field=http.host each filled the requested size, while "
                "field=ip.dst, field=protocols, field=dstIp, field=port.dst and "
                "field=dstPort each returned 0 — every one of them HTTP 200, so "
                "an empty result is the only signal a name was wrong. The db "
                "column is "
                "the storage path for all but seventeen fields, which print a "
                "camelCase alias (srcIp, dstPort, totBytes, dstGEO) and store "
                "under the dotted name (source.ip, destination.port, "
                "network.bytes, destination.geo.country_iso_code); pass the "
                "dotted one for those."
            ),
        ],
        expression: Annotated[
            str,
            Field(
                description="Optional Arkime expression syntax to scope the data. "
                "Empty = all sessions."
            ),
        ] = "",
        size: Annotated[
            int,
            Field(
                description="Number of top values to return. It bounds how many "
                "distinct values are graphed, never how many time buckets each "
                "one is split into — Arkime decides that from the time range.",
                ge=1,
                le=100,
            ),
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

        The bucket width is Arkime's choice, taken from the range asked for and
        not exposed as a parameter — measured on Malcolm v26.07.1: 1 second for a
        10-minute window, 60 seconds from 30 minutes out to 2 days, an hour at
        7 days and wider. Buckets holding no session are left out entirely, so
        a 24-hour window came back as 368 buckets rather than 1,440. Compare
        the shape of two graphs, never their bucket counts.

        An empty items list is HTTP 200 whatever went wrong, but the response
        says which: `recordsFiltered` counts the sessions the expression and
        window matched, before the field is aggregated. Measured on Malcolm v26.07.1,
        field=ip.dst over a window holding data returned 0 items with
        recordsFiltered 6,016,935, while field=destination.ip with no time
        range returned 0 items with recordsFiltered 0. So a non-zero
        recordsFiltered under an empty items list means the FIELD NAME did not
        resolve — re-read the `field` description, the storage-path spelling is
        the usual cause. Only recordsFiltered 0 is a time-range problem: pass
        time_from, since Arkime defaults to a recent-only window that a
        historical capture falls outside.
        """
        if not field.strip():
            raise ToolInputError(
                'field is required — one Arkime field expression, e.g. "ip.dst" or '
                '"http.host". Look it up with arkime_field_search.'
            )

        data = await client.arkime_spigraph(
            field=field.strip(),
            expression=expression.strip(),
            size=min(max(1, size), 100),
            time_from=time_from,
            time_to=time_to,
        )

        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(title="Profile many fields at once", annotations=_READ)
    async def arkime_spiview(
        spi: Annotated[
            str,
            Field(
                description="Comma-separated Arkime fields named by their STORAGE "
                'PATH, each optionally suffixed ":<count>" to cap its values, e.g. '
                '"protocol:10,destination.ip:20,http.host" — the same spelling '
                "arkime_spigraph's field takes. NOT the exp column: measured on "
                "v26.07.1 over one 24-hour window, spi=protocol:10 returned 10 "
                "buckets, spi=destination.ip:20 returned 20 and spi=http.host:5 "
                "returned 5, while spi=protocols:10, spi=ip.dst:20 and spi=dstIp:20 "
                "each returned an empty bucket list under HTTP 200. For the "
                "seventeen fields whose db column is a camelCase alias, pass the "
                "dotted storage path instead (source.ip for srcIp, "
                "destination.port for dstPort). A field left without the suffix "
                "takes Arkime's own default of 10 values, not all of them: "
                "spi=protocol:10 returned 10 of that field's 52 values "
                "(spi=protocol:1000 returns all 52) and swept the remaining 139,902 "
                "sessions into sum_other_doc_count. Pass a count whenever you need "
                "a known depth."
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

        Each field also reports sum_other_doc_count, the sessions its listed
        values do not account for; a large one means the top-N hid most of the
        distribution.

        A field always comes back under its own key, with an empty bucket list
        and HTTP 200 when nothing aggregated, so the key's presence proves
        nothing. `recordsFiltered` is what separates the two causes: it counts
        the sessions the expression and window matched, before any field is
        aggregated. Measured on Malcolm v26.07.1, spi=protocols:10 over a window
        holding data returned 0 buckets with recordsFiltered 6,016,935, while
        spi=protocol:10 with no time range returned 0 buckets with
        recordsFiltered 0. A non-zero recordsFiltered under empty buckets means
        that FIELD NAME did not resolve; only recordsFiltered 0 is a time-range
        problem, fixed by passing time_from.
        """
        if not spi.strip():
            raise ToolInputError(
                "spi is required — comma-separated Arkime fields, each optionally "
                'suffixed ":<count>", e.g. "protocols:10,ip.dst:20".'
            )

        data = await client.arkime_spiview(
            spi=spi.strip(),
            expression=expression.strip(),
            time_from=time_from,
            time_to=time_to,
        )

        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(title="Build connection graph", annotations=_READ)
    async def arkime_connections(
        src_field: Annotated[
            str,
            Field(
                description="Arkime db field for source nodes (default srcIp). "
                "Common choices: srcIp, dstIp, dstPort, node — arkime_field_search's "
                "db column. The dotted storage path works here too and gives the "
                "identical graph: measured on Malcolm v26.07.1 over one 24-hour window, "
                "srcIp/dstIp and source.ip/destination.ip both returned 10 nodes and "
                "8 links. What this route will NOT take is the exp column: "
                "srcField=ip.src returned HTTP 403 and dstField=port.dst HTTP 500 "
                '"TypeError: Cannot read properties of undefined", so the sixteen '
                "expression names whose db spelling differs are refused here before "
                "the request is sent."
            ),
        ] = "srcIp",
        dst_field: Annotated[
            str,
            Field(
                description="Arkime db field for destination nodes (default dstIp; "
                "dstPort graphs by port instead of by host — measured on Malcolm v26.07.1, "
                "srcIp/dstPort returned 15 nodes and 11 links against srcIp/dstIp's "
                "10 and 8). Same vocabulary as src_field: db column or dotted storage "
                "path, never the exp column."
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
        src/dst fields take Arkime *db* names (srcIp, dstIp, dstPort, node) or
        the dotted storage paths (source.ip, destination.port), which resolve to
        the same graph; the one vocabulary this route rejects is the expression
        names arkime_sessions uses in `expression` (ip.src, port.dst). For
        distinct field-tuple pairs as text rather than a graph use
        arkime_multiunique; for a nested top-N hierarchy use
        arkime_spigraphhierarchy. Returns the raw Arkime connections response
        (nodes and links).

        The graph is built from a bounded slice of the matching sessions rather
        than from all of them, and that bound is not a parameter here: measured
        on Malcolm v26.07.1, a 24-hour window whose expression matched 6,005,737
        sessions produced 10 nodes and 8 links, while the same window held 112
        distinct source addresses. Nothing in the response marks the shortfall,
        so narrow with expression and a tight window before reading a sparse
        graph as "these are the only hosts talking".
        """
        data = await client.arkime_connections(
            src_field=src_field.strip() or "srcIp",
            dst_field=dst_field.strip() or "dstIp",
            expression=expression.strip(),
            time_from=time_from,
            time_to=time_to,
        )

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

        "(no values)" with no time range usually means the data predates
        Arkime's default recent window rather than being absent: pass
        time_from. Every field added multiplies the rows, well past the 10,000
        values arkime_unique stops at — measured on Malcolm v26.07.1 over one 24-hour
        window, a two-field tuple returned 22,548 lines and a three-field tuple
        50,817, about 2 MB of text. Scope it with expression first, or size the
        match with
        arkime_sessions_summary before asking for the tuples.
        """
        if not fields.strip():
            raise ToolInputError(
                "fields is required — comma-separated Arkime field names forming the "
                'tuple, e.g. "source.ip,destination.port".'
            )

        text = await client.arkime_multiunique(
            fields=fields.strip(),
            expression=expression.strip(),
            counts=counts,
            time_from=time_from,
            time_to=time_to,
        )

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

        Level 1 is the outermost, and every deeper level's top values are
        counted inside their own parent rather than globally, so a value that
        is common overall can be missing from a branch where it is rare. Each
        level keeps Arkime's top 20 and this tool does not expose that number:
        measured on Malcolm v26.07.1, a two-level tree returned 20 first-level values
        out of the 112 the window held, each parent carrying a different number
        of children. An empty tree with no time range usually means the data
        predates Arkime's default recent window: pass time_from.
        """
        if not fields.strip():
            raise ToolInputError(
                "fields is required — comma-separated Arkime fields naming the "
                'hierarchy levels in order, e.g. "source.ip,destination.ip".'
            )

        data = await client.arkime_spigraphhierarchy(
            fields=fields.strip(),
            expression=expression.strip(),
            time_from=time_from,
            time_to=time_to,
        )

        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    # Arkime's own connections.csv is deliberately not wrapped: on Arkime 6.6.0 it
    # emits nine header columns over seven-column rows, so every column after
    # the second is mislabeled. arkime_connections serves the same question as
    # JSON instead.
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
                "error: measured on Arkime 6.6.0 it either comes back as an empty column "
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
        summary.

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
        except UpstreamError as exc:
            # The client converts every httpx failure to UpstreamError, so the
            # original type survives only as __cause__ -- and a timeout is the
            # one failure here that names its own likely cause. status is None
            # for a connect error too, so it cannot stand in for this test.
            if not isinstance(exc.__cause__, httpx.TimeoutException):
                raise
            raise UpstreamError(
                "Arkime CSV export timed out. When `fields` is set this almost "
                "always means a column name Arkime does not accept: it takes ECS "
                "dotted names such as source.ip and destination.port, and never "
                "answers for a db name (srcIp) or an expression name (ip.src). "
                "Retry with no fields to get the default columns.",
                exc.status,
            ) from exc

        return text or "(no rows)"

    @mcp.tool(title="Size a session set before acting on it", annotations=_READ)
    async def arkime_sessions_summary(
        expression: Annotated[
            str,
            Field(
                description="Arkime expression syntax scoping what is counted, "
                'e.g. "protocols == http && ip.dst == 203.0.113.5". Empty counts '
                "every session in the window."
            ),
        ] = "",
        fields: Annotated[
            str,
            Field(
                description="Comma-separated fields to break the totals down by, one "
                'breakdown each, e.g. "protocols,ip.dst". Arkime expression names '
                '("ip.src") and dotted ECS names ("source.ip") both work; a db name '
                '("srcIp") is silently ignored upstream and is reported back in '
                "ignored_fields. Cannot be empty — Arkime rejects the request "
                "without it — so an empty value falls back to protocols."
            ),
        ] = _SUMMARY_DEFAULT_FIELDS,
        time_from: Annotated[
            str,
            Field(
                description="Start time as EPOCH SECONDS (NOT a dateparser string). "
                "Empty summarises Arkime's default recent window, which on a "
                "historical capture reports zero and looks like a broken tool."
            ),
        ] = "",
        time_to: Annotated[
            str,
            Field(description="End time as EPOCH SECONDS (NOT a dateparser string). Empty = now."),
        ] = "",
    ) -> str:
        """Total sessions, bytes and packets for an expression, plus per-field breakdowns.

        Sizes a result set in one call, before something expensive acts on it.
        It is what arkime_create_hunt's total_sessions wants, in one call and
        in the same dialect — count means a dialect switch, and neither count
        nor arkime_sessions reports bytes or packets. For the matching sessions
        themselves use arkime_sessions, and for a value distribution without
        the totals use arkime_unique or arkime_spiview.

        Returns JSON {"totals", "breakdowns"}: totals carry sessions, bytes,
        dataBytes, packets and the first/last packet timestamps (Arkime's empty
        histogram scaffolding is dropped); each breakdown carries its field name
        and its top values with per-value session/byte/packet counts. An
        expression that matches nothing is a successful answer, not an error:
        the totals read 0 and every field asked for still comes back as a
        breakdown with an empty `data` list — measured with
        "ip == 203.0.113.99" over 1714003200-1714089600. A field Arkime declined
        to break down is listed in ignored_fields rather than passed over in
        silence, since upstream reports it the same way as a field with no
        values.
        """
        wanted = ",".join(f.strip() for f in fields.split(",") if f.strip())
        data = await client.arkime_sessions_summary(
            fields=wanted or _SUMMARY_DEFAULT_FIELDS,
            expression=expression.strip(),
            time_from=time_from.strip(),
            time_to=time_to.strip(),
        )

        # graph is an empty histogram scaffold on this route and map is {}; both
        # cost the caller context and answer nothing.
        totals = {k: v for k, v in (data.get("totals") or {}).items() if k not in ("graph", "map")}
        breakdowns = data.get("breakdowns") or []
        result: dict[str, Any] = {"totals": totals, "breakdowns": breakdowns}

        answered = {b.get("field") for b in breakdowns}
        if ignored := [
            f for f in (wanted or _SUMMARY_DEFAULT_FIELDS).split(",") if f not in answered
        ]:
            result["ignored_fields"] = ignored
            result["ignored_note"] = (
                "Arkime returned no breakdown for these. Either they hold no value in "
                "the matched sessions, or the name is one it does not accept — it takes "
                "expression names (ip.src) and dotted ECS names (source.ip), never db "
                "names (srcIp). Check with arkime_field_search."
            )
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(title="Compile an Arkime expression to OpenSearch DSL", annotations=_READ)
    async def arkime_build_query(
        expression: Annotated[
            str,
            Field(
                description="Arkime expression syntax to compile, e.g. "
                '"protocols == http && ip.dst == 203.0.113.5". Empty compiles the '
                "time window alone, which is a useful starting skeleton."
            ),
        ] = "",
        time_from: Annotated[
            str,
            Field(
                description="Start time as EPOCH SECONDS (NOT a dateparser string). "
                "It becomes a range clause on lastPacket in the compiled query and "
                "decides which daily indices the search covers."
            ),
        ] = "",
        time_to: Annotated[
            str,
            Field(description="End time as EPOCH SECONDS (NOT a dateparser string). Empty = now."),
        ] = "",
    ) -> str:
        """Translate an Arkime expression into the OpenSearch DSL it compiles to, without running it.

        Do NOT use this to run a search: nothing is executed and no session
        comes back. Come here only when the DSL itself is the goal — a
        substring, wildcard, fuzzy or script clause Arkime's syntax cannot say,
        or a look at the compiled query before spending a scan on it. Compile
        the part the expression can express, edit the returned DSL, then run it
        with search_dsl (or count, which takes the inner query clause only).
        When the expression already says what you mean, send it straight to
        arkime_sessions for the rows or arkime_sessions_summary for the totals.

        Returns JSON shaped for that handoff: `index` and `query_dsl`, the two
        arguments search_dsl takes, plus the compiled body's own size and sort,
        which search_dsl overrides with its `size`. `query_dsl` is returned as
        an object so it can be edited, but search_dsl and count declare it a
        JSON STRING: serialise it before the handoff (the object verbatim is
        refused with "Input should be a valid string"). `index` is the concrete
        daily index the window resolves to, so a window covering no captured day
        shows up here rather than as a mysteriously empty search. An expression
        Arkime cannot parse is reported as an error naming the offending token:
        upstream answers 200 with an error field and no query, which would
        otherwise read as success.
        """
        data = await client.arkime_buildquery(
            expression=expression.strip(),
            time_from=time_from.strip(),
            time_to=time_to.strip(),
        )

        esquery = data.get("esquery") if isinstance(data, dict) else None
        if not isinstance(esquery, dict):
            # Measured on Malcolm v26.07.1: a parse error and an unknown field are both
            # HTTP 200 carrying {"error": ...} and no esquery, so nothing raised
            # on the way here. Left alone it would look like a successful
            # translation of an empty query.
            detail = (data or {}).get("error") if isinstance(data, dict) else None
            raise ToolInputError(
                f"Arkime could not compile that expression: {detail or data!r}. "
                f"Field names are Arkime's own — look them up with arkime_field_search — "
                f"and every clause must be field-operator-value."
            )

        return json.dumps(
            {
                "index": data.get("indices", ""),
                "query_dsl": esquery,
                "note": "Hand index to search_dsl unchanged, and query_dsl SERIALISED "
                "as a JSON string — search_dsl declares that argument a string, so the "
                "object as it appears here is refused with "
                '"Input should be a valid string". search_dsl\'s own size argument then '
                "overrides the size inside query_dsl.",
            },
            indent=2,
            ensure_ascii=False,
            default=str,
        )
