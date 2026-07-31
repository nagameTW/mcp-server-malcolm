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
        """Discover the field names Arkime expressions accept — call before writing one.

        Arkime's expression parser has its own vocabulary (ip.src, port.dst,
        protocols, country) and rejects the dotted ECS names malcolm_field_search
        reports (source.ip, destination.port). That makes this the field-discovery
        tool for every arkime_* tool, exactly as malcolm_field_search is for the
        malcolm_* ones. Each row gives both names: use "exp" inside an `expression`
        argument, and "db" where a tool asks for an Arkime db field (arkime_connections,
        arkime_multiunique). Returns "exp | db | type | group" lines with the help text.
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
        # 6,030,807 sessions when it matched 134 (measured on 26.07.1).
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
        arkime_create_hunt needs total_sessions and its own guidance sends you
        to count or arkime_sessions for it: both mean a second call, a dialect
        switch for count, and neither reports bytes or packets. Use this
        instead. For the matching sessions themselves use arkime_sessions, and
        for a value distribution without the totals use arkime_unique or
        arkime_spiview.

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

        Write the easy syntax, get the powerful one. This server's three query
        dialects are not interchangeable, and Arkime's is the friendliest to
        write but cannot express a substring or wildcard match, a fuzzy term or
        a script clause. Compile the part you can say here, edit the returned
        DSL, then run it with search_dsl (or count, which takes the inner query
        clause only). It is also how to see what an expression really asks
        before spending a scan on it — no search is executed here.

        Do NOT use this to run a search: nothing is executed and no session
        comes back. When the expression already says what you mean, send it
        straight to arkime_sessions for the rows, or arkime_sessions_summary for
        the totals — compiling it first buys nothing. Come here only when the
        DSL itself is the goal: a clause Arkime's syntax cannot express, or a
        look at the compiled query before it is run.

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
            # Measured on 26.07.1: a parse error and an unknown field are both
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
