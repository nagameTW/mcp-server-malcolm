"""Field discovery and validation tools -- anti-hallucination layer."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from pydantic import Field

from mcp_server_malcolm.tools._parse import parse_json_object

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from mcp_server_malcolm.client import MalcolmClient

# Shared: every field tool here reads Malcolm's index metadata, never mutates.
_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}


def register_field_tools(mcp: MCPServer, client: MalcolmClient) -> None:
    """Register field search, value enumeration, and profile tools."""

    @mcp.tool(title="Search index fields", annotations=_READ)
    async def malcolm_field_search(
        keyword: Annotated[
            str,
            Field(
                description='Substring to match anywhere in a field name, e.g. "useragent", '
                '"signature". Empty = no keyword filter.'
            ),
        ] = "",
        prefix: Annotated[
            str,
            Field(
                description='Field-name prefix to match, e.g. "zeek.dns", "suricata.alert", '
                '"rule". Empty = no prefix filter.'
            ),
        ] = "",
        field_type: Annotated[
            str,
            Field(
                description="Filter by the type Malcolm reports for a field — measured on "
                'Malcolm v26.07.1 those are "string", "integer", "float", "date", '
                '"ip" and "geo". They are NOT OpenSearch type names: "keyword", "long" '
                'and "text" match nothing here, even though index_mapping reports the '
                "same fields under those names. Empty = any type."
            ),
        ] = "",
    ) -> str:
        """Discover which field NAMES exist in Malcolm's index, by keyword, prefix, or type.

        Use this first, before any query, to confirm a field name exists — Malcolm uses
        non-standard names (e.g. http.useragent, NOT http.user_agent). To then see the
        VALUES a field holds, use malcolm_field_values; to see which datasets contain
        it, use malcolm_field_profile. Do NOT source an arkime_* argument from here:
        these are the names malcolm_* and search_dsl take, and Arkime has its own
        spelling for the same field (ip.src, srcIp) that arkime_field_search reports.
        Pass at least one argument. Returns a text list of "name (type)" lines,
        sorted alphabetically.

        Arguments narrow (AND), they never widen, and the mapping is big enough
        that one keyword rarely lands: it runs to thousands of fields, and a
        keyword as common as "ip" matches over a thousand of them on its own.
        The header line counts every match but only the first 100 names are
        printed, so add a prefix or a field_type rather than reading the printed
        list as the whole answer.
        """
        results = await client.search_fields(
            keyword=keyword,
            prefix=prefix,
            field_type=field_type,
        )

        if not results:
            return "No fields found matching the criteria."

        lines = [f"Found {len(results)} fields:"]
        for name, ftype in results[:100]:
            lines.append(f"  {name} ({ftype})")

        if len(results) > 100:
            lines.append(f"  ... and {len(results) - 100} more")

        return "\n".join(lines)

    @mcp.tool(title="List field values", annotations=_READ)
    async def malcolm_field_values(
        field: Annotated[
            str,
            Field(
                description='Field to enumerate distinct values for, e.g. "event.dataset" -> '
                '["conn","dns","ssl",...]; "network.protocol" -> ["tcp","udp","icmp"]; '
                '"suricata.alert.severity" -> [1,2,3]. Confirm the name with malcolm_field_search.'
            ),
        ],
        limit: Annotated[
            int,
            Field(
                description="Max distinct values to return, ordered by document count.",
                ge=1,
                le=500,
            ),
        ] = 30,
        filters: Annotated[
            str,
            Field(
                description="Optional JSON filter (Malcolm filter syntax) scoping the "
                "enumeration. Empty = all documents."
            ),
        ] = "{}",
        time_from: Annotated[
            str,
            Field(
                description="Start time, dateparser format. Empty = the last 24 hours, "
                "which holds nothing on a capture older than that."
            ),
        ] = "",
        time_to: Annotated[
            str, Field(description="End time, dateparser format. Empty = now.")
        ] = "",
    ) -> str:
        """List a single field's distinct VALUES with per-value document counts.

        Use this to see what values a field actually holds before filtering on it, so
        you don't invent values. To confirm the field NAME exists first, use
        malcolm_field_search; to see which datasets carry the field, use
        malcolm_field_profile. For multi-field or nested bucketing, use
        malcolm_aggregate. A "-" in the output is Malcolm's placeholder for
        documents where the field is absent, not a value you can filter on.
        Returns a text list of "value (N docs)" lines.

        With no time range this reads only the last 24 hours, so a value that
        exists only in older data is missing here and reads as invalid —
        measured on Malcolm v26.07.1, network.protocol lists nothing at the
        default window while its top value carries millions of documents once
        time_from reaches the capture. Pass time_from before concluding a value
        is not in this Malcolm.
        """
        parsed_filters = parse_json_object(filters, "filters", '{"event.dataset":"alert"}')

        buckets = await client.field_values(
            field=field,
            limit=min(max(1, limit), 500),
            filters=parsed_filters,
            time_from=time_from,
            time_to=time_to,
        )

        if not buckets:
            # Distinguish "wrong name" from "no data": Malcolm renames fields on
            # ingest, so a plausible name can be one that is simply never stored.
            if hint := await client.explain_unknown_fields([field]):
                return hint
            return (
                f"No values found for field '{field}'. The field exists but holds no "
                f"data in this window — widen time_from/time_to or relax the filters."
            )

        lines = [f"Values for '{field}' ({len(buckets)} distinct):"]
        for b in buckets:
            lines.append(f"  {b.get('key', '?')}  ({b.get('doc_count', 0):,} docs)")

        return "\n".join(lines)

    @mcp.tool(title="Profile field by dataset", annotations=_READ)
    async def malcolm_field_profile(
        field: Annotated[
            str,
            Field(
                description="Field name to profile across datasets, e.g. "
                '"zeek.ssl.server_name" (only present in SSL records).'
            ),
        ],
        time_from: Annotated[
            str,
            Field(
                description="Start time, dateparser format. Empty = the last 24 hours; "
                "pass a range for historical data."
            ),
        ] = "",
        time_to: Annotated[
            str, Field(description="End time, dateparser format. Empty = now.")
        ] = "",
    ) -> str:
        """Show which event.dataset types actually contain a given field, with doc counts.

        Use this to learn where a field lives (e.g. whether it only appears in SSL or DNS
        records) before scoping a query. To confirm the field NAME first, use
        malcolm_field_search; to list its distinct VALUES, use malcolm_field_values.

        Behavior: first resolves the name against the index mapping, then aggregates over
        event.dataset. Three distinct text outcomes — (1) unknown field → a "not found"
        message with close-name suggestions (no profile); (2) known field but no matching
        documents in the time window → an "exists but no documents" message; (3) a
        per-dataset "event.dataset=<name> (N docs)" list. The dataset counts honor the
        time window: with no range it uses the last 24 hours, so a field that only has
        old data can resolve as known yet profile as empty — pass time_from/time_to to
        reach historical data. Returns plain text, not JSON.
        """
        # First check if the field exists at all
        resolution = await client.resolve_field(field)
        if not resolution.get("exists"):
            suggestions = resolution.get("suggestions", {})
            suggestion = resolution.get("suggestion", "")
            if suggestion:
                return (
                    f"Field '{field}' not found. Did you mean: {suggestion} "
                    f"({suggestions.get(suggestion, 'unknown')})"
                )
            if suggestions:
                lines = [f"Field '{field}' not found. Similar fields:"]
                for s, t in suggestions.items():
                    lines.append(f"  {s} ({t})")
                return "\n".join(lines)
            return f"Field '{field}' not found in the index mapping."

        # Profile: which datasets have this field
        profile = await client.field_profile(field, time_from=time_from, time_to=time_to)

        if not profile:
            return (
                f"Field '{field}' exists ({resolution['type']}) "
                f"but no documents with this field were found."
            )

        lines = [
            f"Field '{field}' ({resolution['type']}) is present in:",
        ]
        for entry in profile:
            lines.append(f"  event.dataset={entry['dataset']}  ({entry['doc_count']:,} docs)")

        return "\n".join(lines)
