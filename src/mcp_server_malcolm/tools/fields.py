"""Field discovery and validation tools -- anti-hallucination layer."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient


def register_field_tools(mcp: FastMCP, client: MalcolmClient) -> None:
    """Register field search, value enumeration, and profile tools."""

    @mcp.tool()
    async def malcolm_field_search(
        keyword: str = "",
        prefix: str = "",
        field_type: str = "",
    ) -> str:
        """Search available field names in Malcolm's index.

        Use this tool BEFORE querying to verify field names exist.
        Malcolm uses NON-STANDARD field names (e.g. http.useragent, NOT http.user_agent).

        Args:
            keyword: Substring to search in field names (e.g. "useragent", "signature").
            prefix: Field name prefix (e.g. "zeek.dns", "suricata.alert", "rule").
            field_type: Filter by type (e.g. "keyword", "ip", "long", "date").

        At least one parameter should be provided. Results sorted alphabetically.
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

    @mcp.tool()
    async def malcolm_field_values(
        field: str,
        limit: int = 30,
        filters: str = "{}",
        time_from: str = "",
        time_to: str = "",
    ) -> str:
        """List distinct values for a field with document counts.

        Use this to discover what values a field actually contains
        BEFORE using it in a filter. Prevents value hallucination.

        Examples:
          field="event.dataset"            -> ["conn", "dns", "ssl", "http", "alert", ...]
          field="network.protocol"         -> ["tcp", "udp", "icmp", ...]
          field="suricata.alert.severity"  -> [1, 2, 3]
          field="event.severity_tags"      -> ["Informational", "Warning", ...]

        Args:
            field: The field to enumerate values for.
            limit: Maximum number of distinct values to return.
            filters: Optional JSON filter to scope the enumeration.
            time_from: Start time.
            time_to: End time.
        """
        parsed_filters = None
        if filters and filters.strip() not in ("", "{}", "null"):
            try:
                parsed_filters = json.loads(filters)
            except json.JSONDecodeError:
                pass

        buckets = await client.field_values(
            field=field,
            limit=min(max(1, limit), 500),
            filters=parsed_filters if isinstance(parsed_filters, dict) else None,
            time_from=time_from,
            time_to=time_to,
        )

        if not buckets:
            return f"No values found for field '{field}'. The field may not exist or has no data."

        lines = [f"Values for '{field}' ({len(buckets)} distinct):"]
        for b in buckets:
            lines.append(f"  {b.get('key', '?')}  ({b.get('doc_count', 0):,} docs)")

        return "\n".join(lines)

    @mcp.tool()
    async def malcolm_field_profile(
        field: str,
        time_from: str = "",
        time_to: str = "",
    ) -> str:
        """Show which event.dataset types contain a specific field.

        Helps determine if a field is available for a given data type.
        For example, zeek.ssl.server_name only exists in SSL records.

        Args:
            field: The field name to profile.
            time_from: Start time. Omit = recent-only; pass a range for historical data.
            time_to: End time.
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
