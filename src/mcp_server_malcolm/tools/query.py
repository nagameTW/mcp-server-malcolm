"""Core query tools -- search, aggregate, alerts."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient

# Shared: every read tool here hits the external Malcolm server, never mutates.
_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}


def register_query_tools(mcp: FastMCP, client: MalcolmClient) -> None:
    """Register search, aggregation, and alert tools."""

    @mcp.tool(title="Search network traffic (Malcolm filters)", annotations=_READ)
    async def malcolm_search(
        filters: Annotated[
            str,
            Field(
                description="JSON object in Malcolm filter syntax (NOT OpenSearch DSL). "
                'Examples: {"event.dataset":"conn"}; {"source.ip":"192.0.2.77"}; '
                '{"event.dataset":"dns","zeek.dns.query":"*example.com*"}; '
                '{"!network.transport":"icmp"} excludes; '
                '{"network.direction":["inbound","outbound"]} is OR; '
                '{"!related.password":null} means the field must exist. Empty = match all.'
            ),
        ] = "{}",
        limit: Annotated[int, Field(description="Max documents to return.", ge=1, le=500)] = 20,
        time_from: Annotated[
            str,
            Field(
                description='Start time, dateparser format ("2024-01-01", "7 days ago"). '
                "Empty = Malcolm's default recent window."
            ),
        ] = "",
        time_to: Annotated[
            str, Field(description="End time, dateparser format. Empty = now.")
        ] = "",
        doctype: Annotated[
            str,
            Field(
                description="Target index. Empty = the Malcolm network index (Zeek/Suricata); "
                '"host"/"beat"* = host/beats logs; "arkime"/"session"* = the Arkime sessions index.'
            ),
        ] = "",
    ) -> str:
        """Search Malcolm's indexed network traffic using Malcolm's simple filter dict.

        Use this for field-based filtering with human-readable time ranges. To
        search with Arkime expression syntax instead, or when you need a session
        id to feed arkime_session_pcap / arkime_add_tags afterward, use
        arkime_sessions (only its rows carry that id). For raw OpenSearch DSL,
        use search_dsl. Confirm field names with malcolm_field_search first —
        Malcolm uses non-standard names. Returns the raw Malcolm /mapi/document
        response (matching documents).
        """
        parsed = _parse_filters(filters)
        data = await client.search(
            filters=parsed,
            limit=min(max(1, limit), 500),
            time_from=time_from,
            time_to=time_to,
            doctype=doctype.strip(),
        )
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(title="Aggregate traffic by field", annotations=_READ)
    async def malcolm_aggregate(
        fields: Annotated[
            str,
            Field(
                description="Comma-separated field names to aggregate on; multiple fields give "
                'multi-level buckets. E.g. "network.protocol"; "source.ip,destination.ip"; '
                '"suricata.alert.signature,suricata.alert.severity".'
            ),
        ],
        filters: Annotated[
            str,
            Field(description="JSON filter object (Malcolm filter syntax, see malcolm_search)."),
        ] = "{}",
        limit: Annotated[
            int, Field(description="Max buckets per aggregation level.", ge=1, le=500)
        ] = 50,
        time_from: Annotated[
            str, Field(description="Start time, dateparser format. Empty = recent window.")
        ] = "",
        time_to: Annotated[
            str, Field(description="End time, dateparser format. Empty = now.")
        ] = "",
        doctype: Annotated[
            str,
            Field(description="Target index selector (see malcolm_search). Empty = network index."),
        ] = "",
    ) -> str:
        """Aggregate network traffic into top-N value buckets for one or more fields.

        Use this to count distinct values (top talkers, protocol distribution)
        rather than fetch documents — for the documents themselves use
        malcolm_search. For distinct values of a single field with less setup,
        malcolm_field_values is simpler. Returns the raw Malcolm /mapi/agg
        response (bucket keys with doc counts).
        """
        parsed = _parse_filters(filters)
        data = await client.aggregate(
            fields=fields.strip(),
            filters=parsed,
            limit=min(max(1, limit), 500),
            time_from=time_from,
            time_to=time_to,
            doctype=doctype.strip(),
        )
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(title="Search Suricata alerts", annotations=_READ)
    async def malcolm_alerts(
        signature: Annotated[
            str, Field(description='Alert signature substring, e.g. "ET MALWARE", "CVE-2024".')
        ] = "",
        severity: Annotated[
            str,
            Field(
                description='Comma-separated severity levels, e.g. "1,2" (1=high, 2=medium, 3=low).'
            ),
        ] = "",
        source_ip: Annotated[str, Field(description="Filter by source IP.")] = "",
        dest_ip: Annotated[str, Field(description="Filter by destination IP.")] = "",
        category: Annotated[
            str,
            Field(
                description="Alert category substring, matched on ECS rule.category "
                "(Malcolm normalizes suricata.alert.category to it)."
            ),
        ] = "",
        action: Annotated[
            str, Field(description='Rule action: "allowed" or "blocked" (Suricata drop/reject).')
        ] = "",
        sid: Annotated[
            str,
            Field(
                description="Comma-separated Suricata signature IDs, matched on ECS rule.id "
                "(Malcolm renames suricata.alert.signature_id to it)."
            ),
        ] = "",
        limit: Annotated[int, Field(description="Max alerts to return.", ge=1, le=500)] = 20,
        time_from: Annotated[
            str, Field(description="Start time, dateparser format. Empty = recent window.")
        ] = "",
        time_to: Annotated[
            str, Field(description="End time, dateparser format. Empty = now.")
        ] = "",
    ) -> str:
        """Search Suricata alerts with structured parameters, no field knowledge needed.

        Use this instead of malcolm_search when hunting Suricata alerts: it maps
        each argument to the correct Malcolm field for you (you don't need to
        know whether it's suricata.alert.signature or rule.name). It always
        filters event.dataset=alert. Returns the raw Malcolm /mapi/document
        response (matching alert documents).
        """
        filters: dict[str, Any] = {"event.dataset": "alert"}

        if signature:
            filters["suricata.alert.signature"] = f"*{signature}*"
        if severity:
            sevs = [int(s.strip()) for s in severity.split(",") if s.strip().isdigit()]
            if len(sevs) == 1:
                filters["suricata.alert.severity"] = sevs[0]
            elif sevs:
                filters["suricata.alert.severity"] = sevs
        if source_ip:
            filters["source.ip"] = source_ip
        if dest_ip:
            filters["destination.ip"] = dest_ip
        if category:
            filters["rule.category"] = f"*{category}*"
        if action:
            filters["suricata.alert.action"] = action
        if sid:
            sids = [int(s.strip()) for s in sid.split(",") if s.strip().isdigit()]
            if len(sids) == 1:
                filters["rule.id"] = sids[0]
            elif sids:
                filters["rule.id"] = sids

        data = await client.search(
            filters=filters,
            limit=min(max(1, limit), 500),
            time_from=time_from,
            time_to=time_to,
        )
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def _parse_filters(raw: str) -> dict[str, Any] | None:
    """Parse filter JSON string, returning None for empty."""
    if not raw or raw.strip() in ("", "{}", "null", "none"):
        return None
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) and parsed else None
    except json.JSONDecodeError:
        return None
