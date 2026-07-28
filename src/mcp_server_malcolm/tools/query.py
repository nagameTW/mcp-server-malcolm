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

# How many distinct values a substring search scans, ordered by document count.
# Malcolm cannot match substrings server-side, so a signature/category search
# has to enumerate first; this bounds that enumeration.
_VALUE_SCAN_LIMIT = 500


def register_query_tools(mcp: FastMCP, client: MalcolmClient) -> None:
    """Register search, aggregation, and alert tools."""

    @mcp.tool(title="Search network traffic (Malcolm filters)", annotations=_READ)
    async def malcolm_search(
        filters: Annotated[
            str,
            Field(
                description="JSON object in Malcolm filter syntax (NOT OpenSearch DSL). "
                "Values are matched EXACTLY — Malcolm compiles this to a terms query, so "
                'wildcards are NOT supported and "*example*" matches only the literal '
                "string. Use search_dsl for substring/wildcard matching. "
                'Examples: {"event.dataset":"conn"}; {"source.ip":"192.0.2.77"}; '
                '{"zeek.dns.query":"ntp.ubuntu.com"}; '
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
                "Empty = ALL history (this tool's default, unlike malcolm_aggregate "
                "which defaults to the last 24 hours)."
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
        response (matching documents); when nothing matched and a filter names a
        field Malcolm does not index, the correct field name is reported above
        the response.
        """
        parsed = _parse_filters(filters)
        data = await client.search(
            filters=parsed,
            limit=min(max(1, limit), 500),
            time_from=time_from,
            time_to=time_to,
            doctype=doctype.strip(),
        )
        body = json.dumps(data, indent=2, ensure_ascii=False, default=str)
        return await _with_empty_hint(client, data.get("results"), parsed, body)

    @mcp.tool(title="Aggregate traffic by field", annotations=_READ)
    async def malcolm_aggregate(
        fields: Annotated[
            str,
            Field(
                description="Comma-separated field names to aggregate on; multiple fields give "
                'multi-level buckets. E.g. "network.protocol"; "source.ip,destination.ip"; '
                '"rule.name,suricata.alert.severity".'
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
            str,
            Field(
                description="Start time, dateparser format. Empty = the LAST 24 HOURS "
                "(unlike malcolm_search, which defaults to all history) — pass a range "
                "to reach older data."
            ),
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
        response (bucket keys with doc counts); when no buckets came back and an
        aggregated or filtered field is not one Malcolm indexes, the correct
        field name is reported above the response.
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
        body = json.dumps(data, indent=2, ensure_ascii=False, default=str)
        checked = [f for f in fields.split(",") if f.strip()] + list(parsed or {})
        return await _with_empty_hint(client, data.get("values"), checked, body)

    @mcp.tool(title="Search Suricata alerts", annotations=_READ)
    async def malcolm_alerts(
        signature: Annotated[
            str,
            Field(
                description='Alert signature substring, e.g. "ET MALWARE", "CVE-2024". '
                "Matched on ECS rule.name (Malcolm renames suricata.alert.signature to it)."
            ),
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
        filters event.dataset=alert.

        Behavior: `signature` and `category` are substring searches, which Malcolm
        cannot express in a filter (its filters are exact terms), so this tool
        resolves the substring against the field's 500 most common values first
        and filters on the matches. A substring that matches no recorded value
        returns a message saying so rather than an empty result set — that is the
        difference between "no such signature here" and "no alerts fired".
        Returns the raw Malcolm /mapi/document response (matching alert documents).
        """
        filters: dict[str, Any] = {"event.dataset": "alert"}

        if signature:
            # 11_suricata_logs.conf renames suricata.alert.signature to rule.name
            # outright — filtering the old name matches nothing, ever.
            matched = await _values_containing(
                client, "rule.name", signature, time_from=time_from, time_to=time_to
            )
            if not matched:
                return (
                    f"No alert signature contains {signature!r}. Call "
                    f'malcolm_field_values(field="rule.name") to see the signatures '
                    f"this Malcolm has actually recorded."
                )
            filters["rule.name"] = matched
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
            matched = await _values_containing(
                client, "rule.category", category, time_from=time_from, time_to=time_to
            )
            if not matched:
                return (
                    f"No alert category contains {category!r}. Call "
                    f'malcolm_field_values(field="rule.category") to see the categories '
                    f"this Malcolm has actually recorded."
                )
            filters["rule.category"] = matched
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


async def _values_containing(
    client: MalcolmClient,
    field: str,
    needle: str,
    time_from: str = "",
    time_to: str = "",
) -> list[str]:
    """Expand a substring into the exact field values that contain it.

    Malcolm's filter dict compiles to a terms query, so there is no wildcard to
    push down — a substring has to become the list of values it matches, which a
    terms filter then treats as an OR.

    Args:
        client: Client used for the bucket aggregation.
        field: Field to enumerate, e.g. "rule.name".
        needle: Case-insensitive substring to look for.
        time_from: Aggregation window start (dateparser format).
        time_to: Aggregation window end (dateparser format).

    Returns:
        Matching values, drawn from the field's top _VALUE_SCAN_LIMIT values by
        document count; empty when nothing matches.
    """
    buckets = await client.field_values(
        field=field,
        limit=_VALUE_SCAN_LIMIT,
        filters={"event.dataset": "alert"},
        time_from=time_from,
        time_to=time_to,
    )
    needle = needle.lower()
    return [str(b["key"]) for b in buckets if needle in str(b.get("key", "")).lower()]


async def _with_empty_hint(
    client: MalcolmClient,
    rows: Any,
    field_names: Any,
    body: str,
) -> str:
    """Prefix an empty result with the field names Malcolm does not index.

    A filter on a renamed field is not an error in Malcolm — it just matches
    nothing, which reads to an agent as "this traffic does not exist". Checking
    only once the result set is already empty keeps the field lookup off the
    happy path.

    Args:
        client: Client used to resolve the names against the index mapping.
        rows: The result rows from the response (any falsy value = empty).
        field_names: Field names the query referenced, or None.
        body: The serialized response to return either way.

    Returns:
        `body`, with the explanation prepended when there is one.
    """
    if rows or not field_names:
        return body
    hint = await client.explain_unknown_fields(field_names)
    return f"{hint}\n\n{body}" if hint else body


def _parse_filters(raw: str) -> dict[str, Any] | None:
    """Parse filter JSON string, returning None for empty."""
    if not raw or raw.strip() in ("", "{}", "null", "none"):
        return None
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) and parsed else None
    except json.JSONDecodeError:
        return None
