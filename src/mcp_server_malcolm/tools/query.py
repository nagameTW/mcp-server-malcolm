"""Core query tools -- search, aggregate, alerts."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from mcp_server_malcolm.client import _extract_buckets
from mcp_server_malcolm.tools._parse import parse_int_list, parse_json_object
from mcp_server_malcolm.tools.files import _first

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from mcp_server_malcolm.client import MalcolmClient

# Shared: every read tool here hits the external Malcolm server, never mutates.
_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}

# How many distinct values a substring search scans, ordered by document count.
# Malcolm cannot match substrings server-side, so a signature/category search
# has to enumerate first; this bounds that enumeration.
_VALUE_SCAN_LIMIT = 500


def register_query_tools(mcp: MCPServer, client: MalcolmClient) -> None:
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

        Two defaults to know before the first call: with no time_from this
        searches ALL retained history, where malcolm_aggregate covers only the
        last 24 hours; and filter values are matched exactly, so any wildcard or
        substring has to go to search_dsl instead.

        Every document comes back whole, 2 to 3.5 KB of JSON each on Malcolm's
        training data, so 20 conn documents run to about 46,000 characters.
        For counts or top values use malcolm_aggregate, and keep limit small
        when reading documents. When the results fill limit, a "Note:" line
        above the JSON says more may match; Malcolm reports no total.
        """
        parsed = _parse_filters(filters)
        limit = min(max(1, limit), 500)
        data = await client.search(
            filters=parsed,
            limit=limit,
            time_from=time_from,
            time_to=time_to,
            doctype=doctype.strip(),
        )
        results = data.get("results")
        body = "\n".join([*_limit_note(results, limit), _compact(data)])
        return await _with_empty_hint(client, results, parsed, body)

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

        With no time_from this covers only the LAST 24 HOURS, unlike
        malcolm_search which covers all history. Against a capture older than a
        day that returns an empty bucket list, which reads as "no such traffic"
        when it means "nothing in the last day" — suspect the window before the
        data.
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
        checked = [f.strip() for f in fields.split(",") if f.strip()] + list(parsed or {})
        # /mapi/agg keys the buckets by the first field. "-" holds documents that
        # lack it, which is all of them when the name is not indexed.
        rows = [b for b in _extract_buckets(data, checked[0]) if b.get("key") != "-"]
        return await _with_empty_hint(client, rows, checked, body)

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
        full: Annotated[
            bool,
            Field(
                description="Return the raw alert documents (about 2 KB each) instead of "
                "one compact row per alert."
            ),
        ] = False,
        time_from: Annotated[
            str,
            Field(
                description="Start time, dateparser format. Empty searches ALL history, "
                "and the signature/category substring pre-scan covers the same window."
            ),
        ] = "",
        time_to: Annotated[
            str, Field(description="End time, dateparser format. Empty = now.")
        ] = "",
    ) -> str:
        """Search Suricata alerts with structured parameters, no field knowledge needed.

        Use this instead of malcolm_search when hunting Suricata alerts: it maps
        each argument to the correct Malcolm field for you (you don't need to
        know whether it's suricata.alert.signature or rule.name). It always
        filters event.dataset=alert. These are Suricata IDS alerts, signature
        matches on the wire; three other things on this server are also called
        alerts and are different mechanisms — malcolm_alerting_monitors and
        malcolm_alerting_alerts are the OpenSearch alerting plugin's standing
        rules and their firings, malcolm_anomaly_detectors is its machine-learning
        baseline, and malcolm_create_alert (alerting write class) records a
        finding of your own.

        Behavior: `signature` and `category` are substring searches, which Malcolm
        cannot express in a filter (its filters are exact terms), so this tool
        resolves the substring against the field's 500 most common values first
        and filters on the matches. A substring that matches no recorded value
        returns a message saying so rather than an empty result set — that is the
        difference between "no such signature here" and "no alerts fired". When
        more than 500 values exist in the window, the message says how many alert
        documents carry the values that were not scanned instead of asserting
        absence; narrow the window, or filter rule.name on the exact name with
        malcolm_search. When the substring did match but rarer values went
        unscanned, a "Note:" line precedes the JSON saying how many alert
        documents those values carry. Another "Note:" line says when the alerts
        filled limit, since Malcolm reports no total.

        Returns {"showing": N, "alerts": [...]}, one row per alert with its
        document id, time, rule name, id and category, Suricata severity and
        action, both endpoints, transport, protocol and community_id (the key
        that finds the same flow in Zeek's conn records through malcolm_search).
        Set full=true for the raw documents, which carry every field.
        """
        filters: dict[str, Any] = {"event.dataset": "alert"}
        notes: list[str] = []

        if signature:
            # 11_suricata_logs.conf renames suricata.alert.signature to rule.name
            # outright — filtering the old name matches nothing, ever.
            matched, unscanned = await _values_containing(
                client, "rule.name", signature, time_from=time_from, time_to=time_to
            )
            if not matched:
                return _no_match("signature", "rule.name", signature, unscanned)
            if unscanned:
                notes.append(_partial_note("signature", len(matched), unscanned))
            filters["rule.name"] = matched
        if severity:
            # Dropping an unparseable level used to leave the key unset, which
            # returned EVERY severity while the caller believed it had filtered.
            sevs = parse_int_list(severity, "severity", '"1,2" (1=high, 2=medium, 3=low)')
            filters["suricata.alert.severity"] = sevs[0] if len(sevs) == 1 else sevs
        if source_ip:
            filters["source.ip"] = source_ip
        if dest_ip:
            filters["destination.ip"] = dest_ip
        if category:
            matched, unscanned = await _values_containing(
                client, "rule.category", category, time_from=time_from, time_to=time_to
            )
            if not matched:
                return _no_match("category", "rule.category", category, unscanned)
            if unscanned:
                notes.append(_partial_note("category", len(matched), unscanned))
            filters["rule.category"] = matched
        if action:
            filters["suricata.alert.action"] = action
        if sid:
            # Same trap as severity: "ET-2019401" is the spelling of a rule
            # NAME, not an id, and skipping it returned every signature.
            sids = parse_int_list(sid, "sid", '"2019401,2024897"')
            filters["rule.id"] = sids[0] if len(sids) == 1 else sids

        limit = min(max(1, limit), 500)
        data = await client.search(
            filters=filters,
            limit=limit,
            time_from=time_from,
            time_to=time_to,
        )
        hits = data.get("results") or []
        notes.extend(_limit_note(hits, limit))
        if not full:
            data = {"showing": len(hits), "alerts": [_alert_row(hit) for hit in hits]}
        return "\n".join([*notes, _compact(data)])


def _compact(data: Any) -> str:
    # No indent: measured on 20 alerts it cut 39% of the characters and 17% of
    # the tokens, for no loss of content.
    return json.dumps(data, ensure_ascii=False, default=str)


def _limit_note(rows: list | None, limit: int) -> list[str]:
    """A note when rows filled limit: /mapi/document returns no total."""
    if not rows or len(rows) < limit:
        return []
    advice = (
        "Narrow the filters" if limit >= 500 else "Raise limit (up to 500) or narrow the filters"
    )
    return [f"Note: {len(rows)} results came back, which is the limit; more may match. {advice}."]


def _alert_row(hit: dict[str, Any]) -> dict[str, Any]:
    """One alert reduced to what triage reads; the raw document runs to ~2 KB."""
    source = hit.get("_source") or {}
    rule = source.get("rule") or {}
    alert = (source.get("suricata") or {}).get("alert") or {}
    src = source.get("source") or {}
    dst = source.get("destination") or {}
    net = source.get("network") or {}
    row = {
        "id": hit.get("_id"),
        "timestamp": source.get("@timestamp"),
        "rule_name": _first(rule.get("name")),
        "rule_id": _first(rule.get("id")),
        "category": _first(rule.get("category")),
        "severity": alert.get("severity"),
        "action": alert.get("action"),
        "source_ip": _first(src.get("ip")),
        "source_port": _first(src.get("port")),
        "destination_ip": _first(dst.get("ip")),
        "destination_port": _first(dst.get("port")),
        "transport": _first(net.get("transport")),
        "protocol": _first(net.get("protocol")),
        "community_id": _first(net.get("community_id")),
    }
    return {key: value for key, value in row.items() if value not in (None, "", [])}


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
        (matches, unscanned): the values containing `needle`, drawn from the
        field's top _VALUE_SCAN_LIMIT values by document count, and the number
        of alert documents whose value fell outside that top list.
    """
    # /mapi/agg defaults to the last 24 hours while /mapi/document defaults to
    # all history, so an empty time_from has to be spelled out here or the scan
    # misses every signature the search would find -- measured on Malcolm's
    # training instance, "Modbus" read as unrecorded beside 5,037 matching alerts.
    buckets, unscanned = await client.field_values(
        field=field,
        limit=_VALUE_SCAN_LIMIT,
        filters={"event.dataset": "alert"},
        time_from=time_from or "0",
        time_to=time_to,
    )
    needle = needle.lower()
    matches = [str(b["key"]) for b in buckets if needle in str(b.get("key", "")).lower()]
    return matches, unscanned


def _partial_note(kind: str, matched: int, unscanned: int) -> str:
    """Note for a substring that matched, when rarer values were never scanned."""
    return (
        f"Note: the {kind} substring matched {matched} of the {_VALUE_SCAN_LIMIT} most "
        f"frequent values in this window; another {unscanned:,} alert documents carry rarer "
        f"values that were not scanned, so a rarer match may be missing below."
    )


def _no_match(kind: str, field: str, needle: str, unscanned: int) -> str:
    """Message for a substring no scanned value contains, honest about the scan's reach."""
    if unscanned:
        return (
            f"No alert {kind} among the {_VALUE_SCAN_LIMIT} most frequent in this window "
            f"contains {needle!r}, but another {unscanned:,} alert documents carry rarer "
            f"values that were not scanned. Narrow time_from/time_to, or filter {field} on "
            f"the exact name with malcolm_search."
        )
    return (
        f"No alert {kind} contains {needle!r}. Call malcolm_field_values(field={field!r}) "
        f"to see the values this Malcolm has actually recorded."
    )


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
    """Parse the filter JSON, None for empty; a malformed value raises."""
    return parse_json_object(raw, "filters", '{"event.dataset":"conn"}')
