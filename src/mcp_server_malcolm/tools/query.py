"""Core query tools -- search, aggregate, alerts."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient


def register_query_tools(mcp: FastMCP, client: MalcolmClient) -> None:
    """Register search, aggregation, and alert tools."""

    @mcp.tool()
    async def malcolm_search(
        filters: str = "{}",
        limit: int = 20,
        time_from: str = "",
        time_to: str = "",
    ) -> str:
        """Search Malcolm indexed network traffic documents.

        Uses Malcolm's simple filter syntax (NOT OpenSearch DSL).

        Filter examples:
          {"event.dataset": "conn"}                       -- Zeek conn logs
          {"source.ip": "192.0.2.77"}                      -- by source IP
          {"event.dataset": "dns", "zeek.dns.query": "*example.com*"}
          {"!network.transport": "icmp"}                   -- exclude ICMP
          {"network.direction": ["inbound", "outbound"]}   -- OR match
          {"!related.password": null}                       -- field must exist

        Args:
            filters: JSON filter object (Malcolm filter syntax).
            limit: Maximum documents to return (1-500).
            time_from: Start time (dateparser format, e.g. "2024-01-01", "7 days ago").
            time_to: End time (default: now).
        """
        parsed = _parse_filters(filters)
        data = await client.search(
            filters=parsed,
            limit=min(max(1, limit), 500),
            time_from=time_from,
            time_to=time_to,
        )
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    @mcp.tool()
    async def malcolm_aggregate(
        fields: str,
        filters: str = "{}",
        limit: int = 50,
        time_from: str = "",
        time_to: str = "",
    ) -> str:
        """Aggregate network traffic by one or more fields.

        Returns bucket counts (top-N values) for the requested fields.
        For multi-level aggregation, pass comma-separated fields.

        Args:
            fields: Comma-separated field names to aggregate on.
                    e.g. "network.protocol"
                    e.g. "source.ip,destination.ip,network.protocol"
                    e.g. "suricata.alert.signature,suricata.alert.severity"
            filters: JSON filter object (Malcolm filter syntax).
            limit: Maximum buckets per aggregation level (1-500).
            time_from: Start time (dateparser format).
            time_to: End time (default: now).
        """
        parsed = _parse_filters(filters)
        data = await client.aggregate(
            fields=fields.strip(),
            filters=parsed,
            limit=min(max(1, limit), 500),
            time_from=time_from,
            time_to=time_to,
        )
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    @mcp.tool()
    async def malcolm_alerts(
        signature: str = "",
        severity: str = "",
        source_ip: str = "",
        dest_ip: str = "",
        limit: int = 20,
        time_from: str = "",
        time_to: str = "",
    ) -> str:
        """Search Suricata alerts with structured parameters.

        Builds the correct Malcolm filters automatically -- you do NOT need
        to know whether the field is suricata.alert.signature or rule.name.

        Args:
            signature: Alert signature substring (e.g. "ET MALWARE", "CVE-2024").
            severity: Comma-separated severity levels, e.g. "1,2" (1=high, 2=medium, 3=low).
            source_ip: Filter by source IP.
            dest_ip: Filter by destination IP.
            limit: Maximum alerts to return.
            time_from: Start time (dateparser format).
            time_to: End time (default: now).
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
