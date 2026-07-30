"""Arkime reads that are not session search: saved objects, capture inventory, health."""

from __future__ import annotations

import ipaddress
import json
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from mcp_server_malcolm.client import MalcolmClient

# Arkime answers 200 with this body when an address has no PTR record, so the
# status code cannot distinguish "no such name" from a real answer.
_NO_PTR = "reverse error"

# Shared: every tool here reads from Arkime (via Malcolm), never mutates it.
_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}


def register_arkime_inventory_tools(mcp: MCPServer, client: MalcolmClient) -> None:
    """Register saved-object, capture-inventory and node-health reads."""

    @mcp.tool(title="List saved Arkime views", annotations=_READ)
    async def arkime_views(
        limit: Annotated[int, Field(description="Max views to return.", ge=1, le=500)] = 100,
    ) -> str:
        """List the saved search views this Arkime holds, with each one's expression.

        Use this to find the queries the human team already curated before
        writing your own — a view names an investigation someone thought worth
        keeping. Take a view's `expression` and pass it to arkime_sessions to
        run it. For named value lists (IOC sets) rather than saved queries, use
        arkime_shortcuts; to discover field names for a new expression, use
        arkime_field_search.

        Returns JSON {"count", "views"}: per view the name, expression, owner
        and the roles it is shared with. Views are per-user and per-role, so
        this shows what the configured account can see, not everything on the
        server.
        """
        try:
            data = await client.arkime_views(length=min(max(1, limit), 500))
        except Exception as exc:  # noqa: BLE001
            return f"Arkime views lookup failed: {exc}"

        rows = data.get("data") or []
        if not rows:
            return (
                "No saved views are visible to this account. Views are owned per "
                "user and shared per role, so another account may still have some."
            )
        views = [
            _drop_empty(
                {
                    "name": row.get("name"),
                    "expression": row.get("expression"),
                    "owner": row.get("user"),
                    "roles": row.get("roles"),
                    "id": row.get("id"),
                }
            )
            for row in rows
        ]
        return json.dumps(
            {"count": len(views), "views": views}, indent=2, ensure_ascii=False, default=str
        )

    @mcp.tool(title="List saved Arkime value lists", annotations=_READ)
    async def arkime_shortcuts(
        limit: Annotated[int, Field(description="Max shortcuts to return.", ge=1, le=500)] = 100,
    ) -> str:
        """List Arkime's named value lists (IOC sets) and what each one contains.

        A shortcut is a named list of IPs, strings or numbers that an expression
        can reference as `$name` instead of spelling every value out. Use this
        before writing an expression so you reference a list that exists and
        know what is in it. For saved queries rather than value lists, use
        arkime_views.

        Returns JSON {"count", "shortcuts"}: per shortcut the name, type, the
        values it holds, and `use_in_expression` — the exact `$name` token to
        put in an arkime_sessions expression.
        """
        try:
            data = await client.arkime_shortcuts(length=min(max(1, limit), 500))
        except Exception as exc:  # noqa: BLE001
            return f"Arkime shortcuts lookup failed: {exc}"

        rows = data.get("data") or []
        if not rows:
            return (
                "No shortcuts are visible to this account. They are created in "
                "Arkime's UI, or by arkime_create_shortcut when the arkime-view "
                "write class is enabled."
            )
        shortcuts = [
            _drop_empty(
                {
                    "name": row.get("name"),
                    "type": row.get("type"),
                    "description": row.get("description"),
                    "values": [v for v in str(row.get("value", "")).splitlines() if v.strip()],
                    "owner": row.get("userId"),
                    "use_in_expression": f"${row.get('name')}" if row.get("name") else None,
                }
            )
            for row in rows
        ]
        return json.dumps(
            {"count": len(shortcuts), "shortcuts": shortcuts},
            indent=2,
            ensure_ascii=False,
            default=str,
        )

    @mcp.tool(title="Reverse-resolve an IP", annotations=_READ)
    async def arkime_reverse_dns(
        ip: Annotated[
            str,
            Field(
                description="One IPv4 or IPv6 address to reverse-resolve, "
                'e.g. "8.8.8.8". Not a hostname, not a CIDR range.'
            ),
        ],
    ) -> str:
        """Resolve one IP address to its PTR hostname, using Arkime's resolver.

        Use this to put a name on an external address a session talked to —
        `idf-rtr.example.com` says more than `198.51.100.1`. This asks the DNS
        resolver live, so it reflects DNS now, not what the capture saw: for the
        names actually observed on the wire, search event.dataset=dns with
        malcolm_search instead. For internal assets, malcolm_netbox_lookup gives
        a far richer answer than a PTR record.

        Returns JSON: `resolved`, and `hostname` when there is one. A private or
        unregistered address normally has no PTR and comes back resolved:false —
        that is a missing DNS record, not an error.
        """
        addr = ip.strip()
        if not addr:
            return "Error: ip is required."
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            return f"Error: {addr!r} is not an IP address (this tool takes one IPv4/IPv6 address)."

        try:
            text = await client.arkime_reverse_dns(addr)
        except Exception as exc:  # noqa: BLE001
            return f"Arkime reverse DNS failed: {exc}"

        if not text or text.lower().startswith(_NO_PTR):
            return json.dumps(
                {
                    "ip": addr,
                    "resolved": False,
                    "note": "No PTR record. Normal for private and unregistered addresses.",
                },
                indent=2,
            )
        return json.dumps({"ip": addr, "resolved": True, "hostname": text}, indent=2)

    @mcp.tool(title="List indexed PCAP files", annotations=_READ)
    async def arkime_pcap_files(
        limit: Annotated[int, Field(description="Max files to return.", ge=1, le=500)] = 50,
    ) -> str:
        """List the PCAP files Arkime has indexed, with each file's coverage.

        Use this to answer "what capture do we actually hold" — which files
        exist, how big they are, how many sessions each carries and the time
        span it covers. That is the file-level view; for the dataset-level view
        (how fresh each sensor is, how many documents per log type) use
        malcolm_data_coverage, and to search the sessions themselves use
        arkime_sessions.

        Returns JSON {"total", "showing", "files"}: per file the path, node,
        size, packet and session counts, and its first/last packet times as
        epoch MILLISECONDS — note that every Arkime *query* parameter takes
        epoch seconds instead.
        """
        try:
            data = await client.arkime_pcap_files(length=min(max(1, limit), 500))
        except Exception as exc:  # noqa: BLE001
            return f"Arkime file list failed: {exc}"

        rows = data.get("data") or []
        if not rows:
            return "Arkime has no indexed PCAP files. Nothing has been ingested yet."
        files = [
            _drop_empty(
                {
                    "name": row.get("name"),
                    "node": row.get("node"),
                    "bytes": row.get("filesize"),
                    "packets": row.get("packets"),
                    "sessions": row.get("sessionsPresent"),
                    "first_packet": row.get("firstTimestamp"),
                    "last_packet": row.get("lastTimestamp"),
                }
            )
            for row in rows
        ]
        return json.dumps(
            {"total": data.get("recordsTotal", len(files)), "showing": len(files), "files": files},
            indent=2,
            ensure_ascii=False,
            default=str,
        )

    @mcp.tool(title="Check capture node health", annotations=_READ)
    async def arkime_node_stats(
        node: Annotated[
            str,
            Field(
                description="Substring of a node name to narrow the list, "
                'e.g. "spark". Empty = every node.'
            ),
        ] = "",
    ) -> str:
        """Report each Arkime capture node's health: drops, disk, memory, queues.

        Use this to decide whether the data can be trusted before concluding
        anything from an absence: a node dropping packets or out of disk has
        gaps that look exactly like "no such traffic". For whether the Malcolm
        services are up at all use malcolm_service_status, and for OpenSearch
        cluster state use cluster_health — this one is about the capture side.

        Returns JSON {"count", "nodes"}: per node the Arkime version, free disk,
        memory and CPU, session and packet totals, dropped-packet counters and
        queue depths. A node currently losing packets also carries a `warning`
        saying so, because that is the finding that changes an analyst's
        conclusions rather than a number to skim past.
        """
        try:
            data = await client.arkime_node_stats(node_filter=node.strip())
        except Exception as exc:  # noqa: BLE001
            return f"Arkime node stats failed: {exc}"

        rows = data.get("data") or []
        if not rows:
            return f"No Arkime capture node matches {node!r}." if node else "No Arkime nodes."

        nodes = []
        for row in rows:
            entry = _drop_empty(
                {
                    "node": row.get("nodeName"),
                    "hostname": row.get("hostname"),
                    "arkime_version": row.get("ver"),
                    "disk_free_mb": row.get("freeSpaceM"),
                    "disk_free_percent": row.get("freeSpaceP"),
                    "memory_percent": row.get("memoryP"),
                    # Arkime stores cpu in hundredths of a percent -- its own
                    # viewer divides by 100 (apiStats.js: item.cpu * 0.01). Left
                    # raw it reads as 134% busy on a node at 1.34%, and it sits
                    # next to two keys that really are percents.
                    "cpu_percent": _percent(row.get("cpu")),
                    "total_sessions": row.get("totalSessions"),
                    "total_packets": row.get("totalPackets"),
                    "packets_dropped": row.get("totalDropped"),
                    "dropped_per_sec": row.get("deltaDroppedPerSec"),
                    "packets_per_sec": row.get("deltaPacketsPerSec"),
                    "queue_packet": row.get("packetQueue"),
                    "queue_disk": row.get("diskQueue"),
                    "queue_opensearch": row.get("esQueue"),
                }
            )
            if _positive(row.get("deltaDroppedPerSec")) or _positive(
                row.get("deltaOverloadDroppedPerSec")
            ):
                entry["warning"] = (
                    "this node is dropping packets right now — sessions are "
                    "missing from the capture, so an empty search result may be "
                    "a gap rather than an absence"
                )
            nodes.append(entry)

        return json.dumps(
            {"count": len(nodes), "nodes": nodes}, indent=2, ensure_ascii=False, default=str
        )


def _percent(value: Any) -> Any:
    """Arkime's hundredths-of-a-percent CPU value as a plain percent."""
    try:
        return round(float(value) / 100, 2)
    except (TypeError, ValueError):
        return None


def _positive(value: Any) -> bool:
    """True for a number above zero, tolerating the strings Arkime sometimes sends."""
    try:
        return float(value) > 0
    except (TypeError, ValueError):
        return False


def _drop_empty(row: dict[str, Any]) -> dict[str, Any]:
    """Drop keys the server did not populate, so a row carries no dead weight."""
    return {key: value for key, value in row.items() if value not in (None, "", [], {})}
