"""Arkime reads that are not session search: saved objects, capture inventory,
health, hunt-job status.

Everything here is a plain GET, so it registers unconditionally. arkime_hunt_status
lived in the hunt-job WRITE module until it moved here: it reads /arkime/api/hunts
and mutates nothing, so gating it only hid queued jobs from a read-only deployment.
"""

from __future__ import annotations

import ipaddress
import json
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field
from typing_extensions import TypedDict

from mcp_server_malcolm.errors import ToolInputError

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from mcp_server_malcolm.client import MalcolmClient

# Arkime answers 200 with this body when an address has no PTR record, so the
# status code cannot distinguish "no such name" from a real answer.
_NO_PTR = "reverse error"


class SavedView(TypedDict, total=False):
    """One saved Arkime search view."""

    name: str
    expression: str
    owner: str
    roles: list[str]
    id: str


class ViewList(TypedDict):
    count: int
    views: list[SavedView]


class Shortcut(TypedDict, total=False):
    """One named value list, plus the token that references it."""

    name: str
    type: str
    description: str
    values: list[str]
    owner: str
    use_in_expression: str


class ShortcutList(TypedDict):
    count: int
    shortcuts: list[Shortcut]


class CronQuery(TypedDict, total=False):
    """One standing periodic query. Keys this deployment left unset are dropped,
    so a query that has never run carries no `last_run`."""

    name: str
    expression: str
    tags: list[str]
    enabled: bool
    action: str
    owner: str
    description: str
    last_run: int
    matched_sessions: int
    id: str


class CronQueryList(TypedDict):
    count: int
    crons: list[CronQuery]


class ReverseDns(TypedDict, total=False):
    """A PTR lookup. `resolved` false with no hostname is a missing record,
    not a failure."""

    ip: str
    resolved: bool
    hostname: str
    note: str


class PcapFile(TypedDict, total=False):
    """One indexed capture file. Timestamps are epoch MILLISECONDS here, unlike
    every Arkime query parameter."""

    name: str
    node: str
    bytes: int
    packets: int
    sessions: int
    first_packet: int
    last_packet: int


class PcapFileList(TypedDict):
    total: int
    showing: int
    files: list[PcapFile]


class NodeStats(TypedDict, total=False):
    """One capture node's health. `warning` is present only when the node is
    losing packets right now."""

    node: str
    hostname: str
    arkime_version: str
    disk_free_mb: int
    disk_free_percent: float
    memory_percent: float
    cpu_percent: float
    total_sessions: int
    total_packets: int
    packets_dropped: int
    dropped_per_sec: float
    packets_per_sec: float
    queue_packet: int
    queue_disk: int
    queue_opensearch: int
    warning: str


class NodeStatsList(TypedDict):
    count: int
    nodes: list[NodeStats]


# Shared: every tool here reads from Arkime (via Malcolm), never mutates it.
_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}


def register_arkime_inventory_tools(mcp: MCPServer, client: MalcolmClient) -> None:
    """Register saved-object, capture-inventory and node-health reads."""

    @mcp.tool(title="List saved Arkime views", annotations=_READ)
    async def arkime_views(
        limit: Annotated[int, Field(description="Max views to return.", ge=1, le=500)] = 100,
    ) -> ViewList | str:
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
        data = await client.arkime_views(length=min(max(1, limit), 500))

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
        return {"count": len(views), "views": views}

    @mcp.tool(title="List saved Arkime value lists", annotations=_READ)
    async def arkime_shortcuts(
        limit: Annotated[int, Field(description="Max shortcuts to return.", ge=1, le=500)] = 100,
    ) -> ShortcutList | str:
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
        data = await client.arkime_shortcuts(length=min(max(1, limit), 500))

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
        return {"count": len(shortcuts), "shortcuts": shortcuts}

    @mcp.tool(title="List Arkime cron queries", annotations=_READ)
    async def arkime_crons() -> CronQueryList | str:
        """List Arkime's cron queries — saved expressions that re-run on a schedule.

        Use this for two questions. First, the same one arkime_views answers:
        which searches has the human team thought worth keeping. Second, and
        only this tool can answer it: where a tag came from. A cron query
        re-runs its expression every few minutes and stamps its own tags onto
        whatever matches, so those tags sit in session data with nothing in the
        session explaining them — this list is the explanation. For saved
        searches nobody schedules use arkime_views, for named value lists (IOC
        sets) use arkime_shortcuts, and to see the tags actually present in the
        data use malcolm_field_values on the `tags` field.

        Returns JSON {"count", "crons"}: per query the name, the expression,
        the tags it applies, whether it is `enabled`, its `action` (what it does
        with a match), owner, and `last_run` as epoch seconds. Disabled queries
        are listed too — a query switched off last week still explains tags
        already sitting in the data. A deployment with none configured gets a
        plain sentence instead of an empty list; that is an answer, not a fault
        (measured: this lab has zero).
        """
        data = await client.arkime_crons()

        # Measured as a bare JSON list on Arkime 6.6.0; the {"data": [...]}
        # envelope its sibling routes use is accepted rather than assumed away.
        if isinstance(data, dict):
            data = data.get("data")
        rows = data if isinstance(data, list) else []
        if not rows:
            return (
                "No cron queries are configured on this Arkime. Nothing is tagging "
                "sessions on a schedule, so any tag in the data came from a person, "
                "from an enrichment pipeline, or from arkime_add_tags."
            )
        crons = [
            _drop_empty(
                {
                    "name": row.get("name"),
                    "expression": row.get("query"),
                    "tags": _tag_list(row.get("tags")),
                    # _drop_empty drops None/""/[]/{} but keeps False, which is
                    # what this key needs: a disabled query is the interesting
                    # one when a tag stopped appearing.
                    "enabled": bool(row.get("enabled")),
                    "action": row.get("action"),
                    "owner": row.get("creator") or row.get("user"),
                    "description": row.get("description"),
                    "last_run": row.get("lastRun") or row.get("lpValue"),
                    "matched_sessions": row.get("count"),
                    "id": row.get("key") or row.get("id"),
                }
            )
            for row in rows
        ]
        return {"count": len(crons), "crons": crons}

    @mcp.tool(title="Reverse-resolve an IP", annotations=_READ)
    async def arkime_reverse_dns(
        ip: Annotated[
            str,
            Field(
                description="One IPv4 or IPv6 address to reverse-resolve, "
                'e.g. "8.8.8.8". Not a hostname, not a CIDR range.'
            ),
        ],
    ) -> ReverseDns | str:
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
            raise ToolInputError('ip is required — one IPv4 or IPv6 address, e.g. "8.8.8.8".')
        try:
            ipaddress.ip_address(addr)
        except ValueError as exc:
            raise ToolInputError(
                f"{addr!r} is not an IP address — this tool takes one IPv4/IPv6 "
                f"address, not a hostname and not a CIDR range."
            ) from exc

        text = await client.arkime_reverse_dns(addr)

        if not text or text.lower().startswith(_NO_PTR):
            return {
                "ip": addr,
                "resolved": False,
                "note": "No PTR record. Normal for private and unregistered addresses.",
            }
        return {"ip": addr, "resolved": True, "hostname": text}

    @mcp.tool(title="List indexed PCAP files", annotations=_READ)
    async def arkime_pcap_files(
        limit: Annotated[int, Field(description="Max files to return.", ge=1, le=500)] = 50,
    ) -> PcapFileList | str:
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
        data = await client.arkime_pcap_files(length=min(max(1, limit), 500))

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
        return {
            "total": data.get("recordsTotal", len(files)),
            "showing": len(files),
            "files": files,
        }

    @mcp.tool(title="Check capture node health", annotations=_READ)
    async def arkime_node_stats(
        node: Annotated[
            str,
            Field(
                description="Substring of a node name to narrow the list, "
                'e.g. "spark". Empty = every node.'
            ),
        ] = "",
    ) -> NodeStatsList | str:
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
        data = await client.arkime_node_stats(node_filter=node.strip())

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

        return {"count": len(nodes), "nodes": nodes}

    @mcp.tool(title="List hunt jobs", annotations=_READ)
    async def arkime_hunt_status(
        active_only: Annotated[
            bool,
            Field(
                description="If true, show queued/running/paused jobs; if false, finished "
                "(history) jobs."
            ),
        ] = True,
        limit: Annotated[int, Field(description="Max hunts to return.", ge=1)] = 50,
    ) -> str:
        """List Arkime hunt jobs and their progress/status (read-only).

        Use this to see what packet-payload searches this Arkime is running or
        has run — the ones a human queued in the Arkime UI as much as the ones
        arkime_create_hunt queued, since both land in the same list. Poll it to
        watch a job finish and see how many sessions matched, and read a hunt's
        `id` here before passing it to arkime_cancel_hunt. Registered
        unconditionally: it only reads /arkime/api/hunts, so it stays available
        with every write class off; creating and cancelling hunts are the parts
        the hunt-job write class gates. Note the two halves are separate lists —
        active_only=true never shows a finished job, so a hunt that vanished
        from one call has moved to the other, not disappeared. A deployment
        that has never run a hunt gets an empty `data` list, which is an answer.
        Returns the raw Arkime hunts response.
        """
        data = await client.arkime_hunts(length=limit, history=not active_only)
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def _tag_list(value: Any) -> list[str]:
    """Arkime keeps a cron query's tags as one comma-separated string.

    A list is accepted as well: this lab has zero crons configured, so the
    populated shape could not be measured and the cheaper assumption is not
    worth a wrong answer.
    """
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [tag.strip() for tag in str(value or "").split(",") if tag.strip()]


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
