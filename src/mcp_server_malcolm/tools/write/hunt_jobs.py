"""Write class: hunt-job — POST /arkime/api/hunt (Arkime v6.5.0).

A hunt makes Arkime capture nodes re-scan raw PCAP for a byte/regex pattern.
Creating one is a persisted WRITE guarded by checkCookieToken, so the client
primitive primes an ARKIME-COOKIE first (see MalcolmClient._write_arkime_hunt).
Reading hunt status (GET /arkime/api/hunts) ships with this class but is a read.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from mcp_server_malcolm.tools.write._common import run_write

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient

_CLASS = "hunt-job"
_SEARCH_TYPES = ("ascii", "asciicase", "hex", "regex", "hexregex")


def register_hunt_job_tools(mcp: FastMCP, client: MalcolmClient, audit_file: str | None) -> None:
    """Register hunt create (write) + status (read). Called only when enabled."""

    @mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False})
    async def arkime_create_hunt(
        name: str,
        search: str,
        search_type: str,
        total_sessions: int,
        start_time: int,
        stop_time: int,
        expression: str,
        packet_type: str = "raw",
        size: int = 50,
        src: bool = True,
        dst: bool = True,
    ) -> str:
        """Create an Arkime hunt (cross-PCAP packet search) — expensive, additive.

        Re-scans raw PCAP on capture nodes for a byte/regex pattern — costly, so
        scope it tightly. First run count (or arkime_sessions) with the same
        expression + time window to get total_sessions and confirm the scope is
        small before creating the hunt. Track progress with arkime_hunt_status.

        Args:
            name: Hunt name (Arkime keeps only [-a-zA-Z0-9_: ]).
            search: The bytes/text/regex to search for inside packets.
            search_type: one of ascii, asciicase, hex, regex, hexregex.
            total_sessions: Number of sessions the query matches (bound the scope).
            start_time: Query window start, epoch seconds (NOT a dateparser string).
            stop_time: Query window stop, epoch seconds.
            expression: Arkime expression scoping which sessions to hunt.
            packet_type: "raw" or "reassembled".
            size: Max packets to examine per session.
            src: Search source packets.
            dst: Search destination packets.
        """
        if not name.strip():
            return "Error: name is required."
        if not search.strip():
            return "Error: search is required."
        if search_type not in _SEARCH_TYPES:
            return f"Error: search_type must be one of {', '.join(_SEARCH_TYPES)}."
        if packet_type not in ("raw", "reassembled"):
            return "Error: packet_type must be 'raw' or 'reassembled'."
        if not (src or dst):
            return "Error: at least one of src/dst must be true."
        if total_sessions <= 0:
            return "Error: total_sessions must be > 0."

        hunt = {
            "name": name.strip(),
            "search": search,
            "searchType": search_type,
            "type": packet_type,
            "size": size,
            "src": src,
            "dst": dst,
            "totalSessions": total_sessions,
            "query": {
                "expression": expression,
                "startTime": start_time,
                "stopTime": stop_time,
            },
        }
        target = f"name={name.strip()}"
        params_summary = {
            "search_type": search_type,
            "total_sessions": total_sessions,
            "expression": expression,
        }

        result, err = await run_write(
            "arkime_create_hunt",
            _CLASS,
            target,
            params_summary,
            audit_file,
            lambda: client._write_arkime_hunt(hunt),
        )
        if err:
            return f"Hunt creation failed: {err}"
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False})
    async def arkime_hunt_status(active_only: bool = True, limit: int = 50) -> str:
        """List Arkime hunt jobs and their status (READ).

        Note: this read tool is only registered when the hunt-job write class is
        enabled — if writes are off, hunt status is not available either.

        Args:
            active_only: If true, show queued/running/paused; if false, finished jobs.
            limit: Max hunts to return.
        """
        try:
            data = await client.arkime_hunts(length=limit, history=not active_only)
        except Exception as exc:  # noqa: BLE001
            return f"Hunt status query failed: {exc}"
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)
