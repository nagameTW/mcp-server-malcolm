"""Write class: hunt-job — POST /arkime/api/hunt (Arkime v6.5.0).

A hunt makes Arkime capture nodes re-scan raw PCAP for a byte/regex pattern.
Creating one is a persisted WRITE guarded by checkCookieToken, so the client
primitive primes an ARKIME-COOKIE first (see MalcolmClient._write_arkime_hunt).
Reading hunt status (GET /arkime/api/hunts) ships with this class but is a read.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated

from pydantic import Field

from mcp_server_malcolm.errors import ToolInputError
from mcp_server_malcolm.tools.write._common import run_write

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from mcp_server_malcolm.client import MalcolmClient

_CLASS = "hunt-job"
_SEARCH_TYPES = ("ascii", "asciicase", "hex", "regex", "hexregex")

# Shared: additive write to the external Arkime server, never idempotent
# (each call queues a new hunt job).
_WRITE = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": True,
}
# The status tool only reads Arkime, never mutates.
_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}


def register_hunt_job_tools(mcp: MCPServer, client: MalcolmClient, audit_file: str | None) -> None:
    """Register hunt create (write) + status (read). Called only when enabled."""

    @mcp.tool(title="Create hunt job", annotations=_WRITE)
    async def arkime_create_hunt(
        name: Annotated[
            str, Field(description="Hunt name; Arkime keeps only [-a-zA-Z0-9_: ] server-side.")
        ],
        search: Annotated[
            str, Field(description="The bytes/text/regex to search for inside packet payloads.")
        ],
        search_type: Annotated[
            str,
            Field(
                description="How to interpret search; one of ascii, asciicase, hex, regex, "
                "hexregex."
            ),
        ],
        total_sessions: Annotated[
            int,
            Field(
                description="Number of sessions the expression + window match; bounds the scope. "
                "Must be > 0. Get it from count / arkime_sessions first.",
            ),
        ],
        start_time: Annotated[
            int,
            Field(description="Query window start as epoch seconds (NOT a dateparser string)."),
        ],
        stop_time: Annotated[int, Field(description="Query window stop as epoch seconds.")],
        expression: Annotated[
            str, Field(description="Arkime expression scoping which sessions to hunt.")
        ],
        packet_type: Annotated[
            str, Field(description='Packet stream to scan: "raw" or "reassembled".')
        ] = "raw",
        size: Annotated[int, Field(description="Max packets to examine per session.", ge=1)] = 50,
        src: Annotated[bool, Field(description="Search source-side packets.")] = True,
        dst: Annotated[bool, Field(description="Search destination-side packets.")] = True,
    ) -> str:
        """Queue an Arkime hunt job that re-scans stored PCAP for a byte/regex pattern.

        Use this only when indexed session metadata can't answer the question
        and you must look inside packet payloads. It is expensive: capture nodes
        re-read raw PCAP, so scope it tightly. Before creating one, run count or
        arkime_sessions with the same expression + time window to size it and
        set total_sessions. To tag sessions you already found instead, use
        arkime_add_tags; to save a metadata search, use arkime_create_view.
        Additive — queues a new job and changes nothing existing (calling twice
        queues two hunts). The action is audited, and the tool is registered
        only when the hunt-job write class is enabled. Track progress with
        arkime_hunt_status. Returns the raw Arkime response.
        """
        if not name.strip():
            raise ToolInputError('name is required — the hunt name, e.g. "beacon-bytes".')
        if not search.strip():
            raise ToolInputError(
                "search is required — the bytes/text/regex to look for inside packet payloads."
            )
        if search_type not in _SEARCH_TYPES:
            raise ToolInputError(
                f"search_type must be one of {', '.join(_SEARCH_TYPES)}; received {search_type!r}."
            )
        if packet_type not in ("raw", "reassembled"):
            raise ToolInputError(
                f"packet_type must be 'raw' or 'reassembled'; received {packet_type!r}."
            )
        if not (src or dst):
            raise ToolInputError(
                "at least one of src/dst must be true — with both false the hunt "
                "would scan no packets at all."
            )
        if total_sessions <= 0:
            raise ToolInputError(
                f"total_sessions must be > 0; received {total_sessions!r}. Size the hunt "
                f"with count or arkime_sessions on the same expression and window first."
            )

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

        result = await run_write(
            "arkime_create_hunt",
            _CLASS,
            target,
            params_summary,
            audit_file,
            lambda: client._write_arkime_hunt(hunt),
        )
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)

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

        Use this to check on hunts created with arkime_create_hunt — poll it to
        see when a job finishes and how many sessions matched. Read-only: it
        never creates or changes a hunt. This tool ships with the hunt-job write
        class, so if that class is disabled hunt status is unavailable too.
        Returns the raw Arkime hunts response.
        """
        data = await client.arkime_hunts(length=limit, history=not active_only)
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)
