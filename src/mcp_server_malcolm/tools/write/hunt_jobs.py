"""Write class: hunt-job — POST /arkime/api/hunt and PUT /api/hunt/<id>/cancel
(Arkime v6.5.0/6.6.0).

A hunt makes Arkime capture nodes re-scan raw PCAP for a byte/regex pattern.
Creating one is a persisted WRITE guarded by checkCookieToken, so the client
primitive primes an ARKIME-COOKIE first (see MalcolmClient._write_arkime_hunt);
cancelling one goes through the same guard. Cancel lives in this class rather
than its own because it is the undo of the write this class already permits.
Reading hunt status is a plain GET and now registers unconditionally from
tools/arkime_inventory.py.
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
# Cancel is the one write here that acts on existing state: it ends a job that
# was making progress and the scan cannot be resumed, so destructiveHint is
# true. Not idempotent either -- an id Arkime cannot act on answers 500
# {"success":false,"text":"Error canceling hunt"} rather than a quiet no-op
# (measured on Malcolm v26.07.1 with an id that does not exist).
_CANCEL = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": True,
}


def register_hunt_job_tools(mcp: MCPServer, client: MalcolmClient, audit_file: str | None) -> None:
    """Register hunt create + cancel. Called only when the class is enabled."""

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
                description="How to read search: ascii ignores case, asciicase does not, hex "
                "matches the packet's hex bytes, and regex / hexregex are RE2 patterns over "
                "the text / the hex.",
                json_schema_extra={"enum": list(_SEARCH_TYPES)},
            ),
        ],
        total_sessions: Annotated[
            int,
            Field(
                description="How many sessions the expression + window match; Arkime uses it as "
                "the progress denominator and refuses a hunt above the huntLimit set in its "
                "own config.ini (Arkime ships that default at 1,000,000; this server cannot "
                "read the deployment's value). Must be > 0. Get it from "
                "arkime_sessions_summary.",
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
            str,
            Field(
                description="raw searches each captured packet on its own; reassembled decodes "
                "the session first, so it is the only one that finds a pattern straddling a "
                "packet boundary.",
                json_schema_extra={"enum": ["raw", "reassembled"]},
            ),
        ] = "raw",
        size: Annotated[int, Field(description="Max packets to examine per session.", ge=1)] = 50,
        src: Annotated[bool, Field(description="Search source-side packets.")] = True,
        dst: Annotated[bool, Field(description="Search destination-side packets.")] = True,
    ) -> str:
        """Queue an Arkime hunt job that re-scans stored PCAP for a byte/regex pattern.

        Use this only when indexed session metadata can't answer the question
        and you must look inside packet payloads. It is expensive: capture nodes
        re-read raw PCAP, so scope it tightly. Before creating one, size it with
        arkime_sessions_summary — same expression, same window, same dialect —
        and pass its session total as total_sessions. To tag sessions you
        already found instead, use arkime_add_tags; to save a metadata search,
        use arkime_create_view. Additive — queues a new job and changes nothing
        existing (calling twice queues two hunts). The action is audited, and
        the tool is registered only when the hunt-job write class is enabled.
        Track progress with arkime_hunt_status, and stop one you scoped too
        widely with arkime_cancel_hunt. total_sessions admits the job rather
        than bounding it: Arkime refuses one above its huntLimit, then replaces
        the number with the count its own query returns as soon as the job
        starts, so a value that is off skews the progress percentage rather
        than truncating the scan. Returns the raw Arkime response.
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

    @mcp.tool(title="Cancel hunt job", annotations=_CANCEL)
    async def arkime_cancel_hunt(
        hunt_id: Annotated[
            str,
            Field(
                description="The hunt's own id, as `id` in arkime_hunt_status output "
                "— an opaque 20-character string, not the hunt name."
            ),
        ],
    ) -> str:
        """Stop an Arkime hunt job that is queued or running (PUT /arkime/api/hunt/<id>/cancel).

        Use this to call off an arkime_create_hunt that was scoped too widely:
        a hunt has every capture node re-read raw PCAP, and this is the only
        way to make it stop. Take the id from arkime_hunt_status with
        active_only=true; the hunt *name* is rejected. Not additive like the
        rest of this class: it ends work in progress and the scan cannot be
        resumed, though the hunt row and whatever it matched before stopping
        stay in place and stay visible to arkime_hunt_status. An id Arkime
        cannot act on — one that never existed, or a job already finished —
        comes back as an upstream error rather than a quiet no-op, so a second
        cancel of the same hunt is not a safe retry. The action is audited, and
        the tool is registered only when the hunt-job write class is enabled.
        Returns the raw Arkime response.
        """
        if not hunt_id.strip():
            raise ToolInputError(
                "hunt_id is required — the opaque id from an arkime_hunt_status "
                "row's `id` field, not the hunt's name."
            )

        result = await run_write(
            "arkime_cancel_hunt",
            _CLASS,
            f"hunt_id={hunt_id.strip()}",
            {},
            audit_file,
            lambda: client._write_arkime_hunt_cancel(hunt_id.strip()),
        )
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)
