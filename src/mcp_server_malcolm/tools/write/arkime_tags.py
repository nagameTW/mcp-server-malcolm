"""Write class: arkime-tag — POST /arkime/api/sessions/addtags (Arkime v6.5.0).

Additive tagging only. Tag REMOVAL is a deliberate non-goal in v1 (needs the
removeEnabled role and its own safety design). Arkime sanitizes tags to
[-a-zA-Z0-9_:,] server-side.
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

_CLASS = "arkime-tag"

# Shared: additive write to the external Arkime server, never idempotent. The
# update script skips a tag the session already carries (db.js addTagsToSession
# only appends when indexOf == -1), so a repeat adds no duplicates -- but it
# re-issues the write against every id, and a batch that landed on some ids and
# not others is indistinguishable from a repeat, so idempotentHint stays false.
_WRITE = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": True,
}


def register_arkime_tag_tools(
    mcp: MCPServer, client: MalcolmClient, audit_file: str | None
) -> None:
    """Register the additive Arkime tagging tool (called only when enabled)."""

    @mcp.tool(title="Tag Arkime sessions", annotations=_WRITE)
    async def arkime_add_tags(
        session_ids: Annotated[
            str,
            Field(
                description="Comma-separated Arkime session ids, taken from the id field of "
                "arkime_sessions rows (only those carry the id this needs)."
            ),
        ],
        tags: Annotated[
            str,
            Field(
                description="Comma-separated tags to add; Arkime keeps only [-a-zA-Z0-9_:,] "
                "server-side and drops any other characters."
            ),
        ],
    ) -> str:
        """Add label tag(s) to existing Arkime session(s) (POST /arkime/api/sessions/addtags).

        Use this to mark sessions you have already found — first run
        arkime_sessions to get the session ids, then pass them here. To label a
        standing pattern instead of one set of ids, Arkime's cron queries do it
        on a schedule; arkime_crons shows the ones this deployment runs.
        Additive only: it appends tags and changes nothing else. Arkime skips a
        tag a session already carries, so a repeat adds no duplicates, but it is
        not a safe retry — it re-runs the update on every id, and a batch that
        reached some ids and not others reads exactly like a repeat. Removing
        tags is a deliberate non-goal of this tool (it needs a separate role and
        safety design). The action is audited, and the tool is registered only
        when the arkime-tag write class is enabled. A success reply means Arkime
        accepted the batch, not that every id matched: unresolvable ids are
        skipped without a count, and only when none resolve does the answer
        change — still HTTP 200, but carrying success:false with Arkime's own
        explanation in `text`. Read the flag, never the status code. Returns the
        raw Arkime response.
        """
        ids = session_ids.strip()
        tg = tags.strip()
        if not ids:
            raise ToolInputError(
                "session_ids is required — the `id` of one or more arkime_sessions "
                "rows, comma-separated."
            )
        if not tg:
            raise ToolInputError("tags is required — one or more tags, comma-separated.")

        target = f"ids={ids}"
        params_summary = {"tags": tg}
        result = await run_write(
            "arkime_add_tags",
            _CLASS,
            target,
            params_summary,
            audit_file,
            lambda: client._write_arkime_tags(ids=ids, tags=tg),
        )
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)
