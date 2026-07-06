"""Write class: arkime-tag — POST /arkime/api/sessions/addtags (Arkime v6.5.0).

Additive tagging only. Tag REMOVAL is a deliberate non-goal in v1 (needs the
removeEnabled role and its own safety design). Arkime sanitizes tags to
[-a-zA-Z0-9_:,] server-side.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import httpx

from mcp_server_malcolm import audit

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient

_CLASS = "arkime-tag"


def register_arkime_tag_tools(mcp: FastMCP, client: MalcolmClient, audit_file: str | None) -> None:
    """Register the additive Arkime tagging tool (called only when enabled)."""

    @mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False})
    async def arkime_add_tags(session_ids: str, tags: str) -> str:
        """Add tag(s) to Arkime session(s) — additive only.

        Args:
            session_ids: Comma-separated Arkime session ids (from arkime_sessions).
            tags: Comma-separated tags to add (Arkime keeps only [-a-zA-Z0-9_:,]).
        """
        ids = session_ids.strip()
        tg = tags.strip()
        if not ids:
            return "Error: session_ids is required."
        if not tg:
            return "Error: tags is required."

        target = f"ids={ids}"
        params_summary = {"tags": tg}
        try:
            result = await client._write_arkime_tags(ids=ids, tags=tg)
        except httpx.HTTPStatusError as exc:
            audit.record(
                "arkime_add_tags",
                _CLASS,
                target,
                params_summary,
                audit.outcome_for_status(exc.response.status_code),
                audit_file,
            )
            return f"Add tags failed: HTTP {exc.response.status_code}"
        except Exception as exc:  # noqa: BLE001
            audit.record(
                "arkime_add_tags",
                _CLASS,
                target,
                params_summary,
                f"error:{type(exc).__name__}",
                audit_file,
            )
            return f"Add tags failed: {exc}"

        audit.record("arkime_add_tags", _CLASS, target, params_summary, "ok", audit_file)
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)
