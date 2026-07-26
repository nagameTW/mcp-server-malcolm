"""Session correlation tools."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated

from pydantic import Field

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient

# Shared: this tool reads correlated sessions from Malcolm, never mutates.
_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}


def register_correlation_tools(mcp: FastMCP, client: MalcolmClient) -> None:
    """Register session correlation tools."""

    @mcp.tool(title="Find related sessions by UID", annotations=_READ)
    async def malcolm_related_sessions(
        uid: Annotated[
            str,
            Field(
                description='Zeek connection UID to correlate on, e.g. "CYeji2z7CKmPRGyga". '
                "Required (non-empty)."
            ),
        ],
        limit: Annotated[
            int,
            Field(
                description="Max sessions to return per side (direct and related counted "
                "separately).",
                ge=1,
            ),
        ] = 50,
    ) -> str:
        """Correlate one Zeek UID across sessions via both direct and cross-reference matches.

        Use this to pivot from a single connection UID to everything tied to it: it
        queries zeek.uid (the direct connection) and related.zeek.uid (references from
        other log types like files, dns, ssl) in one call. For a plain field query
        without the dual direct/related split, use `malcolm_search` with a zeek.uid
        filter.

        Behavior: runs TWO independent Malcolm searches (one per match kind); `limit`
        caps EACH side separately, so up to 2×limit sessions come back total. The two
        searches fail independently — a failure on one side does not abort the other;
        instead the result carries a `direct_error` or `related_error` string for the
        side that failed while still returning the side that succeeded (check for those
        keys). No time filter is applied — both searches use Malcolm's default window.
        Requires Malcolm access (Basic auth), inherited from the server config. Returns a
        JSON object with separate "direct" and "related" hit lists plus a "summary" count
        (and per-side error keys only when a side fails).
        """
        if not uid.strip():
            return "Error: uid is required."

        uid = uid.strip()
        results: dict = {"uid": uid, "direct": [], "related": []}

        # Direct match: sessions with this UID
        try:
            direct = await client.search(
                filters={"zeek.uid": uid},
                limit=limit,
            )
            direct_hits = direct.get("results", direct.get("hits", []))
            if isinstance(direct_hits, dict):
                direct_hits = direct_hits.get("hits", [])
            results["direct"] = direct_hits if isinstance(direct_hits, list) else []
        except Exception as exc:  # noqa: BLE001
            results["direct_error"] = str(exc)

        # Related match: sessions referencing this UID
        try:
            related = await client.search(
                filters={"related.zeek.uid": uid},
                limit=limit,
            )
            related_hits = related.get("results", related.get("hits", []))
            if isinstance(related_hits, dict):
                related_hits = related_hits.get("hits", [])
            results["related"] = related_hits if isinstance(related_hits, list) else []
        except Exception as exc:  # noqa: BLE001
            results["related_error"] = str(exc)

        direct_count = len(results.get("direct", []))
        related_count = len(results.get("related", []))
        results["summary"] = f"{direct_count} direct + {related_count} related sessions"

        return json.dumps(results, indent=2, ensure_ascii=False, default=str)
