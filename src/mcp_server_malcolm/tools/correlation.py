"""Session correlation tools."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient


def register_correlation_tools(mcp: FastMCP, client: MalcolmClient) -> None:
    """Register session correlation tools."""

    @mcp.tool()
    async def malcolm_related_sessions(
        uid: str,
        limit: int = 50,
    ) -> str:
        """Find all sessions related to a Zeek UID.

        Searches both zeek.uid (direct match) and related.zeek.uid
        (cross-reference from other log types like files, dns, ssl).

        Args:
            uid: Zeek connection UID (e.g. "CYeji2z7CKmPRGyga").
            limit: Maximum related sessions to return.
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
