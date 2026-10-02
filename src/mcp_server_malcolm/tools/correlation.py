"""Session correlation tools."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated

from pydantic import Field

from mcp_server_malcolm.errors import ToolInputError, UpstreamError

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from mcp_server_malcolm.client import MalcolmClient

# Shared: this tool reads correlated sessions from Malcolm, never mutates.
_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}


def register_correlation_tools(mcp: MCPServer, client: MalcolmClient) -> None:
    """Register session correlation tools."""

    @mcp.tool(title="Find related sessions by UID", annotations=_READ)
    async def malcolm_related_sessions(
        uid: Annotated[
            str,
            Field(
                description="Zeek connection UID as it appears in the zeek.uid field, "
                'e.g. "CYeji2z7CKmPRGyga". An Arkime session id (the "3@240425-..." '
                "form) is a different key and correlates nothing here."
            ),
        ],
        limit: Annotated[
            int,
            Field(
                description="Max sessions to return per side (direct and related counted "
                "separately).",
                ge=1,
                le=500,
            ),
        ] = 50,
    ) -> str:
        """Correlate one Zeek UID across sessions via both direct and cross-reference matches.

        Use this to pivot from a single connection UID to everything tied to it.
        "direct" is every record carrying the UID in zeek.uid: the conn record and
        its dns, http, ssl, files and other protocol records. "related" is every
        record whose rootId is the UID but whose zeek.uid is not, chiefly the
        connections carried inside a tunnel when the UID is the tunnel's. For an
        ordinary connection "related" is empty, which is the normal answer.
        Zeek UIDs only: to pivot from an Arkime session id use
        arkime_session_detail, and for a plain single-field query without the dual
        direct/related split use malcolm_search with a zeek.uid filter.

        Behavior: runs TWO independent Malcolm searches (one per match kind); `limit`
        caps EACH side separately, so up to 2×limit sessions come back total. The two
        searches fail independently — a failure on one side does not abort the other;
        instead the result carries a `direct_error` or `related_error` string in place
        of that side's hit list, and the summary names the side as failed rather than
        counting it; both failing is reported as an error, since nothing was
        correlated.
        Neither search is time-filtered — like malcolm_search, both cover all
        retained history, so an empty result is a real absence rather than a
        window. Returns a JSON object with separate "direct" and "related" hit
        lists plus a "summary" count (and per-side error keys only when a side
        fails). Malcolm reports no total, so the summary marks a side that
        filled `limit` as possibly holding more.
        """
        if not uid.strip():
            raise ToolInputError(
                'uid is required — a Zeek connection UID such as "CYeji2z7CKmPRGyga", '
                "taken from a zeek.uid field."
            )

        uid = uid.strip()
        results: dict = {"uid": uid}

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

        # Related match: records that point at this UID through rootId without
        # carrying it themselves. Malcolm copies every Zeek record's zeek.uid into
        # rootId (1200_zeek_mutate.conf), so rootId alone repeats the direct hits;
        # what it adds is a conn record inside a tunnel, whose rootId is the
        # tunnel's uid (1015_zeek_conn.conf). There is no related.zeek.uid field.
        try:
            related = await client.search(
                filters={"rootId": uid, "!zeek.uid": uid},
                limit=limit,
            )
            related_hits = related.get("results", related.get("hits", []))
            if isinstance(related_hits, dict):
                related_hits = related_hits.get("hits", [])
            results["related"] = related_hits if isinstance(related_hits, list) else []
        except Exception as exc:  # noqa: BLE001
            results["related_error"] = str(exc)

        if "direct_error" in results and "related_error" in results:
            # Neither side answered, so there is no correlation to report and a
            # document carrying only the two error keys would read as success.
            raise UpstreamError(f"{results['direct_error']}; {results['related_error']}")

        # A failed side has no count; printing 0 would read as a real absence.
        # /mapi/document reports no total, so a side that filled limit may hold more.
        more = " (the limit; more may exist)"
        results["summary"] = (
            " + ".join(
                f"{side} search failed"
                if f"{side}_error" in results
                else f"{len(results[side])} {side}{more if len(results[side]) >= limit else ''}"
                for side in ("direct", "related")
            )
            + " sessions"
        )

        return json.dumps(results, ensure_ascii=False, default=str)
