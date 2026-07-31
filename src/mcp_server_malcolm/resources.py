"""The two field catalogues as MCP resources -- the schema without a tool call.

Field names in Malcolm are non-standard (http.useragent, not http.user_agent),
which is why the server instructions tell an agent never to guess one. That
anti-hallucination layer is otherwise reachable only through
malcolm_field_search / arkime_field_search, one keyword at a time; a client that
would rather hold the whole vocabulary reads it here instead.

The two catalogues are separate on purpose. /mapi/fields is the vocabulary the
malcolm_* and DSL tools accept, /arkime/api/fields is the one Arkime's
expression parser accepts, and a name from either is rejected by the other --
so they are two resources with two descriptions, never one merged list.

Both bodies are full catalogues (thousands of entries: 5,969 and 4,051,
measured against Malcolm 26.07.1), so a read costs a few hundred kilobytes.
That is the caller's explicit choice -- resources/list carries only the
metadata -- and the search tools remain the cheap path for a single lookup.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from mcp_server_malcolm.client import MalcolmClient

MALCOLM_FIELDS_URI = "malcolm://fields/malcolm"
ARKIME_FIELDS_URI = "malcolm://fields/arkime"

# Compact separators, sorted keys: no whitespace to pay for in a body this
# size, and a stable order so two reads of an unchanged catalogue are byte
# identical (worth having now that the read carries a cache TTL).
_COMPACT = (",", ":")


def register_resources(mcp: MCPServer, client: MalcolmClient) -> None:
    """Expose both field catalogues as read-only JSON resources.

    Content comes from the client's own field caches, so a re-read costs
    nothing upstream and the resources cannot disagree with the field-discovery
    tools -- both read the same two cached lists.
    """

    @mcp.resource(
        MALCOLM_FIELDS_URI,
        name="malcolm_field_catalogue",
        title="Malcolm field catalogue",
        description=(
            "Every field name Malcolm's index knows, mapped to its OpenSearch type, as a "
            'JSON object: {"http.useragent": "keyword", "source.ip": "ip", ...}. This is '
            "the vocabulary for malcolm_* tool filters and for search_dsl/count queries. "
            "Names are non-standard (http.useragent, NOT http.user_agent) — check one here "
            "before filtering on it. Arkime expressions use a different vocabulary; see "
            "the Arkime expression field catalogue. Thousands of entries: for a single "
            "lookup malcolm_field_search is cheaper."
        ),
        mime_type="application/json",
    )
    async def malcolm_field_catalogue() -> str:
        return json.dumps(await client.get_fields(), sort_keys=True, separators=_COMPACT)

    @mcp.resource(
        ARKIME_FIELDS_URI,
        name="arkime_field_catalogue",
        title="Arkime expression field catalogue",
        description=(
            "Every field name Arkime's expression parser accepts, as a JSON array of "
            '{"exp", "db", "type", "group", "help"} objects sorted by expression name. '
            'Use "exp" (ip.src, port.dst, protocols) inside an arkime_* `expression` '
            'argument, "db" where a tool asks for an Arkime db field. Arkime rejects the '
            "dotted names in the Malcolm field catalogue, and vice versa — the two are "
            "not interchangeable. Thousands of entries: for a single lookup "
            "arkime_field_search is cheaper."
        ),
        mime_type="application/json",
    )
    async def arkime_field_catalogue() -> str:
        return json.dumps(await client.arkime_fields(), separators=_COMPACT)
