"""Generic OpenSearch DSL tools -- the backend-agnostic query core.

These POST plain OpenSearch DSL to the configured endpoint (Malcolm's
/mapi/opensearch proxy today). They carry NO Malcolm-specific query
shape: repoint the client's base_url and they work against any
OpenSearch-compatible backend. The Malcolm-specific tools live in the
other modules and can be dropped without touching this one.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient

# index/pattern lands in the URL path — no path metachars (/, ?, ..).
_INDEX_RE = re.compile(r"^[A-Za-z0-9_.*-]+$")


def _index_error(index: str) -> str | None:
    if _INDEX_RE.fullmatch(index) and ".." not in index:
        return None
    return f"Error: invalid index pattern: {index!r}"


def register_dsl_tools(mcp: FastMCP, client: MalcolmClient) -> None:
    """Register the generic DSL-core query tools."""

    @mcp.tool()
    async def search_dsl(index: str, query_dsl: str, size: int = 20) -> str:
        """Run a raw OpenSearch DSL query and return the raw response
        (hits + aggregations).

        Use this for full DSL control. When you only need a match count, use
        count; for Malcolm's simpler filter syntax, use malcolm_search.
        Aggregations honor the time filter inside the DSL body, so there is no
        hidden default time window.

        Args:
            index: index or pattern to query (e.g. "arkime_sessions3-*").
                Accepts a wildcard.
            query_dsl: JSON string of a full DSL body, e.g.
                {"query": {...}, "aggs": {...}}. A bare query object (no
                "query" key) is wrapped as {"query": ...} for you.
            size: max hits to return, 0 for aggregation-only, capped at 500.
                Always overrides a "size" key inside query_dsl.
        """
        if err := _index_error(index):
            return err
        try:
            body = json.loads(query_dsl) if isinstance(query_dsl, str) else query_dsl
        except json.JSONDecodeError as exc:
            return f"Error: invalid JSON in query_dsl: {exc}"
        if "query" not in body:
            body = {"query": body}
        body["size"] = min(max(0, size), 500)
        data = await client.opensearch_dsl(index, body)
        return json.dumps(data, ensure_ascii=False, default=str)

    @mcp.tool()
    async def count(index: str = "arkime_sessions3-*", query_dsl: str = "") -> str:
        """Count documents matching a DSL query clause, without returning them.

        Use this instead of search_dsl when you only need the number of
        matches, not the documents. Returns the raw OpenSearch _count response
        ({"count": N, ...}).

        Args:
            index: index or pattern to count over (default the Malcolm
                sessions index "arkime_sessions3-*"). Accepts a wildcard.
            query_dsl: JSON string of a DSL query clause (the inner query, e.g.
                {"term": {"event.dataset": "conn"}}). Empty counts all docs
                (match_all).
        """
        if err := _index_error(index):
            return err
        try:
            query = json.loads(query_dsl) if query_dsl.strip() else {"match_all": {}}
        except json.JSONDecodeError as exc:
            return f"Error: invalid JSON in query_dsl: {exc}"
        data = await client.opensearch_count(index, query)
        return json.dumps(data, ensure_ascii=False, default=str)

    @mcp.tool()
    async def list_indices(pattern: str = "*") -> str:
        """List indices with their health, status, and document count.

        Use this to discover which indices exist before querying one. For the
        field schema of a single index, use index_mapping instead.

        Args:
            pattern: index name or wildcard to match (default "*" for all).
                Only matching indices are returned, e.g. "arkime_sessions3-*".

        Returns a JSON array, one object per index, with name, health, status,
        and doc count.
        """
        if err := _index_error(pattern):
            return err
        data = await client.opensearch_indices(pattern)
        return json.dumps(data, ensure_ascii=False, default=str)

    @mcp.tool()
    async def index_mapping(index: str) -> str:
        """Return the field mapping (schema) for one index: field names and
        their types.

        Use this to learn what fields an index holds and how they are typed
        before writing a DSL query against it. To list which indices exist,
        use list_indices instead. Requesting a non-existent index returns an
        OpenSearch error in the response body.

        Args:
            index: exact index name or pattern to fetch the mapping for
                (e.g. "arkime_sessions3-*"). Accepts a wildcard.
        """
        if err := _index_error(index):
            return err
        data = await client.opensearch_mapping(index)
        return json.dumps(data, ensure_ascii=False, default=str)

    @mcp.tool()
    async def cluster_health() -> str:
        """Report OpenSearch cluster health: the green/yellow/red status plus
        node and shard counts.

        This checks the storage backend (OpenSearch) itself. To check whether
        the Malcolm API is reachable, use malcolm_ping; for the readiness of
        Malcolm's services, use malcolm_service_status. Takes no parameters.

        Returns the raw OpenSearch _cluster/health document.
        """
        data = await client.opensearch_cluster_health()
        return json.dumps(data, ensure_ascii=False, default=str)
