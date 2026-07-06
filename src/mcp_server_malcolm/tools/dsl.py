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
        """Run a raw OpenSearch DSL query. Returns the raw response
        (hits + aggregations). Aggregations honor the time filter inside
        the DSL body, so there is no hidden default time window.

        Args:
            index: index or pattern (e.g. "arkime_sessions3-*").
            query_dsl: JSON string of a full DSL body ({"query": {...}, "aggs": {...}}).
            size: max hits (0 for aggregation-only). Always wins over a
                "size" key inside query_dsl.
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
        """Count documents matching a DSL query clause (default match_all)."""
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
        """List indices (name/health/status/doc count)."""
        if err := _index_error(pattern):
            return err
        data = await client.opensearch_indices(pattern)
        return json.dumps(data, ensure_ascii=False, default=str)

    @mcp.tool()
    async def index_mapping(index: str) -> str:
        """Field mapping/schema for an index."""
        if err := _index_error(index):
            return err
        data = await client.opensearch_mapping(index)
        return json.dumps(data, ensure_ascii=False, default=str)

    @mcp.tool()
    async def cluster_health() -> str:
        """OpenSearch cluster health."""
        data = await client.opensearch_cluster_health()
        return json.dumps(data, ensure_ascii=False, default=str)
