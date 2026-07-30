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
from typing import TYPE_CHECKING, Annotated

from pydantic import Field

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from mcp_server_malcolm.client import MalcolmClient

# index/pattern lands in the URL path — no path metachars (/, ?, ..).
_INDEX_RE = re.compile(r"^[A-Za-z0-9_.*-]+$")

# Shared: every DSL tool here reads from the OpenSearch backend, never mutates.
_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}


def _index_error(index: str) -> str | None:
    if _INDEX_RE.fullmatch(index) and ".." not in index:
        return None
    return f"Error: invalid index pattern: {index!r}"


def register_dsl_tools(mcp: MCPServer, client: MalcolmClient) -> None:
    """Register the generic DSL-core query tools."""

    @mcp.tool(title="Run OpenSearch DSL query", annotations=_READ)
    async def search_dsl(
        index: Annotated[
            str,
            Field(
                description='Index or pattern to query, e.g. "arkime_sessions3-*". '
                "Accepts a wildcard; must contain no path metachars (/, ?, ..)."
            ),
        ],
        query_dsl: Annotated[
            str,
            Field(
                description='JSON string of a full DSL body, e.g. {"query": {...}, "aggs": {...}}. '
                'A bare query object with no "query" key is wrapped as {"query": ...} for you.'
            ),
        ],
        size: Annotated[
            int,
            Field(
                description="Max hits to return; 0 for aggregation-only. "
                'Always overrides any "size" key inside query_dsl.',
                ge=0,
                le=500,
            ),
        ] = 20,
    ) -> str:
        """Run a raw OpenSearch DSL query and return its hits plus aggregations.

        Use this for full DSL control over the query and aggregation bodies. When you
        only need a match count and not the documents, use `count`. For Malcolm's
        simpler field-filter syntax instead of raw DSL, use `malcolm_search`.
        Aggregations honor the time filter inside the DSL body, so there is no hidden
        default time window. Returns the raw OpenSearch _search response.
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

    @mcp.tool(title="Count matching documents", annotations=_READ)
    async def count(
        index: Annotated[
            str,
            Field(
                description="Index or pattern to count over. Accepts a wildcard; "
                "default is the Malcolm sessions index."
            ),
        ] = "arkime_sessions3-*",
        query_dsl: Annotated[
            str,
            Field(
                description="JSON string of the INNER DSL query clause only, e.g. "
                '{"term": {"event.dataset": "conn"}} (no "query" wrapper, no "aggs"/"size"). '
                "Empty counts all documents (match_all)."
            ),
        ] = "",
    ) -> str:
        """Count documents matching a DSL query clause, without returning the documents.

        Use this instead of `search_dsl` when you only need the number of matches, not
        the documents themselves. Note the query_dsl shape differs from `search_dsl`:
        here it is the inner query clause only, whereas `search_dsl` takes a full DSL
        body. Returns the raw OpenSearch _count response ({"count": N, ...}).
        """
        if err := _index_error(index):
            return err
        try:
            query = json.loads(query_dsl) if query_dsl.strip() else {"match_all": {}}
        except json.JSONDecodeError as exc:
            return f"Error: invalid JSON in query_dsl: {exc}"
        data = await client.opensearch_count(index, query)
        return json.dumps(data, ensure_ascii=False, default=str)

    @mcp.tool(title="List indices", annotations=_READ)
    async def list_indices(
        pattern: Annotated[
            str,
            Field(
                description='Index name or wildcard to match; default "*" returns all. '
                'Only matching indices are returned, e.g. "arkime_sessions3-*".'
            ),
        ] = "*",
    ) -> str:
        """List indices with their health, status, and document count.

        Use this to discover which indices exist before querying one. For the field
        schema (field names and types) of a single index, use `index_mapping` instead;
        for cluster-wide health rather than per-index status, use `cluster_health`.
        Returns a JSON array, one object per index, with name, health, status, and doc
        count.
        """
        if err := _index_error(pattern):
            return err
        data = await client.opensearch_indices(pattern)
        return json.dumps(data, ensure_ascii=False, default=str)

    @mcp.tool(title="Get index field mapping", annotations=_READ)
    async def index_mapping(
        index: Annotated[
            str,
            Field(
                description="Exact index name or pattern to fetch the mapping for, "
                'e.g. "arkime_sessions3-*". Accepts a wildcard.'
            ),
        ],
    ) -> str:
        """Return one index's field mapping: every field name and its OpenSearch type.

        Use this to learn what fields an index holds and how they are typed before
        writing a DSL query against it. To list which indices exist rather than inspect
        one index's schema, use `list_indices`. For Malcolm's non-standard field names
        across all indices, `malcolm_field_search` is easier than reading raw mappings.
        Returns the raw OpenSearch _mapping response; a non-existent index yields an
        OpenSearch error in the response body.
        """
        if err := _index_error(index):
            return err
        data = await client.opensearch_mapping(index)
        return json.dumps(data, ensure_ascii=False, default=str)

    @mcp.tool(title="Cluster health", annotations=_READ)
    async def cluster_health() -> str:
        """Report OpenSearch cluster health: green/yellow/red status plus node and shard counts.

        This checks the storage backend (OpenSearch) itself, cluster-wide. To check
        whether the Malcolm API is reachable, use `malcolm_ping`; for the readiness of
        Malcolm's individual services, use `malcolm_service_status`; for per-index
        status rather than the whole cluster, use `list_indices`. Returns the raw
        OpenSearch _cluster/health document.
        """
        data = await client.opensearch_cluster_health()
        return json.dumps(data, ensure_ascii=False, default=str)
