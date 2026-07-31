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
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from mcp_server_malcolm.errors import ToolInputError

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from mcp_server_malcolm.client import MalcolmClient

# index/pattern lands in the URL path — no path metachars (/, ?, ..). The comma
# is admitted because OpenSearch's multi-index form ("idx1,idx2") is ordinary
# here, and MalcolmClient's own guard accepts it: a narrower rule at this layer
# would make that form unreachable through these four tools alone.
_INDEX_RE = re.compile(r"^[A-Za-z0-9_.*,-]+$")

# Shared: every DSL tool here reads from the OpenSearch backend, never mutates.
_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}


def _check_index(index: str) -> None:
    """Reject an index/pattern that could climb out of its endpoint."""
    if not _INDEX_RE.fullmatch(index) or ".." in index:
        raise ToolInputError(
            f"invalid index pattern: {index!r} — expected an index name or wildcard "
            f'such as "arkime_sessions3-*", with no path metachars (/, ?, ..).'
        )


def _load_dsl(query_dsl: str, what: str) -> Any:
    """Parse a DSL body/clause; a malformed one raises rather than running."""
    try:
        return json.loads(query_dsl)
    except json.JSONDecodeError as exc:
        raise ToolInputError(
            f"invalid JSON in query_dsl ({exc}); received {query_dsl!r}. Expected {what}."
        ) from exc


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
        only need a match count and not the documents, use count. For Malcolm's
        simpler field-filter syntax instead of raw DSL, use malcolm_search.
        Aggregations honor the time filter inside the DSL body, so there is no hidden
        default time window. Returns the raw OpenSearch _search response.

        Both input guards run before any request leaves this server: malformed
        query_dsl, and an index containing /, ? or .., are refused as input
        errors rather than costing an upstream scan. When the query is easier to
        say as an Arkime expression, compile it with arkime_build_query and hand
        the index and query_dsl it returns straight to this tool — serialise its
        query_dsl object to a JSON string first, which is what this parameter
        declares.
        """
        _check_index(index)
        body = _load_dsl(query_dsl, 'a full DSL body such as {"query": {"match_all": {}}}')
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

        Use this instead of search_dsl when you only need the number of matches, not
        the documents themselves. Note the query_dsl shape differs from search_dsl's —
        the schema says how. Returns the raw OpenSearch _count response
        ({"count": N, ...}).

        This tool takes no time arguments and applies no default window, so a
        bare call counts everything the index still holds, which on any real
        capture is millions of documents. Bound it with a range clause inside
        query_dsl, use malcolm_search when you want a human-readable time range,
        or arkime_sessions_summary when you want byte and packet totals beside
        the count.
        """
        _check_index(index)
        query = (
            _load_dsl(
                query_dsl, 'an inner query clause such as {"term": {"event.dataset": "conn"}}'
            )
            if query_dsl.strip()
            else {"match_all": {}}
        )
        data = await client.opensearch_count(index, query)
        return json.dumps(data, ensure_ascii=False, default=str)

    @mcp.tool(title="List indices", annotations=_READ)
    async def list_indices(
        pattern: Annotated[
            str,
            Field(
                description='Index name or wildcard to match; default "*" returns all. '
                'Only matching indices are returned, e.g. "arkime_sessions3-*", which '
                "is the narrowing that skips Malcolm's internal indices."
            ),
        ] = "*",
    ) -> str:
        """List indices with their health, status, and document count.

        Use this to discover which indices exist before querying one. For the field
        schema (field names and types) of a single index, use index_mapping instead;
        for cluster-wide health rather than per-index status, use cluster_health.
        Returns a JSON array, one object per index, with name, health, status, and doc
        count.

        This reads OpenSearch's index list directly, so Malcolm's own internals
        come back beside the traffic, and most of what is listed holds no
        network data at all (.kibana_1, .opendistro_security, the arkime_*_v*
        config indices, top_queries-*). The traffic is in the arkime_sessions3-*
        indices alone; Arkime opens a new one per day, so their number grows and
        the newest is usually still empty — read "docs.count" rather than the
        name to find the one carrying the capture. A pattern matching nothing
        returns an empty array, not an error. "health" is a shard-replication
        fact and says nothing about whether capture is still arriving —
        malcolm_data_coverage answers that.
        """
        _check_index(pattern)
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
        one index's schema, use list_indices. For Malcolm's non-standard field names
        across all indices, malcolm_field_search is easier than reading raw mappings.
        Returns the raw OpenSearch _mapping response; a non-existent index yields an
        OpenSearch error in the response body.

        A wildcard returns one mapping block per matching index rather than a
        merged one, and each block repeats the whole schema: "arkime_sessions3-*"
        costs roughly a megabyte of JSON, growing by another block every day
        Arkime opens a new index. Name ONE index when you only need the schema —
        the blocks are near-identical. The types it reports are OpenSearch's own
        (keyword, long, text), while malcolm_field_search reports Malcolm's names
        for the same fields (string, integer) — so come here only when the
        OpenSearch type is what you need.
        """
        _check_index(index)
        data = await client.opensearch_mapping(index)
        return json.dumps(data, ensure_ascii=False, default=str)

    @mcp.tool(title="Cluster health", annotations=_READ)
    async def cluster_health() -> str:
        """Report OpenSearch cluster health: green/yellow/red status plus node and shard counts.

        This checks the storage backend (OpenSearch) itself, cluster-wide. To check
        whether the Malcolm API is reachable, use malcolm_ping; for the readiness of
        Malcolm's individual services, use malcolm_service_status; for per-index
        status rather than the whole cluster, use list_indices. Returns the raw
        OpenSearch _cluster/health document.

        This is a storage-layer answer only: every shard allocated says nothing
        about whether packets are still being captured or parsed. Measured on
        Malcolm v26.07.1 (single node) the steady state is green with
        number_of_nodes=1 and unassigned_shards=0, so treat yellow as something
        to explain rather than as normal. For whether data is still arriving use
        malcolm_data_coverage; for whether a capture node is dropping packets use
        arkime_node_stats.
        """
        data = await client.opensearch_cluster_health()
        return json.dumps(data, ensure_ascii=False, default=str)
