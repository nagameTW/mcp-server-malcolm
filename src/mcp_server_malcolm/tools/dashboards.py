"""OpenSearch Dashboards saved objects: the dashboards, visualizations and saved
searches a human curated, and the query behind one of them.

Alerting monitors and anomaly detectors used to live here too; they are in
detections.py since this file crossed 1000 lines.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field
from typing_extensions import TypedDict

from mcp_server_malcolm.errors import ToolInputError

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from mcp_server_malcolm.client import MalcolmClient

# The saved-object types worth searching. Everything else Dashboards stores
# (config, url, augment-vis) is UI state an agent cannot act on, and a bad type
# would otherwise reach the server as an unbounded query.
_OBJECT_TYPES = ("dashboard", "visualization", "search", "index-pattern")


class SavedObject(TypedDict, total=False):
    """One Dashboards saved object. The panel layout is deliberately absent —
    several KB of positioning JSON that says nothing about what it shows."""

    type: str
    id: str
    title: str
    description: str
    updated_at: str


class SavedObjectList(TypedDict):
    total: int
    showing: int
    objects: list[SavedObject]


class SavedObjectDetail(TypedDict, total=False):
    """One saved object with its query resolved. `columns`/`sort` exist on a
    saved search only; `based_on_search` on a visualization only. Aggregation
    (visState) and panel (panelsJSON) blobs are deliberately absent.

    `query` is always a string, which upstream's is not: on one v26.07.1
    install, 25 of its 141 saved searches store the pre-7.x shape
    {"query_string": {"query": "event.dataset:x509", ...}} instead. See
    _query_text."""

    type: str
    id: str
    title: str
    description: str
    updated_at: str
    query: str
    language: str
    filters: list[Any]
    index_pattern: str
    columns: list[str]
    sort: list[Any]
    based_on_search: str
    note: str


# Shared: every tool here reads, never mutates.
_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}

# Why every tool below returns `X | str` rather than a bare TypedDict, even the
# two that always answer with a row. A bare TypedDict return is built into an
# output schema by the SDK's _create_model_from_typeddict, which gives every
# total=False key `default=None` and leaves its declared type alone. The
# advertised schema then reads {"sort": {"type": "array", "default": null}}
# while the dump -- model_dump with no exclude_unset -- puts "sort": null on the
# wire for every key the row did not populate. The 2026-07-28 spec says a server
# MUST provide structured results that conform to its outputSchema and a client
# SHOULD validate them, and null is not an array, so the official SDK client
# raises instead of returning the answer: measured against this lab, every
# saved-object type failed with "None is not of type 'array'".
#
# The union sends the same TypedDict through pydantic's own NotRequired
# handling: an unpopulated key is absent from `required`, absent from the wire,
# and the row rides inside {"result": ...} like every other typed tool here.
# Declaring the keys `X | None` instead would also validate, but it would put an
# explicit null on the wire for each one, which is the noise _drop_empty exists
# to remove and would contradict every docstring that says a key is present only
# when it means something.


def register_dashboard_tools(mcp: MCPServer, client: MalcolmClient) -> None:
    """Register the Dashboards saved-object reads."""

    @mcp.tool(title="Find Dashboards saved objects", annotations=_READ)
    async def malcolm_saved_objects(
        object_type: Annotated[
            str,
            # No f-string here: with `from __future__ import annotations` the
            # annotation is kept as source text and re-evaluated, and an
            # f-string inside Annotated[...] does not survive that round trip.
            Field(
                description="Which saved-object types to search, comma-separated: "
                'dashboard, visualization, search, index-pattern. E.g. "dashboard"; '
                '"dashboard,search". Values are trimmed and matched '
                'case-insensitively, so "Dashboard, Search" works; anything outside '
                "the four is refused with the list of what is allowed."
            ),
        ] = "dashboard",
        search: Annotated[
            str,
            Field(
                description='Match against the object TITLE only, e.g. "DNS", '
                '"Zeek*". Wildcards work. Empty = every object of the type.'
            ),
        ] = "",
        limit: Annotated[int, Field(description="Max objects to return.", ge=1, le=200)] = 20,
    ) -> SavedObjectList | str:
        """Find the dashboards, visualizations and saved searches this Malcolm ships.

        Use this to discover what pre-built analysis already exists before
        building a query by hand — Malcolm ships over a hundred dashboards, and
        one of them usually already covers the protocol you are looking at. This
        is catalogue metadata only: for the query behind a saved search or
        visualization take its `id` to malcolm_saved_object_detail, and for how
        a DASHBOARD is built take its `id` to malcolm_dashboard_export — that
        endpoint resolves ids as dashboards only, and answers 200 with an
        embedded 404 for a visualization or saved-search id.
        This searches the Dashboards catalogue, NOT network traffic: for traffic
        use malcolm_search, and for the field names behind a visualization use
        malcolm_field_search.

        Returns JSON {"total", "showing", "objects"}; field names are in the
        output schema, which also records why the panel layout is absent.
        """
        wanted = [t.strip().lower() for t in object_type.split(",") if t.strip()]
        unknown = [t for t in wanted if t not in _OBJECT_TYPES]
        if unknown or not wanted:
            raise ToolInputError(
                f"unsupported object_type {', '.join(unknown) or '(empty)'} — expected "
                f"one or more of {', '.join(_OBJECT_TYPES)}, comma-separated."
            )

        data = await client.dashboards_find(
            types=wanted, search=search.strip(), limit=min(max(1, limit), 200)
        )

        rows = data.get("saved_objects") or []
        if not rows:
            scope = f" matching {search!r}" if search.strip() else ""
            return (
                f"No saved objects of type {', '.join(wanted)}{scope}. "
                "Titles are matched as whole words, so try a shorter term or a "
                'trailing wildcard ("dns*").'
            )

        objects = [
            _drop_empty(
                {
                    "type": row.get("type"),
                    "id": row.get("id"),
                    "title": (row.get("attributes") or {}).get("title"),
                    "description": (row.get("attributes") or {}).get("description"),
                    "updated_at": row.get("updated_at"),
                }
            )
            for row in rows
        ]
        return {
            "total": data.get("total", len(objects)),
            "showing": len(objects),
            "objects": objects,
        }

    @mcp.tool(title="Read one saved object's query and filters", annotations=_READ)
    async def malcolm_saved_object_detail(
        object_id: Annotated[
            str,
            Field(
                description="The object's id as malcolm_saved_objects returns it, e.g. "
                '"bc940221-83d5-416e-a353-dc8fc2f84141". Ids are not unique across '
                "types, so object_type has to match."
            ),
        ],
        object_type: Annotated[
            str,
            Field(
                description="The object's type, one of: search (a curated query, the "
                "usual case), visualization, dashboard, index-pattern. A right id with "
                "the wrong type reads upstream as no such object."
            ),
        ] = "search",
        # `| str` is load-bearing, not decoration -- see the note above _READ.
    ) -> SavedObjectDetail | str:
        """Read one saved object with its query, filters and index pattern already resolved.

        Use this on a saved SEARCH to recover the query a human curated —
        Malcolm ships 141 of them, and the Arkime-side equivalent is
        arkime_views — and on a visualization to find the search it is built
        from. malcolm_saved_objects lists the catalogue and stops there;
        malcolm_dashboard_export resolves DASHBOARD ids only and answers 200
        with an embedded 404 for a visualization or saved-search id, so for
        those two this is the only route. For the traffic a query matches, take
        the string to malcolm_search or search_dsl.

        Three indirections are followed here instead of being handed back: the
        query sits in kibanaSavedObjectMeta.searchSourceJSON as a JSON *string*
        needing a second parse, the index is a reference NAME that means nothing
        until it is looked up in the object's own references[] array, and the
        query itself is stored in two shapes — a sixth of one install's saved
        searches used the pre-7.x {"query_string": {"query": "..."}} object
        rather than a plain string. `query` is always the string.

        Field names, and which of them appear for which object type, are in the
        output schema. Read `language` before reusing `query`: "lucene" and
        "kuery" are not interchangeable. On this Malcolm the index-pattern
        reference id is the pattern itself ("arkime_sessions3-*"); elsewhere it
        can be a UUID, which this tool resolves with object_type="index-pattern".
        A visualization has no query of its own — `based_on_search` names the
        saved search it inherits one from — and the aggregation and panel-layout
        blobs behind a dashboard come from malcolm_dashboard_export. Raises if
        nothing has that type and id.
        """
        wanted = object_type.strip().lower()
        if wanted not in _OBJECT_TYPES:
            raise ToolInputError(
                f"unsupported object_type {object_type!r} — expected one of "
                f"{', '.join(_OBJECT_TYPES)}."
            )

        obj = await client.saved_object(wanted, object_id.strip())
        attrs = obj.get("attributes") or {}
        source = obj.get("search_source") or {}

        row: dict[str, Any] = _drop_empty(
            {
                "type": obj.get("type"),
                "id": obj.get("id"),
                "title": attrs.get("title"),
                "description": attrs.get("description"),
                "updated_at": obj.get("updated_at"),
                "query": _query_text(source.get("query")),
                "language": source.get("language"),
                "filters": source.get("filters"),
                "index_pattern": source.get("index_pattern"),
                "columns": attrs.get("columns"),
                "sort": attrs.get("sort"),
                "based_on_search": _referenced_search(obj),
            }
        )
        if not row.get("query"):
            row["note"] = _no_query_note(wanted, row.get("based_on_search", ""))
        return row


def _no_query_note(object_type: str, based_on_search: str) -> str:
    """Why a saved object came back with no query, which differs by type.

    An absent query is not one fact. A visualization defers to a saved search;
    an index-pattern is the thing queries point AT and never has one; a search
    or dashboard without one really does select everything in its index. Saying
    "no query" alone would let a model read all four as the last case.
    """
    if based_on_search:
        return (
            "this object has no query of its own; it inherits the saved search in "
            f"based_on_search — call this tool again with object_id={based_on_search!r} "
            "and object_type='search'"
        )
    if object_type == "index-pattern":
        return (
            "an index pattern holds no query: `title` is the pattern itself, and it is "
            "what the index_pattern of a saved search resolves to. Its field list is "
            "hundreds of KB and is not included; use malcolm_field_search for fields"
        )
    return (
        "this object carries no query string, so it selects everything in index_pattern "
        "— what makes it worth reading is its columns, its filters or what is built on "
        "it, not a query"
    )


def _query_text(query: Any) -> str:
    """A saved object's query as the string the docstring promises.

    Dashboards stores two shapes under searchSourceJSON.query.query and only
    one of them is a string. Counted on one v26.07.1 install, 25 of its 141
    saved searches -- about a sixth -- carry the pre-7.x
    {"query_string": {"query": "event.dataset:x509", "analyze_wildcard": true}}
    instead, and handing that dict back both breaks the declared type (the tool
    raised "Input should be a valid string") and gives the caller something
    malcolm_search cannot take. The inner string is the same lucene the newer
    shape stores flat, so unwrapping it loses nothing.

    Any other dict is serialised rather than dropped or raised on: an
    unrecognised query shape is still evidence about the object, and this tool
    degrading to JSON text beats it failing.
    """
    if isinstance(query, str):
        return query
    if not query:
        return ""
    inner = query.get("query_string") if isinstance(query, dict) else None
    if isinstance(inner, dict) and isinstance(inner.get("query"), str):
        return inner["query"]
    return json.dumps(query, ensure_ascii=False, default=str)


def _referenced_search(obj: dict[str, Any]) -> str:
    """The saved search a visualization inherits its query from, resolved to an id.

    A visualization names it in attributes.savedSearchRefName, which is a
    reference NAME ("search_0") and only becomes an id through references[] --
    the same indirection the client resolves for the index pattern. Measured on
    this Malcolm, 150 of 200 sampled visualizations have one and carry an empty
    query of their own, so reporting that empty query alone would read as
    "matches everything".
    """
    name = (obj.get("attributes") or {}).get("savedSearchRefName")
    if not isinstance(name, str) or not name:
        return ""
    for ref in obj.get("references") or []:
        if isinstance(ref, dict) and ref.get("name") == name:
            return ref.get("id") or ""
    return ""


def _drop_empty(row: dict[str, Any]) -> dict[str, Any]:
    """Drop keys the server did not populate, keeping False and 0 (both real)."""
    return {key: value for key, value in row.items() if value not in (None, "", [], {})}
