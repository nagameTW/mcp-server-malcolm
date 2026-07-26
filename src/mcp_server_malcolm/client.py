"""Malcolm HTTP client -- core reusable component.

All Malcolm API interactions go through this client.
Usable standalone (direct import) or via the MCP server layer.

Configuration via environment variables:
    MALCOLM_URL         Base URL (default: https://localhost)
    MALCOLM_USERNAME    Basic auth user (default: admin)
    MALCOLM_PASSWORD    Basic auth password (default: admin)
    MALCOLM_SSL_VERIFY  Verify TLS certs (default: true; "false" or a CA path)
    MALCOLM_TIMEOUT     Request timeout seconds (default: 30)
"""

from __future__ import annotations

import asyncio
import logging
import os
from difflib import get_close_matches
from typing import Any

import httpx

logger = logging.getLogger(__name__)


def _parse_ssl_verify(raw: str) -> bool | str:
    """Parse MALCOLM_SSL_VERIFY: "true"/"false" → bool, anything else → CA path.

    Verification is ON by default (empty/unset → True): the secure default must
    not silently ship credentials over an unauthenticated channel. A self-signed
    Malcolm deployment should point this at its CA-bundle path, not "false".
    """
    val = raw.strip()
    low = val.lower()
    if low == "false":
        return False
    if low == "true" or not val:
        return True
    return val  # treat as a CA-bundle path for httpx verify=


class MalcolmClient:
    """Async HTTP client for the Malcolm REST API.

    Wraps /mapi/* endpoints (unified gateway) and /arkime/api/* endpoints.
    Handles authentication, SSL, timeouts, and field caching.
    """

    def __init__(
        self,
        base_url: str = "https://localhost",
        username: str = "admin",
        password: str = "admin",
        ssl_verify: bool | str = True,
        timeout: float = 30.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = httpx.BasicAuth(username, password)
        self._ssl_verify = ssl_verify
        self._timeout = timeout
        self._http: httpx.AsyncClient | None = None
        self._http_lock = asyncio.Lock()
        self._field_cache: dict[str, str] | None = None

    @property
    def base_url(self) -> str:
        """The configured Malcolm base URL (trailing slash stripped)."""
        return self._base_url

    @classmethod
    def from_env(cls) -> MalcolmClient:
        """Create client from environment variables.

        MALCOLM_SSL_VERIFY accepts "true"/"false" (case-insensitive) or a path
        to a CA bundle — anything that is not "true"/"false" is passed through
        to httpx's verify= as a CA path, so verification is never silently
        disabled when an operator supplies a real bundle. Unset defaults to
        "true": the secure default never ships credentials over an unverified
        channel. For a self-signed Malcolm, set this to its CA-cert path.
        """
        return cls(
            base_url=os.environ.get("MALCOLM_URL", "https://localhost"),
            username=os.environ.get("MALCOLM_USERNAME", "admin"),
            password=os.environ.get("MALCOLM_PASSWORD", "admin"),
            ssl_verify=_parse_ssl_verify(os.environ.get("MALCOLM_SSL_VERIFY", "true")),
            timeout=float(os.environ.get("MALCOLM_TIMEOUT", "30")),
        )

    # -- HTTP primitives ------------------------------------------------

    async def _client(self) -> httpx.AsyncClient:
        # Lock the check-and-create so two racing coroutines can't each build a
        # client and leak the first one's connection pool (unclosed sockets).
        async with self._http_lock:
            if self._http is None or self._http.is_closed:
                self._http = httpx.AsyncClient(
                    base_url=self._base_url,
                    auth=self._auth,
                    verify=self._ssl_verify,
                    # Short connect budget: a dead/unreachable host must fail in
                    # seconds, not hang the full read timeout on every call.
                    timeout=httpx.Timeout(self._timeout, connect=5.0),
                    follow_redirects=True,
                )
            return self._http

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """HTTP GET, returns parsed JSON."""
        c = await self._client()
        resp = await c.get(path, params=params)
        resp.raise_for_status()
        return resp.json()

    async def post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        """HTTP POST with JSON body, returns parsed JSON."""
        c = await self._client()
        resp = await c.post(path, json=body or {})
        resp.raise_for_status()
        return resp.json()

    async def get_raw(self, path: str, params: dict[str, Any] | None = None) -> httpx.Response:
        """HTTP GET returning the raw response (for binary downloads)."""
        c = await self._client()
        return await c.get(path, params=params)

    async def close(self) -> None:
        if self._http is not None and not self._http.is_closed:
            await self._http.aclose()
            self._http = None

    # -- Search & Aggregation -------------------------------------------

    async def search(
        self,
        filters: dict[str, Any] | None = None,
        limit: int = 20,
        time_from: str = "",
        time_to: str = "",
        doctype: str = "",
    ) -> dict[str, Any]:
        """Search indexed documents via POST /mapi/document.

        doctype selects the target index server-side: "host"/"beat"* -> the
        other/beats index, "arkime"/"session"* -> the Arkime sessions index,
        anything else (or empty) -> the default Malcolm network index.
        """
        body: dict[str, Any] = {"limit": limit}
        if filters:
            body["filter"] = filters
        if time_from:
            body["from"] = time_from
        if time_to:
            body["to"] = time_to
        if doctype:
            body["doctype"] = doctype
        return await self.post("/mapi/document", body)

    async def aggregate(
        self,
        fields: str,
        filters: dict[str, Any] | None = None,
        limit: int = 500,
        time_from: str = "",
        time_to: str = "",
        doctype: str = "",
    ) -> dict[str, Any]:
        """Aggregate on one or more fields via POST /mapi/agg/<fields>.

        Args:
            fields: Comma-separated field names, e.g. "source.ip,destination.ip".
            doctype: Target index selector (see search()).
        """
        body: dict[str, Any] = {"limit": limit}
        if filters:
            body["filter"] = filters
        if time_from:
            body["from"] = time_from
        if time_to:
            body["to"] = time_to
        if doctype:
            body["doctype"] = doctype
        return await self.post(f"/mapi/agg/{fields}", body)

    # -- OpenSearch DSL (generic; backend-agnostic) ---------------------
    # These speak plain OpenSearch DSL against the configured endpoint via
    # Malcolm's /mapi/opensearch proxy. No Malcolm-specific query shape —
    # point the base_url elsewhere and they work against any OpenSearch.

    async def opensearch_dsl(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST a raw DSL search body; returns the raw OpenSearch response."""
        return await self.post(f"/mapi/opensearch/{index}/_search", body)

    async def opensearch_count(self, index: str, query: dict[str, Any]) -> dict[str, Any]:
        """Count docs matching a DSL query clause."""
        return await self.post(f"/mapi/opensearch/{index}/_count", {"query": query})

    async def opensearch_indices(self, pattern: str = "*") -> Any:
        """List indices (name/health/status/docs.count) as JSON."""
        return await self.get(
            f"/mapi/opensearch/_cat/indices/{pattern}",
            params={"format": "json", "h": "index,health,status,docs.count"},
        )

    async def opensearch_mapping(self, index: str) -> dict[str, Any]:
        """Field mapping for an index."""
        return await self.get(f"/mapi/opensearch/{index}/_mapping")

    async def opensearch_cluster_health(self) -> dict[str, Any]:
        """Cluster health document."""
        return await self.get("/mapi/opensearch/_cluster/health")

    # -- Fields ---------------------------------------------------------

    async def get_fields(self) -> dict[str, str]:
        """Return {field_name: field_type} from /mapi/fields (cached)."""
        if self._field_cache is not None:
            return self._field_cache

        data = await self.get("/mapi/fields")
        fields_raw = data.get("fields", {})
        self._field_cache = {
            name: info.get("type", "unknown") if isinstance(info, dict) else "unknown"
            for name, info in fields_raw.items()
        }
        logger.info("[malcolm] Cached %d fields", len(self._field_cache))
        return self._field_cache

    def invalidate_field_cache(self) -> None:
        """Force re-fetch of field list on next call."""
        self._field_cache = None

    async def search_fields(
        self,
        keyword: str = "",
        prefix: str = "",
        field_type: str = "",
    ) -> list[tuple[str, str]]:
        """Search fields by keyword, prefix, or type. Returns [(name, type)]."""
        fields = await self.get_fields()
        results: list[tuple[str, str]] = []

        for name, ftype in sorted(fields.items()):
            if prefix and not name.startswith(prefix):
                continue
            if field_type and ftype != field_type:
                continue
            if keyword and keyword.lower() not in name.lower():
                continue
            results.append((name, ftype))

        return results

    async def resolve_field(self, name: str, max_suggestions: int = 5) -> dict[str, Any]:
        """Check if a field exists; if not, suggest alternatives."""
        fields = await self.get_fields()

        if name in fields:
            return {"exists": True, "field": name, "type": fields[name]}

        all_names = list(fields.keys())

        # Normalized match (ignore underscores/hyphens/dots)
        norm = name.lower().replace("_", "").replace("-", "").replace(".", "")
        for f in all_names:
            f_norm = f.lower().replace("_", "").replace("-", "").replace(".", "")
            if norm == f_norm:
                return {"exists": False, "field": name, "suggestion": f, "type": fields[f]}

        # Fuzzy match
        similar = get_close_matches(name, all_names, n=max_suggestions, cutoff=0.5)

        # Substring match
        lower = name.lower()
        for f in all_names:
            if lower in f.lower() and f not in similar:
                similar.append(f)
                if len(similar) >= max_suggestions:
                    break

        suggestions = {s: fields[s] for s in similar}
        return {"exists": False, "field": name, "suggestions": suggestions}

    # -- Health & Status ------------------------------------------------

    async def ping(self) -> dict[str, Any]:
        return await self.get("/mapi/ping")

    async def ready(self) -> dict[str, Any]:
        return await self.get("/mapi/ready")

    async def version(self) -> dict[str, Any]:
        return await self.get("/mapi/version")

    async def ingest_stats(self) -> dict[str, Any]:
        return await self.get("/mapi/ingest-stats")

    # -- Indices --------------------------------------------------------

    async def indices(self) -> dict[str, Any]:
        return await self.get("/mapi/indices")

    # -- Dashboard Export -----------------------------------------------

    async def dashboard_export(self, dashboard_id: str) -> dict[str, Any]:
        return await self.get(f"/mapi/dashboard-export/{dashboard_id}")

    # -- NetBox (forwarded) ---------------------------------------------

    async def netbox_get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Query NetBox API via Malcolm's /mapi/netbox/ proxy."""
        return await self.get(f"/mapi/netbox/{path.lstrip('/')}", params=params)

    async def netbox_sites(self) -> dict[str, Any]:
        """Site directory from /mapi/netbox-sites (ids + metadata)."""
        return await self.get("/mapi/netbox-sites")

    # -- Arkime (forwarded) ---------------------------------------------

    async def arkime_sessions(
        self,
        expression: str,
        limit: int = 10,
        order: str = "lastPacket:desc",
        time_from: str = "",
        time_to: str = "",
    ) -> dict[str, Any]:
        """Search Arkime sessions. Omitting the range uses Arkime's default
        (recent) window; pass epoch-seconds strings in time_from/time_to
        (as startTime/stopTime) to reach historical data."""
        params: dict[str, Any] = {"expression": expression, "length": limit, "order": order}
        if time_from:
            params["startTime"] = time_from
        if time_to:
            params["stopTime"] = time_to
        return await self.get("/arkime/api/sessions", params=params)

    async def arkime_session_pcap(self, session_id: str, max_bytes: int = 0) -> bytes:
        """Download PCAP bytes for a single Arkime session.

        Uses GET /arkime/api/sessions.pcap?ids=<id> (the id from
        arkime_sessions, e.g. "3@240425-..."; the node prefix is optional).
        Verified live against Malcolm 25.12.1 — the expression=id==<id> form
        returns 404 "no sessions found", and there is no
        /arkime/api/session/<id>/pcap route.

        Args:
            session_id: One or more comma-separated Arkime session ids.
            max_bytes: Refuse a download larger than this (0 = no cap). The body
                is streamed so an oversized response is aborted before it is all
                read into memory.

        Raises:
            ValueError: the response exceeds max_bytes.
        """
        c = await self._client()
        async with c.stream("GET", "/arkime/api/sessions.pcap", params={"ids": session_id}) as resp:
            resp.raise_for_status()
            if max_bytes:
                declared = resp.headers.get("content-length")
                if declared is not None and int(declared) > max_bytes:
                    raise ValueError(
                        f"PCAP too large: {int(declared)} bytes exceeds cap {max_bytes}"
                    )
            chunks: list[bytes] = []
            total = 0
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if max_bytes and total > max_bytes:
                    raise ValueError(f"PCAP exceeds cap {max_bytes} bytes")
                chunks.append(chunk)
            return b"".join(chunks)

    async def arkime_hunts(self, length: int = 50, history: bool = False) -> dict[str, Any]:
        """List Arkime hunt jobs (READ). Ships with the hunt-job write class."""
        params = {"length": length, "history": "true" if history else "false"}
        return await self.get("/arkime/api/hunts", params=params)

    async def arkime_session_detail(self, session_id: str) -> dict[str, Any]:
        """All fields for one session via GET /arkime/api/session/<id>.

        The list search (arkime_sessions) returns a trimmed view; this returns
        the full SPI document for a single session id.
        """
        return await self.get(f"/arkime/api/session/{session_id}")

    async def arkime_unique(
        self,
        expression: str,
        field: str,
        counts: bool = True,
    ) -> str:
        """Distinct values of one field via GET /arkime/api/unique.

        Returns text (one value per line), not JSON — this Arkime endpoint
        streams a plain-text body, optionally suffixed with counts.
        """
        params: dict[str, Any] = {
            "exp": field,
            "counts": 1 if counts else 0,
        }
        if expression:
            params["expression"] = expression
        resp = await self.get_raw("/arkime/api/unique", params=params)
        resp.raise_for_status()
        return resp.text

    async def arkime_spigraph(
        self,
        field: str,
        expression: str = "",
        size: int = 20,
        time_from: str = "",
        time_to: str = "",
    ) -> dict[str, Any]:
        """Top values of one field with a time graph via GET /api/spigraph."""
        params = _arkime_query_params(expression, time_from, time_to)
        params["field"] = field
        params["size"] = size
        return await self.get("/arkime/api/spigraph", params=params)

    async def arkime_spiview(
        self,
        spi: str,
        expression: str = "",
        time_from: str = "",
        time_to: str = "",
    ) -> dict[str, Any]:
        """Field-value profile across fields via GET /api/spiview.

        Args:
            spi: Comma-separated db fields, each optionally ":<count>", e.g.
                "protocols:10,ip.dst:20".
        """
        params = _arkime_query_params(expression, time_from, time_to)
        params["spi"] = spi
        return await self.get("/arkime/api/spiview", params=params)

    async def arkime_connections(
        self,
        src_field: str = "srcIp",
        dst_field: str = "dstIp",
        expression: str = "",
        time_from: str = "",
        time_to: str = "",
    ) -> dict[str, Any]:
        """Source/destination connection graph via GET /api/connections.

        srcField/dstField take Arkime *db* field names (srcIp, dstIp, dstPort,
        node), NOT the dotted ECS names the search tools use — Arkime's viewer
        resolves them itself and errors (a 500 TypeError inside Arkime) on an
        unknown db field like "ip.src". Verified live against Malcolm 25.12.1.

        Returns {"nodes": [...], "links": [...]} for tracing who talked to whom.
        """
        params = _arkime_query_params(expression, time_from, time_to)
        params["srcField"] = src_field
        params["dstField"] = dst_field
        return await self.get("/arkime/api/connections", params=params)

    async def arkime_multiunique(
        self,
        fields: str,
        expression: str = "",
        counts: bool = True,
        time_from: str = "",
        time_to: str = "",
    ) -> str:
        """Unique value combinations across several fields via GET /api/multiunique.

        Args:
            fields: Comma-separated Arkime expression field names, e.g.
                "source.ip,destination.port".

        Returns plain text (one combined row per unique tuple), not JSON — this
        Arkime endpoint streams a text body.
        """
        params = _arkime_query_params(expression, time_from, time_to)
        params["exp"] = fields
        params["counts"] = 1 if counts else 0
        resp = await self.get_raw("/arkime/api/multiunique", params=params)
        resp.raise_for_status()
        return resp.text

    async def arkime_spigraphhierarchy(
        self,
        fields: str,
        expression: str = "",
        time_from: str = "",
        time_to: str = "",
    ) -> dict[str, Any]:
        """Hierarchical top-N treemap across fields via GET /api/spigraphhierarchy.

        Args:
            fields: Comma-separated db fields defining the hierarchy levels,
                e.g. "source.ip,destination.ip".

        Returns {"hierarchicalResults": {...}, "tableResults": [...]}.
        """
        params = _arkime_query_params(expression, time_from, time_to)
        params["exp"] = fields
        return await self.get("/arkime/api/spigraphhierarchy", params=params)

    async def arkime_file_by_hash(self, file_hash: str) -> httpx.Response:
        """Extract the transferred file whose content hash matches, via
        GET /api/sessions/bodyhash/<hash>.

        Arkime finds the most recent session carrying a body with this hash
        (md5 or sha256, as it appears in Arkime's http.md5/http.sha256 fields),
        resolves the capture node itself, and returns the raw file bytes. No
        node name is needed. Returns the raw response so the caller can inspect
        status (400 "No Match Found" when nothing matches) and the bytes.
        """
        return await self.get_raw(f"/arkime/api/sessions/bodyhash/{file_hash}")

    # -- Write primitives (gated) ---------------------------------------
    # Every method here issues a mutating request. By convention they are
    # named _write_* and imported ONLY from tools/write/*.py — a seam test
    # asserts no other module references them. Do not call these from a
    # read tool.

    async def _write_event(self, alert: dict[str, Any]) -> dict[str, Any]:
        """POST /mapi/event — index an external alert as a session document.

        Malcolm's own purpose-built write endpoint (26.06.1). Wraps the caller
        payload as {"alert": alert}; Malcolm deep-merges alert["body"] into an
        ECS-ish doc and indexes it into arkime_sessions3-<yymmdd>.
        """
        return await self.post("/mapi/event", {"alert": alert})

    async def _write_arkime_tags(self, ids: str, tags: str, segments: str = "no") -> dict[str, Any]:
        """POST /arkime/api/sessions/addtags — additive tagging (Arkime v6.5.0).

        checkHeaderToken passes with no token when the request has no
        cookie/referer. But a prior hunt-prime may have left an ARKIME-COOKIE
        in the shared jar; httpx would then send it as a Cookie header, which
        flips Arkime to checkCookieToken. So if a cookie is present, replay it
        as x-arkime-cookie too (same first-party token, same Basic-auth user)
        to stay consistent. Tags are sanitized to [-a-zA-Z0-9_:,] server-side.
        """
        c = await self._client()
        token = c.cookies.get("ARKIME-COOKIE")
        headers = {"x-arkime-cookie": token} if token else {}
        resp = await c.post(
            "/arkime/api/sessions/addtags",
            json={"ids": ids, "tags": tags, "segments": segments},
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()

    async def _arkime_token_post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST to a checkCookieToken-guarded Arkime route with the token dance.

        First GET /arkime/api/hunts so Arkime's setCookie middleware issues an
        ARKIME-COOKIE, then replay it as the x-arkime-cookie header on the POST.
        The userId in the token matches because both requests carry the same
        Basic auth → same X-Forwarded-User. Shared by hunt/view/shortcut writes.
        """
        c = await self._client()
        await c.get("/arkime/api/hunts", params={"length": 1})
        token = c.cookies.get("ARKIME-COOKIE")
        headers = {"x-arkime-cookie": token} if token else {}
        resp = await c.post(path, json=body, headers=headers)
        resp.raise_for_status()
        return resp.json()

    async def _write_arkime_hunt(self, hunt: dict[str, Any]) -> dict[str, Any]:
        """POST /arkime/api/hunt — create a cross-PCAP packet-search job.

        Guarded by checkCookieToken (Arkime v6.5.0); see _arkime_token_post.
        """
        return await self._arkime_token_post("/arkime/api/hunt", hunt)

    async def _write_arkime_view(self, view: dict[str, Any]) -> dict[str, Any]:
        """POST /arkime/api/view — create a saved search view (additive).

        Guarded by checkCookieToken (Arkime v6.x); see _arkime_token_post. Note
        the create route is the SINGULAR /api/view (/api/views is GET-only).
        """
        return await self._arkime_token_post("/arkime/api/view", view)

    async def _write_arkime_shortcut(self, shortcut: dict[str, Any]) -> dict[str, Any]:
        """POST /arkime/api/shortcut — create a value list / named IOC list.

        Guarded by checkCookieToken (Arkime v6.x); see _arkime_token_post. The
        list is referenced in expressions as $<name>.
        """
        return await self._arkime_token_post("/arkime/api/shortcut", shortcut)

    async def _write_upload_pcap(
        self, filename: str, content: bytes, tags: str = ""
    ) -> httpx.Response:
        """POST /server/php/submit.php — FilePond multipart PCAP upload.

        FilePond field name is 'filepond' (config.php ENTRY_FIELD). Returns the
        raw response so the caller can inspect status/text (FilePond replies 200
        with an empty/transfer-id body on success). A downstream libmagic check
        (pcap-monitor) does the real type enforcement. Verified live against
        Malcolm 25.12.1 — the bare /upload path is a rewrite target and 405s on
        a direct POST; the FilePond processor is under /server/php/submit.php.
        """
        c = await self._client()
        files = {"filepond": (filename, content, "application/octet-stream")}
        data = {"tags": tags} if tags else None
        return await c.post("/server/php/submit.php", files=files, data=data)

    # -- Convenience helpers --------------------------------------------

    async def field_values(
        self,
        field: str,
        limit: int = 30,
        filters: dict[str, Any] | None = None,
        time_from: str = "",
        time_to: str = "",
    ) -> list[dict[str, Any]]:
        """Get distinct values for a field via aggregation.

        Returns list of {"key": ..., "doc_count": ...}.
        """
        data = await self.aggregate(
            fields=field,
            filters=filters,
            limit=limit,
            time_from=time_from,
            time_to=time_to,
        )
        return _extract_buckets(data, field)

    async def field_profile(
        self, field: str, time_from: str = "", time_to: str = ""
    ) -> list[dict[str, Any]]:
        """Show which datasets contain a given field, over a time range.

        Omitting the range uses Malcolm's default (recent) window — pass
        time_from/time_to (dateparser format) to reach historical data.

        Returns list of {"dataset": ..., "doc_count": ...}.
        """
        data = await self.aggregate(
            fields="event.dataset",
            filters={f"!{field}": None},
            time_from=time_from,
            time_to=time_to,
        )
        buckets = _extract_buckets(data, "event.dataset")
        return [{"dataset": b["key"], "doc_count": b["doc_count"]} for b in buckets]


def _extract_buckets(data: dict[str, Any], field: str) -> list[dict[str, Any]]:
    """Extract aggregation buckets from Malcolm /mapi/agg response."""
    # Malcolm agg response nests buckets under the field name (dots replaced)
    # Try several extraction strategies
    if "results" in data:
        results = data["results"]
        if isinstance(results, list):
            return results
        if isinstance(results, dict):
            # Nested agg: look for the first key with buckets
            for val in results.values():
                if isinstance(val, dict) and "buckets" in val:
                    return val["buckets"]
                if isinstance(val, list):
                    return val

    # Flat bucket list at top level
    if "buckets" in data:
        return data["buckets"]

    # Field-keyed access. Malcolm /mapi/agg keys the agg by the literal
    # field name WITH dots (e.g. {"event.dataset": {"buckets": [...]}});
    # keep the underscore variant as a fallback for older responses.
    for field_key in (field, field.replace(".", "_")):
        if field_key in data:
            sub = data[field_key]
            if isinstance(sub, dict) and "buckets" in sub:
                return sub["buckets"]
            if isinstance(sub, list):
                return sub

    # Last resort: if response has 'values' key
    if "values" in data:
        vals = data["values"]
        if isinstance(vals, list):
            return vals

    logger.warning("[malcolm] Could not extract buckets from agg response for field=%s", field)
    return []


def _arkime_query_params(expression: str, time_from: str, time_to: str) -> dict[str, Any]:
    """Standard Arkime SessionsQuery params (expression + time window)."""
    params: dict[str, Any] = {}
    if expression:
        params["expression"] = expression
    if time_from:
        params["startTime"] = time_from
    if time_to:
        params["stopTime"] = time_to
    return params
