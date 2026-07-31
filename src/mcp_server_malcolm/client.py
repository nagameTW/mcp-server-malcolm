"""Malcolm HTTP client -- core reusable component.

All Malcolm API interactions go through this client.
Usable standalone (direct import) or via the MCP server layer.

Configuration via environment variables:
    MALCOLM_URL                      Base URL (default: https://localhost)
    MALCOLM_USERNAME                 Basic auth user (default: admin)
    MALCOLM_PASSWORD                 Basic auth password (default: admin)
    MALCOLM_SSL_VERIFY               Verify TLS certs (default: true; "false" or a CA path)
    MALCOLM_TIMEOUT                  Request timeout seconds (default: 30)
    MALCOLM_MAX_CONCURRENCY          Simultaneous upstream requests (default: 8)
    MALCOLM_MAX_REQUESTS_PER_MINUTE  Upstream request-rate cap (default: 600)
"""

from __future__ import annotations

import asyncio
import functools
import logging
import os
import re
import time
from collections import deque
from collections.abc import Awaitable, Callable, Iterable
from difflib import get_close_matches
from typing import Any, ParamSpec, TypeVar
from urllib.parse import quote

import httpx

from mcp_server_malcolm.errors import ToolInputError, UpstreamError, redact
from mcp_server_malcolm.field_aliases import alias_for

logger = logging.getLogger(__name__)

# Bounds on upstream traffic. The MCP tools spec makes rate-limiting a server
# obligation, and this client is the single point every tool's traffic crosses.
# Both defaults are set far above an interactive session -- no tool in this
# server fans out, so a hunt issues requests one at a time -- and exist to stop
# a runaway loop from hammering Malcolm, not to pace a human.
_DEFAULT_MAX_CONCURRENCY = 8
_DEFAULT_MAX_REQUESTS_PER_MINUTE = 600
_RATE_WINDOW_SECONDS = 60.0


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


_DIGITS = re.compile(r"[0-9]+")


def _positive_int_env(name: str, default: int) -> int:
    """Read a positive integer setting, falling back on anything unusable.

    A bound that is absent, blank or nonsense must not be read as "no bound":
    a typo in a deployment's env file would then silently remove the limiter.
    """
    raw = os.environ.get(name, "").strip()
    # _DIGITS, not str.isdigit(): the latter is True for characters int() then
    # refuses ("①"), which would crash from_env() on a typo in a deployment's
    # env file -- the exact failure this fallback exists to prevent.
    if _DIGITS.fullmatch(raw) and int(raw) > 0:
        return int(raw)
    if raw:
        logger.warning("[malcolm] ignoring %s=%r; using %d", name, raw, default)
    return default


def _positive_arg(name: str, value: int) -> int:
    """Reject a non-positive bound handed to the constructor.

    The two paths differ on purpose. An env var is a deployment's input, and a
    typo there must not stop the server from starting, so _positive_int_env
    logs and keeps the default -- the limiter stays on either way. A constructor
    argument is a programmer's input, reached only by the standalone use the
    module docstring advertises; substituting a default would hide the caller's
    bug instead of reporting it. Unchecked, the two values fail far from their
    cause: max_requests_per_minute=0 makes _rate_limit index an empty deque
    (IndexError), and max_concurrency=0 leaves every request queued forever on a
    pool that can never open a connection.
    """
    if value < 1:
        raise ValueError(f"{name} must be a positive integer, got {value!r}")
    return value


# -- Path-splicing guards ---------------------------------------------------
# Every value below is interpolated into an upstream URL path. httpx removes
# dot segments before sending, so an unchecked value walks out of its endpoint:
# aggregate(fields="../../arkime/api/hunts") posts to /arkime/api/hunts with
# this client's Basic auth, defeating the read-only boundary and the write-class
# gate, which both assume an unregistered endpoint is unreachable. The classes
# are allow-lists, so "/", "?", "#", "%" and "\" can never appear. A new method
# that splices a value into a path needs its own entry here.

# Field names, taken from the live catalogue rather than guessed: all 5969
# names /mapi/fields returns on Malcolm v26.07.1 are drawn from letters, digits
# and "_ . - @ [ ]" -- e.g. "@timestamp", "destination.mac-cnt",
# "suricata.smb.client_dialects[]", "http.request-content-type". One name ends
# in a stray space ("suricata.ftp.command "); the space-free spelling is indexed
# too, so whitespace is stripped rather than admitted.
_FIELD_RE = re.compile(r"[A-Za-z0-9_.@\[\]-]+")
_FIELD_SHAPE = "a Malcolm field name such as 'source.ip' (letters, digits and _ . - @ [ ])"

# Index names and patterns: the 25 indices on the lab use letters, digits and
# "_ . -"; "*" is the wildcard the query tools advertise and "," joins several.
_INDEX_RE = re.compile(r"[A-Za-z0-9_.*,-]+")
_INDEX_SHAPE = "an index or pattern such as 'arkime_sessions3-*'"

# Saved-object ids: the 50 dashboards on the lab are UUIDs plus named ones like
# "Metricbeat-system-overview", so letters, digits and "_ . -".
_DASHBOARD_ID_RE = re.compile(r"[A-Za-z0-9_.-]+")
_DASHBOARD_ID_SHAPE = "a saved-object id such as 'd2dd0180-06b1-11ec-8c6b-353266ade330'"

# NetBox REST paths are app/model segments, so a slash is legitimate here and
# the "no dot segment" check below is what keeps it from traversing.
_NETBOX_PATH_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9/_-]*")
_NETBOX_PATH_SHAPE = "a NetBox REST path such as 'api/ipam/ip-addresses/'"

# A body hash is hex. The window spans the digests Arkime stores (md5 32,
# sha1 40, sha256 64) with room either side rather than pinning those three
# exactly, so a deployment hashing with something else still resolves.
_HASH_RE = re.compile(r"[A-Fa-f0-9]{16,128}")
_HASH_SHAPE = "an md5 or sha256 hex digest"

# A path segment that is exactly "..", which is what httpx collapses. Written
# as a segment test rather than a substring one so a carved filename like
# "report..pdf" -- percent-encoded into a single segment -- still goes through.
_DOT_SEGMENT = re.compile(r"(?:^|/)\.\.(?:/|$)")


def _checked(value: str, pattern: re.Pattern[str], what: str, shape: str) -> str:
    """Return value unchanged if it is safe to splice into a path, else raise."""
    if not pattern.fullmatch(value) or _DOT_SEGMENT.search(value):
        raise ToolInputError(f"invalid {what}: {value!r} — expected {shape}")
    return value


def _checked_field_list(fields: str) -> str:
    """Validate a comma-separated field list and return it whitespace-free.

    /mapi/agg takes the list as one path segment, so each name is checked
    separately and the result rejoined -- that way "source.ip, destination.ip",
    the spelling an analyst types, is accepted instead of rejected for a space.
    """
    names = [_checked(n.strip(), _FIELD_RE, "field name", _FIELD_SHAPE) for n in fields.split(",")]
    return ",".join(names)


def _checked_path(path: str) -> str:
    """Backstop on an assembled request path.

    The per-argument guards above are the fix; this catches the next method
    that interpolates a value into a path and forgets one, because httpx
    collapses the dot segments before sending and the escape leaves no trace.
    """
    if _DOT_SEGMENT.search(path):
        raise ToolInputError(f"refusing a request path with a '..' segment: {path!r}")
    return path


_P = ParamSpec("_P")
_R = TypeVar("_R")


def _upstream(fn: Callable[_P, Awaitable[_R]]) -> Callable[_P, Awaitable[_R]]:
    """Convert any httpx failure raised inside into an UpstreamError.

    httpx exception text is written for an operator: it carries the full
    request URL, and MALCOLM_URL may embed credentials as userinfo. Converting
    here rather than at each tool means the redaction happens once, and every
    tool sees one exception type carrying the status it may want to branch on.
    """

    @functools.wraps(fn)
    async def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        try:
            return await fn(*args, **kwargs)
        except httpx.HTTPStatusError as exc:
            raise UpstreamError(redact(str(exc)), exc.response.status_code) from exc
        except httpx.HTTPError as exc:
            raise UpstreamError(redact(str(exc))) from exc

    return wrapper


class MalcolmClient:
    """Async HTTP client for the Malcolm REST API.

    Wraps /mapi/* endpoints (unified gateway) and /arkime/api/* endpoints.
    Handles authentication, SSL, timeouts, and field caching.

    Raises:
        ValueError: max_concurrency or max_requests_per_minute below 1. See
            _positive_arg for why this raises where the env path falls back.
    """

    def __init__(
        self,
        base_url: str = "https://localhost",
        username: str = "admin",
        password: str = "admin",
        ssl_verify: bool | str = True,
        timeout: float = 30.0,
        max_concurrency: int = _DEFAULT_MAX_CONCURRENCY,
        max_requests_per_minute: int = _DEFAULT_MAX_REQUESTS_PER_MINUTE,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = httpx.BasicAuth(username, password)
        self._ssl_verify = ssl_verify
        self._timeout = timeout
        self._max_concurrency = _positive_arg("max_concurrency", max_concurrency)
        self._max_requests_per_minute = _positive_arg(
            "max_requests_per_minute", max_requests_per_minute
        )
        self._request_times: deque[float] = deque()
        self._rate_lock = asyncio.Lock()
        self._http: httpx.AsyncClient | None = None
        self._http_lock = asyncio.Lock()
        self._field_cache: dict[str, str] | None = None
        self._arkime_field_cache: list[dict[str, str]] | None = None

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

        MALCOLM_MAX_CONCURRENCY and MALCOLM_MAX_REQUESTS_PER_MINUTE bound the
        upstream traffic; see the module docstring for the defaults.
        """
        return cls(
            base_url=os.environ.get("MALCOLM_URL", "https://localhost"),
            username=os.environ.get("MALCOLM_USERNAME", "admin"),
            password=os.environ.get("MALCOLM_PASSWORD", "admin"),
            ssl_verify=_parse_ssl_verify(os.environ.get("MALCOLM_SSL_VERIFY", "true")),
            timeout=float(os.environ.get("MALCOLM_TIMEOUT", "30")),
            max_concurrency=_positive_int_env("MALCOLM_MAX_CONCURRENCY", _DEFAULT_MAX_CONCURRENCY),
            max_requests_per_minute=_positive_int_env(
                "MALCOLM_MAX_REQUESTS_PER_MINUTE", _DEFAULT_MAX_REQUESTS_PER_MINUTE
            ),
        )

    # -- HTTP primitives ------------------------------------------------

    async def _rate_limit(self, request: httpx.Request) -> None:
        """Hold a request back until it fits under the per-minute cap.

        Registered as an httpx request event hook, so every route out -- get,
        post, the streaming downloads, the write primitives -- crosses it
        without each having to remember to. Sleeping while holding the lock
        releases waiters in arrival order; at these rates fairness is worth
        more than the throughput a shared wakeup would buy.
        """
        async with self._rate_lock:
            while True:
                now = time.monotonic()
                while self._request_times and now - self._request_times[0] >= _RATE_WINDOW_SECONDS:
                    self._request_times.popleft()
                if len(self._request_times) < self._max_requests_per_minute:
                    self._request_times.append(now)
                    return
                wait = _RATE_WINDOW_SECONDS - (now - self._request_times[0])
                logger.debug("[malcolm] rate cap reached, holding %s for %.1fs", request.url, wait)
                await asyncio.sleep(wait)

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
                    # The pool is where bounded concurrency already exists:
                    # httpx queues anything over max_connections, so no separate
                    # semaphore has to be threaded through every call site.
                    limits=httpx.Limits(max_connections=self._max_concurrency),
                    event_hooks={"request": [self._rate_limit]},
                    follow_redirects=True,
                )
            return self._http

    @_upstream
    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """HTTP GET, returns parsed JSON."""
        c = await self._client()
        resp = await c.get(_checked_path(path), params=params)
        resp.raise_for_status()
        return resp.json()

    @_upstream
    async def post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        """HTTP POST with JSON body, returns parsed JSON."""
        c = await self._client()
        resp = await c.post(_checked_path(path), json=body or {})
        resp.raise_for_status()
        return resp.json()

    @_upstream
    async def get_raw(self, path: str, params: dict[str, Any] | None = None) -> httpx.Response:
        """HTTP GET returning the raw response (for binary downloads).

        Converts a failure that produced no response -- DNS, TLS, connect,
        timeout -- into UpstreamError, but hands back any status untouched.
        Every caller of this method reads ``resp.status_code`` itself precisely
        because a 400 or 404 here is an answer ("no match", "file pruned"), not
        a fault; raising on those would take that decision away from them.
        """
        c = await self._client()
        return await c.get(_checked_path(path), params=params)

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

        Raises:
            ToolInputError: a name is not a Malcolm field name. The list becomes
                a URL path segment, so an unchecked value reaches another
                endpoint entirely.
        """
        safe_fields = _checked_field_list(fields)
        body: dict[str, Any] = {"limit": limit}
        if filters:
            body["filter"] = filters
        if time_from:
            body["from"] = time_from
        if time_to:
            body["to"] = time_to
        if doctype:
            body["doctype"] = doctype
        return await self.post(f"/mapi/agg/{safe_fields}", body)

    # -- OpenSearch DSL (generic; backend-agnostic) ---------------------
    # These speak plain OpenSearch DSL against the configured endpoint via
    # Malcolm's /mapi/opensearch proxy. No Malcolm-specific query shape —
    # point the base_url elsewhere and they work against any OpenSearch.

    async def opensearch_dsl(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST a raw DSL search body; returns the raw OpenSearch response."""
        safe = _checked(index, _INDEX_RE, "index", _INDEX_SHAPE)
        return await self.post(f"/mapi/opensearch/{safe}/_search", body)

    async def opensearch_count(self, index: str, query: dict[str, Any]) -> dict[str, Any]:
        """Count docs matching a DSL query clause."""
        safe = _checked(index, _INDEX_RE, "index", _INDEX_SHAPE)
        return await self.post(f"/mapi/opensearch/{safe}/_count", {"query": query})

    async def opensearch_indices(self, pattern: str = "*") -> Any:
        """List indices (name/health/status/docs.count) as JSON."""
        safe = _checked(pattern, _INDEX_RE, "index pattern", _INDEX_SHAPE)
        return await self.get(
            f"/mapi/opensearch/_cat/indices/{safe}",
            params={"format": "json", "h": "index,health,status,docs.count"},
        )

    async def opensearch_mapping(self, index: str) -> dict[str, Any]:
        """Field mapping for an index."""
        safe = _checked(index, _INDEX_RE, "index", _INDEX_SHAPE)
        return await self.get(f"/mapi/opensearch/{safe}/_mapping")

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
        """Force re-fetch of both field lists on next call."""
        self._field_cache = None
        self._arkime_field_cache = None

    async def arkime_fields(self) -> list[dict[str, str]]:
        """Return Arkime's field table (cached), expression name paired with db name.

        Arkime's expression parser accepts only Arkime's own names — `ip.src`,
        `port.dst`, `protocols` — and /mapi/fields does not list them: Malcolm
        merges Arkime's field table keyed by `dbField2` and drops the `exp`
        alias, so that list holds `srcIp` and `source.ip` but never `ip.src`.
        This endpoint is the only place an agent can discover a name that will
        work inside an `expression` argument.

        Returns:
            One dict per field with "exp" (use in expressions), "db" (use where
            a tool asks for an Arkime db field, e.g. arkime_connections), plus
            "type", "group" and "help". Sorted by expression name.
        """
        if self._arkime_field_cache is not None:
            return self._arkime_field_cache

        data = await self.get("/arkime/api/fields", params={"array": "true"})
        # Arkime returns an array with array=true, a map keyed by exp without it;
        # tolerate both so a viewer version change cannot blank the tool.
        entries = data.values() if isinstance(data, dict) else data
        fields = sorted(
            (
                {
                    "exp": entry.get("exp", ""),
                    "db": entry.get("dbField2") or entry.get("dbField", ""),
                    "type": entry.get("type", ""),
                    "group": entry.get("group", ""),
                    "help": entry.get("help", ""),
                }
                for entry in entries
                if isinstance(entry, dict) and entry.get("exp")
            ),
            key=lambda field: field["exp"],
        )
        self._arkime_field_cache = fields
        logger.info("[malcolm] Cached %d Arkime expression fields", len(fields))
        return fields

    async def search_arkime_fields(
        self, keyword: str = "", group: str = ""
    ) -> list[dict[str, str]]:
        """Filter the Arkime field table by substring and/or group.

        Args:
            keyword: Matched against the expression name, db name and help text.
            group: Exact Arkime field group, e.g. "http", "dns", "general".

        Returns:
            The matching subset of arkime_fields(); everything when both
            arguments are empty.
        """
        keyword = keyword.lower().strip()
        group = group.lower().strip()
        results = []
        for field in await self.arkime_fields():
            if group and field["group"].lower() != group:
                continue
            if (
                keyword
                and keyword not in " ".join((field["exp"], field["db"], field["help"])).lower()
            ):
                continue
            results.append(field)
        return results

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
        """Check if a field exists; if not, suggest alternatives.

        A known pipeline rename wins over string similarity: for a field like
        suricata.alert.signature, difflib returns real-but-wrong siblings
        (suricata.alert.rev, ...) with no way for the caller to tell them from
        the truth, whereas the alias table names the one correct target.
        """
        fields = await self.get_fields()

        if name in fields:
            return {"exists": True, "field": name, "type": fields[name]}

        if (renamed := alias_for(name)) and renamed in fields:
            return {
                "exists": False,
                "field": name,
                "suggestion": renamed,
                "type": fields[renamed],
                "reason": "renamed by Malcolm's ingest pipeline",
            }

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

    async def explain_unknown_fields(self, names: Iterable[str]) -> str:
        """Report which of these field names are absent from the index.

        Intended for the moment a query comes back empty: a filter on a field
        Malcolm renamed during ingest returns zero documents and no error, so
        without this an agent sees a valid-looking "no results" and concludes
        the traffic is not there. Costs nothing on the happy path — callers
        only ask once a result set is already empty.

        Args:
            names: Filter keys as written by the caller; a leading "!"
                (Malcolm's negation prefix) is ignored.

        Returns:
            A multi-line explanation, or "" when every name exists (an empty
            result set is then genuine) or when the field list is unreachable.
        """
        lines: list[str] = []
        try:
            for raw in names:
                name = raw.lstrip("!").strip()
                if not name:
                    continue
                resolution = await self.resolve_field(name, max_suggestions=3)
                if resolution.get("exists"):
                    continue
                if suggestion := resolution.get("suggestion"):
                    lines.append(f"  {name} is not indexed — Malcolm stores this as {suggestion}")
                elif suggestions := resolution.get("suggestions"):
                    lines.append(f"  {name} is not indexed — similar: {', '.join(suggestions)}")
                else:
                    lines.append(f"  {name} is not indexed and has no close match")
        except Exception as exc:  # noqa: BLE001
            # A diagnostic must never turn a successful (if empty) query into a
            # failure — drop the hint and let the empty result stand.
            logger.debug("[malcolm] field diagnostic unavailable: %s", exc)
            return ""

        if not lines:
            return ""
        return "No documents matched. These filter fields do not exist:\n" + "\n".join(lines)

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
        safe = _checked(dashboard_id, _DASHBOARD_ID_RE, "dashboard id", _DASHBOARD_ID_SHAPE)
        return await self.get(f"/mapi/dashboard-export/{safe}")

    # -- OpenSearch Dashboards & plugins --------------------------------

    async def dashboards_find(
        self, types: list[str], search: str = "", limit: int = 20
    ) -> dict[str, Any]:
        """Saved objects via GET /dashboards/api/saved_objects/_find.

        `fields` is set to title/description so the server trims the payload
        before sending it: measured on v26.07.1, five dashboards are 19.7 KB in
        full and 6.0 KB trimmed, because a dashboard is mostly its panelsJSON
        layout blob.

        Args:
            types: Object types, repeated as separate `type` params.
            search: simple_query_string matched against the title only.
        """
        params: list[tuple[str, Any]] = [("type", t) for t in types]
        params += [("fields", "title"), ("fields", "description"), ("per_page", limit)]
        if search:
            params += [("search", search), ("search_fields", "title")]
        return await self.get("/dashboards/api/saved_objects/_find", params=params)

    async def alerting_monitors(self, limit: int = 50) -> dict[str, Any]:
        """Alerting monitors via POST /_plugins/_alerting/monitors/_search.

        The Dashboards-side route (/dashboards/api/alerting/monitors) needs
        from/size/search all present and 400s otherwise, so this goes straight
        to the OpenSearch plugin through Malcolm's proxy.
        """
        return await self.post(
            "/mapi/opensearch/_plugins/_alerting/monitors/_search",
            {"query": {"match_all": {}}, "size": limit},
        )

    async def alerting_alerts(self) -> dict[str, Any]:
        """Currently-raised alerts via GET /_plugins/_alerting/monitors/alerts.

        alertState is pinned to ACTIVE: the API defaults to ALL, which counts
        COMPLETED and ACKNOWLEDGED history alongside what is firing now, so the
        default would answer a different question from the one asked.
        """
        return await self.get(
            "/mapi/opensearch/_plugins/_alerting/monitors/alerts",
            params={"alertState": "ACTIVE"},
        )

    async def anomaly_detectors(self, limit: int = 50) -> dict[str, Any]:
        """Anomaly detectors via POST /_plugins/_anomaly_detection/detectors/_search."""
        return await self.post(
            "/mapi/opensearch/_plugins/_anomaly_detection/detectors/_search",
            {"query": {"match_all": {}}, "size": limit},
        )

    async def anomaly_result_count(self) -> dict[str, Any]:
        """How many ANOMALOUS results exist, via the detectors results search.

        The results index holds one document per detection interval per entity
        whether or not anything was anomalous — that is why the documents carry
        an `is_anomaly` boolean and an `anomaly_grade` at all. A match_all count
        therefore counts detector runs, which for Malcolm's four shipped
        MULTI_ENTITY detectors at a ten-minute interval reaches five or six
        figures within a day of being started. The range filter counts the
        anomalies themselves.

        track_total_hits is set because OpenSearch otherwise stops counting at
        10,000 and reports the total as a lower bound, which would silently cap
        exactly the number this is here to report.
        """
        return await self.post(
            "/mapi/opensearch/_plugins/_anomaly_detection/detectors/results/_search",
            {"query": {"range": {"anomaly_grade": {"gt": 0}}}, "size": 0, "track_total_hits": True},
        )

    # -- NetBox (forwarded) ---------------------------------------------

    async def netbox_get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Query NetBox API via Malcolm's /mapi/netbox/ proxy."""
        safe = _checked(path.lstrip("/"), _NETBOX_PATH_RE, "NetBox path", _NETBOX_PATH_SHAPE)
        return await self.get(f"/mapi/netbox/{safe}", params=params)

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

    @_upstream
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
            return await _read_capped(resp, max_bytes, "PCAP")

    @_upstream
    async def extracted_file(self, name: str, max_bytes: int = 0) -> tuple[int, bytes]:
        """Download one Zeek-extracted file from Malcolm's extracted-files server.

        GET /extracted-files/<name>, the directory Malcolm serves when
        FILESCAN_HTTP_SERVER_ENABLE is on (the same path zeek.files.extracted_uri
        records). The name is percent-encoded here because httpx does not escape
        it: a '#' or '?' in a carved SMB filename would otherwise be parsed as a
        fragment or query and fetch the wrong file. Encoding collapses the name
        to one segment, so it cannot traverse; the path backstop then catches
        the one name that would survive that, a bare "..".

        Args:
            name: Bare filename, no directory part (the directory is flat).
            max_bytes: Refuse a download larger than this (0 = no cap). The body
                is streamed so an oversized response is aborted before it is all
                read into memory.

        Returns:
            (status_code, body). The body is empty for an error status, so a 404
            — the record is indexed but the file was pruned or never preserved —
            is reportable without raising.

        Raises:
            ValueError: the response exceeds max_bytes.
        """
        c = await self._client()
        path = _checked_path(f"/extracted-files/{quote(name, safe='')}")
        async with c.stream("GET", path) as resp:
            if resp.status_code >= 400:
                return resp.status_code, b""
            return resp.status_code, await _read_capped(resp, max_bytes, "Extracted file")

    async def arkime_hunts(self, length: int = 50, history: bool = False) -> dict[str, Any]:
        """List Arkime hunt jobs (READ). Ships with the hunt-job write class."""
        params = {"length": length, "history": "true" if history else "false"}
        return await self.get("/arkime/api/hunts", params=params)

    async def arkime_views(self, length: int = 100) -> dict[str, Any]:
        """Saved search views via GET /arkime/api/views (the plural route is
        GET-only; the singular /api/view is the create route)."""
        return await self.get("/arkime/api/views", params={"length": length})

    async def arkime_shortcuts(self, length: int = 100) -> dict[str, Any]:
        """Named value lists via GET /arkime/api/shortcuts.

        A shortcut is referenced inside an expression as $<name>.
        """
        return await self.get("/arkime/api/shortcuts", params={"length": length})

    @_upstream
    async def arkime_reverse_dns(self, ip: str) -> str:
        """PTR name for an address via GET /arkime/api/reversedns.

        Returns a bare hostname as plain text. Arkime answers 200 with the body
        "reverse error" when there is no PTR record (verified on 6.6.0 for a
        private address), so the status code cannot be used to tell the two
        apart — the caller has to read the body.
        """
        resp = await self.get_raw("/arkime/api/reversedns", params={"ip": ip})
        resp.raise_for_status()
        return resp.text.strip()

    async def arkime_pcap_files(self, length: int = 100) -> dict[str, Any]:
        """The PCAP files Arkime has indexed, via GET /arkime/api/files."""
        return await self.get("/arkime/api/files", params={"length": length})

    async def arkime_node_stats(self, node_filter: str = "") -> dict[str, Any]:
        """Capture-node statistics via GET /arkime/api/stats.

        Narrowing is done with `filter`, a substring match on the node name.
        Verified on 6.6.0: `nodeName` is accepted and silently ignored, which
        returns every node and reads as though the filter matched everything.
        """
        params: dict[str, Any] = {}
        if node_filter:
            params["filter"] = node_filter
        return await self.get("/arkime/api/stats", params=params)

    @_upstream
    async def arkime_sessions_csv(
        self,
        expression: str = "",
        limit: int = 100,
        fields: str = "",
        time_from: str = "",
        time_to: str = "",
    ) -> str:
        """Sessions as CSV via GET /arkime/api/sessions.csv.

        There is a matching connections.csv, deliberately not wrapped: on
        Arkime 6.6.0 it emits a 9-column header over 7-column rows, so every
        column after "Sessions" is mislabeled. See arkime_connections for the
        correct source/destination summary.

        Args:
            fields: Comma-separated ECS dotted names (source.ip, destination.port).
                Arkime NEVER ANSWERS for a db name (srcIp) or an expression name
                (ip.src) here: measured on 6.6.0, both hang until the client
                times out rather than returning an error.

        Returns the CSV text, header row included. `length` bounds the rows
        exactly here (measured: 1000 in, 1000 out).
        """
        params = _arkime_query_params(expression, time_from, time_to)
        params["length"] = limit
        if fields:
            params["fields"] = fields
        resp = await self.get_raw("/arkime/api/sessions.csv", params=params)
        resp.raise_for_status()
        return resp.text

    async def arkime_session_detail(self, session_id: str) -> dict[str, Any]:
        """Full SPI document for one session, via the sessions search.

        GET /arkime/api/session/<id> serves the Arkime SPA HTML shell, not JSON,
        so a single session is fetched through /arkime/api/sessions with an
        `id ==` expression and date=-1 (all time). The id is indexed, so this
        stays a point lookup rather than a scan.

        The id is reduced to its bare form first. arkime_sessions hands out the
        node-prefixed id ("3@240425:240425-IrHoGmqqp7SR6TWIWoG0Dw") but Arkime's
        `id ==` matches only the part after the last ':' — measured on 26.07.1,
        the prefixed form returns 0 rows and the bare one returns the session.
        Feeding this tool the id its sibling produced therefore always missed.
        Only this expression needs the bare form: sessions.pcap takes the
        prefixed id as-is, so arkime_session_pcap passes it through untouched.

        Returns {} when no session matches the id.
        """
        bare_id = session_id.rsplit(":", 1)[-1].rsplit("@", 1)[-1]
        result = await self.get(
            "/arkime/api/sessions",
            params={"expression": f"id == {bare_id}", "date": -1, "length": 1},
        )
        data = result.get("data") if isinstance(result, dict) else None
        return data[0] if data else {}

    @_upstream
    async def arkime_unique(
        self,
        expression: str,
        field: str,
        counts: bool = True,
        time_from: str = "",
        time_to: str = "",
    ) -> str:
        """Distinct values of one field via GET /arkime/api/unique.

        Omitting the range uses Arkime's default (recent) window, which returns
        nothing on a historical capture — pass epoch-seconds strings to reach it.
        Verified on 26.07.1: with no window this endpoint returned an empty body
        over a 6M-session index whose data is a year old, and the same call with
        startTime/stopTime returned the value list.

        Returns text (one value per line), not JSON — this Arkime endpoint
        streams a plain-text body, optionally suffixed with counts.
        """
        params: dict[str, Any] = _arkime_query_params(expression, time_from, time_to)
        params["exp"] = field
        params["counts"] = 1 if counts else 0
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

    @_upstream
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
        safe = _checked(file_hash, _HASH_RE, "body hash", _HASH_SHAPE)
        return await self.get_raw(f"/arkime/api/sessions/bodyhash/{safe}")

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

    @_upstream
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

    @_upstream
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

    @_upstream
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


async def _read_capped(resp: httpx.Response, max_bytes: int, what: str) -> bytes:
    """Read an open streaming response into memory, refusing to exceed max_bytes.

    Args:
        resp: An open streaming response whose status is already checked.
        max_bytes: Hard cap in bytes; 0 disables it.
        what: Noun for the error message, e.g. "PCAP".

    Returns:
        The whole body.

    Raises:
        ValueError: the declared or streamed length exceeds max_bytes. Checking
            Content-Length first refuses the oversized body before reading it;
            the running total catches a server that does not declare one.
    """
    if max_bytes:
        declared = resp.headers.get("content-length")
        if declared is not None and int(declared) > max_bytes:
            raise ValueError(f"{what} too large: {int(declared)} bytes exceeds cap {max_bytes}")
    chunks: list[bytes] = []
    total = 0
    async for chunk in resp.aiter_bytes():
        total += len(chunk)
        if max_bytes and total > max_bytes:
            raise ValueError(f"{what} exceeds cap {max_bytes} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


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
