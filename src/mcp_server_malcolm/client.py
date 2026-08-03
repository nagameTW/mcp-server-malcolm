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
import html
import json
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

# Arkime capture-node names, measured on Malcolm v26.07.1: "arkime" and
# "capture-4f2a-node". Arkime derives the name from the capture host unless an
# operator overrides it in config.ini, so the class is the host-name characters
# plus "_", which that override allows.
_ARKIME_NODE_RE = re.compile(r"[A-Za-z0-9_.-]+")
_ARKIME_NODE_SHAPE = "an Arkime capture-node name such as 'capture-4f2a-node'"

# Arkime session ids, measured over 1000 of them here: the base64url alphabet,
# e.g. "240425-yATE05tK50pD37H4n83ww_-M". ":" and "@" are in the class because
# the search tools hand out the prefixed spelling ("3@240425:240425-...") and
# the payload routes accept it -- verified byte-identical responses for both
# forms -- so rejecting it would break the id a caller copied from a sibling
# tool. Neither character is a path separator.
_ARKIME_SESSION_ID_RE = re.compile(r"[A-Za-z0-9_:@-]+")
_ARKIME_SESSION_ID_SHAPE = "an Arkime session id such as '240425-yATE05tK50pD37H4n83ww_-M'"

# OpenSearch auto-generated document ids: this lab's one alerting monitor, its
# five anomaly detectors and any Arkime hunt all carry the same shape, measured
# as 20 characters of the base64url alphabet ("NYUZsZ8Bao8axaN3ef1f").
_OS_DOC_ID_RE = re.compile(r"[A-Za-z0-9_-]+")
_OS_DOC_ID_SHAPE = "an OpenSearch document id such as 'NYUZsZ8Bao8axaN3ef1f'"

# Saved-object types, measured across all 1064 objects this lab holds: search,
# visualization, dashboard, index-pattern and config -- lowercase words joined
# by a hyphen.
_SAVED_TYPE_RE = re.compile(r"[a-z][a-z-]*")
_SAVED_TYPE_SHAPE = "a saved-object type such as 'search', 'visualization' or 'dashboard'"

# Saved-object ids, from the same 1064: mostly UUIDs, some named
# ("Metricbeat-system-overview"), some legacy Kibana ("AWDG9Qx0xQT5EBNmq3_2").
# "*" is in the class because the three index-pattern ids ARE their pattern
# ("arkime_sessions3-*"), and resolving a saved search's references[] entry
# lands on exactly those; "*" is an ordinary character inside a path segment.
_SAVED_ID_RE = re.compile(r"[A-Za-z0-9_.*-]+")
_SAVED_ID_SHAPE = "a saved-object id such as 'abd55c60-06a5-11ec-8c6b-353266ade330'"

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
            raise UpstreamError(_upstream_text(exc), exc.response.status_code) from exc
        except httpx.HTTPError as exc:
            raise UpstreamError(_upstream_text(exc)) from exc

    return wrapper


def _upstream_text(exc: httpx.HTTPError) -> str:
    """Redacted text for an httpx failure, never empty.

    httpx raises ConnectTimeout with no message at all -- the anyio timeout it
    wraps carries no text -- so passing str(exc) straight through reaches the
    caller as "Error executing tool <name>: " with nothing after the colon.
    That is the least useful thing this server can say, on the failure a first
    run hits most often after a certificate problem. Connection *refused* does
    carry text ("All connection attempts failed"); only the timeout is blank.

    The fallback names the exception and the target, because the host is what
    makes the error actionable -- the same reason redact() strips credentials
    from the URL rather than dropping the URL.
    """
    text = redact(str(exc))
    if text:
        return text
    request = getattr(exc, "request", None)
    where = f" for {redact(str(request.url))}" if request is not None else ""
    return f"{type(exc).__name__}{where}"


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

    async def arkime_fields(self) -> list[dict[str, str]]:
        """Return Arkime's field table (cached), expression name paired with db name.

        Arkime's expression parser wants Arkime's own names — `ip.src`,
        `port.dst`, `protocols` — and /mapi/fields does not list them: Malcolm
        merges Arkime's field table keyed by `dbField2` and drops the `exp`
        alias, so that list holds `srcIp` and `source.ip` but never `ip.src`.
        This endpoint is the only place an agent can discover a name that will
        work inside an `expression` argument. Getting it wrong is quiet, not
        loud: measured on Malcolm v26.07.1, `srcIp==<addr>` matched 0 sessions with no
        error while `ip.src==<addr>` matched 2,055,400.

        Returns:
            One dict per field with "exp" (use in expressions and in the field
            lists of unique / multiunique / spigraphhierarchy), "db" — Arkime's
            `dbField2`, for arkime_connections' srcField/dstField — plus
            "type", "group" and "help". Sorted by expression name. Passing one
            column's name where the other belongs raises ToolInputError for the
            sixteen fields whose two spellings differ.

            Neither column is the whole story for spigraph/spiview, which want
            `dbField`: identical to "db" for 4,034 of 26.07.1's 4,051 rows, but
            for the seventeen that fork it is the dotted path (source.ip for
            srcIp) and this list does not carry it.
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
        before sending it: measured on Malcolm v26.07.1, five dashboards are 19.7 KB in
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

    async def alerting_monitor(self, monitor_id: str) -> dict[str, Any]:
        """One monitor in full via GET /_plugins/_alerting/monitors/<id>.

        The search in alerting_monitors() returns the list; this returns the
        parts that list omits and that decide whether a monitor is worth
        trusting: `monitor.inputs[].search` holds the indices and the whole
        OpenSearch query, `monitor.triggers[]` the firing condition and
        severity, `monitor.schedule` the interval, and `monitor.enabled` says
        whether it runs at all -- measured false for this lab's one monitor,
        which is why nothing ever alerts here.

        Raises:
            ToolInputError: monitor_id is not shaped like an OpenSearch id.
            UpstreamError: no monitor has that id (upstream 404).
        """
        safe = _checked(monitor_id, _OS_DOC_ID_RE, "monitor id", _OS_DOC_ID_SHAPE)
        return await self.get(f"/mapi/opensearch/_plugins/_alerting/monitors/{safe}")

    async def alerting_alerts(
        self,
        alert_state: str = "ACTIVE",
        monitor_id: str = "",
        severity: str = "",
        search: str = "",
    ) -> dict[str, Any]:
        """Raised alerts via GET /_plugins/_alerting/monitors/alerts.

        Args:
            alert_state: ACTIVE (the default here) restricts the answer to what
                is firing now. Upstream defaults to ALL, which mixes COMPLETED
                and ACKNOWLEDGED history in with it and answers a different
                question, so the pin stays unless a caller asks for history on
                purpose. Other values: ERROR, DELETED.
            monitor_id: Restrict to one monitor. The parameter is singular --
                measured, `monitorIds` is a 400 with OpenSearch itself
                suggesting `monitorId`.
            severity: Trigger severity level, "1" (highest) through "5".
            search: Free-text match across the alert fields.

        Returns:
            {"alerts": [...], "totalAlerts": N}. Zero alerts is a successful
            answer -- measured {"alerts": [], "totalAlerts": 0} here, because
            the only monitor is disabled.
        """
        params: dict[str, Any] = {}
        if alert_state:
            params["alertState"] = alert_state
        if monitor_id:
            params["monitorId"] = monitor_id
        if severity:
            params["severityLevel"] = severity
        if search:
            params["searchString"] = search
        return await self.get("/mapi/opensearch/_plugins/_alerting/monitors/alerts", params=params)

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

    async def anomaly_detector_profile(self, detector_id: str) -> dict[str, Any]:
        """Run state of one detector via GET
        /_plugins/_anomaly_detection/detectors/<id>/_profile.

        The one call that separates "this detector has never run" from "it ran
        and found nothing", which the detector list and a zero result count
        cannot tell apart. Measured on Malcolm v26.07.1, all five detectors here answer:
        {"state": "DISABLED"} -- so the zero anomalies this lab reports mean
        the detectors were never started, not that the traffic is clean.

        Raises:
            ToolInputError: detector_id is not shaped like an OpenSearch id.
        """
        safe = _checked(detector_id, _OS_DOC_ID_RE, "detector id", _OS_DOC_ID_SHAPE)
        return await self.get(
            f"/mapi/opensearch/_plugins/_anomaly_detection/detectors/{safe}/_profile"
        )

    @_upstream
    async def anomaly_top_results(
        self,
        detector_id: str,
        start_time_ms: int,
        end_time_ms: int,
        size: int = 10,
        order: str = "severity",
        category_fields: list[str] | None = None,
        historical: bool = False,
    ) -> dict[str, Any]:
        """Worst anomalies a detector found, via POST
        /_plugins/_anomaly_detection/detectors/<id>/results/_topAnomalies.

        Args:
            start_time_ms/end_time_ms: EPOCH MILLISECONDS. Every arkime_* method
                in this client takes seconds; this one does not, and seconds go
                through without complaint as a window in 1970, so the answer
                comes back empty and looks like clean traffic. The lab's window
                is 1714003200000-1714089600000.
            order: "severity" (highest anomaly grade) or "occurrence" (most
                frequent). Lowercase only -- measured, "SEVERITY" is a 400
                reading "Ordering by SEVERITY is not a valid option".
            category_fields: Entity fields to group by, for a multi-entity
                detector. Optional: measured, omitting it still answers 200.
            historical: True asks for the results of a historical analysis
                task, false (the default) for the real-time detector. It is a
                QUERY parameter upstream, and putting it in the body instead is
                silently ignored -- measured, the body form answers 200 from
                the real-time results, so a caller who thinks they asked for
                history gets a different question answered. True raises here
                unless a historical task exists: measured 500
                "No historical tasks found for detector ID <id>" on all five of
                this lab's detectors, none of which was ever started.

        Returns:
            {"buckets": [...]}, empty when the detector found nothing in the
            window -- a successful answer. GET is not an option: measured, a
            GET without a body is a 400 "request body is required".

        Raises:
            ToolInputError: detector_id is not shaped like an OpenSearch id.
            UpstreamError: the plugin refused the query; .status is the HTTP
                status and the message carries the plugin's own reason.
        """
        safe = _checked(detector_id, _OS_DOC_ID_RE, "detector id", _OS_DOC_ID_SHAPE)
        body: dict[str, Any] = {
            "size": size,
            "order": order,
            "start_time_ms": start_time_ms,
            "end_time_ms": end_time_ms,
        }
        if category_fields:
            body["category_field"] = category_fields
        path = (
            f"/mapi/opensearch/_plugins/_anomaly_detection/detectors/{safe}"
            f"/results/_topAnomalies?historical={'true' if historical else 'false'}"
        )
        # Not self.post(): raise_for_status() there keeps httpx's message, which
        # is the internal URL and the status and nothing else. This route's 4xx
        # bodies name what is actually wrong -- measured on Malcolm v26.07.1, a detector
        # with no category field answers 400 {"error":{"reason":"No category
        # fields found for detector ID ..."}} -- and that reason is the only
        # part a caller can act on. Same shape as _write_arkime_hunt_cancel.
        c = await self._client()
        resp = await c.post(_checked_path(path), json=body)
        if resp.status_code >= 400:
            raise UpstreamError(
                f"the anomaly-detection plugin refused the top-anomalies query "
                f"({resp.status_code}): {redact(resp.text[:200])}",
                resp.status_code,
            )
        return resp.json()

    async def saved_object(self, obj_type: str, obj_id: str) -> dict[str, Any]:
        """Fetch one saved object in full via GET /dashboards/api/saved_objects/<type>/<id>.

        dashboards_find() lists titles; this is what turns a title into the
        query behind it. For a saved search that means the KQL/Lucene string an
        analyst wrote, which is directly reusable as a hunt.

        Args:
            obj_type: "search", "visualization" or "dashboard" (this lab also
                holds "index-pattern" and "config").
            obj_id: The id dashboards_find() returned.

        Returns:
            The object as Dashboards sends it, plus a "search_source" key this
            client decodes, because the query is not reachable by ordinary
            traversal: attributes.kibanaSavedObjectMeta.searchSourceJSON is a
            JSON *string* that needs a second parse, and the index it runs
            against is never inline -- searchSourceJSON.indexRefName is a
            placeholder resolved against the top-level references[] array.
            "search_source" is {"query", "language", "filters", "index_pattern"}
            with "" for whatever the object does not carry, and {} when there is
            no searchSourceJSON at all.

            A visualization has no indexRefName: measured, its index arrives
            through references[] as a "search" entry, so the chain is
            visualization -> that search's id -> this method again.

        Raises:
            ToolInputError: obj_type or obj_id is not shaped like one.
            UpstreamError: nothing has that type/id pair (upstream 404, which
                is also what an unknown *type* returns).
        """
        safe_type = _checked(obj_type, _SAVED_TYPE_RE, "saved-object type", _SAVED_TYPE_SHAPE)
        safe_id = _checked(obj_id, _SAVED_ID_RE, "saved-object id", _SAVED_ID_SHAPE)
        obj = await self.get(f"/dashboards/api/saved_objects/{safe_type}/{safe_id}")
        return {**obj, "search_source": _decode_search_source(obj)}

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
        GET-only; the singular /api/view is the create route).

        `all=true` for the reason spelled out on arkime_crons: without it even
        an arkimeAdmin account is served only its own.
        """
        return await self.get("/arkime/api/views", params={"length": length, "all": "true"})

    async def arkime_shortcuts(self, length: int = 100) -> dict[str, Any]:
        """Named value lists via GET /arkime/api/shortcuts.

        A shortcut is referenced inside an expression as $<name>. `all=true`
        for the reason spelled out on arkime_crons.
        """
        return await self.get("/arkime/api/shortcuts", params={"length": length, "all": "true"})

    @_upstream
    async def arkime_reverse_dns(self, ip: str) -> str:
        """PTR name for an address via GET /arkime/api/reversedns.

        Returns a bare hostname as plain text. Arkime answers 200 with the body
        "reverse error" when there is no PTR record (verified on Arkime 6.6.0 for a
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
        Verified on Arkime 6.6.0: `nodeName` is accepted and silently ignored, which
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
                (ip.src) here: measured on Arkime 6.6.0, both hang until the client
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

        Fetched through /arkime/api/sessions with an `id ==` expression and
        date=-1 (all time). The id is indexed, so this stays a point lookup
        rather than a scan.

        This docstring used to justify that detour by claiming GET
        /arkime/api/session/<id> serves the SPA HTML shell rather than JSON.
        That is false on Arkime 6.6.0: measured here it answers 200
        application/json in 10,794 bytes with 36 top-level keys, for both the
        bare and the node-prefixed id, and 500 {"text":"Session not found"} for
        an unknown one.

        The detour is not equivalent to it. Measured on the same session, the
        search answers 14 top-level keys against the route's 36 -- a strict
        subset, adding nothing of its own and missing 22: @timestamp, event,
        tags, tagsCnt, tcpflags, protocol, protocolCnt, length, ethertype,
        segmentCnt, packetPos, packetRange, srcOui, srcOuiCnt, dstOui,
        dstOuiCnt, srcTTL, srcTTLCnt, dstTTL, dstTTLCnt, srcRIR and dstRIR.
        (`id` and `nodehost` are in both.) It is kept only because swapping the
        URL widens every answer this tool has ever returned, which is a
        behavior change rather than a docstring correction. Swap it when that
        widening is wanted: both id forms work and the route needs no time
        window.

        The id is reduced to its bare form first. arkime_sessions hands out the
        node-prefixed id ("3@240425:240425-IrHoGmqqp7SR6TWIWoG0Dw") but Arkime's
        `id ==` matches only the part after the last ':' — measured on Malcolm v26.07.1,
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

        `field` is an Arkime EXPRESSION name (ip.src, port.dst). A db name
        fails silently here rather than loudly, which is why the same guard
        multiunique uses rejects it before the request: measured on Malcolm v26.07.1,
        exp=srcIp and exp=dstPort each returned HTTP 200 with a zero-byte body
        — indistinguishable from a field that genuinely holds no values —
        while ip.src returned 112 lines and port.dst 10000.

        Omitting the range uses Arkime's default (recent) window, which returns
        nothing on a historical capture — pass epoch-seconds strings to reach it.
        Verified on Malcolm v26.07.1: with no window this endpoint returned an empty body
        over a 6M-session index whose data is a year old, and the same call with
        startTime/stopTime returned the value list.

        Returns text (one value per line), not JSON — this Arkime endpoint
        streams a plain-text body, optionally suffixed with counts.
        """
        _require_arkime_exp_names(field)
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
        """Top values of one field with a time graph via GET /api/spigraph.

        Args:
            field: The storage path, i.e. Arkime's `dbField`. For 4,034 of the
                4,051 fields in 26.07.1's catalogue that is what
                arkime_field_search prints in its db column (protocol for
                protocols); the other seventeen fork dbField from dbField2 and
                the db column shows dbField2, which does not work here.
                Measured on Malcolm v26.07.1 over 1714003200-1714089600,
                field=destination.ip, field=protocol and field=http.host each
                returned 10 items, while ip.dst, protocols, dstIp, port.dst and
                dstPort each returned 0, all HTTP 200.

                Left unguarded on purpose. A wrong value is not statically
                separable at the scale that matters: 534 of the 4,051 rows
                spell exp differently from dbField, and the sixteen-pair table
                behind the expression guard covers 32 of the ~551 names that
                fail here — missing `protocols`, the one an agent reaches for
                first. A guard that catches 6% while reading as a check on the
                rest is worse than none. The response separates the two causes
                anyway: an empty items list with recordsFiltered > 0 is a field
                name that did not resolve, recordsFiltered == 0 is an empty
                window (measured: field=ip.dst over the window above returned 0
                items and recordsFiltered 6,016,935; field=destination.ip with
                no window returned 0 items and recordsFiltered 0).
        """
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
            spi: Comma-separated storage paths, each optionally ":<count>",
                e.g. "protocol:10,destination.ip:20" — the same spelling
                arkime_spigraph takes, not the expression names the field
                lists of unique/multiunique take. Measured on Malcolm v26.07.1 over
                1714003200-1714089600: spi=protocol:10 returned 10 buckets,
                spi=destination.ip:20 returned 20 and spi=http.host:5 returned
                5, while protocols, ip.dst, dstIp and communityId each returned
                an empty bucket list under their own key, HTTP 200.

                Unguarded for the same reason as arkime_spigraph's field, and
                readable the same way: recordsFiltered > 0 under empty buckets
                means the name did not resolve (spi=protocols:10 over that
                window returned 0 buckets and recordsFiltered 6,016,935), while
                recordsFiltered == 0 means the window matched nothing
                (spi=protocol:10 with no window: 0 buckets, recordsFiltered 0).
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
        node) or the dotted storage paths behind them; this route resolves the
        field itself instead of parsing it as an expression, so both spellings
        of one field land on the same graph and only the expression spelling
        fails. Measured on Malcolm v26.07.1 over 1714003200-1714089600, srcIp/dstIp and
        source.ip/destination.ip both returned 10 nodes and 8 links,
        srcIp/dstPort and source.ip/destination.port both 15 and 11, and the
        pairs (network.bytes, totBytes), (client.bytes, srcDataBytes),
        (destination.geo.country_iso_code, dstGEO) and (network.community_id,
        communityId) each agreed node-for-node; ip.src/dstIp and port.src/dstIp
        returned HTTP 403 "ResponseError: x_content_parse_exception" and
        srcIp/port.dst a 500 "TypeError: Cannot read properties of undefined
        (reading 'match')". Expression names are rejected before the request by
        _require_arkime_db_names.

        Returns {"nodes": [...], "links": [...]} for tracing who talked to whom.
        """
        _require_arkime_db_names(src_field, "srcField")
        _require_arkime_db_names(dst_field, "dstField")
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
            fields: Comma-separated Arkime EXPRESSION field names, e.g.
                "ip.src,port.dst". A db name is not an error Arkime signals in
                the status line: measured on Malcolm v26.07.1, exp=srcIp,dstIp returned
                HTTP 200 whose whole body was "Unknown expression srcIp", so
                db names are rejected here first.

        Returns plain text (one combined row per unique tuple), not JSON — this
        Arkime endpoint streams a text body.
        """
        _require_arkime_exp_names(fields)
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
            fields: Comma-separated Arkime EXPRESSION field names defining the
                hierarchy levels, e.g. "ip.src,ip.dst". Same vocabulary as
                multiunique, louder failure: measured on Malcolm v26.07.1,
                exp=srcIp,dstIp returned HTTP 403 {"success": false, "text":
                "Unknown expression srcIp"}, while exp=ip.src,ip.dst returned
                140 table rows. Db names are rejected before the request.

        Returns {"hierarchicalResults": {...}, "tableResults": [...]}.
        """
        _require_arkime_exp_names(fields)
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

    @_upstream
    async def arkime_session_packets(
        self,
        node: str,
        session_id: str,
        base: str = "hex",
        packets: int = 10,
    ) -> str:
        """Decode one session's packet payload via GET /api/session/<node>/<id>/packets.

        Arkime answers this route with an HTML *fragment* (text/html), not
        JSON: two Bootstrap columns, source on the left and destination on the
        right, one row per coalesced packet. The tags are flattened to text
        here rather than in the tool layer because the direction of each packet
        is recorded nowhere but the column's CSS class, and a caller stripping
        tags naively merges the two halves of the conversation without noticing.

        Args:
            node: Capture node from the session document. Measured on Malcolm v26.07.1:
                Arkime resolves the capture file itself and returns the same
                6,008 bytes for a node that did not record the session, so this
                is positional bookkeeping rather than a filter.
            session_id: Either spelling works. The bare id and the prefixed
                "3@240425:240425-..." form arkime_sessions hands out returned
                byte-identical bodies.
            base: "hex" for the offset + hex + ASCII gutter that renders a
                modbus PDU legibly, or "ascii"/"utf8" for text protocols. An
                unknown value is not an error -- Arkime silently falls back to
                its ASCII rendering.
            packets: How many packets to read. Left off upstream, Arkime renders
                the whole session -- measured 1,066,665 bytes of HTML at
                base=hex for one 11 MB session, against 54,017 at packets=10 --
                hence the default of 10. It counts packets, not rendered
                blocks: consecutive same-direction packets are coalesced into
                one block, and a packet with no payload renders none at all, so
                on a session that opens with a TCP handshake packets=2 is a
                legitimate 391-byte answer carrying only the column headers.

        Returns:
            Plain text, with "[src]" / "[dst]" marking each packet's direction.
            Two answers are empty rather than failed, both arriving as HTTP 200
            and both returned as their own short text: "No pcap data found"
            when the session has no fileId (only ~186,551 of this lab's ~6M
            documents have one, and only those carry payload), and "Problem
            loading packets for <id> Error: Not found" when no session has that
            id.

        Raises:
            ToolInputError: node or session_id is not shaped like one.
        """
        safe_node = _checked(node, _ARKIME_NODE_RE, "Arkime node", _ARKIME_NODE_SHAPE)
        safe_id = _checked(
            session_id, _ARKIME_SESSION_ID_RE, "session id", _ARKIME_SESSION_ID_SHAPE
        )
        resp = await self.get_raw(
            f"/arkime/api/session/{safe_node}/{safe_id}/packets",
            params={"base": base, "packets": packets},
        )
        resp.raise_for_status()
        return _packets_to_text(resp.text)

    @_upstream
    async def arkime_session_bodyhash(
        self, node: str, session_id: str, body_hash: str, max_bytes: int = 0
    ) -> tuple[int, bytes]:
        """Download a session body by content hash, via
        GET /api/session/<node>/<id>/bodyhash/<hash>.

        Scoped to one session, unlike arkime_file_by_hash, which searches every
        session for the most recent body with that hash and needs no node. Use
        this when a session is already in hand and its own transfer is wanted;
        use the sibling to find where a known-bad hash appeared at all.

        Returns:
            (status_code, body). Measured against a hash this dataset does not
            hold: HTTP 400 with the body b"No match", so a 400 here is the
            answer "nothing in this session hashes to that", not a fault -- the
            body is returned empty and nothing is raised.

        Raises:
            ToolInputError: node, session_id or body_hash is not shaped like one.
            ValueError: the response exceeds max_bytes.
        """
        safe_node = _checked(node, _ARKIME_NODE_RE, "Arkime node", _ARKIME_NODE_SHAPE)
        safe_id = _checked(
            session_id, _ARKIME_SESSION_ID_RE, "session id", _ARKIME_SESSION_ID_SHAPE
        )
        safe_hash = _checked(body_hash, _HASH_RE, "body hash", _HASH_SHAPE)
        c = await self._client()
        path = _checked_path(f"/arkime/api/session/{safe_node}/{safe_id}/bodyhash/{safe_hash}")
        async with c.stream("GET", path) as resp:
            if resp.status_code >= 400:
                return resp.status_code, b""
            return resp.status_code, await _read_capped(resp, max_bytes, "Session body")

    async def arkime_sessions_summary(
        self,
        fields: str,
        expression: str = "",
        time_from: str = "",
        time_to: str = "",
    ) -> dict[str, Any]:
        """Total sessions/bytes/packets plus a per-field breakdown, via
        POST /api/sessions/summary.

        POST, not GET, and the difference is a wrong answer rather than an
        error. The parameters only travel in a JSON body -- the same values as
        query parameters are a 400 -- and a GET carrying that body drops the
        window on the floor: measured side by side on Malcolm v26.07.1, GET answered
        sessions=0 over graph.xmin=1785468240000 (Arkime's default recent
        window) where POST answered sessions=4,377,209 over the
        graph.xmin=1714003200000 that was asked for.

        Args:
            fields: Comma-separated field names, one breakdown per name.
                Arkime accepts its expression names ("ip.src") and the dotted
                ECS names ("source.ip", "destination.port"), and SILENTLY
                IGNORES db names: measured, fields="srcIp" returns the totals
                and no breakdown at all rather than an error. Required upstream
                -- omitting it is an HTTP 400.
            expression: Arkime expression scoping the summary.
            time_from/time_to: Epoch-seconds strings. Omitted, Arkime summarises
                its default recent window, which on a historical capture reports
                zero and looks like a broken tool.

        Returns:
            {"totals": {...}, "breakdowns": [...]}. Upstream sends a bare list
            -- totals first, then one entry per field, then a trailing empty
            dict as a sentinel -- so it is reshaped here; the sentinel and any
            field Arkime dropped are filtered out, which means comparing the
            "field" key of each breakdown against what was asked is how a
            caller detects a name Arkime did not recognise. An expression that
            matches nothing is a successful answer with sessions/bytes 0, and
            it still carries one breakdown per field, each with an empty "data"
            list -- measured with "ip == 203.0.113.99" over
            1714003200-1714089600. Only a field Arkime refused collapses to the
            sentinel, which is what keeps the two cases apart.
        """
        body: dict[str, Any] = {"fields": fields}
        if expression:
            body["expression"] = expression
        if time_from:
            body["startTime"] = time_from
        if time_to:
            body["stopTime"] = time_to
        data = await self._arkime_post("/arkime/api/sessions/summary", body)
        if not isinstance(data, list) or not data:
            return {"totals": {}, "breakdowns": []}
        return {
            "totals": data[0],
            "breakdowns": [e for e in data[1:] if isinstance(e, dict) and e.get("field")],
        }

    async def arkime_buildquery(
        self, expression: str = "", time_from: str = "", time_to: str = ""
    ) -> dict[str, Any]:
        """Translate an Arkime expression into OpenSearch DSL, via POST /api/buildquery.

        Arkime compiles the expression and the window without running the
        search, which is how a caller checks what an expression really asks
        before spending a scan on it, and how an expression gets handed to
        search_dsl for clauses Arkime's own syntax cannot express.

        Returns:
            {"esquery": {...}, "indices": "..."}. `indices` is the concrete
            list the window resolves to (measured: "arkime_sessions3-240425"
            for 2024-04-25), so an empty-looking hunt can be traced to a window
            that selected no daily index at all. An expression Arkime cannot
            parse comes back as an upstream 400 and therefore raises.

        Through _arkime_post, not self.post, even though this route does not
        currently demand the token: measured, the parity run reaches
        arkime_sessions (which sets ARKIME-COOKIE) before this call and still
        gets an answer. One shared path for every Arkime POST is what keeps
        that "currently" from being load-bearing, and keeps the next Arkime
        POST from being written as a plain self.post because this one was.
        """
        return await self._arkime_post(
            "/arkime/api/buildquery", _arkime_query_params(expression, time_from, time_to)
        )

    async def arkime_crons(self) -> Any:
        """List Arkime's standing periodic queries, via GET /api/crons.

        A cron query re-runs an expression on a schedule and tags what it
        matches, so this is where a tag nobody recognises comes from. Returns a
        list, empty when a deployment has none configured -- measured [] here,
        which is a fact about this deployment and not a route fault.

        `all=true` because Arkime scopes this listing per request rather than
        per role: apiCrons.js:150 in the shipped 6.6.0 viewer gates on
        `req.query.all && roles.includes('arkimeAdmin')`, with the same pair at
        apiViews.js:31 and apiShortcuts.js:137. Omitting it filters the answer
        to this account's own no matter how privileged the account is, which
        made an empty list unfalsifiable. A non-admin account sending it is
        unchanged -- the role half of that condition still fails.
        """
        return await self.get("/arkime/api/crons", params={"all": "true"})

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

        Tags are sanitized to [-a-zA-Z0-9_:,] server-side. See _arkime_post for
        why this cannot be a plain self.post().
        """
        return await self._arkime_post(
            "/arkime/api/sessions/addtags",
            {"ids": ids, "tags": tags, "segments": segments},
        )

    @_upstream
    async def _arkime_post(self, path: str, body: dict[str, Any]) -> Any:
        """POST an Arkime route whose token demand depends on the cookie jar.

        Arkime's checkHeaderToken accepts a request carrying no token at all,
        as long as it also carries no cookie or referer. The catch is that any
        earlier GET of a session route answers with Set-Cookie ARKIME-COOKIE;
        httpx keeps it in the jar this client shares for its whole lifetime,
        and Arkime then sees a cookie and switches to checkCookieToken. So the
        same POST that worked on a fresh process answers HTTP 500
        {"success":false,"text":"Missing token"} from that moment on -- and
        arkime_sessions, which sets the cookie, is the centre of this server's
        own documented hunt flow, so in practice "from that moment on" means
        "after the first search".

        Replaying the cookie as the header satisfies both states: same
        first-party token, same Basic-auth user. Every Arkime POST that is not
        one of the always-guarded write routes (those use _arkime_token_post,
        which primes a token instead of waiting for one) goes through here, so
        a route added later cannot rediscover this the hard way. Checked by
        test_every_arkime_post_shares_the_cookie_path, because the claim is
        only worth making if something fails when it stops being true.

        @_upstream here rather than on each caller: self.post carries it, so a
        method moved off self.post onto this one would otherwise silently lose
        the redaction that keeps userinfo credentials in MALCOLM_URL out of an
        httpx error message, and hand tools a bare httpx exception instead of
        the one type they branch on. Harmless where a caller already wraps it
        (_write_arkime_tags does): UpstreamError is not an httpx error, so the
        outer wrapper passes it straight through.

        A unit test only reproduces it if its transport keeps cookies -- the
        failure is cross-call state, not a bad request in isolation.
        """
        c = await self._client()
        token = c.cookies.get("ARKIME-COOKIE")
        headers = {"x-arkime-cookie": token} if token else {}
        resp = await c.post(path, json=body, headers=headers)
        resp.raise_for_status()
        return resp.json()

    async def _arkime_cookie_headers(self, c: httpx.AsyncClient) -> dict[str, str]:
        """Prime and return the x-arkime-cookie header a CSRF-guarded route needs.

        GET /arkime/api/hunts first so Arkime's setCookie middleware issues an
        ARKIME-COOKIE, then hand it back to replay as the header. The userId in
        the token matches because both requests carry the same Basic auth →
        same X-Forwarded-User. The one mechanism for every guarded route:
        without it, Arkime answers 500 {"success":false,"text":"Missing token"}.
        """
        await c.get("/arkime/api/hunts", params={"length": 1})
        token = c.cookies.get("ARKIME-COOKIE")
        return {"x-arkime-cookie": token} if token else {}

    @_upstream
    async def _arkime_token_post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST to a checkCookieToken-guarded Arkime route with the token dance.

        See _arkime_cookie_headers for the dance itself. Shared by the
        hunt/view/shortcut writes.
        """
        c = await self._client()
        headers = await self._arkime_cookie_headers(c)
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
    async def _write_arkime_hunt_cancel(self, hunt_id: str) -> dict[str, Any]:
        """PUT /arkime/api/hunt/<id>/cancel — stop a running hunt job.

        CSRF-guarded exactly like the POST writes, and through the same
        _arkime_cookie_headers dance rather than a second mechanism: measured
        on Malcolm v26.07.1, the bare PUT answers 500 {"success":false,"text":"Missing
        token"}, and the same PUT with the primed cookie replayed as
        x-arkime-cookie gets past the guard and fails on the id instead
        (500 {"success":false,"text":"Error canceling hunt"} for one that does
        not exist). Cancelling leaves the hunt row in place with its partial
        results, so it stops work rather than destroying it.

        A non-2xx raises with Arkime's own text attached, because those two
        500s mean opposite things -- the plumbing broke, or the id was wrong --
        and httpx's message carries only the status.

        Raises:
            ToolInputError: hunt_id is not shaped like an Arkime hunt id.
            UpstreamError: Arkime refused the cancel; .status is the HTTP status.
        """
        safe = _checked(hunt_id, _OS_DOC_ID_RE, "hunt id", _OS_DOC_ID_SHAPE)
        c = await self._client()
        headers = await self._arkime_cookie_headers(c)
        resp = await c.put(_checked_path(f"/arkime/api/hunt/{safe}/cancel"), headers=headers)
        if resp.status_code >= 400:
            raise UpstreamError(
                f"Arkime refused the hunt cancel ({resp.status_code}): {redact(resp.text[:200])}",
                resp.status_code,
            )
        return resp.json()

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


# Arkime records each packet's direction in the column's CSS class and nowhere
# else in the fragment, so the class becomes a marker before the tags go.
_PACKET_DIRECTION = re.compile(r'<div class="[^"]*session(src|dst)"[^>]*>')
_BLOCK_CLOSE = re.compile(r"</(?:div|pre|h4|em)>")
_HTML_TAG = re.compile(r"<[^>]*>")
_BLANK_RUN = re.compile(r"\n{3,}")


def _packets_to_text(fragment: str) -> str:
    """Flatten Arkime's packets HTML fragment into readable text.

    Entities are unescaped LAST, after the tags are gone: the hex gutter
    renders payload bytes as &amp;, &gt; and &#47;, so unescaping first would
    manufacture markup out of data and the tag strip would then eat it. &nbsp;
    becomes a plain space rather than U+00A0 so the result stays greppable.
    """
    marked = _PACKET_DIRECTION.sub(lambda m: f"\n[{m.group(1)}]\n", fragment)
    text = html.unescape(_HTML_TAG.sub("", _BLOCK_CLOSE.sub("\n", marked)))
    lines = "\n".join(line.rstrip() for line in text.replace("\xa0", " ").splitlines())
    return _BLANK_RUN.sub("\n\n", lines).strip()


def _decode_search_source(obj: dict[str, Any]) -> dict[str, Any]:
    """Pull the query out of a Dashboards saved object; {} when it carries none.

    Two indirections upstream, both of which a caller traversing the object
    normally would miss: searchSourceJSON is a JSON string inside the parsed
    object, and the index it queries is a reference *name* that only means
    something once looked up in the object's own references[] array.
    """
    meta = obj.get("attributes", {}).get("kibanaSavedObjectMeta", {})
    raw = meta.get("searchSourceJSON")
    if not isinstance(raw, str):
        return {}
    try:
        source = json.loads(raw)
    except ValueError:
        logger.warning("[malcolm] saved object %s has unparseable searchSourceJSON", obj.get("id"))
        return {}
    refs = {r.get("name"): r for r in obj.get("references", []) if isinstance(r, dict)}
    query = source.get("query") or {}
    return {
        "query": query.get("query", ""),
        "language": query.get("language", ""),
        "filters": source.get("filter", []),
        "index_pattern": refs.get(source.get("indexRefName"), {}).get("id", ""),
    }


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


# The sixteen fields Arkime spells twice: an expression name (ip.src) for the
# routes that parse a field list as an expression, a db name (srcIp) for
# /api/connections. Taken from the /arkime/api/fields rows whose dbField2
# differs from dbField -- 17 of 4051 on Malcolm 26.07.1, minus communityId
# whose exp name and db name are the same string. Every other field spells exp
# and db alike, so only these sixteen can be sent to the wrong route by
# mistake.
#
# ponytail: a static table, not the cached catalogue, because the catalogue
# cannot answer this question. Its db column is dbField2, and the *other*
# column (dbField, e.g. source.mac for mac.src) is accepted by the expression
# routes -- measured on /arkime/api/multiunique: exp=source.mac returned 105
# rows while exp=srcOui, exp=protocol and exp=totBytes all returned "Unknown
# expression". The routes disagree, which is the point: on /arkime/api/unique
# those same three answer with data (srcOui 18 rows, protocol 52) or with an
# empty 200 (totBytes), so a name this table would reject is a working call
# somewhere. Rejecting every db-column name would break them. Consulting
# it would also mean an extra /arkime/api/fields fetch inside every guarded
# call, which fails closed when Arkime is unreachable. These sixteen are
# Arkime's built-in session fields, stable across viewer versions.
_ARKIME_DB_FOR_EXP = {
    "asn.dst": "dstASN",
    "asn.src": "srcASN",
    "bytes": "totBytes",
    "bytes.dst": "dstBytes",
    "bytes.src": "srcBytes",
    "country.dst": "dstGEO",
    "country.src": "srcGEO",
    "databytes.dst": "dstDataBytes",
    "databytes.src": "srcDataBytes",
    "ip.dst": "dstIp",
    "ip.src": "srcIp",
    "packets": "totPackets",
    "packets.dst": "dstPackets",
    "packets.src": "srcPackets",
    "port.dst": "dstPort",
    "port.src": "srcPort",
}
_ARKIME_EXP_FOR_DB = {db: exp for exp, db in _ARKIME_DB_FOR_EXP.items()}


def _require_arkime_exp_names(fields: str) -> None:
    """Reject Arkime db names on a parameter Arkime parses as an expression.

    Only a name in the sixteen-pair table raises; anything else is passed
    through to Arkime, because a name this table does not know may still be
    valid -- Malcolm's own dotted paths (source.ip, source.mac) resolve on
    these routes even though they are in neither Arkime vocabulary.

    Raises:
        ToolInputError: the field list names a db-only spelling.
    """
    for name in (part.strip() for part in fields.split(",")):
        if exp := _ARKIME_EXP_FOR_DB.get(name):
            raise ToolInputError(
                f"'{name}' is an Arkime db name; this parameter takes expression names. "
                f"arkime_field_search reports both -- use the exp column. "
                f"Did you mean '{exp}'?"
            )


def _require_arkime_db_names(name: str, param: str) -> None:
    """Reject Arkime expression names on /api/connections' field parameters.

    Mirror of :func:`_require_arkime_exp_names`, and equally narrow: an
    unrecognised name goes through to Arkime untouched.

    Raises:
        ToolInputError: the name is an expression-only spelling.
    """
    if db := _ARKIME_DB_FOR_EXP.get(name.strip()):
        raise ToolInputError(
            f"'{name}' is an Arkime expression name; {param} takes db names. "
            f"arkime_field_search reports both -- use the db column. "
            f"Did you mean '{db}'?"
        )
