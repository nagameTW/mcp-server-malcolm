"""MCP server setup — read tools always, write tools per enabled class."""

from __future__ import annotations

import logging
import sys

from mcp.server.caching import CacheableMethod, CacheHint
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm import __version__
from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.config import WriteConfig
from mcp_server_malcolm.prompts import register_prompts
from mcp_server_malcolm.resources import register_resources
from mcp_server_malcolm.tools import register_all_tools, register_write_tools

logger = logging.getLogger(__name__)

# One hour, everywhere below. The three list methods are frozen the moment
# create_server() returns and this server never sends a listChanged
# notification, so only a process restart can change them -- which is the one
# event this TTL exists to bound. Deliberately not reasoned in terms of a
# session: at 2026-07-28 requests are self-contained and no session exists, so
# the hour caps how long a cache may still advertise the tool set of a process
# since restarted with different MALCOLM_MCP_ENABLE_* flags. Both directions of
# that staleness fail safe -- a withdrawn tool is refused as unregistered, and a
# newly enabled one is merely invisible until the entry expires.
_FROZEN_AT_STARTUP_MS = 3_600_000

# scope="public" for the three list methods: they are derived from this
# server's own startup config -- registered tools, prompts, resource metadata.
# Nothing in them varies by caller (there is no per-request authorization
# here), so one cached copy is correct for every authorization context.
#
# scope="private" for resources/read: same TTL reasoning -- both catalogues are
# served from MalcolmClient's process-lifetime field caches, so a re-read
# returns byte-identical content until the server restarts -- but the body is
# this deployment's network schema rather than server config. If an operator
# ever puts per-user auth in front of this server, "public" would be the wrong
# default to have shipped, and the only cost of "private" is cross-context
# reuse of a body nobody else was going to ask for.
#
# Deliberately absent: server/discover, whose result is derived per connection
# from the negotiated protocol version, so a single method-keyed hint would
# invite serving a modern-era result to a legacy peer; and
# resources/templates/list, which is permanently empty because this server
# registers no resource templates -- add a hint with the first template.
_CACHE_HINTS: dict[CacheableMethod, CacheHint] = {
    "tools/list": CacheHint(ttl_ms=_FROZEN_AT_STARTUP_MS, scope="public"),
    "prompts/list": CacheHint(ttl_ms=_FROZEN_AT_STARTUP_MS, scope="public"),
    "resources/list": CacheHint(ttl_ms=_FROZEN_AT_STARTUP_MS, scope="public"),
    "resources/read": CacheHint(ttl_ms=_FROZEN_AT_STARTUP_MS, scope="private"),
}

_INSTRUCTIONS = """\
Malcolm network traffic analysis server (Zeek + Suricata + Arkime + OpenSearch, \
optional NetBox): search, aggregation, field discovery, Suricata alerts, the \
standing detections (OpenSearch alerting monitors, anomaly detectors, saved \
dashboards), Arkime sessions, PCAP/payload/file extraction, NetBox asset \
lookup, and health.

DATA MODEL
- All network data lives in one unified index, arkime_sessions3-* .
- event.dataset distinguishes record types: conn, dns, http, ssl, files, alert, \
plus whatever else this deployment parses (an OT capture adds modbus, dnp3 and \
more). Filter on it to narrow to a log type; malcolm_field_values lists the ones \
present.
- Field names are NON-STANDARD (e.g. http.useragent, not http.user_agent). \
NEVER guess a field name — look it up before every unfamiliar filter. TWO \
vocabularies, one per dialect: malcolm_field_search / malcolm_field_values for \
malcolm_* and DSL tools, arkime_field_search for anything you put in an \
arkime_* `expression`. They are not interchangeable.
- Every tool authenticates as the one account this server was configured with, \
so a list shows what that account can see: an Arkime view carries its owner and \
the roles it is shared with. The three inventory listings do ask for every \
owner, but Arkime grants that only to an arkimeAdmin account, so below that role \
an empty arkime_views / arkime_shortcuts / arkime_crons list is still not proof \
there are none.

THREE QUERY DIALECTS — pick deliberately:
1. malcolm_search / malcolm_aggregate / malcolm_alerts — Malcolm's simple filter \
dict ({"event.dataset": "conn"}), human time strings ("7 days ago"). Default \
for field-based filtering.
2. arkime_sessions and the other arkime_* tools — Arkime EXPRESSION syntax \
(ip==1.2.3.4 && protocols==dns), time as EPOCH SECONDS (not "7 days ago"). \
arkime_sessions is the ONLY search that returns a session id, and every \
session-scoped tool needs one: arkime_session_detail, arkime_session_pcap, \
arkime_session_payload, arkime_session_file_by_hash, arkime_add_tags.
3. search_dsl / count — raw OpenSearch DSL, full control. Reach for it when \
dialect 2 cannot say what you mean (wildcard, fuzzy, script): arkime_build_query \
compiles an expression into the DSL it becomes, so you edit that rather than \
write one from nothing.
Names carry the subsystem: malcolm_* go through Malcolm's own API, arkime_* \
through Arkime's, and the five unprefixed tools (search_dsl, count, \
list_indices, index_mapping, cluster_health) are raw OpenSearch through \
Malcolm's proxy.

TIME FORMATS DIFFER BY DIALECT: Malcolm/DSL tools take dateparser strings, every \
arkime_* tool takes epoch SECONDS, and malcolm_anomaly_results alone takes epoch \
MILLISECONDS. Mixing them silently returns wrong/empty data.

TYPICAL HUNT FLOW
malcolm_field_search -> malcolm_field_values (learn the schema) -> malcolm_search \
or arkime_sessions (find sessions; arkime_sessions_summary sizes a match in \
sessions/bytes/packets first, in one call) -> arkime_session_detail / \
arkime_session_pcap / arkime_session_payload / arkime_session_file_by_hash \
(drill into one) -> malcolm_create_alert / arkime_add_tags (record the finding, \
if those write classes are on). When metadata cannot answer it, search the \
payloads: arkime_sessions_summary (size it first) -> arkime_create_hunt -> \
arkime_hunt_status (present even with every write class off) -> \
arkime_cancel_hunt. See the "hunt_workflow" prompt for a worked example.

WRITES are opt-in per class (alerting, arkime-tag, hunt-job, pcap-upload, \
arkime-view), off by default; a disabled class's tools are absent entirely. \
Every write is additive except arkime_cancel_hunt, which ends a scan already \
running and alone declares destructiveHint. Deletion, tag removal and NetBox \
writes are not exposed at all."""


def create_server() -> MCPServer:
    """Build and return a fully configured MCP server.

    Read tools are always registered. Write tools are registered only for the
    classes enabled via MALCOLM_MCP_ENABLE_* — a disabled class's tools are not
    registered at all (an unregistered tool cannot be called).

    Everything registered here is registered exactly once, at startup, which is
    what makes the cache hints above honest.
    """
    # version is passed explicitly: SDK 2.0 defaults it to "" and never
    # substitutes one, where 1.x filled in the SDK's own version. Unset, the
    # initialize response advertises an empty server version.
    mcp = MCPServer(
        "mcp-server-malcolm",
        version=__version__,
        instructions=_INSTRUCTIONS,
        cache_hints=_CACHE_HINTS,
    )
    client = MalcolmClient.from_env()
    cfg = WriteConfig.from_env()

    disabled_read = register_all_tools(mcp, client)
    register_write_tools(mcp, client, cfg)
    register_resources(mcp, client)
    register_prompts(mcp)

    # Operators must be able to see the write posture instantly.
    print(
        f"[mcp-server-malcolm] write classes: {cfg.enabled_summary()}", file=sys.stderr, flush=True
    )
    # Silent when nothing is disabled: the default deployment should not have
    # to read a line saying so, but a missing tool must be traceable to the
    # flag that removed it rather than looking like a broken build.
    if disabled_read:
        print(
            f"[mcp-server-malcolm] read groups disabled: {', '.join(sorted(disabled_read))}",
            file=sys.stderr,
            flush=True,
        )
    return mcp
