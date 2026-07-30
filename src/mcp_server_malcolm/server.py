"""MCP server setup — read tools always, write tools per enabled class."""

from __future__ import annotations

import logging
import sys

from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.config import WriteConfig
from mcp_server_malcolm.prompts import register_prompts
from mcp_server_malcolm.tools import register_all_tools, register_write_tools

logger = logging.getLogger(__name__)

_INSTRUCTIONS = """\
Malcolm network traffic analysis server (Zeek + Suricata + Arkime + OpenSearch, \
optional NetBox). Tools for search, aggregation, field discovery, Suricata \
alerts, Arkime sessions, PCAP/payload extraction, NetBox asset lookup, and \
health.

DATA MODEL
- All network data lives in one unified index, arkime_sessions3-* .
- event.dataset distinguishes record types: conn, dns, ssl, http, tls, files, \
alert, etc. Filter on it to narrow to a log type.
- Field names are NON-STANDARD (e.g. http.useragent, not http.user_agent). \
NEVER guess a field name — look it up first. This is the anti-hallucination \
layer; use it before every unfamiliar filter. TWO vocabularies, one per \
dialect: malcolm_field_search / malcolm_field_values for malcolm_* and DSL \
tools, arkime_field_search for anything you put in an arkime_* `expression`. \
They are not interchangeable.

THREE QUERY DIALECTS — pick deliberately:
1. malcolm_search / malcolm_aggregate / malcolm_alerts — Malcolm's simple filter \
dict ({"event.dataset": "conn"}), human time strings ("7 days ago"). Default \
for field-based filtering.
2. arkime_sessions and the other arkime_* tools — Arkime EXPRESSION syntax \
(ip==1.2.3.4 && protocols==dns), time as EPOCH SECONDS (not "7 days ago"). \
arkime_sessions is the ONLY search that returns a session id usable with \
arkime_session_pcap / arkime_session_payload / arkime_add_tags.
3. search_dsl / count — raw OpenSearch DSL, full control.

TIME FORMATS DIFFER BY DIALECT: Malcolm/DSL tools take dateparser strings; every \
arkime_* tool takes epoch seconds. Mixing them silently returns wrong/empty data.

TYPICAL HUNT FLOW
malcolm_field_search -> malcolm_field_values (learn the schema) -> malcolm_search \
or arkime_sessions (find sessions) -> arkime_session_detail / arkime_session_pcap \
/ arkime_session_payload (drill into one) -> malcolm_create_alert / \
arkime_add_tags (record the finding, if those write classes are on). See the \
"hunt_workflow" prompt for a worked example.

WRITES are opt-in per class (alerting, arkime-tag, hunt-job, pcap-upload), off by \
default; a disabled class's tools are absent entirely. Destructive actions \
(delete, tag removal, NetBox writes) are deliberately NOT exposed."""


def create_server() -> MCPServer:
    """Build and return a fully configured MCP server.

    Read tools are always registered. Write tools are registered only for the
    classes enabled via MALCOLM_MCP_ENABLE_* — a disabled class's tools are not
    registered at all (an unregistered tool cannot be called).
    """
    mcp = MCPServer("mcp-server-malcolm", instructions=_INSTRUCTIONS)
    client = MalcolmClient.from_env()
    cfg = WriteConfig.from_env()

    register_all_tools(mcp, client)
    register_write_tools(mcp, client, cfg)
    register_prompts(mcp)

    # Operators must be able to see the write posture instantly.
    print(
        f"[mcp-server-malcolm] write classes: {cfg.enabled_summary()}", file=sys.stderr, flush=True
    )
    return mcp
