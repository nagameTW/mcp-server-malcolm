"""Write class: alerting — POST /mapi/event (Malcolm 26.06.1).

Malcolm's own purpose-built, schema'd write endpoint: it indexes a caller-
supplied alert as a session/event document viewable in Malcolm's dashboards.
This is the template the other write classes follow.

The rest of the stored document, measured on Malcolm v26.07.1 by writing five
alerts, reading each back and deleting them again. None of this changes what a
caller should do, so it stays out of the tool description:

- `event.risk_score_norm` and `event.severity` carry the SAME number as
  event.risk_score, and `event.severity_tags` is the literal "Alert".
- Malcolm stamps `event.provider: "malcolm"`, `event.module: "alerting"`,
  `event.kind: "alert"`, `event.url: "/dashboards/app/alerting#/dashboard"`,
  and `event.id` = the document id with its "<yymmdd>-" prefix removed.
- `event.start`, `event.end`, `event.ingested` and `firstPacket` are all the
  write time, not any time the described traffic happened.

One search caveat found the same way: event.reason is a keyword field, so
match_phrase on a SUBSTRING of a title returns nothing — use a term query on
the whole title. An unqualified query_string is worse: it tokenises the search
text and ORs the tokens, so a marker string matched hundreds of unrelated
traffic records on one two-letter token.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from mcp_server_malcolm.errors import ToolInputError
from mcp_server_malcolm.tools.write._common import run_write

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from mcp_server_malcolm.client import MalcolmClient

_CLASS = "alerting"

# Shared: additive write to the external Malcolm server, never idempotent
# (each call indexes a new alert document).
_WRITE = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": True,
}


def register_alerting_tools(mcp: MCPServer, client: MalcolmClient, audit_file: str | None) -> None:
    """Register the alerting write tool (called only when the class is enabled)."""

    @mcp.tool(title="Create Malcolm alert", annotations=_WRITE)
    async def malcolm_create_alert(
        title: Annotated[
            str,
            Field(
                description="Short alert name; it lands on the document as event.reason, which "
                "is the field to search for it afterwards (rule.name is fixed to this server's "
                "name for every alert it writes)."
            ),
        ],
        severity: Annotated[
            int,
            Field(
                description="1 (highest) .. 4 (lowest); Malcolm stores it as event.risk_score "
                "100 / 80 / 60 / 40, which is what a dashboard filters on.",
                json_schema_extra={"enum": [1, 2, 3, 4]},
            ),
        ],
        description: Annotated[
            str,
            Field(
                description="Free-text detail. Measured on Malcolm v26.07.1 it does not reach "
                "the document: the server overwrites event.reason with the title, so put "
                "anything that must survive into the title."
            ),
        ] = "",
        source_ip: Annotated[
            str,
            Field(
                description="Optional related source IP. Measured on Malcolm v26.07.1 it is "
                "stored at related.source_ip, NOT at related.ip where Malcolm puts every "
                "address it parses out of traffic — so a query filtering related.ip will "
                "not find an alert this tool wrote."
            ),
        ] = "",
        dest_ip: Annotated[
            str,
            Field(
                description="Optional related destination IP, sent under related.dest_ip. "
                "Only source_ip was read back and verified; this takes the same code path."
            ),
        ] = "",
    ) -> str:
        """Create a Malcolm alert document from an analyst/agent finding (POST /mapi/event).

        Use this to record a hunting conclusion as an alert that shows up in
        Malcolm's dashboards alongside Suricata alerts. This is the only write
        tool that mints a Malcolm-native event; to persist a reusable search
        instead use arkime_create_view, or to tag sessions use arkime_add_tags.
        Additive — indexes a new document and changes nothing that already
        exists (calling twice creates two alerts). The action is audited, and
        the tool is registered only when the alerting write class is enabled.
        Read it back with malcolm_search on {"event.dataset": "alerting"}, not
        with malcolm_alerts: the document lands in the arkime_sessions3-* index
        set, but Malcolm files it under event.dataset=alerting while
        malcolm_alerts filters event.dataset=alert and so never returns it.
        Where and when it lands were both measured on Malcolm v26.07.1, by
        writing alerts and reading them back. WHERE: today's index
        (arkime_sessions3-<yymmdd>), never the index holding the traffic the
        alert describes — an alert about 2024 traffic is found in a 2026 index,
        so a time filter set to the traffic's own window will never return it.
        WHEN: that index carries refresh_interval 60s and one write took 19.1
        seconds to become visible, so a search fired straight after the write
        can still miss the document it just created.
        Returns JSON with the created flag and the raw server result.
        """
        if not title.strip():
            raise ToolInputError('title is required — a short alert name, e.g. "C2 beacon".')
        if severity not in (1, 2, 3, 4):
            raise ToolInputError(
                f"severity must be 1 (highest), 2, 3 or 4 (lowest); received {severity!r}."
            )

        body: dict[str, Any] = {"event": {"kind": "alert"}}
        if description:
            body["event"]["reason"] = description
        related: dict[str, Any] = {}
        if source_ip:
            related["source_ip"] = source_ip
        if dest_ip:
            related["dest_ip"] = dest_ip
        if related:
            body["related"] = related

        alert = {
            "monitor": {"name": "mcp-server-malcolm"},
            "trigger": {"name": title.strip(), "severity": severity},
            "body": body,
        }
        target = f"title={title.strip()}"
        params_summary = {"severity": severity, "source_ip": source_ip, "dest_ip": dest_ip}

        result = await run_write(
            "malcolm_create_alert",
            _CLASS,
            target,
            params_summary,
            audit_file,
            lambda: client._write_event(alert),
        )
        return json.dumps(
            {"created": True, "result": result}, indent=2, ensure_ascii=False, default=str
        )
