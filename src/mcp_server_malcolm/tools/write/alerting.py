"""Write class: alerting — POST /mapi/event (Malcolm 26.06.1).

Malcolm's own purpose-built, schema'd write endpoint: it indexes a caller-
supplied alert as a session/event document viewable in Malcolm's dashboards.
This is the template the other write classes follow.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

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
            Field(description="Short alert name; becomes trigger.name / rule.name in Malcolm."),
        ],
        severity: Annotated[
            int,
            Field(
                description="Severity 1 (highest) .. 4 (lowest); Malcolm maps this to risk_score. "
                "Must be 1, 2, 3, or 4.",
            ),
        ],
        description: Annotated[
            str, Field(description="Free-text detail; stored as event.reason.")
        ] = "",
        source_ip: Annotated[
            str, Field(description="Optional related source IP (stored under related).")
        ] = "",
        dest_ip: Annotated[
            str, Field(description="Optional related destination IP (stored under related).")
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
        Returns JSON with the created flag and the raw server result.
        """
        if not title.strip():
            return "Error: title is required."
        if severity not in (1, 2, 3, 4):
            return "Error: severity must be 1, 2, 3, or 4."

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

        result, err = await run_write(
            "malcolm_create_alert",
            _CLASS,
            target,
            params_summary,
            audit_file,
            lambda: client._write_event(alert),
        )
        if err:
            return f"Alert creation failed: {err}"
        return json.dumps(
            {"created": True, "result": result}, indent=2, ensure_ascii=False, default=str
        )
