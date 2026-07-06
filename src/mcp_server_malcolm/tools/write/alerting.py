"""Write class: alerting — POST /mapi/event (Malcolm 26.06.1).

Malcolm's own purpose-built, schema'd write endpoint: it indexes a caller-
supplied alert as a session/event document viewable in Malcolm's dashboards.
This is the template the other write classes follow.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import httpx

from mcp_server_malcolm import audit

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient

_CLASS = "alerting"


def register_alerting_tools(mcp: FastMCP, client: MalcolmClient, audit_file: str | None) -> None:
    """Register the alerting write tool (called only when the class is enabled)."""

    @mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False})
    async def malcolm_create_alert(
        title: str,
        severity: int,
        description: str = "",
        source_ip: str = "",
        dest_ip: str = "",
    ) -> str:
        """Create a Malcolm alert document (POST /mapi/event).

        Indexes an analyst/agent-generated finding as an alert visible in
        Malcolm's dashboards. Additive — creates a new document, changes
        nothing existing.

        Args:
            title: Short alert name (becomes trigger.name / rule.name).
            severity: 1 (highest) .. 4 (lowest) — Malcolm maps this to risk_score.
            description: Free-text detail (stored under event fields).
            source_ip: Optional related source IP.
            dest_ip: Optional related destination IP.
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

        try:
            result = await client._write_event(alert)
        except httpx.HTTPStatusError as exc:
            audit.record(
                "malcolm_create_alert",
                _CLASS,
                target,
                params_summary,
                audit.outcome_for_status(exc.response.status_code),
                audit_file,
            )
            return f"Alert creation failed: HTTP {exc.response.status_code}"
        except Exception as exc:  # noqa: BLE001
            audit.record(
                "malcolm_create_alert",
                _CLASS,
                target,
                params_summary,
                f"error:{type(exc).__name__}",
                audit_file,
            )
            return f"Alert creation failed: {exc}"

        audit.record("malcolm_create_alert", _CLASS, target, params_summary, "ok", audit_file)
        return json.dumps(
            {"created": True, "result": result}, indent=2, ensure_ascii=False, default=str
        )
