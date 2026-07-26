"""MCP prompts — worked workflow templates surfaced to the agent.

These are cold-start guides: an agent can read the hunt_workflow prompt to learn
the tool-chaining pattern (schema discovery -> search -> drill-in -> record)
without inferring it from individual tool docstrings.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


_HUNT_WORKFLOW = """\
You are threat hunting on Malcolm (network traffic analysis). Follow this loop.

1. LEARN THE SCHEMA before filtering on any unfamiliar field.
   - malcolm_field_search(keyword="useragent")  -> confirm the real field name
     (Malcolm uses http.useragent, NOT http.user_agent).
   - malcolm_field_values(field="event.dataset") -> see what record types exist
     (conn, dns, ssl, http, alert, ...).

2. GET YOUR BEARINGS.
   - malcolm_data_coverage() -> what data exists and how fresh it is.
   - malcolm_alerts(signature="ET MALWARE", time_from="24 hours ago") -> triage
     Suricata alerts with structured filters.

3. FIND SESSIONS. Pick the dialect:
   - Field filter + human time: malcolm_search(
       filters='{"event.dataset":"dns","zeek.dns.query":"*.example.com"}',
       time_from="7 days ago")
   - Arkime expression + a session id you can drill into (epoch seconds!):
       arkime_sessions(expression="ip==192.0.2.77 && protocols==ssh")
     ONLY arkime_sessions returns an id usable in step 4.

4. DRILL INTO ONE SESSION (use the id from arkime_sessions):
   - arkime_session_detail(session_id) -> full SPI document (all fields).
   - arkime_session_pcap(session_id)   -> validate/size the PCAP.
   - arkime_file_by_hash(file_hash="<md5-or-sha256>") -> extract the actual
     transferred file whose content hash matches (pull the malware sample; the
     hash comes from a session's http.md5 / http.sha256 field).

5. PIVOT with aggregation:
   - malcolm_aggregate(fields="source.ip,destination.ip", filters=...) -> top
     talkers (flat buckets).
   - arkime_multiunique(fields="source.ip,destination.port") -> distinct tuples
     (e.g. a host scanning many ports).
   - arkime_spigraphhierarchy(fields="source.ip,destination.ip") -> nested
     drill-down hierarchy.
   - arkime_connections(expression=...) -> who-talked-to-whom graph for lateral
     movement.
   - malcolm_related_sessions(uid="<zeek.uid>") -> tie a Zeek connection to its
     dns/ssl/files records.

6. ENRICH with asset context:
   - malcolm_netbox_lookup(ip="192.0.2.77") -> is this a known server? what role?
     Decides whether the behavior is normal or anomalous.

7. RECORD THE FINDING (only if the write classes are enabled; if a tool is
   absent, that class is off):
   - malcolm_create_alert(title=..., severity=2, source_ip=..., description=...)
   - arkime_add_tags(session_ids="<ids>", tags="c2,triaged")
   - arkime_create_view(name="hunt_c2", expression=...) -> save the query for
     the team to rerun.
   - arkime_create_shortcut(name="c2_ips", value="1.2.3.4\n5.6.7.8", type="ip")
     -> save an IOC list, then reference it as $c2_ips in later expressions.

Golden rules: confirm field names before you use them; Arkime tools take EPOCH
seconds while Malcolm/DSL tools take strings like "7 days ago"; only
arkime_sessions yields an id you can feed to the PCAP/payload/tag tools."""


def register_prompts(mcp: FastMCP) -> None:
    """Register workflow prompts (always available, read-only)."""

    @mcp.prompt(
        name="hunt_workflow",
        description="Worked Malcolm threat-hunting workflow: which tools to chain, "
        "in what order, with the field/time/session-id gotchas called out.",
    )
    def hunt_workflow() -> str:
        return _HUNT_WORKFLOW
