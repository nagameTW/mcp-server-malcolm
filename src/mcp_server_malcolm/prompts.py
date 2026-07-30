"""MCP prompts — worked workflow templates surfaced to the agent.

These are cold-start guides: an agent can read the hunt_workflow prompt to learn
the tool-chaining pattern (schema discovery -> search -> drill-in -> record)
without inferring it from individual tool docstrings.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer


_HUNT_WORKFLOW = """\
You are threat hunting on Malcolm (network traffic analysis). Follow this loop.

1. LEARN THE SCHEMA before filtering on any unfamiliar field.
   - malcolm_field_search(keyword="useragent")  -> confirm the real field name
     (Malcolm uses http.useragent, NOT http.user_agent).
   - malcolm_field_values(field="event.dataset") -> see what record types exist
     (conn, dns, ssl, http, alert, ...).
   - arkime_field_search(keyword="user") -> the SEPARATE vocabulary Arkime
     expressions use (ip.src, not source.ip). Needed before step 4's Arkime
     dialect; the two field lists do not overlap.

2. GET YOUR BEARINGS, and check the data can be trusted.
   - malcolm_data_coverage() -> what data exists and how fresh it is.
   - arkime_node_stats() -> is a capture node dropping packets or out of disk?
     Check this BEFORE concluding anything from an absence: a gap in the
     capture looks exactly like "no such traffic" in every search built on it.
   - arkime_pcap_files() -> which capture files are indexed and what span each
     covers, when you want the file-level view rather than the dataset one.
   - malcolm_alerts(signature="ET MALWARE", time_from="24 hours ago") -> triage
     Suricata's signature-based alerts with structured filters.
   - malcolm_alerting_monitors() / malcolm_anomaly_detectors() -> the standing
     detections someone already configured, and whether they have fired. Both
     call out the state that reads like good news but is not: every monitor
     disabled, or detectors that were never started. These are OpenSearch
     alerting rules and ML baselines — a different mechanism from Suricata.

3. REUSE WHAT THE TEAM ALREADY BUILT before writing a query yourself.
   - arkime_views() -> saved search expressions someone curated. Take a view's
     expression straight to arkime_sessions.
   - arkime_shortcuts() -> named value lists (IOC sets). Each row gives the
     exact $name token to drop into an expression, so you reference the list
     rather than pasting every value.
   - malcolm_saved_objects(object_type="dashboard", search="DNS") -> Malcolm
     ships over a hundred dashboards and one usually already covers your
     protocol. Feed a dashboard id to malcolm_dashboard_export to read how it
     is built.

4. FIND SESSIONS. Pick the dialect:
   - Field filter + human time: malcolm_search(
       filters='{"event.dataset":"dns","zeek.dns.query":"ntp.ubuntu.com"}',
       time_from="7 days ago")
     Filter values are EXACT (Malcolm compiles them to a terms query). No
     wildcards: enumerate with malcolm_field_values and pass a list, or use
     search_dsl to write a wildcard query yourself.
   - Arkime expression + a session id you can drill into (epoch seconds!):
       arkime_sessions(expression="ip==192.0.2.77 && protocols==ssh")
     ONLY arkime_sessions returns an id usable in step 5.
   - Many rows rather than a few: arkime_sessions_csv(expression=...) returns
     the same sessions as a compact table at roughly half the tokens. It
     carries no session id, so use arkime_sessions when you need to drill in.

5. DRILL INTO ONE SESSION (use the id from arkime_sessions):
   - arkime_session_detail(session_id) -> full SPI document (all fields).
   - arkime_session_pcap(session_id)   -> validate/size the PCAP.
   - arkime_file_by_hash(file_hash="<md5-or-sha256>") -> extract the actual
     transferred file whose content hash matches (pull the malware sample; the
     hash comes from a session's http.md5 / http.sha256 field).

6. CHASE THE FILES that crossed the wire (needs Zeek file extraction on):
   - malcolm_file_scans(executables_only=True) -> the binaries Zeek carved out,
     with hashes and any Strelka/YARA/ClamAV hits. Take a sha256 to VirusTotal.
   - malcolm_file_scans(file_hash="<hash>") -> the reverse pivot: every session
     that carried a known-bad hash.
   - malcolm_extract_file(filename="<the row's `extracted` value>") -> size,
     sha256 and file-magic of the carved file itself. Metadata only: these are
     real samples, so the bytes never come back in the response.

7. PIVOT with aggregation:
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

8. PUT NAMES ON THE ADDRESSES.
   - malcolm_netbox_lookup(ip="192.0.2.77") -> internal assets: is this a known
     server, and what role? Decides whether the behavior is normal.
   - arkime_reverse_dns(ip="198.51.100.1") -> external addresses, via a live
     PTR lookup. That reflects DNS now, not what the capture saw; for the names
     actually observed on the wire, search event.dataset=dns instead.

9. RECORD THE FINDING (only if the write classes are enabled; if a tool is
   absent, that class is off):
   - malcolm_create_alert(title=..., severity=2, source_ip=..., description=...)
   - arkime_add_tags(session_ids="<ids>", tags="c2,triaged")
   - arkime_create_view(name="hunt_c2", expression=...) -> save the query for
     the team to rerun, where arkime_views will find it next time.
   - arkime_create_shortcut(name="c2_ips", value="1.2.3.4\n5.6.7.8",
       shortcut_type="ip")
     -> save an IOC list, then reference it as $c2_ips in later expressions.

Golden rules: confirm field names before you use them; Arkime tools take EPOCH
seconds while Malcolm/DSL tools take strings like "7 days ago"; only
arkime_sessions yields an id you can feed to the PCAP/payload/tag tools; and an
empty result is not evidence until you know the capture had no gap."""


def register_prompts(mcp: MCPServer) -> None:
    """Register workflow prompts (always available, read-only)."""

    @mcp.prompt(
        name="hunt_workflow",
        description="Worked Malcolm threat-hunting workflow: which tools to chain, "
        "in what order, with the field/time/session-id gotchas called out.",
    )
    def hunt_workflow() -> str:
        return _HUNT_WORKFLOW
