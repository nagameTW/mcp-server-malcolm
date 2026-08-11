import asyncio

from mcp_server_malcolm.server import create_server

_READ = {
    "search_dsl",
    "count",
    "list_indices",
    "index_mapping",
    "cluster_health",
    "malcolm_search",
    "malcolm_aggregate",
    "malcolm_alerts",
    "malcolm_field_search",
    "malcolm_field_values",
    "malcolm_field_profile",
    "malcolm_service_status",
    "malcolm_data_coverage",
    "malcolm_netbox_lookup",
    "malcolm_netbox_sites",
    "malcolm_netbox_query",
    "arkime_field_search",
    "arkime_sessions",
    "arkime_sessions_summary",
    "arkime_build_query",
    "arkime_session_pcap",
    "arkime_session_detail",
    "arkime_session_payload",
    "arkime_session_file_by_hash",
    "arkime_unique",
    "arkime_multiunique",
    "arkime_spigraph",
    "arkime_spiview",
    "arkime_spigraphhierarchy",
    "arkime_connections",
    "arkime_file_by_hash",
    "arkime_sessions_csv",
    "arkime_views",
    "arkime_shortcuts",
    "arkime_reverse_dns",
    "arkime_pcap_files",
    "arkime_node_stats",
    "arkime_crons",
    "arkime_hunt_status",
    "malcolm_file_scans",
    "malcolm_extract_file",
    "malcolm_related_sessions",
    "malcolm_ping",
    "malcolm_dashboard_export",
    "malcolm_saved_objects",
    "malcolm_saved_object_detail",
    "malcolm_alerting_monitors",
    "malcolm_alerting_alerts",
    "malcolm_alerting_monitor_detail",
    "malcolm_anomaly_detectors",
    "malcolm_anomaly_results",
}
_WRITE = {
    "malcolm_create_alert",
    "arkime_add_tags",
    "arkime_create_hunt",
    "arkime_cancel_hunt",
    "malcolm_upload_pcap",
    "arkime_create_view",
    "arkime_create_shortcut",
}


def _names(monkeypatch, **flags):
    for k in ("ALERTING", "ARKIME_TAGS", "HUNT_JOBS", "PCAP_UPLOAD", "ARKIME_VIEWS"):
        monkeypatch.delenv(f"MALCOLM_MCP_ENABLE_{k}", raising=False)
    # This file asserts the read set exactly; a leaked read-group disable list
    # would make that comparison fail for a reason that has nothing to do with
    # the write gate under test.
    monkeypatch.delenv("MALCOLM_MCP_DISABLE_READ_GROUPS", raising=False)
    for k, v in flags.items():
        monkeypatch.setenv(f"MALCOLM_MCP_ENABLE_{k}", v)
    mcp = create_server()
    return {t.name for t in asyncio.run(mcp.list_tools())}


def test_default_is_read_only(monkeypatch):
    names = _names(monkeypatch)
    # Exact match: with every write class off, the ONLY tools are the always-on
    # read set — no write tool may slip in.
    assert names == _READ
    assert not (_WRITE & names)


def test_hunt_status_reads_hunts_with_every_write_class_off(monkeypatch):
    """It used to register inside the hunt-job write branch, which hid queued
    hunt jobs from every read-only deployment. GET /arkime/api/hunts mutates
    nothing, so the gate cost coverage and bought no protection."""
    assert "arkime_hunt_status" in _names(monkeypatch)
    assert "arkime_hunt_status" in _names(monkeypatch, HUNT_JOBS="true")
    # the write half of the same endpoint family stays gated
    assert "arkime_create_hunt" not in _names(monkeypatch)
    assert "arkime_cancel_hunt" not in _names(monkeypatch)


def test_each_write_class_enables_independently(monkeypatch):
    assert "malcolm_create_alert" in _names(monkeypatch, ALERTING="true")
    assert "arkime_add_tags" in _names(monkeypatch, ARKIME_TAGS="true")
    hunt = _names(monkeypatch, HUNT_JOBS="true")
    assert "arkime_create_hunt" in hunt and "arkime_cancel_hunt" in hunt
    assert "malcolm_upload_pcap" in _names(monkeypatch, PCAP_UPLOAD="true")
    views = _names(monkeypatch, ARKIME_VIEWS="true")
    assert "arkime_create_view" in views and "arkime_create_shortcut" in views


def test_enabling_one_class_does_not_enable_others(monkeypatch):
    names = _names(monkeypatch, ALERTING="true")
    assert "malcolm_create_alert" in names
    assert "arkime_add_tags" not in names
    assert "arkime_create_hunt" not in names
    assert "malcolm_upload_pcap" not in names
