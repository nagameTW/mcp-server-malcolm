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
    "arkime_sessions",
    "arkime_session_pcap",
    "malcolm_related_sessions",
    "malcolm_ping",
    "malcolm_dashboard_export",
}
_WRITE = {"malcolm_create_alert", "arkime_add_tags", "arkime_create_hunt", "malcolm_upload_pcap"}


def _names(monkeypatch, **flags):
    for k in ("ALERTING", "ARKIME_TAGS", "HUNT_JOBS", "PCAP_UPLOAD"):
        monkeypatch.delenv(f"MALCOLM_MCP_ENABLE_{k}", raising=False)
    for k, v in flags.items():
        monkeypatch.setenv(f"MALCOLM_MCP_ENABLE_{k}", v)
    mcp = create_server()
    return {t.name for t in asyncio.run(mcp.list_tools())}


def test_default_is_read_only(monkeypatch):
    names = _names(monkeypatch)
    assert _READ <= names
    assert not (_WRITE & names)


def test_each_write_class_enables_independently(monkeypatch):
    assert "malcolm_create_alert" in _names(monkeypatch, ALERTING="true")
    assert "arkime_add_tags" in _names(monkeypatch, ARKIME_TAGS="true")
    hunt = _names(monkeypatch, HUNT_JOBS="true")
    assert "arkime_create_hunt" in hunt and "arkime_hunt_status" in hunt
    assert "malcolm_upload_pcap" in _names(monkeypatch, PCAP_UPLOAD="true")


def test_enabling_one_class_does_not_enable_others(monkeypatch):
    names = _names(monkeypatch, ALERTING="true")
    assert "malcolm_create_alert" in names
    assert "arkime_add_tags" not in names
    assert "arkime_create_hunt" not in names
    assert "malcolm_upload_pcap" not in names
