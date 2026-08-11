"""MALCOLM_MCP_DISABLE_READ_GROUPS: opting out of read groups at startup.

The full read surface is 51 tools and roughly 34k tokens of schema, spent
before a model has asked anything. A deployment that runs no NetBox, or that
cannot afford the context, needs to drop groups it will never call -- and
needs a typo in that list to fail rather than silently leave the group on.
"""

import asyncio

import pytest

from mcp_server_malcolm.server import create_server
from mcp_server_malcolm.tools import DISABLE_READ_GROUPS_ENV, _read_groups

# Every group's exact membership. Written out rather than derived so that
# moving a tool between modules has to be a deliberate edit here: the group
# names are operator-facing config, and a tool quietly changing groups would
# change what a deployed disable list removes.
_MEMBERSHIP = {
    "dsl": {"search_dsl", "count", "list_indices", "index_mapping", "cluster_health"},
    "query": {"malcolm_search", "malcolm_aggregate", "malcolm_alerts"},
    "fields": {"malcolm_field_search", "malcolm_field_values", "malcolm_field_profile"},
    "health": {
        "malcolm_service_status",
        "malcolm_data_coverage",
        "malcolm_ping",
        "malcolm_dashboard_export",
    },
    "netbox": {"malcolm_netbox_lookup", "malcolm_netbox_sites", "malcolm_netbox_query"},
    "arkime": {
        "arkime_field_search",
        "arkime_sessions",
        "arkime_sessions_csv",
        "arkime_sessions_summary",
        "arkime_build_query",
        "arkime_unique",
        "arkime_multiunique",
        "arkime_spigraph",
        "arkime_spiview",
        "arkime_spigraphhierarchy",
        "arkime_connections",
    },
    "arkime-content": {
        "arkime_session_pcap",
        "arkime_session_detail",
        "arkime_session_payload",
        "arkime_session_file_by_hash",
        "arkime_file_by_hash",
    },
    "correlation": {"malcolm_related_sessions"},
    "files": {"malcolm_file_scans", "malcolm_extract_file"},
    "arkime-inventory": {
        "arkime_views",
        "arkime_shortcuts",
        "arkime_crons",
        "arkime_reverse_dns",
        "arkime_pcap_files",
        "arkime_node_stats",
        "arkime_hunt_status",
    },
    "dashboards": {"malcolm_saved_objects", "malcolm_saved_object_detail"},
    "detections": {
        "malcolm_alerting_monitors",
        "malcolm_alerting_alerts",
        "malcolm_alerting_monitor_detail",
        "malcolm_anomaly_detectors",
        "malcolm_anomaly_results",
    },
}


def _names(monkeypatch, disable=None):
    for k in ("ALERTING", "ARKIME_TAGS", "HUNT_JOBS", "PCAP_UPLOAD", "ARKIME_VIEWS"):
        monkeypatch.delenv(f"MALCOLM_MCP_ENABLE_{k}", raising=False)
    if disable is None:
        monkeypatch.delenv(DISABLE_READ_GROUPS_ENV, raising=False)
    else:
        monkeypatch.setenv(DISABLE_READ_GROUPS_ENV, disable)
    return {t.name for t in asyncio.run(create_server().list_tools())}


def test_group_table_covers_every_registrar():
    """A new tool module must be given a group name, not left unreachable."""
    assert set(_read_groups()) == set(_MEMBERSHIP)


def test_default_registers_every_group(monkeypatch):
    names = _names(monkeypatch)
    assert names == set().union(*_MEMBERSHIP.values())
    assert len(names) == 51


@pytest.mark.parametrize("group", sorted(_MEMBERSHIP))
def test_disabling_one_group_removes_exactly_its_tools(monkeypatch, group):
    baseline = _names(monkeypatch)
    names = _names(monkeypatch, disable=group)
    assert baseline - names == _MEMBERSHIP[group]
    # Nothing else moves: a group is not allowed to take a neighbour with it.
    assert names == baseline - _MEMBERSHIP[group]


def test_disabling_several_groups_is_cumulative(monkeypatch):
    names = _names(monkeypatch, disable="netbox,dashboards,detections")
    gone = _MEMBERSHIP["netbox"] | _MEMBERSHIP["dashboards"] | _MEMBERSHIP["detections"]
    assert not (gone & names)
    assert len(names) == 51 - len(gone)


def test_whitespace_and_empty_entries_are_tolerated(monkeypatch):
    """Operators hand-edit this in a JSON config; stray spaces are not typos."""
    names = _names(monkeypatch, disable="  netbox , , dashboards,")
    assert not ((_MEMBERSHIP["netbox"] | _MEMBERSHIP["dashboards"]) & names)


def test_empty_value_disables_nothing(monkeypatch):
    assert _names(monkeypatch, disable="") == _names(monkeypatch)


def test_unknown_group_name_fails_loudly(monkeypatch):
    with pytest.raises(ValueError) as exc:
        _names(monkeypatch, disable="netboxx")
    message = str(exc.value)
    assert "netboxx" in message
    # The error has to be self-correcting -- an operator reading stderr should
    # not have to go find the valid names in the source.
    assert "netbox" in message and "detections" in message


def test_one_bad_name_rejects_the_whole_list(monkeypatch):
    """Registering the good half of a mistyped list would be the worst of both."""
    with pytest.raises(ValueError):
        _names(monkeypatch, disable="netbox,typo")


def test_startup_banner_names_the_disabled_groups(monkeypatch, capsys):
    _names(monkeypatch, disable="netbox,dashboards")
    err = capsys.readouterr().err
    assert "read groups disabled: dashboards, netbox" in err


def test_banner_stays_quiet_when_nothing_is_disabled(monkeypatch, capsys):
    _names(monkeypatch)
    assert "read groups disabled" not in capsys.readouterr().err
