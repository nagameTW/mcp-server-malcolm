from mcp_server_malcolm.config import WriteConfig


def _clear(monkeypatch):
    for v in (
        "MALCOLM_MCP_ENABLE_ALERTING",
        "MALCOLM_MCP_ENABLE_ARKIME_TAGS",
        "MALCOLM_MCP_ENABLE_HUNT_JOBS",
        "MALCOLM_MCP_ENABLE_PCAP_UPLOAD",
        "MALCOLM_MCP_AUDIT_FILE",
        "MALCOLM_MCP_UPLOAD_DIR",
    ):
        monkeypatch.delenv(v, raising=False)


def test_defaults_all_off(monkeypatch):
    _clear(monkeypatch)
    cfg = WriteConfig.from_env()
    assert cfg == WriteConfig(False, False, False, False, None, None)
    assert cfg.any_enabled() is False
    assert cfg.enabled_summary() == "alerting=off arkime-tag=off hunt-job=off pcap-upload=off"
    assert cfg.upload_dir is None


def test_upload_dir_none_when_empty(monkeypatch):
    _clear(monkeypatch)
    assert WriteConfig.from_env().upload_dir is None
    monkeypatch.setenv("MALCOLM_MCP_UPLOAD_DIR", "/srv/staging")
    assert WriteConfig.from_env().upload_dir == "/srv/staging"


def test_flags_parse_case_insensitively(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("MALCOLM_MCP_ENABLE_ALERTING", "TRUE")
    monkeypatch.setenv("MALCOLM_MCP_ENABLE_HUNT_JOBS", "true")
    monkeypatch.setenv("MALCOLM_MCP_ENABLE_ARKIME_TAGS", "0")
    cfg = WriteConfig.from_env()
    assert cfg.alerting is True
    assert cfg.hunt_jobs is True
    assert cfg.arkime_tags is False
    assert cfg.any_enabled() is True
    assert cfg.enabled_summary() == "alerting=on arkime-tag=off hunt-job=on pcap-upload=off"


def test_audit_file_none_when_empty(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("MALCOLM_MCP_AUDIT_FILE", "")
    assert WriteConfig.from_env().audit_file is None
    monkeypatch.setenv("MALCOLM_MCP_AUDIT_FILE", "/tmp/audit.jsonl")
    assert WriteConfig.from_env().audit_file == "/tmp/audit.jsonl"


def test_is_frozen():
    import dataclasses

    cfg = WriteConfig(False, False, False, False, None, None)
    try:
        cfg.alerting = True  # type: ignore[misc]
        raised = False
    except dataclasses.FrozenInstanceError:
        raised = True
    assert raised
