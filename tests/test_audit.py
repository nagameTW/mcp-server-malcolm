import json

from mcp_server_malcolm.audit import outcome_for_status, record


def test_outcome_for_status():
    assert outcome_for_status(200) == "ok"
    assert outcome_for_status(201) == "ok"
    assert outcome_for_status(403) == "http_4xx"
    assert outcome_for_status(500) == "http_5xx"
    assert outcome_for_status(301) == "http_other"


def test_record_to_file_is_single_line_json(tmp_path):
    f = tmp_path / "audit.jsonl"
    record("arkime_add_tags", "arkime-tag", "ids=id1", {"tags": "malicious"}, "ok", str(f))
    record("malcolm_create_alert", "alerting", "sig=x", {"severity": 2}, "http_5xx", str(f))
    lines = f.read_text().splitlines()
    assert len(lines) == 2
    row = json.loads(lines[0])
    assert row["tool"] == "arkime_add_tags"
    assert row["class"] == "arkime-tag"
    assert row["outcome"] == "ok"
    assert row["params"]["tags"] == "malicious"
    assert "ts" in row


def test_record_truncates_long_params(tmp_path):
    f = tmp_path / "audit.jsonl"
    record("t", "c", "target", {"blob": "x" * 5000}, "ok", str(f))
    row = json.loads(f.read_text().splitlines()[0])
    assert len(row["params"]["blob"]) <= 201


def test_record_to_stderr(capsys):
    record("t", "c", "target", {"k": "v"}, "ok", None)
    err = capsys.readouterr().err
    row = json.loads(err.strip())
    assert row["tool"] == "t"
    assert row["outcome"] == "ok"
