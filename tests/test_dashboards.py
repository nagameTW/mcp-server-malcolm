"""Tests for the Dashboards / OpenSearch-plugin tools (batch 3).

Endpoint shapes and parameter behavior were measured against a live Malcolm
v26.07.1 (OpenSearch 3.7.0, alerting + anomaly-detection plugins installed)
before these were written.
"""

import asyncio
import json

import httpx
import pytest
from conftest import raised_by, tool_text
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.errors import ToolInputError, UpstreamError
from mcp_server_malcolm.server import create_server
from mcp_server_malcolm.tools.dashboards import register_dashboard_tools
from mcp_server_malcolm.tools.detections import register_detection_tools


def _mock_client(handler):
    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example",
        transport=httpx.MockTransport(handler),
    )
    return c


def _tools(handler):
    """Saved objects and the detections that were split out of that module: one
    server, so these tests keep asking the same questions after the split."""
    mcp = MCPServer("t")
    client = _mock_client(handler)
    register_dashboard_tools(mcp, client)
    register_detection_tools(mcp, client)
    return mcp


def test_batch3_tools_registered():
    names = [t.name for t in asyncio.run(create_server().list_tools())]
    for name in (
        "malcolm_saved_objects",
        "malcolm_alerting_monitors",
        "malcolm_anomaly_detectors",
        "malcolm_alerting_alerts",
        "malcolm_alerting_monitor_detail",
        "malcolm_anomaly_results",
        "malcolm_saved_object_detail",
    ):
        assert name in names


# -- malcolm_saved_objects ----------------------------------------------

_DASHBOARD = {
    "type": "dashboard",
    "id": "665d1610-523d-11e9-a30e-e3576242f3ed",
    "updated_at": "2026-07-30T03:00:00.000Z",
    "attributes": {
        "title": "DNS",
        "description": "Zeek DNS queries and responses",
        # The bulk of a real object, and useless to an agent: one dashboard is
        # ~5.4 KB and this is nearly all of it.
        "panelsJSON": "[{...4KB of layout...}]",
        "optionsJSON": "{}",
        "kibanaSavedObjectMeta": {"searchSourceJSON": "{}"},
    },
    "references": [{"type": "search", "id": "abc", "name": "panel_1"}],
    "migrationVersion": {"dashboard": "7.9.3"},
    "score": 0,
}


@pytest.mark.asyncio
async def test_saved_objects_finds_by_type_and_trims_the_layout_blobs():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        seen["params"] = req.url.params.multi_items()
        return httpx.Response(
            200, json={"page": 1, "per_page": 20, "total": 111, "saved_objects": [_DASHBOARD]}
        )

    out = json.loads(
        tool_text(
            await _tools(handler).call_tool("malcolm_saved_objects", {"object_type": "dashboard"})
        )
    )

    assert seen["path"] == "/dashboards/api/saved_objects/_find"
    assert ("type", "dashboard") in seen["params"]
    assert out["total"] == 111
    assert out["objects"][0] == {
        "type": "dashboard",
        "id": "665d1610-523d-11e9-a30e-e3576242f3ed",
        "title": "DNS",
        "description": "Zeek DNS queries and responses",
        "updated_at": "2026-07-30T03:00:00.000Z",
    }


@pytest.mark.asyncio
async def test_saved_objects_asks_the_server_to_send_only_the_useful_fields():
    """Measured live: 5 dashboards are 19.7 KB in full and 6.0 KB with
    fields=title&fields=description, so the trim belongs server-side too."""
    seen = {}

    def handler(req):
        seen["params"] = req.url.params.multi_items()
        return httpx.Response(200, json={"total": 0, "saved_objects": []})

    await _tools(handler).call_tool("malcolm_saved_objects", {"object_type": "dashboard"})

    assert ("fields", "title") in seen["params"]
    assert ("fields", "description") in seen["params"]


@pytest.mark.asyncio
async def test_saved_objects_accepts_several_types_at_once():
    seen = {}

    def handler(req):
        seen["params"] = req.url.params.multi_items()
        return httpx.Response(200, json={"total": 252, "saved_objects": []})

    await _tools(handler).call_tool("malcolm_saved_objects", {"object_type": "dashboard, search"})

    assert ("type", "dashboard") in seen["params"]
    assert ("type", "search") in seen["params"]


@pytest.mark.asyncio
async def test_saved_objects_searches_titles():
    seen = {}

    def handler(req):
        seen["params"] = dict(req.url.params)
        return httpx.Response(200, json={"total": 1, "saved_objects": [_DASHBOARD]})

    await _tools(handler).call_tool(
        "malcolm_saved_objects", {"object_type": "dashboard", "search": "DNS"}
    )

    assert seen["params"]["search"] == "DNS"
    # Without search_fields the query also matches description and body text.
    assert seen["params"]["search_fields"] == "title"


@pytest.mark.asyncio
async def test_saved_objects_rejects_an_unknown_type():
    def handler(req):
        raise AssertionError("no request may leave for an unsupported object type")

    raised = await raised_by(_tools(handler), "malcolm_saved_objects", {"object_type": "widget"})

    assert isinstance(raised, ToolInputError)
    assert "widget" in str(raised)
    assert "dashboard" in str(raised)


@pytest.mark.asyncio
async def test_saved_objects_reports_no_match():
    def handler(req):
        return httpx.Response(200, json={"total": 0, "saved_objects": []})

    out = tool_text(
        await _tools(handler).call_tool(
            "malcolm_saved_objects", {"object_type": "dashboard", "search": "nothing"}
        )
    )

    assert "no saved objects" in out.lower()


# -- malcolm_alerting_monitors ------------------------------------------

_MONITOR = {
    "_id": "NYUZsZ8Bao8axaN3ef1f",
    "_source": {
        "type": "monitor",
        "name": "Malcolm API Loopback Monitor",
        "monitor_type": "query_level_monitor",
        "enabled": False,
        "schedule": {"period": {"interval": 10, "unit": "MINUTES"}},
        "inputs": [{"search": {"indices": ["arkime_sessions3-*"], "query": {"size": 0}}}],
        "triggers": [{"query_level_trigger": {"id": "t1", "name": "Loopback trigger"}}],
        "last_update_time": 1785382000000,
    },
}


def _alerting_handler(monitors, alerts, seen=None):
    def handler(req):
        if seen is not None:
            seen.setdefault("paths", []).append(req.url.path)
        if req.url.path.endswith("/monitors/alerts"):
            return httpx.Response(200, json={"alerts": alerts, "totalAlerts": len(alerts)})
        return httpx.Response(
            200,
            json={"hits": {"total": {"value": len(monitors)}, "hits": monitors}},
        )

    return handler


@pytest.mark.asyncio
async def test_alerting_monitors_lists_config_and_whether_it_is_on():
    seen = {}
    out = json.loads(
        tool_text(
            await _tools(_alerting_handler([_MONITOR], [], seen)).call_tool(
                "malcolm_alerting_monitors", {}
            )
        )
    )

    assert "/mapi/opensearch/_plugins/_alerting/monitors/_search" in seen["paths"]
    row = out["monitors"][0]
    assert row["name"] == "Malcolm API Loopback Monitor"
    assert row["enabled"] is False
    assert row["schedule"] == "every 10 MINUTES"
    assert row["indices"] == ["arkime_sessions3-*"]
    assert row["triggers"] == ["Loopback trigger"]


@pytest.mark.asyncio
async def test_alerting_monitors_reports_the_active_alert_count():
    """A monitor's config says what it watches; only the alert count says
    whether it has fired, which is the part an analyst acts on."""
    alerts = [{"id": "a1", "monitor_name": "Malcolm API Loopback Monitor", "state": "ACTIVE"}]
    out = json.loads(
        tool_text(
            await _tools(_alerting_handler([_MONITOR], alerts)).call_tool(
                "malcolm_alerting_monitors", {}
            )
        )
    )

    assert out["active_alerts"] == 1


@pytest.mark.asyncio
async def test_alerting_monitors_warns_when_every_monitor_is_disabled():
    """A disabled monitor is silent in exactly the way a healthy one is."""
    out = tool_text(
        await _tools(_alerting_handler([_MONITOR], [])).call_tool("malcolm_alerting_monitors", {})
    )

    assert "disabled" in out.lower()


@pytest.mark.asyncio
async def test_alerting_monitors_still_answers_when_the_alert_call_fails():
    """The alert count is an enrichment; losing it must not lose the monitors."""

    def handler(req):
        if req.url.path.endswith("/monitors/alerts"):
            raise httpx.ConnectError("alerts endpoint down")
        return httpx.Response(200, json={"hits": {"total": {"value": 1}, "hits": [_MONITOR]}})

    out = json.loads(tool_text(await _tools(handler).call_tool("malcolm_alerting_monitors", {})))

    assert out["monitors"][0]["name"] == "Malcolm API Loopback Monitor"
    assert "active_alerts" not in out


@pytest.mark.asyncio
async def test_alerting_monitors_reports_none_configured():
    out = tool_text(
        await _tools(_alerting_handler([], [])).call_tool("malcolm_alerting_monitors", {})
    )

    assert "no alerting monitors" in out.lower()


# -- malcolm_anomaly_detectors ------------------------------------------

_DETECTOR = {
    "_id": "7YUZsZ8Bao8axaN3Dfzu",
    "_source": {
        "name": "action_result_user",
        "description": "Detect anomalies in action, result and user",
        "indices": ["arkime_sessions3-*"],
        "detector_type": "MULTI_ENTITY",
        "category_field": ["event.action", "event.result"],
        "detection_interval": {"period": {"unit": "Minutes", "interval": 10}},
        "window_delay": {"period": {"unit": "Minutes", "interval": 1}},
        "shingle_size": 8,
        "feature_attributes": [
            {
                "feature_id": "6YUZsZ8Bao8axaN3DPwc",
                "feature_name": "event_action",
                "feature_enabled": True,
                "aggregation_query": {"event_action": {"value_count": {"field": "event.action"}}},
            }
        ],
    },
}


def _detector_handler(detectors, anomaly_total, seen=None):
    def handler(req):
        if seen is not None:
            seen.setdefault("paths", []).append(req.url.path)
        if req.url.path.endswith("/detectors/results/_search"):
            return httpx.Response(200, json={"hits": {"total": {"value": anomaly_total}}})
        return httpx.Response(
            200, json={"hits": {"total": {"value": len(detectors)}, "hits": detectors}}
        )

    return handler


@pytest.mark.asyncio
async def test_anomaly_detectors_lists_what_each_one_watches():
    seen = {}
    out = json.loads(
        tool_text(
            await _tools(_detector_handler([_DETECTOR], 0, seen)).call_tool(
                "malcolm_anomaly_detectors", {}
            )
        )
    )

    assert "/mapi/opensearch/_plugins/_anomaly_detection/detectors/_search" in seen["paths"]
    row = out["detectors"][0]
    assert row["name"] == "action_result_user"
    assert row["indices"] == ["arkime_sessions3-*"]
    assert row["category_fields"] == ["event.action", "event.result"]
    assert row["interval"] == "every 10 Minutes"
    assert row["features"] == ["event_action"]
    # The aggregation internals are configuration noise, not triage material.
    assert "aggregation_query" not in json.dumps(out)


@pytest.mark.asyncio
async def test_anomaly_detectors_reports_how_many_anomalies_exist():
    out = json.loads(
        tool_text(
            await _tools(_detector_handler([_DETECTOR], 42)).call_tool(
                "malcolm_anomaly_detectors", {}
            )
        )
    )

    assert out["recorded_anomalies"] == 42


@pytest.mark.asyncio
async def test_anomaly_detectors_says_when_nothing_has_been_detected():
    """Zero results with detectors configured usually means they were never
    started, which reads identically to "nothing anomalous happened"."""
    out = tool_text(
        await _tools(_detector_handler([_DETECTOR], 0)).call_tool("malcolm_anomaly_detectors", {})
    )

    assert "no anomalous results" in out.lower()
    # ...and it must still warn that a stopped detector looks the same.
    assert "never started" in out.lower()


@pytest.mark.asyncio
async def test_anomaly_detectors_still_answers_when_the_result_count_fails():
    def handler(req):
        if req.url.path.endswith("/detectors/results/_search"):
            raise httpx.ConnectError("results index missing")
        return httpx.Response(200, json={"hits": {"total": {"value": 1}, "hits": [_DETECTOR]}})

    out = json.loads(tool_text(await _tools(handler).call_tool("malcolm_anomaly_detectors", {})))

    assert out["detectors"][0]["name"] == "action_result_user"
    assert "recorded_anomalies" not in out


@pytest.mark.asyncio
async def test_anomaly_detectors_reports_none_configured():
    out = tool_text(
        await _tools(_detector_handler([], 0)).call_tool("malcolm_anomaly_detectors", {})
    )

    assert "no anomaly detectors" in out.lower()


# -- malcolm_alerting_alerts --------------------------------------------

# One alert as the plugin sends it. Kept whole on purpose: this lab has never
# raised one (its only monitor is disabled), so the tool passes rows through
# rather than trimming to a key set nobody has measured.
_ALERT = {
    "id": "s6xUsZ8Bao8axaN3Ff2K",
    "monitor_id": "NYUZsZ8Bao8axaN3ef1f",
    "monitor_name": "Malcolm API Loopback Monitor",
    "trigger_name": "Malcolm API Loopback Trigger",
    "severity": "4",
    "state": "COMPLETED",
    "start_time": 1714003200000,
    "end_time": 1714006800000,
}


@pytest.mark.asyncio
async def test_alerting_alerts_reaches_the_history_the_monitor_list_hides():
    """malcolm_alerting_monitors pins alertState=ACTIVE, so a monitor that fired
    and recovered is invisible there. Every filter has to reach the request."""
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        seen["params"] = dict(req.url.params)
        return httpx.Response(200, json={"alerts": [_ALERT], "totalAlerts": 1})

    out = json.loads(
        tool_text(
            await _tools(handler).call_tool(
                "malcolm_alerting_alerts",
                {
                    "alert_state": "completed",
                    "monitor_id": "NYUZsZ8Bao8axaN3ef1f",
                    "severity": "4",
                    "search": "loopback",
                },
            )
        )
    )

    assert seen["path"] == "/mapi/opensearch/_plugins/_alerting/monitors/alerts"
    # Upstream names them singular; monitorIds is a 400 suggesting monitorId.
    assert seen["params"] == {
        "alertState": "COMPLETED",
        "monitorId": "NYUZsZ8Bao8axaN3ef1f",
        "severityLevel": "4",
        "searchString": "loopback",
    }
    assert out["total"] == 1
    assert out["showing"] == 1
    # Passed through unrenamed: which trigger fired, when, and at what severity.
    assert out["alerts"][0] == _ALERT


@pytest.mark.asyncio
async def test_alerting_alerts_reports_none_without_raising():
    """Zero alerts is an answer, not a failure — and the usual cause is a
    disabled monitor, which the sentence has to point at."""

    def handler(req):
        return httpx.Response(200, json={"alerts": [], "totalAlerts": 0})

    out = tool_text(await _tools(handler).call_tool("malcolm_alerting_alerts", {}))

    assert "no alerts in any state" in out.lower()
    assert "malcolm_alerting_monitors" in out


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("args", "needle"),
    [
        ({"alert_state": "FIRING"}, "FIRING"),
        ({"severity": "high"}, "high"),
    ],
)
async def test_alerting_alerts_rejects_a_filter_upstream_would_swallow(args, needle):
    """Measured on v26.07.1: alertState=BOGUS and severityLevel=high both answer
    200 with an empty list rather than 400, so an unchecked typo reads to an
    agent as "nothing ever fired"."""

    def handler(req):
        raise AssertionError("no request may leave with an unknown filter value")

    raised = await raised_by(_tools(handler), "malcolm_alerting_alerts", args)

    assert isinstance(raised, ToolInputError)
    assert needle in str(raised)


# -- malcolm_alerting_monitor_detail ------------------------------------

_MONITOR_DETAIL = {
    "_id": "NYUZsZ8Bao8axaN3ef1f",
    "_version": 1,
    "monitor": {
        "name": "Malcolm API Loopback Monitor",
        "monitor_type": "query_level_monitor",
        "enabled": False,
        "schedule": {"period": {"interval": 10, "unit": "MINUTES"}},
        "inputs": [
            {
                "search": {
                    "indices": ["arkime_sessions3-*"],
                    "query": {
                        "size": 0,
                        "query": {
                            "bool": {"filter": [{"range": {"firstPacket": {"from": "now-10m"}}}]}
                        },
                    },
                }
            }
        ],
        "triggers": [
            {
                "query_level_trigger": {
                    "id": "MoUZsZ8Bao8axaN3d_3-",
                    "name": "Malcolm API Loopback Trigger",
                    "severity": "4",
                    "condition": {
                        "script": {
                            "source": "ctx.results[0].hits.total.value > 999999999",
                            "lang": "painless",
                        }
                    },
                    "actions": [{"id": "a1", "name": "Malcolm API Loopback Action"}],
                }
            }
        ],
    },
}


@pytest.mark.asyncio
async def test_monitor_detail_shows_the_query_and_the_firing_condition():
    """The two things the monitor LIST cannot show, and the only way to judge
    whether a monitor's silence means anything: this one fires above 999999999
    hits, so it is configured never to."""
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        return httpx.Response(200, json=_MONITOR_DETAIL)

    out = json.loads(
        tool_text(
            await _tools(handler).call_tool(
                "malcolm_alerting_monitor_detail", {"monitor_id": "NYUZsZ8Bao8axaN3ef1f"}
            )
        )
    )

    assert seen["path"] == "/mapi/opensearch/_plugins/_alerting/monitors/NYUZsZ8Bao8axaN3ef1f"
    assert out["id"] == "NYUZsZ8Bao8axaN3ef1f"
    assert out["schedule"] == "every 10 MINUTES"
    assert out["inputs"][0]["indices"] == ["arkime_sessions3-*"]
    assert out["inputs"][0]["query"]["size"] == 0
    assert out["triggers"][0] == {
        "name": "Malcolm API Loopback Trigger",
        "severity": "4",
        "condition": "ctx.results[0].hits.total.value > 999999999",
        "actions": ["Malcolm API Loopback Action"],
    }
    assert "disabled" in out["note"]


@pytest.mark.asyncio
async def test_monitor_detail_answers_for_a_monitor_with_nothing_configured():
    """A monitor with no inputs and no triggers is the empty case here. It must
    answer rather than raise, and say why it can never alert — that silence is
    indistinguishable from a healthy monitor with nothing to report."""
    bare = {"_id": "empty", "monitor": {"name": "Bare monitor", "enabled": True}}

    def handler(req):
        return httpx.Response(200, json=bare)

    out = json.loads(
        tool_text(
            await _tools(handler).call_tool(
                "malcolm_alerting_monitor_detail", {"monitor_id": "empty"}
            )
        )
    )

    assert out["name"] == "Bare monitor"
    assert "inputs" not in out
    assert "no triggers" in out["note"]
    assert "disabled" not in out["note"]


@pytest.mark.asyncio
async def test_monitor_detail_keeps_a_bucket_level_trigger_it_cannot_read_a_script_from():
    """A bucket-level trigger's condition is not a painless script. The trigger
    still has to appear, with `condition` absent rather than invented."""
    bucket = {
        "_id": "b",
        "monitor": {
            "name": "Bucket monitor",
            "enabled": True,
            "triggers": [
                {
                    "bucket_level_trigger": {
                        "name": "Bucket trigger",
                        "severity": "2",
                        "condition": {"buckets_path": {"count": "_count"}},
                    }
                }
            ],
        },
    }

    def handler(req):
        return httpx.Response(200, json=bucket)

    out = json.loads(
        tool_text(
            await _tools(handler).call_tool("malcolm_alerting_monitor_detail", {"monitor_id": "b"})
        )
    )

    assert out["triggers"] == [{"name": "Bucket trigger", "severity": "2"}]
    assert "note" not in out


# -- malcolm_anomaly_results --------------------------------------------

# The lab's traffic window, in the milliseconds this route wants.
_START_MS, _END_MS = 1714003200000, 1714089600000


def _anomaly_handler(buckets, state="DISABLED", seen=None):
    def handler(req):
        if req.url.path.endswith("/_profile"):
            return httpx.Response(200, json={"state": state})
        if seen is not None:
            seen["path"] = req.url.path
            seen["params"] = dict(req.url.params)
            seen["body"] = json.loads(req.content)
        return httpx.Response(200, json={"buckets": buckets})

    return handler


@pytest.mark.asyncio
async def test_anomaly_results_asks_the_named_detector_for_its_own_window():
    seen = {}
    bucket = {
        "key": {"source.ip": "192.0.2.10", "destination.ip": "198.51.100.7"},
        "doc_count": 3,
        "max_anomaly_grade": 0.87,
    }
    out = json.loads(
        tool_text(
            await _tools(_anomaly_handler([bucket], state="RUNNING", seen=seen)).call_tool(
                "malcolm_anomaly_results",
                {
                    "detector_id": "94UZsZ8Bao8axaN3EPyz",
                    "start_time_ms": _START_MS,
                    "end_time_ms": _END_MS,
                    "order": "Occurrence",
                },
            )
        )
    )

    assert seen["path"].endswith("/detectors/94UZsZ8Bao8axaN3EPyz/results/_topAnomalies")
    assert seen["body"]["start_time_ms"] == _START_MS
    assert seen["body"]["end_time_ms"] == _END_MS
    # Lowercased for the caller: "SEVERITY" is a 400 upstream.
    assert seen["body"]["order"] == "occurrence"
    assert out["detector_state"] == "RUNNING"
    # Buckets are the plugin's own, keyed by the detector's category fields.
    assert out["anomalies"] == [bucket]
    # The window is echoed so a millisecond mix-up is visible in the answer.
    assert out["window"] == "2024-04-25T00:00:00Z to 2024-04-26T00:00:00Z"


@pytest.mark.asyncio
async def test_anomaly_results_explains_an_empty_window_by_the_detector_state():
    """The gap this tool closes: no buckets from a DISABLED detector means
    nothing was ever computed, not that the traffic was clean. It must answer,
    not raise."""
    out = tool_text(
        await _tools(_anomaly_handler([])).call_tool(
            "malcolm_anomaly_results",
            {
                "detector_id": "94UZsZ8Bao8axaN3EPyz",
                "start_time_ms": _START_MS,
                "end_time_ms": _END_MS,
            },
        )
    )

    assert "no anomalies" in out.lower()
    assert "disabled" in out.lower()
    assert "never ran" in out.lower()


@pytest.mark.asyncio
async def test_anomaly_results_still_answers_when_the_state_lookup_fails():
    def handler(req):
        if req.url.path.endswith("/_profile"):
            raise httpx.ConnectError("profile route down")
        return httpx.Response(200, json={"buckets": [{"key": {"a": "b"}, "doc_count": 1}]})

    out = json.loads(
        tool_text(
            await _tools(handler).call_tool(
                "malcolm_anomaly_results",
                {
                    "detector_id": "94UZsZ8Bao8axaN3EPyz",
                    "start_time_ms": _START_MS,
                    "end_time_ms": _END_MS,
                },
            )
        )
    )

    assert out["showing"] == 1
    assert "detector_state" not in out
    assert "profile route down" in out["detector_state_error"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("args", "needle"),
    [
        ({"start_time_ms": 1714003200, "end_time_ms": _END_MS}, "SECONDS"),
        ({"start_time_ms": _START_MS, "end_time_ms": 1714089600}, "SECONDS"),
        ({"start_time_ms": _END_MS, "end_time_ms": _START_MS}, "later than"),
        ({"start_time_ms": _START_MS, "end_time_ms": _END_MS, "order": "worst"}, "worst"),
    ],
)
async def test_anomaly_results_rejects_a_window_that_would_answer_empty(args, needle):
    """Epoch seconds are a window in 1970 upstream and answer empty, which is
    indistinguishable from a detector that scored nothing. Same for a reversed
    window and for an order upstream 400s on."""

    def handler(req):
        raise AssertionError("no request may leave with a window that cannot answer")

    raised = await raised_by(
        _tools(handler), "malcolm_anomaly_results", {"detector_id": "d1", **args}
    )

    assert isinstance(raised, ToolInputError)
    assert needle in str(raised)


@pytest.mark.asyncio
async def test_anomaly_results_hands_back_the_plugins_own_refusal():
    """A 4xx here carries the only actionable part, and httpx's message does not.

    Measured on 26.07.1: one of this lab's five detectors has no category field,
    and _topAnomalies answers it 400 {"error":{"reason":"No category fields
    found for detector ID ..."}}. Raised through raise_for_status that reason is
    dropped and the agent is handed httpx's text instead -- the status and the
    internal URL, neither of which it can act on, one of which it should not see.
    """

    def handler(req):
        if req.url.path.endswith("/_profile"):
            return httpx.Response(200, json={"state": "DISABLED"})
        return httpx.Response(
            400,
            json={
                "error": {
                    "reason": "No category fields found for detector ID IoZBtp8Bao8axaN3dQNb"
                },
                "status": 400,
            },
        )

    raised = await raised_by(
        _tools(handler),
        "malcolm_anomaly_results",
        {
            "detector_id": "IoZBtp8Bao8axaN3dQNb",
            "start_time_ms": _START_MS,
            "end_time_ms": _END_MS,
        },
    )

    assert isinstance(raised, UpstreamError)
    assert raised.status == 400
    assert "No category fields found" in str(raised)
    assert "malcolm.example" not in str(raised), "the upstream URL is not the agent's business"
    assert "_topAnomalies" not in str(raised)


# -- malcolm_saved_object_detail ----------------------------------------

# A saved search as this Malcolm stores one: the query is a JSON *string* two
# levels down, and its index is a reference NAME resolved through references[].
_SAVED_SEARCH = {
    "id": "bc940221-83d5-416e-a353-dc8fc2f84141",
    "type": "search",
    "updated_at": "2026-07-30T03:34:22.282Z",
    "attributes": {
        "title": "DCE/RPC - Logs",
        "description": "",
        "hits": 0,
        "columns": ["source.ip", "destination.ip", "zeek.dce_rpc.operation"],
        "sort": [["firstPacket", "desc"]],
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps(
                {
                    "highlightAll": False,
                    "version": True,
                    "filter": [
                        {
                            "meta": {"negate": False, "key": "network.protocol", "type": "phrase"},
                            "query": {"match_phrase": {"network.protocol": "dce_rpc"}},
                        }
                    ],
                    "query": {"query": "event.dataset:dce_rpc", "language": "lucene"},
                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                }
            )
        },
    },
    "references": [
        {
            "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
            "type": "index-pattern",
            "id": "arkime_sessions3-*",
        }
    ],
}


@pytest.mark.asyncio
async def test_saved_object_detail_resolves_the_query_and_the_index_reference():
    """Both indirections in one object: searchSourceJSON needs a second parse,
    and indexRefName is meaningless until looked up in references[]. Leaving
    either to the caller is what this tool exists to avoid."""
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        return httpx.Response(200, json=_SAVED_SEARCH)

    out = json.loads(
        tool_text(
            await _tools(handler).call_tool(
                "malcolm_saved_object_detail",
                {"object_id": "bc940221-83d5-416e-a353-dc8fc2f84141"},
            )
        )
    )

    assert seen["path"] == (
        "/dashboards/api/saved_objects/search/bc940221-83d5-416e-a353-dc8fc2f84141"
    )
    assert out["query"] == "event.dataset:dce_rpc"
    # lucene and kuery are not interchangeable, so the dialect travels with it.
    assert out["language"] == "lucene"
    assert out["index_pattern"] == "arkime_sessions3-*"
    assert out["filters"][0]["query"] == {"match_phrase": {"network.protocol": "dce_rpc"}}
    assert out["columns"] == ["source.ip", "destination.ip", "zeek.dce_rpc.operation"]
    assert out["sort"] == [["firstPacket", "desc"]]
    assert "note" not in out


@pytest.mark.asyncio
async def test_saved_object_detail_follows_a_visualization_to_its_saved_search():
    """150 of 200 visualizations sampled on this Malcolm carry an empty query of
    their own and inherit one from a saved search named only as "search_0"."""
    vis = {
        "id": "bcfa8900-06ac-11ec-8c6b-353266ade330",
        "type": "visualization",
        "attributes": {
            "title": "Severity Tags",
            "visState": '{"title":"Severity Tags","type":"table","aggs":[]}',
            "savedSearchRefName": "search_0",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": '{"query":{"query":"","language":"kuery"},"filter":[]}'
            },
        },
        "references": [
            {"name": "search_0", "type": "search", "id": "abd55c60-06a5-11ec-8c6b-353266ade330"}
        ],
    }

    def handler(req):
        return httpx.Response(200, json=vis)

    out = json.loads(
        tool_text(
            await _tools(handler).call_tool(
                "malcolm_saved_object_detail",
                {
                    "object_id": "bcfa8900-06ac-11ec-8c6b-353266ade330",
                    "object_type": "visualization",
                },
            )
        )
    )

    assert out["based_on_search"] == "abd55c60-06a5-11ec-8c6b-353266ade330"
    # An empty query must not read as "matches everything".
    assert "query" not in out
    assert "abd55c60-06a5-11ec-8c6b-353266ade330" in out["note"]
    # The aggregation blob is the bulk of a visualization and is left out.
    assert "visState" not in json.dumps(out)


@pytest.mark.asyncio
async def test_saved_object_detail_answers_for_an_object_that_carries_no_query():
    """The empty path: an object with no searchSourceJSON at all. It must still
    answer with what it does have, and must not raise."""
    index_pattern = {
        "id": "arkime_sessions3-*",
        "type": "index-pattern",
        "attributes": {"title": "arkime_sessions3-*", "fields": "[...400 KB of field JSON...]"},
        "references": [],
    }

    def handler(req):
        return httpx.Response(200, json=index_pattern)

    out = json.loads(
        tool_text(
            await _tools(handler).call_tool(
                "malcolm_saved_object_detail",
                {"object_id": "arkime_sessions3-*", "object_type": "index-pattern"},
            )
        )
    )

    assert out["title"] == "arkime_sessions3-*"
    # The note is type-aware: an index pattern is what a query points AT, so
    # "no query" here does not mean "selects everything" as it would elsewhere.
    assert "holds no query" in out["note"]
    # The field list is hundreds of KB (949,909 bytes measured live) and is
    # never part of the answer.
    assert "fields" not in out


@pytest.mark.asyncio
async def test_saved_object_detail_rejects_an_unknown_type():
    def handler(req):
        raise AssertionError("no request may leave for an unsupported object type")

    raised = await raised_by(
        _tools(handler),
        "malcolm_saved_object_detail",
        {"object_id": "abc", "object_type": "widget"},
    )

    assert isinstance(raised, ToolInputError)
    assert "widget" in str(raised)


# -- failure handling ---------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("malcolm_saved_objects", {"object_type": "dashboard"}),
        ("malcolm_alerting_monitors", {}),
        ("malcolm_anomaly_detectors", {}),
        ("malcolm_alerting_alerts", {}),
        ("malcolm_alerting_monitor_detail", {"monitor_id": "NYUZsZ8Bao8axaN3ef1f"}),
        (
            "malcolm_anomaly_results",
            {"detector_id": "d1", "start_time_ms": _START_MS, "end_time_ms": _END_MS},
        ),
        ("malcolm_saved_object_detail", {"object_id": "abc"}),
    ],
)
async def test_every_dashboard_tool_reports_a_transport_failure(tool, args):
    """A transport failure raises, so the caller sees isError rather than a
    sentence it might read as an answer."""

    def handler(req):
        raise httpx.ConnectError("connection refused")

    raised = await raised_by(_tools(handler), tool, args)

    assert isinstance(raised, UpstreamError)
    assert raised.status is None
    assert "connection refused" in str(raised)


# -- shape tolerance ----------------------------------------------------


@pytest.mark.asyncio
async def test_alerting_monitor_survives_a_shape_it_does_not_recognise():
    """A cron-scheduled monitor has no `period`, and a bucket-level monitor
    wraps its trigger under a different key. Neither may take the tool down or
    invent a schedule that is not there."""
    odd = {
        "_id": "x",
        "_source": {
            "name": "Cron monitor",
            "monitor_type": "bucket_level_monitor",
            "enabled": True,
            "schedule": {"cron": {"expression": "0 */2 * * *", "timezone": "UTC"}},
            "inputs": ["not-a-dict"],
            "triggers": ["not-a-dict", {"bucket_level_trigger": {"name": "Bucket trigger"}}],
        },
    }
    out = json.loads(
        tool_text(
            await _tools(_alerting_handler([odd], [])).call_tool("malcolm_alerting_monitors", {})
        )
    )
    row = out["monitors"][0]

    assert row["name"] == "Cron monitor"
    # A cron schedule is rendered, not dropped: dropping it showed a monitor
    # with no schedule at all while the docstring promised one.
    assert row["schedule"] == "cron 0 */2 * * * (UTC)"
    assert row["triggers"] == ["Bucket trigger"]
    assert "indices" not in row


@pytest.mark.asyncio
async def test_alerting_monitor_skips_a_non_search_input():
    """OpenSearch also has document-level and remote-monitor inputs; one of
    those must not cost the caller the whole monitor list."""
    doc_level = {
        "_id": "y",
        "_source": {
            "name": "Doc level monitor",
            "enabled": True,
            "inputs": [{"doc_level_input": {"description": "no indices here"}}],
            "triggers": [],
        },
    }
    out = json.loads(
        tool_text(
            await _tools(_alerting_handler([doc_level], [])).call_tool(
                "malcolm_alerting_monitors", {}
            )
        )
    )

    assert out["monitors"][0]["name"] == "Doc level monitor"
    assert "indices" not in out["monitors"][0]


@pytest.mark.asyncio
async def test_saved_objects_passes_the_page_size_through():
    """The row bound has to reach the request; hardcoding it server-side is
    invisible to any test that only looks at the response."""
    seen = {}

    def handler(req):
        seen["per_page"] = req.url.params.get("per_page")
        return httpx.Response(200, json={"total": 111, "saved_objects": [_DASHBOARD]})

    await _tools(handler).call_tool(
        "malcolm_saved_objects", {"object_type": "dashboard", "limit": 75}
    )

    assert seen["per_page"] == "75"


@pytest.mark.asyncio
async def test_saved_objects_rejects_an_empty_type():
    """An empty object_type would otherwise reach the server with no type at
    all, which returns every saved object there is."""

    def handler(req):
        raise AssertionError("no request may leave without a type")

    raised = await raised_by(_tools(handler), "malcolm_saved_objects", {"object_type": " , "})

    assert isinstance(raised, ToolInputError)
    assert "(empty)" in str(raised)


@pytest.mark.asyncio
async def test_alerting_monitors_does_not_claim_all_disabled_when_one_is_on():
    """The note must say "every monitor", not "some monitor" — a mixed set has
    working coverage and telling the agent otherwise inverts the conclusion."""
    enabled = {
        "_id": "on",
        "_source": {"name": "Live monitor", "enabled": True, "inputs": [], "triggers": []},
    }
    out = json.loads(
        tool_text(
            await _tools(_alerting_handler([_MONITOR, enabled], [])).call_tool(
                "malcolm_alerting_monitors", {}
            )
        )
    )

    assert out["total"] == 2
    assert out["showing"] == 2
    assert "note" not in out


@pytest.mark.asyncio
async def test_alerting_monitor_with_an_unrecognised_schedule_kind_omits_it():
    """OpenSearch could grow a third schedule shape; guessing at one is worse
    than saying nothing, but it must not take the monitor down either."""
    odd = {
        "_id": "z",
        "_source": {
            "name": "Odd schedule",
            "enabled": True,
            "schedule": {"something_new": {"every": "fortnight"}},
            "inputs": [],
            "triggers": [],
        },
    }
    out = json.loads(
        tool_text(
            await _tools(_alerting_handler([odd], [])).call_tool("malcolm_alerting_monitors", {})
        )
    )

    assert out["monitors"][0]["name"] == "Odd schedule"
    assert "schedule" not in out["monitors"][0]


@pytest.mark.asyncio
async def test_alerting_monitors_reports_the_server_total_not_the_page():
    """size caps the page; hits.total is what says how many exist. Without it a
    truncated page reads as the complete set of standing detections."""
    handler = _alerting_handler([_MONITOR], [])

    def truncated(req):
        if req.url.path.endswith("/monitors/alerts"):
            return handler(req)
        return httpx.Response(200, json={"hits": {"total": {"value": 120}, "hits": [_MONITOR]}})

    out = json.loads(tool_text(await _tools(truncated).call_tool("malcolm_alerting_monitors", {})))

    assert out["total"] == 120
    assert out["showing"] == 1
    # The all-disabled note must not speak for the 119 monitors it never saw.
    assert "on this page" in out["note"]
    assert "raise limit" in out["note"]


@pytest.mark.asyncio
async def test_anomaly_detectors_reports_the_server_total_not_the_page():
    def handler(req):
        if req.url.path.endswith("/detectors/results/_search"):
            return httpx.Response(200, json={"hits": {"total": {"value": 0}}})
        return httpx.Response(200, json={"hits": {"total": {"value": 40}, "hits": [_DETECTOR]}})

    out = json.loads(tool_text(await _tools(handler).call_tool("malcolm_anomaly_detectors", {})))

    assert out["total"] == 40
    assert out["showing"] == 1


@pytest.mark.asyncio
async def test_anomaly_count_asks_only_for_anomalous_results():
    """The results index holds one document per detection interval per entity
    whether or not anything was anomalous, so match_all counts detector runs.
    Malcolm's four MULTI_ENTITY detectors at 10-minute intervals reach five
    figures within a day of being started."""
    seen = {}

    def handler(req):
        if req.url.path.endswith("/detectors/results/_search"):
            seen["body"] = json.loads(req.content)
            return httpx.Response(200, json={"hits": {"total": {"value": 3}}})
        return httpx.Response(200, json={"hits": {"total": {"value": 1}, "hits": [_DETECTOR]}})

    await _tools(handler).call_tool("malcolm_anomaly_detectors", {})

    assert seen["body"]["query"] == {"range": {"anomaly_grade": {"gt": 0}}}
    # Without this OpenSearch stops counting at 10,000 and reports a lower bound.
    assert seen["body"]["track_total_hits"] is True


@pytest.mark.asyncio
async def test_alert_count_asks_only_for_active_alerts():
    """The Get Alerts API defaults to alertState=ALL, which counts COMPLETED and
    ACKNOWLEDGED history as though it were firing now."""
    seen = {}

    def handler(req):
        if req.url.path.endswith("/monitors/alerts"):
            seen["state"] = req.url.params.get("alertState")
            return httpx.Response(200, json={"alerts": [], "totalAlerts": 0})
        return httpx.Response(200, json={"hits": {"total": {"value": 1}, "hits": [_MONITOR]}})

    await _tools(handler).call_tool("malcolm_alerting_monitors", {})

    assert seen["state"] == "ACTIVE"
