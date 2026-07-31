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


def _mock_client(handler):
    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example",
        transport=httpx.MockTransport(handler),
    )
    return c


def _tools(handler):
    mcp = MCPServer("t")
    register_dashboard_tools(mcp, _mock_client(handler))
    return mcp


def test_batch3_tools_registered():
    names = [t.name for t in asyncio.run(create_server().list_tools())]
    for name in (
        "malcolm_saved_objects",
        "malcolm_alerting_monitors",
        "malcolm_anomaly_detectors",
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


# -- failure handling ---------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("malcolm_saved_objects", {"object_type": "dashboard"}),
        ("malcolm_alerting_monitors", {}),
        ("malcolm_anomaly_detectors", {}),
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
