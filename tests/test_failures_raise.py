"""Every tool failure raises, so the MCP layer reports isError: true.

A tool that ``return``s "Error: ..." produces a *successful* call result --
isError false -- which the 2026-07-28 tools spec treats as an answer. Worse,
an exception escaping a tool body does set isError true, so before this fix
the flag meant different things in different tools.

These tests pin the three halves of the rule:
  * a bad argument raises ToolInputError,
  * an upstream failure raises UpstreamError,
  * an EMPTY result still comes back as prose, because "nothing matched" is a
    real answer and a client must not retry it.
"""

from __future__ import annotations

import ast
import pathlib

import httpx
import pytest
from conftest import raised_by, tool_text
from mcp.client import Client
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.errors import ToolInputError, UpstreamError
from mcp_server_malcolm.tools import (
    arkime,
    arkime_content,
    arkime_inventory,
    correlation,
    dashboards,
    detections,
    dsl,
    fields,
    files,
    health,
    netbox,
    query,
)
from mcp_server_malcolm.tools.write.alerting import register_alerting_tools
from mcp_server_malcolm.tools.write.arkime_tags import register_arkime_tag_tools
from mcp_server_malcolm.tools.write.arkime_views import register_arkime_view_tools
from mcp_server_malcolm.tools.write.hunt_jobs import register_hunt_job_tools
from mcp_server_malcolm.tools.write.pcap_upload import register_pcap_upload_tools

SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "mcp_server_malcolm" / "tools"


def _client(handler) -> MalcolmClient:
    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example", transport=httpx.MockTransport(handler)
    )
    return c


def _refuse(req):  # pragma: no cover - a validation failure must never get here
    raise AssertionError(f"the argument guard let a request through: {req.url}")


def _unreachable(req):
    raise httpx.ConnectError("connection refused")


def _every_tool(handler, upload_dir: str | None = None) -> MCPServer:
    """One server carrying every tool, read and write, on a mocked transport."""
    mcp = MCPServer("t")
    client = _client(handler)
    for register in (
        dsl.register_dsl_tools,
        query.register_query_tools,
        fields.register_field_tools,
        files.register_file_tools,
        health.register_health_tools,
        netbox.register_netbox_tools,
        correlation.register_correlation_tools,
        arkime.register_arkime_tools,
        arkime_content.register_arkime_content_tools,
        arkime_inventory.register_arkime_inventory_tools,
        dashboards.register_dashboard_tools,
        detections.register_detection_tools,
    ):
        register(mcp, client)
    for register_write in (
        register_alerting_tools,
        register_arkime_tag_tools,
        register_arkime_view_tools,
        register_hunt_job_tools,
    ):
        register_write(mcp, client, None)
    register_pcap_upload_tools(mcp, client, None, upload_dir)
    return mcp


# -- the whole point: isError reaches the client ------------------------------


@pytest.mark.asyncio
async def test_a_bad_argument_reaches_the_client_as_is_error():
    """Round trip through the real client, because the conversion from a raised
    exception to isError happens in the server's request handler, not in
    MCPServer.call_tool -- a unit test alone cannot see it."""
    async with Client(_every_tool(_refuse)) as client:
        result = await client.call_tool("search_dsl", {"index": "../_bulk", "query_dsl": "{}"})
    assert result.is_error is True


@pytest.mark.asyncio
async def test_an_upstream_failure_reaches_the_client_as_is_error():
    async with Client(_every_tool(_unreachable)) as client:
        result = await client.call_tool(
            "search_dsl", {"index": "arkime_sessions3-*", "query_dsl": "{}"}
        )
    assert result.is_error is True


# -- bad arguments ------------------------------------------------------------

_BAD_ARGUMENTS = [
    ("search_dsl", {"index": "../_bulk", "query_dsl": "{}"}),
    ("search_dsl", {"index": "arkime_sessions3-*", "query_dsl": "{not json"}),
    ("count", {"index": "../_bulk"}),
    ("count", {"query_dsl": "{not json"}),
    ("list_indices", {"pattern": "../x"}),
    ("index_mapping", {"index": "../x"}),
    ("malcolm_search", {"filters": "{not json}"}),
    ("malcolm_search", {"filters": "{'event.dataset': 'conn'}"}),
    ("malcolm_search", {"filters": "[1,2]"}),
    ("malcolm_aggregate", {"fields": "source.ip", "filters": "{not json}"}),
    ("malcolm_alerts", {"severity": "high"}),
    ("malcolm_alerts", {"sid": "ET-2019401"}),
    ("malcolm_field_values", {"field": "event.dataset", "filters": "{not json}"}),
    ("malcolm_field_values", {"field": "event.dataset", "filters": "[1,2]"}),
    ("malcolm_file_scans", {"filters": "{not json}"}),
    ("malcolm_file_scans", {"filters": "[1,2]"}),
    ("malcolm_extract_file", {"filename": ""}),
    ("malcolm_extract_file", {"filename": "sub/dir/a.exe"}),
    ("malcolm_extract_file", {"filename": ".."}),
    ("malcolm_dashboard_export", {"dashboard_id": "  "}),
    ("malcolm_related_sessions", {"uid": " "}),
    ("malcolm_netbox_lookup", {}),
    ("malcolm_netbox_query", {"path": ""}),
    ("malcolm_netbox_query", {"path": "../admin"}),
    ("malcolm_netbox_query", {"path": "ipam/services/", "params": "{not json}"}),
    ("malcolm_netbox_query", {"path": "ipam/services/", "params": "[1,2]"}),
    ("malcolm_saved_objects", {"object_type": "config"}),
    ("malcolm_saved_objects", {"object_type": " "}),
    ("arkime_sessions", {"expression": "  "}),
    ("arkime_session_pcap", {"session_id": ""}),
    ("arkime_session_pcap", {"session_id": "3@240425/../x"}),
    ("arkime_session_detail", {"session_id": ""}),
    ("arkime_session_detail", {"session_id": "id with spaces"}),
    ("arkime_unique", {"field": " "}),
    ("arkime_spigraph", {"field": " "}),
    ("arkime_spiview", {"spi": " "}),
    ("arkime_multiunique", {"fields": " "}),
    ("arkime_spigraphhierarchy", {"fields": " "}),
    ("arkime_file_by_hash", {"file_hash": ""}),
    ("arkime_file_by_hash", {"file_hash": "not-a-hash"}),
    ("arkime_reverse_dns", {"ip": ""}),
    ("arkime_reverse_dns", {"ip": "malcolm.example"}),
    ("malcolm_create_alert", {"title": " ", "severity": 1}),
    ("malcolm_create_alert", {"title": "x", "severity": 9}),
    ("arkime_add_tags", {"session_ids": " ", "tags": "x"}),
    ("arkime_add_tags", {"session_ids": "id1", "tags": " "}),
    ("arkime_create_view", {"name": " ", "expression": "ip==192.0.2.7"}),
    ("arkime_create_view", {"name": "v", "expression": " "}),
    ("arkime_create_shortcut", {"name": " ", "value": "1"}),
    ("arkime_create_shortcut", {"name": "s", "value": " "}),
    ("arkime_create_shortcut", {"name": "s", "value": "1", "shortcut_type": "cidr"}),
]

_HUNT = {
    "name": "h",
    "search": "evil",
    "search_type": "ascii",
    "total_sessions": 10,
    "start_time": 1,
    "stop_time": 2,
    "expression": "ip==192.0.2.7",
}
_BAD_ARGUMENTS += [
    ("arkime_create_hunt", {**_HUNT, "name": " "}),
    ("arkime_create_hunt", {**_HUNT, "search": " "}),
    ("arkime_create_hunt", {**_HUNT, "search_type": "morse"}),
    ("arkime_create_hunt", {**_HUNT, "packet_type": "both"}),
    ("arkime_create_hunt", {**_HUNT, "src": False, "dst": False}),
    ("arkime_create_hunt", {**_HUNT, "total_sessions": 0}),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("tool", "args"), _BAD_ARGUMENTS)
async def test_a_bad_argument_raises_tool_input_error(tool, args):
    """And it raises before any request goes out -- the handler asserts on that."""
    raised = await raised_by(_every_tool(_refuse), tool, args)
    assert isinstance(raised, ToolInputError), f"{tool} raised {type(raised).__name__}: {raised}"


@pytest.mark.asyncio
async def test_upload_argument_failures_raise(tmp_path):
    staging = tmp_path / "staging"
    staging.mkdir()
    (tmp_path / "secret.key").write_bytes(b"TOPSECRET")
    big = staging / "big.pcap"
    big.write_bytes(b"\x00" * (2 * 1024 * 1024))

    mcp = _every_tool(_refuse, upload_dir=str(staging))
    for args in (
        {"file_path": ""},
        {"file_path": str(staging / "nope.pcap")},
        {"file_path": str(staging / ".." / "secret.key")},
        {"file_path": str(big), "max_mb": 1},
    ):
        raised = await raised_by(mcp, "malcolm_upload_pcap", args)
        assert isinstance(raised, ToolInputError), f"{args} raised {type(raised).__name__}"


@pytest.mark.asyncio
async def test_upload_is_refused_without_a_staging_directory(tmp_path):
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\xa1\xb2\xc3\xd4")
    mcp = _every_tool(_refuse, upload_dir=None)
    raised = await raised_by(mcp, "malcolm_upload_pcap", {"file_path": str(pcap)})
    assert isinstance(raised, ToolInputError)
    assert "MALCOLM_MCP_UPLOAD_DIR" in str(raised)


# -- upstream failures --------------------------------------------------------

_UPSTREAM = [
    ("search_dsl", {"index": "arkime_sessions3-*", "query_dsl": "{}"}),
    ("count", {}),
    ("list_indices", {}),
    ("index_mapping", {"index": "arkime_sessions3-*"}),
    ("cluster_health", {}),
    ("malcolm_search", {}),
    ("malcolm_aggregate", {"fields": "source.ip"}),
    ("malcolm_alerts", {}),
    ("malcolm_field_search", {"keyword": "ip"}),
    ("malcolm_field_values", {"field": "event.dataset"}),
    ("malcolm_field_profile", {"field": "event.dataset"}),
    ("malcolm_file_scans", {}),
    ("malcolm_extract_file", {"filename": "a.exe"}),
    ("malcolm_ping", {}),
    ("malcolm_dashboard_export", {"dashboard_id": "abc"}),
    ("malcolm_service_status", {}),
    ("malcolm_data_coverage", {}),
    ("malcolm_related_sessions", {"uid": "CYeji2z7CKmPRGyga"}),
    ("malcolm_netbox_lookup", {"ip": "192.0.2.7"}),
    ("malcolm_netbox_sites", {}),
    ("malcolm_netbox_query", {"path": "ipam/services/"}),
    ("malcolm_saved_objects", {}),
    ("malcolm_alerting_monitors", {}),
    ("malcolm_anomaly_detectors", {}),
    ("arkime_field_search", {"keyword": "ip"}),
    ("arkime_sessions", {"expression": "ip==192.0.2.7"}),
    ("arkime_session_pcap", {"session_id": "3@240425-abc"}),
    ("arkime_session_detail", {"session_id": "3@240425-abc"}),
    ("arkime_unique", {"field": "ip.dst"}),
    ("arkime_spigraph", {"field": "ip.dst"}),
    ("arkime_spiview", {"spi": "protocols:10"}),
    ("arkime_multiunique", {"fields": "source.ip"}),
    ("arkime_spigraphhierarchy", {"fields": "source.ip"}),
    ("arkime_connections", {}),
    ("arkime_sessions_csv", {}),
    ("arkime_file_by_hash", {"file_hash": "a" * 32}),
    ("arkime_views", {}),
    ("arkime_shortcuts", {}),
    ("arkime_reverse_dns", {"ip": "192.0.2.7"}),
    ("arkime_pcap_files", {}),
    ("arkime_node_stats", {}),
    ("arkime_hunt_status", {}),
    ("malcolm_create_alert", {"title": "x", "severity": 1}),
    ("arkime_add_tags", {"session_ids": "id1", "tags": "t"}),
    ("arkime_create_view", {"name": "v", "expression": "ip==192.0.2.7"}),
    ("arkime_create_shortcut", {"name": "s", "value": "1"}),
    ("arkime_create_hunt", dict(_HUNT)),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("tool", "args"), _UPSTREAM)
async def test_an_unreachable_malcolm_raises_upstream_error(tool, args):
    raised = await raised_by(_every_tool(_unreachable), tool, args)
    assert isinstance(raised, UpstreamError), f"{tool} raised {type(raised).__name__}: {raised}"
    assert raised.status is None, "no response arrived, so there is no status to report"


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["malcolm_ping", "malcolm_saved_objects", "arkime_views"])
async def test_an_error_status_raises_upstream_error_carrying_the_status(tool):
    def handler(req):
        return httpx.Response(503, text="service unavailable")

    raised = await raised_by(_every_tool(handler), tool, {})
    assert isinstance(raised, UpstreamError)
    assert raised.status == 503


@pytest.mark.asyncio
async def test_upload_reports_a_rejected_status_as_upstream_error(tmp_path):
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\xa1\xb2\xc3\xd4")

    def handler(req):
        return httpx.Response(403, text="forbidden")

    mcp = _every_tool(handler, upload_dir=str(tmp_path))
    raised = await raised_by(mcp, "malcolm_upload_pcap", {"file_path": str(pcap)})
    assert isinstance(raised, UpstreamError)
    assert raised.status == 403


# -- an empty result is an answer, not a failure ------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "args", "body", "expected"),
    [
        ("arkime_views", {}, {"data": []}, "no saved views"),
        ("arkime_shortcuts", {}, {"data": []}, "no shortcuts"),
        ("arkime_pcap_files", {}, {"data": []}, "no indexed pcap"),
        ("arkime_node_stats", {}, {"data": []}, "no arkime nodes"),
        ("malcolm_saved_objects", {}, {"saved_objects": []}, "no saved objects"),
        ("malcolm_alerting_monitors", {}, {"hits": {"hits": []}}, "no alerting monitors"),
        ("malcolm_anomaly_detectors", {}, {"hits": {"hits": []}}, "no anomaly detectors"),
        ("malcolm_file_scans", {}, {"results": []}, "no extracted-file records"),
    ],
)
async def test_an_empty_result_is_still_a_successful_answer(tool, args, body, expected):
    def handler(req):
        return httpx.Response(200, json=body)

    out = tool_text(await _every_tool(handler).call_tool(tool, args))
    assert expected in out.lower()


@pytest.mark.asyncio
async def test_a_pruned_extracted_file_is_a_finding_not_a_failure():
    """404 from /extracted-files/ means the index record outlived the file --
    a real answer. Only some other status is a fault."""

    def handler(req):
        return httpx.Response(404, text="not found")

    result = await _every_tool(handler).call_tool("malcolm_extract_file", {"filename": "a.exe"})
    assert result.is_error is False
    text = tool_text(result).lower()
    assert '"found": false' in text and "prune" in text


@pytest.mark.asyncio
async def test_a_non_404_from_the_extracted_files_server_raises_with_its_status():
    def handler(req):
        return httpx.Response(403, text="forbidden")

    raised = await raised_by(_every_tool(handler), "malcolm_extract_file", {"filename": "a.exe"})
    assert isinstance(raised, UpstreamError)
    assert raised.status == 403
    assert "prune" not in str(raised).lower()


@pytest.mark.asyncio
async def test_no_match_for_a_body_hash_is_an_answer():
    """Arkime answers 400 "No Match Found" when no session carried the hash."""

    def handler(req):
        return httpx.Response(400, text="No Match Found")

    result = await _every_tool(handler).call_tool("arkime_file_by_hash", {"file_hash": "a" * 32})
    assert result.is_error is False
    assert "false" in "".join(b.text for b in result.content).lower()


# -- the four silent-discard sites --------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "args", "wanted"),
    [
        # A Python dict literal is the shape a model reaches for first; taking it
        # as "no filter" answers a question nobody asked.
        ("malcolm_search", {"filters": "{'event.dataset': 'conn'}"}, "filters"),
        ("malcolm_aggregate", {"fields": "source.ip", "filters": "{'a': 'b'}"}, "filters"),
        ("malcolm_field_values", {"field": "event.dataset", "filters": "{'a': 'b'}"}, "filters"),
        ("malcolm_alerts", {"severity": "high"}, "severity"),
        ("malcolm_alerts", {"sid": "ET-2019401"}, "sid"),
    ],
)
async def test_a_malformed_argument_is_never_silently_dropped(tool, args, wanted):
    """Dropping it would answer a WIDER question than the one asked, and the
    caller cannot tell that result from the real one."""
    raised = await raised_by(_every_tool(_refuse), tool, args)
    assert isinstance(raised, ToolInputError)
    text = str(raised)
    assert wanted in text
    # Name what arrived and what shape was expected, as tools/files.py does.
    assert any(token in text for token in ("'", '"')), f"message shows neither: {text}"


@pytest.mark.asyncio
async def test_a_partly_numeric_severity_list_still_raises():
    """ "1,high" must not quietly become severity=1: the caller believes both
    levels were included."""
    raised = await raised_by(_every_tool(_refuse), "malcolm_alerts", {"severity": "1,high"})
    assert isinstance(raised, ToolInputError)


# -- the sweep ----------------------------------------------------------------


def _returned_strings(node: ast.AST) -> list[str]:
    """Every literal string reachable from a return value, f-strings included."""
    found: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            found.append(child.value)
    return found


def _prose_failure_returns(path: pathlib.Path) -> list[str]:
    hits: list[str] = []
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Return) or node.value is None:
            continue
        text = " ".join(_returned_strings(node.value)).lower()
        if text.startswith("error:") or "failed" in text:
            hits.append(f"{path.name}:{node.lineno}")
    return hits


def test_no_tool_reports_a_failure_by_returning_prose():
    """The acceptance sweep. An AST walk rather than the two greps that found
    the original 77, so a failure string split across lines cannot hide."""
    offenders = [hit for py in sorted(SRC.rglob("*.py")) for hit in _prose_failure_returns(py)]
    assert not offenders, f"failures still returned as prose: {offenders}"
