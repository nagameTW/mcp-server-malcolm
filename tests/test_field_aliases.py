"""Tests for the ingest-rename corrections and the Arkime field vocabulary.

Covers the three fixes that came out of auditing Malcolm's logstash pipelines:
- fields Malcolm renames on ingest resolve to their real name, not to a
  string-similar sibling
- a query that comes back empty says WHY when a filter names a dead field
- Arkime expression names are discoverable (they are absent from /mapi/fields)
"""

import json

import httpx
import pytest
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.field_aliases import alias_for
from mcp_server_malcolm.tools.arkime import register_arkime_tools
from mcp_server_malcolm.tools.correlation import register_correlation_tools
from mcp_server_malcolm.tools.query import register_query_tools

# A field list shaped like Malcolm's: the ECS targets exist, the pre-rename
# names do not, and each renamed field has plausible siblings that difflib
# would otherwise return instead of the truth.
_FIELDS = {
    "rule.name": "string",
    "rule.id": "integer",
    "rule.category": "string",
    "suricata.alert.rev": "integer",
    "suricata.alert.severity": "integer",
    "suricata.alert.metadata.signature_severity": "string",
    "source.ip": "ip",
    "destination.ip": "ip",
    "network.transport": "string",
    "zeek.uid": "string",
    "rootId": "string",
    "event.dataset": "string",
    "http.useragent": "string",
}


def _mock_client(handler):
    client = MalcolmClient(base_url="https://malcolm.example")
    client._http = httpx.AsyncClient(
        base_url="https://malcolm.example",
        transport=httpx.MockTransport(handler),
    )
    return client


def _fields_handler(extra=None):
    """Serve the field list, delegating anything else to `extra`."""

    def handler(req):
        if req.url.path == "/mapi/fields":
            return httpx.Response(
                200, json={"fields": {k: {"type": v} for k, v in _FIELDS.items()}}
            )
        return extra(req) if extra else httpx.Response(200, json={})

    return handler


# -- alias_for --------------------------------------------------------------


def test_suricata_alert_signature_maps_to_ecs_rule_name():
    assert alias_for("suricata.alert.signature") == "rule.name"


def test_zeek_hoisted_column_maps_for_any_log_type():
    # The hoist is applied to every Zeek log type, so the rule must not be
    # keyed on the log name in the middle.
    assert alias_for("zeek.dns.orig_h") == "source.ip"
    assert alias_for("zeek.smb_files.resp_p") == "destination.port"
    assert alias_for("id.orig_h") == "source.ip"


def test_field_that_hoists_to_itself_is_not_reported_as_renamed():
    assert alias_for("zeek.ts") is None
    assert alias_for("zeek.uid") is None


def test_unknown_field_has_no_alias():
    assert alias_for("something.invented") is None


# -- resolve_field ----------------------------------------------------------


@pytest.mark.asyncio
async def test_rename_wins_over_string_similarity():
    # difflib would answer suricata.alert.rev / .severity here — all real
    # fields, all wrong. The pipeline rename is authoritative.
    client = _mock_client(_fields_handler())
    resolution = await client.resolve_field("suricata.alert.signature")

    assert resolution["exists"] is False
    assert resolution["suggestion"] == "rule.name"
    assert resolution["type"] == "string"
    assert "renamed" in resolution["reason"]


@pytest.mark.asyncio
async def test_existing_field_still_resolves_directly():
    client = _mock_client(_fields_handler())
    assert await client.resolve_field("rule.name") == {
        "exists": True,
        "field": "rule.name",
        "type": "string",
    }


# -- explain_unknown_fields -------------------------------------------------


@pytest.mark.asyncio
async def test_no_explanation_when_every_field_exists():
    client = _mock_client(_fields_handler())
    assert await client.explain_unknown_fields(["source.ip", "!rule.name"]) == ""


@pytest.mark.asyncio
async def test_explanation_names_the_real_field():
    client = _mock_client(_fields_handler())
    hint = await client.explain_unknown_fields(["suricata.alert.signature"])

    assert "suricata.alert.signature is not indexed" in hint
    assert "rule.name" in hint


@pytest.mark.asyncio
async def test_diagnostic_failure_never_breaks_the_caller():
    def handler(req):
        raise httpx.ConnectError("field list unreachable")

    client = _mock_client(handler)
    assert await client.explain_unknown_fields(["whatever"]) == ""


# -- empty-result hint in the query tools -----------------------------------


@pytest.mark.asyncio
async def test_empty_search_explains_a_renamed_filter_field():
    mcp = MCPServer("t")
    register_query_tools(
        mcp, _mock_client(_fields_handler(lambda req: httpx.Response(200, json={"results": []})))
    )

    result = await mcp.call_tool(
        "malcolm_search", {"filters": json.dumps({"suricata.alert.signature": "*ET*"})}
    )

    assert "rule.name" in str(result)


@pytest.mark.asyncio
async def test_non_empty_search_adds_no_hint():
    def extra(req):
        return httpx.Response(200, json={"results": [{"_id": "1"}]})

    mcp = MCPServer("t")
    register_query_tools(mcp, _mock_client(_fields_handler(extra)))

    result = await mcp.call_tool(
        "malcolm_search", {"filters": json.dumps({"suricata.alert.signature": "*ET*"})}
    )

    assert "not indexed" not in str(result)


# -- confirmed field-name bugs ----------------------------------------------


_SIGNATURES = [
    "ET MALWARE Win32/Agent CnC",
    "ET MALWARE Observed DNS Query",
    "SURICATA TCPv4 invalid checksum",
]


def _alert_handler(seen, signatures=None, results=None):
    """Serve fields, the rule.name buckets, and the document search."""

    def extra(req):
        if req.url.path.startswith("/mapi/agg/"):
            buckets = _SIGNATURES if signatures is None else signatures
            return httpx.Response(
                200, json={"values": [{"key": s, "doc_count": 1} for s in buckets]}
            )
        if req.url.path == "/mapi/document":
            seen["body"] = req.content.decode()
            return httpx.Response(200, json={"results": results if results else [{"_id": "1"}]})
        return httpx.Response(200, json={})

    return _fields_handler(extra)


@pytest.mark.asyncio
async def test_alerts_signature_resolves_substring_to_exact_rule_names():
    # Two things at once: suricata.alert.signature is renamed to rule.name, and
    # Malcolm's filter is a terms query — a "*ET MALWARE*" value would match a
    # signature literally spelled that way, i.e. nothing.
    seen = {}
    mcp = MCPServer("t")
    register_query_tools(mcp, _mock_client(_alert_handler(seen)))
    await mcp.call_tool("malcolm_alerts", {"signature": "et malware"})

    body = json.loads(seen["body"])
    assert body["filter"]["rule.name"] == _SIGNATURES[:2]  # case-insensitive match
    assert "suricata.alert.signature" not in seen["body"]
    assert "*" not in seen["body"]


@pytest.mark.asyncio
async def test_alerts_says_so_when_no_signature_contains_the_substring():
    # "no signature by that name" must not look like "no alerts fired".
    seen = {}
    mcp = MCPServer("t")
    register_query_tools(mcp, _mock_client(_alert_handler(seen)))

    result = str(await mcp.call_tool("malcolm_alerts", {"signature": "log4shell"}))

    assert "No alert signature contains" in result
    assert "malcolm_field_values" in result
    assert "body" not in seen  # never ran a search that could not match


@pytest.mark.asyncio
async def test_related_sessions_pivots_on_root_id():
    # There is no related.zeek.uid field in Malcolm; rootId is the cross-log link.
    bodies = []

    def extra(req):
        if req.url.path == "/mapi/document":
            bodies.append(req.content.decode())
        return httpx.Response(200, json={"results": []})

    mcp = MCPServer("t")
    register_correlation_tools(mcp, _mock_client(_fields_handler(extra)))
    await mcp.call_tool("malcolm_related_sessions", {"uid": "CYeji2z7CKmPRGyga"})

    assert any('"rootId"' in body for body in bodies)
    assert not any("related.zeek.uid" in body for body in bodies)


# -- Arkime expression vocabulary -------------------------------------------

_ARKIME_FIELDS = [
    {"exp": "ip.src", "dbField2": "source.ip", "type": "ip", "group": "general", "help": "Src IP"},
    {"exp": "port.dst", "dbField2": "destination.port", "type": "integer", "group": "general"},
    {"exp": "http.user", "dbField2": "http.user", "type": "lotermfield", "group": "http"},
]


def _arkime_handler(payload):
    def handler(req):
        if req.url.path == "/arkime/api/fields":
            return httpx.Response(200, json=payload)
        return httpx.Response(200, json={})

    return handler


@pytest.mark.asyncio
async def test_arkime_field_search_surfaces_expression_and_db_names():
    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock_client(_arkime_handler(_ARKIME_FIELDS)))

    result = str(await mcp.call_tool("arkime_field_search", {"keyword": "src"}))

    # Both names matter: exp goes in an expression, db in arkime_connections.
    assert "ip.src" in result
    assert "source.ip" in result
    assert "port.dst" not in result


@pytest.mark.asyncio
async def test_arkime_field_search_filters_by_group():
    mcp = MCPServer("t")
    register_arkime_tools(mcp, _mock_client(_arkime_handler(_ARKIME_FIELDS)))

    result = str(await mcp.call_tool("arkime_field_search", {"group": "http"}))

    assert "http.user" in result
    assert "ip.src" not in result


@pytest.mark.asyncio
async def test_arkime_fields_accepts_the_map_response_shape():
    # Older Arkime viewers answer with a map keyed by expression name.
    payload = {field["exp"]: field for field in _ARKIME_FIELDS}
    client = _mock_client(_arkime_handler(payload))

    fields = await client.arkime_fields()

    assert [f["exp"] for f in fields] == ["http.user", "ip.src", "port.dst"]


@pytest.mark.asyncio
async def test_arkime_field_list_is_cached():
    calls = []

    def handler(req):
        calls.append(req.url.path)
        return httpx.Response(200, json=_ARKIME_FIELDS)

    client = _mock_client(handler)
    await client.arkime_fields()
    await client.arkime_fields()

    assert calls.count("/arkime/api/fields") == 1
