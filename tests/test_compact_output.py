"""Search results sized for a tool-result budget, and page sizes marked as such.

Measured on Malcolm's training instance with the indented output: 20 alerts ran
to 77,963 characters (about 22,000 tokens), and a 50-document malcolm_search on
Modbus alerts to 252,422, which Claude Code refused while recording the demo.
/mapi/document returns no total, so the only honest marker for a cut list is
that it reached the limit.
"""

from __future__ import annotations

import json

import httpx
from mcp.client import Client
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.tools.arkime_inventory import register_arkime_inventory_tools
from mcp_server_malcolm.tools.files import register_file_tools
from mcp_server_malcolm.tools.query import register_query_tools

# One alert as /mapi/document returns it on the training instance, trimmed of
# bookkeeping the row drops anyway.
_ALERT = {
    "_id": "210301-Oi8r9m76JB_uG6f3KMJlcg",
    "_index": "arkime_sessions3-210301",
    "_source": {
        "@timestamp": "2021-03-01T07:00:00.017Z",
        "rule": {
            "category": ["A Network Trojan was detected"],
            "id": 3317444,
            "name": "Outgoing connection to an IP address seen in Conti Ransomware Leak",
        },
        "event": {"dataset": "alert", "severity": 91, "hash": "Oi8r9m76JB_uG6f3KMJlcg"},
        "suricata": {
            "alert": {"action": "allowed", "rev": 1, "severity": 1},
            "flow_id": 76459003373123,
            "pcap_filename": "HTTP_1.pcap",
        },
        "source": {"ip": "192.0.2.10", "port": 49710},
        "destination": {"ip": "198.51.100.5", "port": 443},
        "network": {
            "community_id": "1:xYk6J9nJ27HbINUkeGdFulk/BRI=",
            "transport": "tcp",
            "protocol": ["tls"],
        },
        "srcOui": ["VMware, Inc."],
    },
}


def _client(responder) -> MalcolmClient:
    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example", transport=httpx.MockTransport(responder)
    )
    return c


def _documents(results):
    return _client(lambda r: httpx.Response(200, json={"results": results}))


async def _call(register, client, tool, args) -> tuple[bool, str, object]:
    mcp = MCPServer("t")
    register(mcp, client)
    async with Client(mcp) as session:
        result = await session.call_tool(tool, args)
    text = "".join(getattr(c, "text", "") for c in result.content)
    # Union-returning tools nest their structured content under "result".
    return result.is_error, text, (result.structured_content or {}).get("result")


def _json_tail(text: str) -> object:
    return json.loads(text[text.index("{") :])


# -- malcolm_alerts ------------------------------------------------------------


async def test_alerts_return_one_compact_row_per_alert():
    _, text, _ = await _call(register_query_tools, _documents([_ALERT]), "malcolm_alerts", {})
    assert json.loads(text) == {
        "showing": 1,
        "alerts": [
            {
                "id": "210301-Oi8r9m76JB_uG6f3KMJlcg",
                "timestamp": "2021-03-01T07:00:00.017Z",
                "rule_name": "Outgoing connection to an IP address seen in Conti Ransomware Leak",
                "rule_id": 3317444,
                "category": "A Network Trojan was detected",
                "severity": 1,
                "action": "allowed",
                "source_ip": "192.0.2.10",
                "source_port": 49710,
                "destination_ip": "198.51.100.5",
                "destination_port": 443,
                "transport": "tcp",
                "protocol": "tls",
                "community_id": "1:xYk6J9nJ27HbINUkeGdFulk/BRI=",
            }
        ],
    }


async def test_alerts_full_returns_the_raw_documents_unindented():
    _, text, _ = await _call(
        register_query_tools, _documents([_ALERT]), "malcolm_alerts", {"full": True}
    )
    assert json.loads(text)["results"][0]["_source"]["srcOui"] == ["VMware, Inc."]
    assert "\n" not in text


async def test_alerts_say_when_the_list_reached_the_limit():
    _, text, _ = await _call(
        register_query_tools, _documents([_ALERT, _ALERT]), "malcolm_alerts", {"limit": 2}
    )
    assert text.startswith("Note:")
    assert _json_tail(text)["showing"] == 2


# -- malcolm_search ------------------------------------------------------------


async def test_search_output_is_not_indented():
    _, text, _ = await _call(
        register_query_tools, _documents([_ALERT]), "malcolm_search", {"limit": 5}
    )
    assert "\n" not in text
    assert json.loads(text)["results"][0]["_id"] == _ALERT["_id"]


async def test_search_says_when_the_list_reached_the_limit():
    _, text, _ = await _call(
        register_query_tools, _documents([_ALERT, _ALERT]), "malcolm_search", {"limit": 2}
    )
    assert text.startswith("Note:")
    assert len(_json_tail(text)["results"]) == 2


async def test_search_adds_no_note_below_the_limit():
    _, text, _ = await _call(
        register_query_tools, _documents([_ALERT]), "malcolm_search", {"limit": 2}
    )
    assert not text.startswith("Note:")


# -- malcolm_file_scans --------------------------------------------------------

_FILE = {"_source": {"event": {"dataset": "files"}, "file": {"name": ["a.exe"]}}}


async def test_file_scans_mark_a_page_that_reached_the_limit():
    _, _, data = await _call(
        register_file_tools, _documents([_FILE, _FILE]), "malcolm_file_scans", {"limit": 2}
    )
    assert data["count"] == 2
    assert data["limit_reached"] is True


async def test_file_scans_below_the_limit_carry_no_marker():
    _, _, data = await _call(
        register_file_tools, _documents([_FILE]), "malcolm_file_scans", {"limit": 2}
    )
    assert "limit_reached" not in data


# -- arkime_views / arkime_shortcuts -------------------------------------------


async def test_views_report_arkimes_total_beside_the_page():
    # Measured on the training instance: /api/views answers recordsTotal.
    body = {"data": [{"name": "v1", "expression": "ip==10.0.0.1"}], "recordsTotal": 9}
    _, _, data = await _call(
        register_arkime_inventory_tools,
        _client(lambda r: httpx.Response(200, json=body)),
        "arkime_views",
        {"limit": 1},
    )
    assert (data["count"], data["total"]) == (1, 9)


async def test_shortcuts_report_arkimes_total_beside_the_page():
    body = {"data": [{"name": "bad", "type": "ip", "value": "10.0.0.1"}], "recordsTotal": 4}
    _, _, data = await _call(
        register_arkime_inventory_tools,
        _client(lambda r: httpx.Response(200, json=body)),
        "arkime_shortcuts",
        {"limit": 1},
    )
    assert (data["count"], data["total"]) == (1, 4)


async def test_the_limit_note_does_not_suggest_raising_a_limit_already_at_500():
    _, text, _ = await _call(
        register_query_tools, _documents([_ALERT] * 500), "malcolm_search", {"limit": 500}
    )
    assert text.startswith("Note:")
    assert "Raise limit" not in text.splitlines()[0]
