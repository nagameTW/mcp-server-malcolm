"""Parity harness: every MCP tool's answer vs the raw Malcolm API's answer.

Run against a real deployment:

    MALCOLM_URL=https://malcolm.example \
    MALCOLM_USERNAME=... MALCOLM_PASSWORD=... \
    PARITY_TIME_FROM=<epoch> PARITY_TIME_TO=<epoch> \
    uv run --with mcp python scripts/api_parity_check.py

Exits non-zero if any tool disagrees with the API, or if a tool is exposed but
not compared — so a newly added tool fails this until a check is written for it.


For each tool this asks the SAME question twice — once through a real MCP stdio
session against the installed server binary, once with a direct HTTP call to
Malcolm — and compares the facts that carry meaning, not the formatting. The
tools deliberately trim and rename, so a byte diff would be noise; what must
hold is that no fact differs and none is invented.

Each check declares: the tool call, the raw request, and a comparison that
pulls the same values out of both sides.
"""

import asyncio
import hashlib
import json
import os
import pathlib

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

BASE = os.environ.get("MALCOLM_URL", "https://localhost")
USER = os.environ.get("MALCOLM_USERNAME", "admin")
PASSWORD = os.environ.get("MALCOLM_PASSWORD", "admin")
VERIFY = os.environ.get("MALCOLM_SSL_VERIFY", "true").lower() != "false"

# The window the Arkime tools are asked about, as epoch seconds. Arkime's own
# default is a recent window, which finds nothing in an older capture, so this
# has to name the period the deployment actually holds.
T0 = os.environ.get("PARITY_TIME_FROM", "1714003200")
T1 = os.environ.get("PARITY_TIME_TO", "1714089600")

ENV = {
    **os.environ,
    "MALCOLM_URL": BASE,
    "MALCOLM_USERNAME": USER,
    "MALCOLM_PASSWORD": PASSWORD,
    "MALCOLM_SSL_VERIFY": os.environ.get("MALCOLM_SSL_VERIFY", "true"),
}

results: list[tuple[str, bool, str]] = []


def check(tool: str, ok: bool, detail: str) -> None:
    results.append((tool, ok, detail))
    print(f"  {'MATCH   ' if ok else 'MISMATCH'} {tool:26} {detail}")


def jtext(result) -> str:
    return "".join(b.text for b in result.content if getattr(b, "type", None) == "text")


async def main() -> None:
    params = StdioServerParameters(
        command=str(pathlib.Path.cwd() / ".venv" / "bin" / "mcp-server-malcolm"), env=ENV
    )
    async with (
        httpx.AsyncClient(
            base_url=BASE,
            verify=VERIFY,
            auth=httpx.BasicAuth(USER, PASSWORD),
            timeout=120,
            follow_redirects=True,
        ) as api,
        stdio_client(params) as (read, write),
        ClientSession(read, write) as s,
    ):
        await s.initialize()
        names = sorted(t.name for t in (await s.list_tools()).tools)
        print(f"tools exposed: {len(names)}\n")

        async def call(tool, args):
            return jtext(await s.call_tool(tool, args))

        async def jcall(tool, args):
            return json.loads(await call(tool, args))

        # ---- health / cluster -----------------------------------------
        t = await jcall("malcolm_ping", {})
        r = (await api.get("/mapi/ping")).json()
        check("malcolm_ping", t == r, f"tool={t} api={r}")

        t = await jcall("cluster_health", {})
        r = (await api.get("/mapi/opensearch/_cluster/health")).json()
        check(
            "cluster_health",
            t["status"] == r["status"] and t["number_of_nodes"] == r["number_of_nodes"],
            f"status={t['status']} nodes={t['number_of_nodes']}",
        )

        t = await jcall("malcolm_service_status", {})
        r = (await api.get("/mapi/version")).json()
        check(
            "malcolm_service_status",
            t["malcolm_version"] == r.get("version"),
            f"version={t['malcolm_version']}",
        )

        # ---- counting / DSL -------------------------------------------
        t = await jcall("count", {"query": '{"match_all":{}}', "index": "arkime_sessions3-*"})
        r = (
            await api.post(
                "/mapi/opensearch/arkime_sessions3-*/_count", json={"query": {"match_all": {}}}
            )
        ).json()
        check("count", t["count"] == r["count"], f"{t['count']:,} docs both sides")

        # search_dsl's `size` argument always overrides any size inside the
        # body, so the raw call has to be given the same number.
        body = '{"query":{"term":{"event.dataset":"dns"}}}'
        t = await jcall("search_dsl", {"query_dsl": body, "index": "arkime_sessions3-*", "size": 2})
        r = (
            await api.post(
                "/mapi/opensearch/arkime_sessions3-*/_search",
                json={**json.loads(body), "size": 2},
            )
        ).json()
        check(
            "search_dsl",
            t["hits"]["total"] == r["hits"]["total"]
            and [h["_id"] for h in t["hits"]["hits"]] == [h["_id"] for h in r["hits"]["hits"]],
            f"total={t['hits']['total']['value']:,} same ids",
        )

        t = await jcall("list_indices", {"pattern": "arkime_sessions3-*"})
        r = (
            await api.get(
                "/mapi/opensearch/_cat/indices/arkime_sessions3-*",
                params={"format": "json", "h": "index,health,status,docs.count"},
            )
        ).json()
        check(
            "list_indices",
            {i["index"] for i in t} == {i["index"] for i in r},
            f"{len(t)} indices, same names",
        )

        t = await jcall("index_mapping", {"index": "arkime_sessions3-240425"})
        r = (await api.get("/mapi/opensearch/arkime_sessions3-240425/_mapping")).json()
        check("index_mapping", t == r, "mapping identical")

        # ---- Malcolm query layer ---------------------------------------
        t = await jcall("malcolm_search", {"filters": '{"event.dataset":"dns"}', "limit": 3})
        r = (
            await api.post("/mapi/document", json={"limit": 3, "filter": {"event.dataset": "dns"}})
        ).json()
        check(
            "malcolm_search",
            [d["_id"] for d in t["results"]] == [d["_id"] for d in r["results"]],
            f"{len(t['results'])} docs, same ids in order",
        )

        t = await jcall(
            "malcolm_aggregate",
            {"fields": "network.protocol", "time_from": "2024-01-01", "limit": 5},
        )
        r = (
            await api.post("/mapi/agg/network.protocol", json={"limit": 5, "from": "2024-01-01"})
        ).json()
        tb = {b["key"]: b["doc_count"] for b in t["network.protocol"]["buckets"]}
        rb = {b["key"]: b["doc_count"] for b in r["network.protocol"]["buckets"]}
        check("malcolm_aggregate", tb == rb, f"{len(tb)} buckets, counts equal")

        t = await call(
            "malcolm_field_values",
            {"field": "event.dataset", "limit": 5, "time_from": "2024-01-01"},
        )
        r = (
            await api.post("/mapi/agg/event.dataset", json={"limit": 5, "from": "2024-01-01"})
        ).json()
        top = r["event.dataset"]["buckets"][0]
        check(
            "malcolm_field_values",
            top["key"] in t and f"{top['doc_count']:,}" in t,
            f"top bucket {top['key']} ({top['doc_count']:,}) present",
        )

        t = await call("malcolm_field_search", {"keyword": "useragent"})
        r = (await api.get("/mapi/fields")).json()
        expected = sorted(f for f in r["fields"] if "useragent" in f.lower())
        check(
            "malcolm_field_search",
            all(f in t for f in expected) and f"Found {len(expected)} fields" in t,
            f"{len(expected)} matching field names, all listed",
        )

        t = await jcall("malcolm_alerts", {"limit": 3, "time_from": "2024-01-01"})
        r = (
            await api.post(
                "/mapi/document",
                json={"limit": 3, "from": "2024-01-01", "filter": {"event.dataset": "alert"}},
            )
        ).json()
        check(
            "malcolm_alerts",
            [d["_id"] for d in t["results"]] == [d["_id"] for d in r["results"]],
            f"{len(t['results'])} alerts, same ids",
        )

        # ---- NetBox ----------------------------------------------------
        t = await jcall("malcolm_netbox_sites", {})
        r = (await api.get("/mapi/netbox-sites")).json()
        check("malcolm_netbox_sites", t == r, f"{len(t)} site(s), identical")

        t = await jcall("malcolm_netbox_query", {"path": "dcim/devices", "limit": 2})
        r = (await api.get("/mapi/netbox/dcim/devices", params={"limit": 2})).json()
        check("malcolm_netbox_query", t["count"] == r["count"], f"count={t['count']}")

        t = await jcall("malcolm_netbox_lookup", {"ip": "192.168.65.7"})
        r = (
            await api.get("/mapi/netbox/ipam/ip-addresses", params={"address": "192.168.65.7"})
        ).json()
        check(
            "malcolm_netbox_lookup",
            t["ip_lookup"]["found"] == (r["count"] > 0),
            f"found={t['ip_lookup']['found']} api_count={r['count']}",
        )

        # ---- Arkime ------------------------------------------------------
        aq = {"startTime": T0, "stopTime": T1}
        t = await jcall(
            "arkime_sessions",
            {"expression": "protocols == dns", "limit": 3, "time_from": T0, "time_to": T1},
        )
        r = (
            await api.get(
                "/arkime/api/sessions",
                params={
                    **aq,
                    "expression": "protocols == dns",
                    "length": 3,
                    "order": "lastPacket:desc",
                },
            )
        ).json()
        check(
            "arkime_sessions",
            t["matched"] == r["recordsFiltered"]
            and [x["id"] for x in t["sessions"]] == [x["id"] for x in r["data"]],
            f"matched={t['matched']:,} (api recordsFiltered) same ids",
        )
        sid = t["sessions"][0]["id"]

        t = await jcall("arkime_session_detail", {"session_id": sid})
        bare = sid.rsplit(":", 1)[-1].rsplit("@", 1)[-1]
        r = (
            await api.get(
                "/arkime/api/sessions",
                params={"expression": f"id == {bare}", "date": -1, "length": 1},
            )
        ).json()
        check("arkime_session_detail", t == r["data"][0], f"full SPI doc identical for {sid}")

        # A session with no stored packets would make this 0 == 0, which proves
        # nothing; search for one that actually yields a capture.
        candidates = (
            await api.get(
                "/arkime/api/sessions",
                params={
                    **aq,
                    "expression": "protocols == http",
                    "length": 25,
                    "order": "lastPacket:desc",
                },
            )
        ).json()["data"]
        pcap_sid, raw = None, b""
        for cand in candidates:
            body = (await api.get("/arkime/api/sessions.pcap", params={"ids": cand["id"]})).content
            if len(body) > 24:  # bigger than a bare pcap file header
                pcap_sid, raw = cand["id"], body
                break
        assert pcap_sid, "no session in the window yields PCAP bytes"
        t = await jcall("arkime_session_pcap", {"session_id": pcap_sid})
        check(
            "arkime_session_pcap",
            t["size_bytes"] == len(raw) and t["magic"] == raw[:4].hex() and t["valid_pcap"] is True,
            f"{t['size_bytes']:,} real bytes, magic {t['magic']} ({t['format']})",
        )

        t = await call("arkime_unique", {"field": "protocols", "time_from": T0, "time_to": T1})
        r = (
            await api.get("/arkime/api/unique", params={**aq, "exp": "protocols", "counts": 1})
        ).text
        check(
            "arkime_unique",
            t.strip() == r.strip(),
            f"{len(t.strip().splitlines())} lines identical",
        )

        t = await call(
            "arkime_multiunique",
            {"fields": "source.ip,destination.port", "time_from": T0, "time_to": T1},
        )
        r = (
            await api.get(
                "/arkime/api/multiunique",
                params={**aq, "exp": "source.ip,destination.port", "counts": 1},
            )
        ).text
        check("arkime_multiunique", t.strip() == r.strip(), "text identical")

        t = await jcall("arkime_spiview", {"spi": "protocols:5", "time_from": T0, "time_to": T1})
        r = (await api.get("/arkime/api/spiview", params={**aq, "spi": "protocols:5"})).json()
        check("arkime_spiview", t == r, "spiview response identical")

        t = await jcall("arkime_spigraph", {"field": "node", "time_from": T0, "time_to": T1})
        r = (
            await api.get("/arkime/api/spigraph", params={**aq, "field": "node", "size": 20})
        ).json()
        check(
            "arkime_spigraph",
            [i["name"] for i in t["items"]] == [i["name"] for i in r["items"]],
            f"{len(t['items'])} item(s), same names",
        )

        t = await jcall(
            "arkime_spigraphhierarchy",
            {"fields": "ip.src,ip.dst", "time_from": T0, "time_to": T1},
        )
        r = (
            await api.get("/arkime/api/spigraphhierarchy", params={**aq, "exp": "ip.src,ip.dst"})
        ).json()
        check(
            "arkime_spigraphhierarchy",
            t["tableResults"] == r["tableResults"],
            f"{len(t['tableResults'])} rows identical",
        )

        t = await jcall("arkime_connections", {"time_from": T0, "time_to": T1})
        r = (
            await api.get(
                "/arkime/api/connections", params={**aq, "srcField": "srcIp", "dstField": "dstIp"}
            )
        ).json()
        check(
            "arkime_connections",
            [n["id"] for n in t["nodes"]] == [n["id"] for n in r["nodes"]],
            f"{len(t['nodes'])} nodes, same ids",
        )

        t = await call("arkime_field_search", {"keyword": "user"})
        r = (await api.get("/arkime/api/fields", params={"array": "true"})).json()
        entries = r.values() if isinstance(r, dict) else r
        expected = [
            e
            for e in entries
            if isinstance(e, dict)
            and e.get("exp")
            and "user"
            in " ".join(
                (e.get("exp", ""), e.get("dbField2") or e.get("dbField", ""), e.get("help", ""))
            ).lower()
        ]
        check(
            "arkime_field_search",
            f"Found {len(expected)} Arkime fields" in t,
            f"{len(expected)} matching Arkime fields",
        )

        t = await jcall("arkime_views", {})
        r = (await api.get("/arkime/api/views", params={"length": 100})).json()
        check(
            "arkime_views",
            t["count"] == len(r["data"])
            and [v["name"] for v in t["views"]] == [v["name"] for v in r["data"]],
            f"{t['count']} views, same names in order",
        )

        t = await call("arkime_shortcuts", {})
        r = (await api.get("/arkime/api/shortcuts", params={"length": 100})).json()
        check(
            "arkime_shortcuts",
            (len(r["data"]) == 0) == ("No shortcuts" in t),
            f"api has {len(r['data'])}, tool reports accordingly",
        )

        t = await jcall("arkime_reverse_dns", {"ip": "8.8.8.8"})
        r = (await api.get("/arkime/api/reversedns", params={"ip": "8.8.8.8"})).text.strip()
        check("arkime_reverse_dns", t["hostname"] == r, f"{t['hostname']!r} both sides")

        t = await jcall("arkime_pcap_files", {"limit": 3})
        r = (await api.get("/arkime/api/files", params={"length": 3})).json()
        check(
            "arkime_pcap_files",
            t["total"] == r["recordsTotal"]
            and [f["name"] for f in t["files"]] == [f["name"] for f in r["data"]]
            and [f["bytes"] for f in t["files"]] == [f["filesize"] for f in r["data"]],
            f"total={t['total']}, same names and sizes",
        )

        t = await jcall("arkime_node_stats", {})
        r = (await api.get("/arkime/api/stats")).json()
        by_node = {n["nodeName"]: n for n in r["data"]}
        check(
            "arkime_node_stats",
            all(
                n["packets_dropped"] == by_node[n["node"]]["totalDropped"]
                and abs(n["cpu_percent"] - by_node[n["node"]]["cpu"] / 100) < 0.01
                for n in t["nodes"]
            ),
            f"{t['count']} nodes; drops equal, cpu = api/100",
        )

        t = await call(
            "arkime_sessions_csv",
            {"expression": "protocols == dns", "limit": 5, "time_from": T0, "time_to": T1},
        )
        r = (
            await api.get(
                "/arkime/api/sessions.csv",
                params={**aq, "expression": "protocols == dns", "length": 5},
            )
        ).text
        check("arkime_sessions_csv", t.strip() == r.strip(), "CSV identical, 5 rows")

        t = await jcall(
            "arkime_file_by_hash",
            {"file_hash": "52ad569e4fd4739f640fc3de54a1c063", "url_only": True},
        )
        check(
            "arkime_file_by_hash",
            t["download_url"]
            == f"{BASE}/arkime/api/sessions/bodyhash/52ad569e4fd4739f640fc3de54a1c063",
            "url_only URL matches the documented route",
        )

        # ---- correlation / dashboards ------------------------------------
        conn = (
            await api.post("/mapi/document", json={"limit": 1, "filter": {"event.dataset": "conn"}})
        ).json()
        uid = conn["results"][0]["_source"]["zeek"]["uid"]
        t = await jcall("malcolm_related_sessions", {"uid": uid})
        r = (
            await api.post("/mapi/document", json={"limit": 20, "filter": {"zeek.uid": uid}})
        ).json()
        check(
            "malcolm_related_sessions",
            [d["_id"] for d in t["direct"]] == [d["_id"] for d in r["results"]],
            f"uid={uid}: {len(t['direct'])} direct, same ids",
        )

        t = await jcall("malcolm_saved_objects", {"object_type": "dashboard", "limit": 3})
        r = (
            await api.get(
                "/dashboards/api/saved_objects/_find",
                params=[
                    ("type", "dashboard"),
                    ("fields", "title"),
                    ("fields", "description"),
                    ("per_page", 3),
                ],
            )
        ).json()
        check(
            "malcolm_saved_objects",
            t["total"] == r["total"]
            and [o["title"] for o in t["objects"]]
            == [o["attributes"]["title"] for o in r["saved_objects"]],
            f"total={t['total']}, same titles in order",
        )

        dash_id = t["objects"][0]["id"]
        t = await jcall("malcolm_dashboard_export", {"dashboard_id": dash_id})
        r = (await api.get(f"/mapi/dashboard-export/{dash_id}")).json()
        check("malcolm_dashboard_export", t == r, f"export identical for {dash_id}")

        t = await jcall("malcolm_alerting_monitors", {})
        r = (
            await api.post(
                "/mapi/opensearch/_plugins/_alerting/monitors/_search",
                json={"query": {"match_all": {}}, "size": 50},
            )
        ).json()
        alerts = (
            await api.get(
                "/mapi/opensearch/_plugins/_alerting/monitors/alerts",
                params={"alertState": "ACTIVE"},
            )
        ).json()
        check(
            "malcolm_alerting_monitors",
            t["total"] == r["hits"]["total"]["value"]
            and [m["name"] for m in t["monitors"]]
            == [h["_source"]["name"] for h in r["hits"]["hits"]]
            and t["active_alerts"] == alerts["totalAlerts"],
            f"total={t['total']}, active_alerts={t['active_alerts']} both sides",
        )

        t = await jcall("malcolm_anomaly_detectors", {})
        r = (
            await api.post(
                "/mapi/opensearch/_plugins/_anomaly_detection/detectors/_search",
                json={"query": {"match_all": {}}, "size": 50},
            )
        ).json()
        anom = (
            await api.post(
                "/mapi/opensearch/_plugins/_anomaly_detection/detectors/results/_search",
                json={
                    "query": {"range": {"anomaly_grade": {"gt": 0}}},
                    "size": 0,
                    "track_total_hits": True,
                },
            )
        ).json()
        check(
            "malcolm_anomaly_detectors",
            t["total"] == r["hits"]["total"]["value"]
            and [d["name"] for d in t["detectors"]]
            == [h["_source"]["name"] for h in r["hits"]["hits"]]
            and t["recorded_anomalies"] == anom["hits"]["total"]["value"],
            f"total={t['total']}, anomalies={t['recorded_anomalies']} both sides",
        )

        # ---- file analysis -------------------------------------------------
        exe_mimes = [
            "application/x-dosexec",
            "application/vnd.microsoft.portable-executable",
            "application/x-executable",
            "application/x-sharedlib",
            "application/x-object",
            "application/x-pie-executable",
            "application/x-mach-o-executable",
            "application/x-mach-binary",
        ]
        t = await jcall("malcolm_file_scans", {"executables_only": True, "limit": 3})
        r = (
            await api.post(
                "/mapi/document",
                json={
                    "limit": 3,
                    "filter": {"event.dataset": "files", "file.mime_type": exe_mimes},
                },
            )
        ).json()
        srcs = [d["_source"] for d in r["results"]]

        def first(v):
            return v[0] if isinstance(v, list) else v

        check(
            "malcolm_file_scans",
            [f["sha256"] for f in t["files"]] == [first(s["file"]["hash"]["sha256"]) for s in srcs]
            and [f["source_ip"] for f in t["files"]] == [s["source"]["ip"] for s in srcs]
            and [f["destination_ip"] for f in t["files"]] == [s["destination"]["ip"] for s in srcs]
            and [f["filename"] for f in t["files"]] == [first(s["file"]["name"]) for s in srcs],
            f"{len(t['files'])} rows: sha256, both IPs and filename all equal",
        )

        many = await jcall("malcolm_file_scans", {"limit": 40})
        on_disk = None
        for cand in many["files"]:
            if not cand.get("extracted"):
                continue
            probe = await api.get(f"/extracted-files/{cand['extracted']}")
            if probe.status_code == 200:
                on_disk, raw = cand, probe.content
                break
        t = await jcall("malcolm_extract_file", {"filename": on_disk["extracted"]})
        check(
            "malcolm_extract_file",
            t["size_bytes"] == len(raw)
            and t["sha256"] == hashlib.sha256(raw).hexdigest()
            and t["sha256"] == on_disk["sha256"]
            and t["magic"] == raw[:4].hex(),
            f"{t['size_bytes']} bytes; sha256 == API bytes == index record",
        )

        t = await jcall("malcolm_data_coverage", {})
        r = (await api.get("/mapi/ingest-stats")).json()
        # The tool renames Malcolm's "sources" key to "sensors"; the mapping
        # of sensor -> last-ingest timestamp must be identical.
        check(
            "malcolm_data_coverage",
            t["sensors"] == r["sources"],
            f"{sorted(t['sensors'])} with identical timestamps",
        )

        t = await call(
            "malcolm_field_profile", {"field": "zeek.dns.query", "time_from": "2024-01-01"}
        )
        r = (
            await api.post(
                "/mapi/agg/event.dataset",
                json={"from": "2024-01-01", "filter": {"!zeek.dns.query": None}},
            )
        ).json()
        top = r["event.dataset"]["buckets"][0]
        check(
            "malcolm_field_profile",
            f"event.dataset={top['key']}" in t and f"{top['doc_count']:,}" in t,
            f"{top['key']} ({top['doc_count']:,}) reported",
        )

        # ---- coverage accounting ------------------------------------------
        covered = {name for name, _, _ in results}
        missing = sorted(set(names) - covered)
        print(f"\n{'=' * 66}")
        passed = sum(1 for _, ok, _ in results if ok)
        print(f"parity: {passed}/{len(results)} checks matched")
        print(f"tools covered: {len(covered)}/{len(names)}")
        if missing:
            print(f"NOT COMPARED: {missing}")
        bad = [n for n, ok, _ in results if not ok]
        if bad:
            print(f"MISMATCHED: {bad}")
        if bad or missing:
            raise SystemExit(1)


asyncio.run(main())
