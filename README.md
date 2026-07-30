# mcp-server-malcolm

<!-- mcp-name: io.github.nagameTW/mcp-server-malcolm -->

[![CI](https://github.com/nagameTW/mcp-server-malcolm/actions/workflows/ci.yml/badge.svg)](https://github.com/nagameTW/mcp-server-malcolm/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mcp-server-malcolm)](https://pypi.org/project/mcp-server-malcolm/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://pypi.org/project/mcp-server-malcolm/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Glama score](https://glama.ai/mcp/servers/nagameTW/mcp-server-malcolm/badges/score.svg)](https://glama.ai/mcp/servers/nagameTW/mcp-server-malcolm)

**English** | [繁體中文](README.zh-TW.md)

[![mcp-server-malcolm MCP server](https://glama.ai/mcp/servers/nagameTW/mcp-server-malcolm/badges/card.svg)](https://glama.ai/mcp/servers/nagameTW/mcp-server-malcolm)

The first MCP server for [Malcolm](https://malcolm.fyi), the open-source network traffic analysis platform (Zeek + Suricata + Arkime + OpenSearch, with optional NetBox).

It gives any MCP-compatible AI agent structured access to Malcolm: search and aggregate network traffic, discover field names, query Suricata alerts, browse Arkime sessions, resolve NetBox assets, and check system health. Turn on the write classes and it can also create alerts, tag sessions, launch hunts, and upload PCAP.

## Read-only until you opt in

With no configuration, this server exposes read tools only. It behaves like a read-only client, and nothing it does can change data in Malcolm.

The server splits write access into five classes, each behind its own environment flag and each off by default. It doesn't register a disabled class, so that class's tools never appear in `list_tools()` and can't be called. At startup it prints which classes are on:

```
[mcp-server-malcolm] write classes: alerting=off arkime-tag=off hunt-job=off pcap-upload=off arkime-view=off
```

Every write is additive. Version 1 has no tool that deletes data, removes a tag, or touches user accounts. It leaves those out on purpose (see [Non-goals](#non-goals)).

## Why an MCP layer

Malcolm keeps all network metadata in one OpenSearch index (`arkime_sessions3-*`) with non-standard field names and its own filter syntax. An LLM asked to write raw OpenSearch DSL against that index gets it wrong more often than not. This server takes that job off the model:

- It exposes Malcolm's filter syntax instead of raw DSL.
- It provides field discovery so the model checks field names before it queries.
- It provides value enumeration so the model sees what values a field actually holds.
- It covers both field vocabularies. Arkime expressions take Arkime's own names (`ip.src`), the rest of Malcolm takes ECS names (`source.ip`), and Malcolm's own field list carries only the second set. `arkime_field_search` supplies the first.
- It wraps Suricata alert queries and handles the field mapping (`suricata.alert.*` vs `rule.*`).
- It adds NetBox asset context (IP-to-device, network segments).

The failure mode this is built against is a quiet one. Malcolm answers a query
against a field it does not index with an empty result rather than an error, so
a model that guesses a plausible-but-wrong name reads "no such traffic" and
moves on. When a search comes back empty, this server checks the fields the
query named and reports the name Malcolm actually stores the value under. That
lookup runs only after a result set is already empty, so nothing is added to
the model's context on queries that worked.

The write side follows the same idea. Rather than hand an agent the raw OpenSearch and NetBox passthroughs that Malcolm already leaves open to any authenticated user, this server exposes a small, named, audited set of write actions. More on that under [Security model](#security-model).

## Read tools

These are always registered.

### DSL core (backend-agnostic)

Plain OpenSearch DSL against the configured endpoint (Malcolm's `/mapi/opensearch` proxy). No Malcolm-specific query shape: point the base URL at any OpenSearch-compatible backend and they still work.

| Tool | Description |
|------|-------------|
| `search_dsl` | Run a raw OpenSearch DSL query (hits + aggregations, no hidden time window) |
| `count` | Count documents matching a DSL query clause |
| `list_indices` | List indices (name/health/status/doc count) |
| `index_mapping` | Field mapping/schema for an index |
| `cluster_health` | OpenSearch cluster health |

### Core query

| Tool | Description |
|------|-------------|
| `malcolm_search` | Search network traffic with Malcolm filter syntax |
| `malcolm_aggregate` | Aggregate traffic by one or more fields (top-N with counts) |
| `malcolm_alerts` | Search Suricata alerts by signature, severity, IP |

### Field discovery (anti-hallucination)

| Tool | Description |
|------|-------------|
| `malcolm_field_search` | Search available field names by keyword, prefix, or type |
| `malcolm_field_values` | List distinct values for a field |
| `malcolm_field_profile` | Show which `event.dataset` types contain a field |
| `arkime_field_search` | Search the field names Arkime *expressions* accept (listed again under [Arkime](#arkime)) |

These three `malcolm_*` tools cover the ECS names used by `malcolm_search`, `malcolm_aggregate` and the DSL tools. Anything going into an `expression` argument needs `arkime_field_search` instead: Arkime's parser accepts `ip.src` and rejects `source.ip`, and Malcolm's `/mapi/fields` does not list the expression names at all.

### System health

| Tool | Description |
|------|-------------|
| `malcolm_service_status` | Readiness of all Malcolm services plus version info |
| `malcolm_data_coverage` | Data freshness per sensor, doc counts per dataset, index info |
| `malcolm_ping` | Quick liveness check of the Malcolm API |

### Asset context (NetBox)

| Tool | Description |
|------|-------------|
| `malcolm_netbox_lookup` | Look up an IP, device, or network prefix in NetBox |
| `malcolm_netbox_sites` | List the NetBox site directory (id, name, metadata) |
| `malcolm_netbox_query` | Read any other NetBox endpoint (services, VLANs, interfaces, VMs, contacts) |

### Arkime

| Tool | Description |
|------|-------------|
| `arkime_field_search` | Look up the field names Arkime expressions accept (`ip.src`, `port.dst`) — a separate vocabulary from the ECS names `malcolm_field_search` returns |
| `arkime_sessions` | Search Arkime sessions with Arkime expression syntax |
| `arkime_session_detail` | Fetch all fields (full SPI document) for one session |
| `arkime_session_pcap` | Fetch a session's PCAP and report its size and file-magic validity (metadata only, nothing written to disk) |
| `arkime_unique` | List distinct values of one field, with optional counts |
| `arkime_multiunique` | Unique value combinations across several fields (e.g. src.ip + dst.port pairs) |
| `arkime_spigraph` | Top values of one field with a time-series graph |
| `arkime_spiview` | Value profile across several fields in one call |
| `arkime_spigraphhierarchy` | Hierarchical top-N breakdown across fields (nested drill-down) |
| `arkime_connections` | Source/destination connection graph (nodes and links) |
| `arkime_file_by_hash` | Extract the transferred file whose md5/sha256 matches (metadata only, nothing written to disk) |
| `arkime_sessions_csv` | Export sessions as a compact CSV table — about half the tokens of the same rows as JSON |

### Arkime saved objects and capture health

| Tool | Description |
|------|-------------|
| `arkime_views` | List the saved search views the team curated, with each one's expression |
| `arkime_shortcuts` | List named value lists (IOC sets) and what each holds, plus the `$name` token to use in an expression |
| `arkime_reverse_dns` | Reverse-resolve one IP to its PTR hostname |
| `arkime_pcap_files` | List the PCAP files Arkime has indexed, with each file's size, packet/session counts and time span |
| `arkime_node_stats` | Capture-node health: dropped packets, disk, memory, queues — warns when a node is losing packets, since that turns a gap into what looks like an absence |

Arkime's `connections.csv` is deliberately not wrapped: on Arkime 6.6.0 it emits a nine-column header over seven-column rows, so every column after the second is mislabeled. `arkime_connections` answers the same question correctly.

### File analysis

| Tool | Description |
|------|-------------|
| `malcolm_file_scans` | List the files Zeek carved out of traffic — name, MIME type, size, md5/sha256, both endpoints, Malcolm's severity, and any Strelka/YARA/ClamAV hits |
| `malcolm_extract_file` | Fetch one carved file from Malcolm's extracted-files server and report its size, sha256, and file-magic (metadata only, nothing written to disk) |

`malcolm_file_scans` reads Zeek's record of every file transfer it saw, which does not require the file extractor. Reaching the file itself does: `malcolm_extract_file` needs `ZEEK_EXTRACTOR_MODE` set and the extracted-files HTTP server on (`FILESCAN_HTTP_SERVER_ENABLE`), and a scan row only appears where Strelka is running. A carved file may be live malware, so the bytes never enter the MCP response.

### Correlation and export

| Tool | Description |
|------|-------------|
| `malcolm_related_sessions` | Find all sessions related to a Zeek UID |
| `malcolm_saved_objects` | Find the dashboards, visualizations and saved searches this Malcolm ships (111 dashboards, without their multi-KB layout blobs) |
| `malcolm_dashboard_export` | Export an OpenSearch Dashboards saved object as JSON |
| `malcolm_alerting_monitors` | List OpenSearch alerting monitors, what each watches, and whether any have fired — flags when every monitor is disabled |
| `malcolm_anomaly_detectors` | List anomaly detectors, what each models, and how many anomalies exist — flags when none were ever recorded |

## Write tools (opt-in)

Each class is enabled by setting its flag to `true`. Nothing here runs unless you ask for it.

| Class | Flag | Tools | Endpoint |
|-------|------|-------|----------|
| alerting | `MALCOLM_MCP_ENABLE_ALERTING` | `malcolm_create_alert` | `POST /mapi/event` |
| arkime-tag | `MALCOLM_MCP_ENABLE_ARKIME_TAGS` | `arkime_add_tags` | `POST /arkime/api/sessions/addtags` |
| hunt-job | `MALCOLM_MCP_ENABLE_HUNT_JOBS` | `arkime_create_hunt`, `arkime_hunt_status` | `POST /arkime/api/hunt` |
| pcap-upload | `MALCOLM_MCP_ENABLE_PCAP_UPLOAD` | `malcolm_upload_pcap` | `POST /server/php/submit.php` |
| arkime-view | `MALCOLM_MCP_ENABLE_ARKIME_VIEWS` | `arkime_create_view`, `arkime_create_shortcut` | `POST /arkime/api/view`, `POST /arkime/api/shortcut` |

- **alerting**: `malcolm_create_alert` indexes an analyst- or agent-generated finding as an alert document you can see in Malcolm's dashboards. It uses `/mapi/event`, Malcolm's own purpose-built write endpoint, which is the template the other classes follow.
- **arkime-tag**: `arkime_add_tags` adds tags to sessions. It only adds; tag removal needs a higher Arkime role and its own safety design, so it's deferred.
- **hunt-job**: `arkime_create_hunt` launches a cross-PCAP packet search (expensive, so scope the query first). `arkime_hunt_status` reads job progress and ships with the class.
- **pcap-upload**: `malcolm_upload_pcap` sends a local capture file to Malcolm for ingestion, with a client-side size cap. The file must live inside `MALCOLM_MCP_UPLOAD_DIR`; if that staging directory is unset, uploads are refused, so the tool can never be steered into reading an arbitrary file off the host.
- **arkime-view**: `arkime_create_view` saves a named search expression and `arkime_create_shortcut` saves a named value list (IOC set) referenced in expressions as `$name`. Both are additive — they let an agent persist hunting knowledge for the human team, and neither deletes or overwrites.

Every write tool carries the MCP annotations `readOnlyHint: false` and `destructiveHint: false`, so an MCP client can apply its own confirmation step before the call runs.

## Security model

Malcolm's default deployment already gives any authenticated user unrestricted write access to raw OpenSearch (`/mapi/opensearch/*`) and full NetBox CRUD (`/mapi/netbox/*`). Both are bare reverse-proxies with no HTTP-verb filtering; Malcolm's own read-only mode removes them rather than trying to filter them. In the common auth modes, "logged in" means admin-equivalent.

Turning on a write class here does not open a door that was otherwise shut. That door is already open at the platform level. This server adds a curated way through it:

- A small, named set of write actions instead of a raw passthrough.
- Off by default, enabled one class at a time.
- An audit line for every write attempt.
- MCP annotations so the client can require confirmation.

This server does **not** expose the raw OpenSearch and NetBox write passthroughs, behind a flag or otherwise. Curating that surface is what it is for.

## Audit

Every write attempt emits one line of JSON, on success and on failure:

```json
{"ts": "2026-07-06T09:12:44Z", "tool": "arkime_add_tags", "class": "arkime-tag", "target": "ids=240601-abc", "params": {"tags": "suspicious"}, "outcome": "ok"}
```

`outcome` is one of `ok`, `http_4xx`, `http_5xx`, or `error:<type>`. Long parameter values are truncated, and PCAP bytes are never logged. The sink is stderr by default; set `MALCOLM_MCP_AUDIT_FILE` to append to a file instead. Read tools are not audited.

## Quick start

You don't write any code to use this. An MCP client (Claude Code, Claude Desktop, Cursor, …) launches the server as a subprocess and talks to it over stdio; your job is to tell the client how to launch it and which credentials to inject.

### 1. Install

```bash
pip install mcp-server-malcolm
```

Or from source:

```bash
git clone https://github.com/nagameTW/mcp-server-malcolm.git
cd mcp-server-malcolm
pip install -e .
```

### 2. Register it with your client

**Claude Code** — one command, no config file to find:

```bash
claude mcp add malcolm \
  -e MALCOLM_URL=https://malcolm.example \
  -e MALCOLM_USERNAME=analyst \
  -e MALCOLM_PASSWORD='your-password' \
  -e MALCOLM_SSL_VERIFY=/path/to/malcolm-ca.crt \
  -- mcp-server-malcolm
```

Everything after `--` is the launch command; each `-e` is an environment variable injected into it. Pick where the entry is stored with `-s`:

| Scope | Stored in | Use for |
| --- | --- | --- |
| `local` (default) | your own settings, this project only | credentials — nothing is committed |
| `user` | your own settings, every project | a Malcolm you use everywhere |
| `project` | `.mcp.json` at the repo root, **committed to git** | sharing with a team — never put a password here |

Confirm it came up with `claude mcp list`, which health-checks each server, and `claude mcp get malcolm` for the details.

For a `project`-scope entry, keep the secret in each person's shell rather than in the file:

```json
{
  "mcpServers": {
    "malcolm": {
      "command": "mcp-server-malcolm",
      "env": { "MALCOLM_PASSWORD": "${MALCOLM_PASSWORD}" }
    }
  }
}
```

**Other MCP clients** — no equivalent CLI, so edit the client's own JSON config. The block is the same shape:

```json
{
  "mcpServers": {
    "malcolm": {
      "command": "mcp-server-malcolm",
      "env": {
        "MALCOLM_URL": "https://malcolm.example",
        "MALCOLM_USERNAME": "analyst",
        "MALCOLM_PASSWORD": "your-password",
        "MALCOLM_SSL_VERIFY": "/path/to/malcolm-ca.crt"
      }
    }
  }
}
```

Claude Desktop reads `claude_desktop_config.json`; other clients vary — check their docs for the path.

If `mcp-server-malcolm` isn't on the `PATH` your client sees (common with a virtualenv), give the absolute path to the executable instead: `/path/to/.venv/bin/mcp-server-malcolm`.

### 3. Connection settings

| Variable | Notes |
| --- | --- |
| `MALCOLM_URL` | Malcolm base URL, e.g. `https://malcolm.example` |
| `MALCOLM_USERNAME` / `MALCOLM_PASSWORD` | Malcolm basic-auth credentials |
| `MALCOLM_SSL_VERIFY` | `true` (default), `false`, or a path to a CA bundle |
| `MALCOLM_TIMEOUT` | HTTP timeout in seconds, default `30` |

On TLS: verification is on by default, and Malcolm ships self-signed certs. Pointing `MALCOLM_SSL_VERIFY` at Malcolm's CA bundle only works if Malcolm's server certificate carries a `subjectAltName` matching the hostname you connect to — the certificate generated by Malcolm's own setup has no SAN extension, so verification fails against it even with the right CA. For a remote Malcolm, install a certificate with a correct SAN. `MALCOLM_SSL_VERIFY="false"` disables verification entirely and is only acceptable against an isolated localhost lab; over a network it would send credentials and query results down an unauthenticated channel.

### 4. Enabling write tools (optional)

All five write classes are off unless you set their flag, so the default install is read-only. Add the flags to the same `-e` / `env` block:

```bash
-e MALCOLM_MCP_ENABLE_ALERTING=true
-e MALCOLM_MCP_AUDIT_FILE=/var/log/malcolm-mcp-audit.jsonl
```

The full flag list is in [Configuration](#configuration).

### Running it by hand

Only useful for troubleshooting. A stdio MCP server has no interactive interface: started from a terminal it sits silently waiting for JSON-RPC on stdin, which is what a working server looks like. It does print the enabled write classes to stderr on startup, so this confirms the flags took effect:

```bash
mcp-server-malcolm          # or: python -m mcp_server_malcolm
```

## Usage

### Python (direct import)

Use `MalcolmClient` without the MCP layer:

```python
import asyncio
from mcp_server_malcolm import MalcolmClient

async def main():
    client = MalcolmClient(
        base_url="https://malcolm.example",
        username="admin",
        password="admin",
    )

    # Search network traffic
    results = await client.search(
        filters={"event.dataset": "conn", "source.ip": "192.0.2.77"},
        limit=10,
    )

    # Aggregate by protocol
    agg = await client.aggregate(
        fields="network.protocol",
        filters={"network.direction": ["inbound", "outbound"]},
    )

    # Discover field names
    fields = await client.search_fields(keyword="useragent")

    # Get distinct values
    datasets = await client.field_values(field="event.dataset")

    # Look up a NetBox asset
    asset = await client.netbox_get(
        "api/ipam/ip-addresses/",
        params={"address": "192.0.2.77"},
    )

    await client.close()

asyncio.run(main())
```

Write primitives live behind the `_write_*` methods. Only the gated write tools reach them, not the direct-import path.

## Malcolm filter syntax

Malcolm uses a simple JSON filter syntax, not OpenSearch DSL:

```python
# Exact match
{"event.dataset": "conn"}

# Multiple values (OR)
{"network.direction": ["inbound", "outbound"]}

# Negation
{"!network.transport": "icmp"}

# Field must exist (not null)
{"!related.password": null}

# Combined (AND)
{"event.dataset": "dns", "source.ip": "192.0.2.77"}
```

Values match **exactly**. Malcolm compiles this dict to an OpenSearch `terms`
query, so there is no wildcard: `{"rule.name": "*MALWARE*"}` looks for a
signature literally named `*MALWARE*` and quietly finds nothing. For substring
matching either enumerate the values first with `malcolm_field_values` and pass
the ones you want as a list, or use `search_dsl` and write the wildcard query
yourself. `malcolm_alerts` does that enumeration for you on its `signature` and
`category` arguments.

## Examples

### Search DNS queries to a suspicious domain

```
malcolm_search(
  filters='{"event.dataset": "dns", "zeek.dns.query": "ntp.ubuntu.com"}',
  limit=20,
  time_from="7 days ago"
)
```

### Aggregate top talkers by protocol

```
malcolm_aggregate(
  fields="source.ip,destination.ip,network.protocol",
  filters='{"network.direction": ["inbound", "outbound"]}',
  limit=20
)
```

### Verify field names before querying

```
malcolm_field_search(prefix="zeek.dns")
malcolm_field_values(field="event.dataset")
malcolm_field_profile(field="zeek.ssl.server_name")

# Before writing an Arkime expression, look the name up in Arkime's own
# vocabulary. This returns "ip.src | srcIp | ip | general": the first name
# goes in an expression, the second wherever a tool asks for a db field.
arkime_field_search(keyword="src")
```

### Create an alert (alerting class enabled)

```
malcolm_create_alert(
  title="Periodic beacon to 192.0.2.77",
  severity=2,
  description="60s-interval C2 candidate",
  source_ip="192.0.2.10",
  dest_ip="192.0.2.77"
)
```

### Tag sessions for review (arkime-tag class enabled)

```
arkime_add_tags(session_ids="240601-abc,240601-def", tags="review,beacon")
```

### Launch a hunt (hunt-job class enabled)

```
arkime_create_hunt(
  name="beacon-bytes",
  search="deadbeef",
  search_type="hex",
  total_sessions=42,
  start_time=1717200000,
  stop_time=1717203600,
  expression="ip==192.0.2.77"
)
```

## Configuration reference

| Variable | Default | Description |
|----------|---------|-------------|
| `MALCOLM_URL` | `https://localhost` | Malcolm base URL |
| `MALCOLM_USERNAME` | `admin` | Basic auth username |
| `MALCOLM_PASSWORD` | `admin` | Basic auth password |
| `MALCOLM_SSL_VERIFY` | `true` | Verify TLS certs. `true`/`false`, or a CA-bundle path (use the path for self-signed Malcolm) |
| `MALCOLM_TIMEOUT` | `30` | HTTP request timeout (seconds) |
| `MALCOLM_MCP_ENABLE_ALERTING` | `false` | Enable the alerting write class |
| `MALCOLM_MCP_ENABLE_ARKIME_TAGS` | `false` | Enable additive session tagging |
| `MALCOLM_MCP_ENABLE_HUNT_JOBS` | `false` | Enable Arkime hunt create + status |
| `MALCOLM_MCP_ENABLE_PCAP_UPLOAD` | `false` | Enable PCAP upload (also needs `MALCOLM_MCP_UPLOAD_DIR`) |
| `MALCOLM_MCP_ENABLE_ARKIME_VIEWS` | `false` | Enable saved-view + shortcut (value-list) create |
| `MALCOLM_MCP_UPLOAD_DIR` | unset | Staging dir that files must live inside to be uploadable; unset ⇒ uploads refused |
| `MALCOLM_MCP_AUDIT_FILE` | unset | Write-audit file (stderr when unset) |

## Malcolm API endpoints used

| Endpoint | Method | Used by |
|----------|--------|---------|
| `/mapi/document` | POST | `malcolm_search`, `malcolm_alerts`, `malcolm_related_sessions`, `malcolm_file_scans` |
| `/mapi/agg/<fields>` | POST | `malcolm_aggregate`, `malcolm_field_values`, `malcolm_field_profile`, `malcolm_data_coverage` |
| `/mapi/fields` | GET | `malcolm_field_search`, `malcolm_field_profile` |
| `/mapi/ready`, `/mapi/version` | GET | `malcolm_service_status` |
| `/mapi/ping` | GET | `malcolm_ping` |
| `/mapi/ingest-stats`, `/mapi/indices` | GET | `malcolm_data_coverage` |
| `/mapi/dashboard-export/<id>` | GET | `malcolm_dashboard_export` |
| `/dashboards/api/saved_objects/_find` | GET | `malcolm_saved_objects` |
| `/mapi/opensearch/_plugins/_alerting/monitors/*` | POST, GET | `malcolm_alerting_monitors` |
| `/mapi/opensearch/_plugins/_anomaly_detection/detectors/*` | POST | `malcolm_anomaly_detectors` |
| `/mapi/opensearch/<index>/_search` | POST | `search_dsl` |
| `/mapi/opensearch/<index>/_count` | POST | `count` |
| `/mapi/opensearch/_cat/indices` | GET | `list_indices` |
| `/mapi/opensearch/<index>/_mapping` | GET | `index_mapping` |
| `/mapi/opensearch/_cluster/health` | GET | `cluster_health` |
| `/mapi/netbox/*` | GET | `malcolm_netbox_lookup`, `malcolm_netbox_query` |
| `/mapi/netbox-sites` | GET | `malcolm_netbox_sites` |
| `/mapi/event` | POST | `malcolm_create_alert` (write) |
| `/arkime/api/fields` | GET | `arkime_field_search` |
| `/arkime/api/sessions` | GET | `arkime_sessions`, `arkime_session_detail` (via an `id ==` expression) |
| `/arkime/api/sessions.pcap` | GET | `arkime_session_pcap` |
| `/arkime/api/unique`, `/arkime/api/multiunique` | GET | `arkime_unique`, `arkime_multiunique` |
| `/arkime/api/spigraph` | GET | `arkime_spigraph` |
| `/arkime/api/spiview` | GET | `arkime_spiview` |
| `/arkime/api/spigraphhierarchy` | GET | `arkime_spigraphhierarchy` |
| `/arkime/api/connections` | GET | `arkime_connections` |
| `/arkime/api/sessions/bodyhash/<hash>` | GET | `arkime_file_by_hash` |
| `/arkime/api/sessions.csv` | GET | `arkime_sessions_csv` |
| `/arkime/api/views`, `/arkime/api/shortcuts` | GET | `arkime_views`, `arkime_shortcuts` |
| `/arkime/api/reversedns` | GET | `arkime_reverse_dns` |
| `/arkime/api/files` | GET | `arkime_pcap_files` |
| `/arkime/api/stats` | GET | `arkime_node_stats` |
| `/arkime/api/sessions/addtags` | POST | `arkime_add_tags` (write) |
| `/arkime/api/hunt`, `/arkime/api/hunts` | POST, GET | `arkime_create_hunt`, `arkime_hunt_status` (write + read) |
| `/arkime/api/view`, `/arkime/api/shortcut` | POST | `arkime_create_view`, `arkime_create_shortcut` (write) |
| `/extracted-files/<name>` | GET | `malcolm_extract_file` |
| `/server/php/submit.php` | POST | `malcolm_upload_pcap` (write) |

These endpoint paths and body shapes match Malcolm `26.06.1` and Arkime `v6.5.0`. Both drift between releases, so re-check against your own version if a write tool returns an unexpected error.

## Non-goals

Version 1 leaves these out on purpose:

- Destructive writes (Arkime session delete, tag removal, user management).
- Raw OpenSearch write or raw NetBox CRUD passthrough, behind a flag or otherwise.
- The `streamable-http` transport (stdio only).

## Requirements

- Python 3.11+
- A Malcolm instance with API access
- Network connectivity to Malcolm (HTTPS)

## License

MIT © nagameTW
