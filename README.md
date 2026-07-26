# mcp-server-malcolm

<!-- mcp-name: io.github.nagametw/mcp-server-malcolm -->

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
- It wraps Suricata alert queries and handles the field mapping (`suricata.alert.*` vs `rule.*`).
- It adds NetBox asset context (IP-to-device, network segments).

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

### Correlation and export

| Tool | Description |
|------|-------------|
| `malcolm_related_sessions` | Find all sessions related to a Zeek UID |
| `malcolm_dashboard_export` | Export an OpenSearch Dashboards saved object as JSON |

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

### Install

```bash
pip install mcp-server-malcolm
```

Or from source:

```bash
git clone https://github.com/nagameTW/mcp-server-malcolm.git
cd mcp-server-malcolm
pip install -e .
```

### Configure

Set the connection variables for your Malcolm instance:

```bash
export MALCOLM_URL="https://malcolm.example"
export MALCOLM_USERNAME="admin"
export MALCOLM_PASSWORD="admin"
# TLS verification is ON by default. Malcolm ships self-signed certs, so point
# this at Malcolm's CA cert rather than disabling verification:
export MALCOLM_SSL_VERIFY="/path/to/malcolm-ca.crt"
# Only for an isolated localhost lab: MALCOLM_SSL_VERIFY="false" disables
# verification entirely — never do this against a remote host (credentials and
# query results would travel over an unauthenticated channel).
export MALCOLM_TIMEOUT="30"
```

Leave the write flags unset to run read-only. To enable a class, set its flag:

```bash
export MALCOLM_MCP_ENABLE_ALERTING="true"
export MALCOLM_MCP_AUDIT_FILE="/var/log/malcolm-mcp-audit.jsonl"
```

### Run

```bash
# As an MCP server (stdio transport)
mcp-server-malcolm

# Or via the Python module
python -m mcp_server_malcolm
```

## Usage

### MCP client (config file)

Add the server to your MCP client's configuration:

```json
{
  "mcpServers": {
    "malcolm": {
      "command": "mcp-server-malcolm",
      "env": {
        "MALCOLM_URL": "https://malcolm.example",
        "MALCOLM_USERNAME": "admin",
        "MALCOLM_PASSWORD": "admin",
        "MALCOLM_SSL_VERIFY": "/path/to/malcolm-ca.crt"
      }
    }
  }
}
```

For the exact config-file location, check your MCP client's docs. Many use a project-level `.mcp.json` or a global config file.

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

# Wildcard
{"suricata.alert.signature": "*MALWARE*"}

# Combined (AND)
{"event.dataset": "dns", "source.ip": "192.0.2.77"}
```

## Examples

### Search DNS queries to a suspicious domain

```
malcolm_search(
  filters='{"event.dataset": "dns", "zeek.dns.query": "*example.com*"}',
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
| `/mapi/document` | POST | `malcolm_search`, `malcolm_alerts`, `malcolm_related_sessions` |
| `/mapi/agg/<fields>` | POST | `malcolm_aggregate`, `malcolm_field_values`, `malcolm_field_profile`, `malcolm_data_coverage` |
| `/mapi/fields` | GET | `malcolm_field_search`, `malcolm_field_profile` |
| `/mapi/ready`, `/mapi/version` | GET | `malcolm_service_status` |
| `/mapi/ping` | GET | `malcolm_ping` |
| `/mapi/ingest-stats`, `/mapi/indices` | GET | `malcolm_data_coverage` |
| `/mapi/dashboard-export/<id>` | GET | `malcolm_dashboard_export` |
| `/mapi/opensearch/<index>/_search` | POST | `search_dsl` |
| `/mapi/opensearch/<index>/_count` | POST | `count` |
| `/mapi/opensearch/_cat/indices` | GET | `list_indices` |
| `/mapi/opensearch/<index>/_mapping` | GET | `index_mapping` |
| `/mapi/opensearch/_cluster/health` | GET | `cluster_health` |
| `/mapi/netbox/*` | GET | `malcolm_netbox_lookup`, `malcolm_netbox_query` |
| `/mapi/netbox-sites` | GET | `malcolm_netbox_sites` |
| `/mapi/event` | POST | `malcolm_create_alert` (write) |
| `/arkime/api/sessions` | GET | `arkime_sessions` |
| `/arkime/api/session/<id>` | GET | `arkime_session_detail` |
| `/arkime/api/sessions.pcap` | GET | `arkime_session_pcap` |
| `/arkime/api/unique`, `/arkime/api/multiunique` | GET | `arkime_unique`, `arkime_multiunique` |
| `/arkime/api/spigraph` | GET | `arkime_spigraph` |
| `/arkime/api/spiview` | GET | `arkime_spiview` |
| `/arkime/api/spigraphhierarchy` | GET | `arkime_spigraphhierarchy` |
| `/arkime/api/connections` | GET | `arkime_connections` |
| `/arkime/api/sessions/bodyhash/<hash>` | GET | `arkime_file_by_hash` |
| `/arkime/api/sessions/addtags` | POST | `arkime_add_tags` (write) |
| `/arkime/api/hunt`, `/arkime/api/hunts` | POST, GET | `arkime_create_hunt`, `arkime_hunt_status` (write + read) |
| `/arkime/api/view`, `/arkime/api/shortcut` | POST | `arkime_create_view`, `arkime_create_shortcut` (write) |
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
