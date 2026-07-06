# mcp-server-malcolm

**English** | [繁體中文](README.zh-TW.md)

MCP server for [Malcolm](https://malcolm.fyi) — the open-source network traffic analysis platform (Zeek + Suricata + Arkime).

Gives any MCP-compatible AI agent structured access to Malcolm's unified API for network traffic search, aggregation, field discovery, Suricata alerts, Arkime sessions, NetBox asset lookup, and system health monitoring.

**Read-only by design** — no tool writes, posts, or ingests anything. The server is layered: a **backend-agnostic DSL core** (5 generic OpenSearch query tools that work against any OpenSearch-compatible endpoint) plus a **Malcolm module** (Malcolm-specific convenience tools) that can be dropped without touching the core.

## Why

Malcolm stores all network metadata in a single OpenSearch index (`arkime_sessions3-*`) with non-standard field names and a custom filter syntax. LLMs writing raw OpenSearch DSL against Malcolm get it wrong most of the time. This MCP server solves that by:

- Exposing Malcolm's **simple filter syntax** instead of OpenSearch DSL
- Providing **field discovery tools** so the LLM can verify field names before querying
- Providing **field value enumeration** so the LLM knows what values actually exist
- Wrapping **Suricata alert queries** with automatic field mapping (`suricata.alert.*` vs `rule.*`)
- Adding **NetBox asset context** (IP-to-device resolution, network segments)

## Tools

### DSL Core (backend-agnostic)

Plain OpenSearch DSL against the configured endpoint (Malcolm's `/mapi/opensearch`
proxy). No Malcolm-specific query shape — repoint the base URL and they work
against any OpenSearch-compatible backend.

| Tool | Description |
|------|-------------|
| `search_dsl` | Run a raw OpenSearch DSL query (hits + aggregations, no hidden time window) |
| `count` | Count documents matching a DSL query clause |
| `list_indices` | List indices (name/health/status/doc count) |
| `index_mapping` | Field mapping/schema for an index |
| `cluster_health` | OpenSearch cluster health |

### Core Query

| Tool | Description |
|------|-------------|
| `malcolm_search` | Search network traffic documents with Malcolm filter syntax |
| `malcolm_aggregate` | Aggregate traffic by one or more fields (top-N with counts) |
| `malcolm_alerts` | Search Suricata alerts by signature, severity, IP |

### Field Discovery (Anti-Hallucination)

| Tool | Description |
|------|-------------|
| `malcolm_field_search` | Search/browse available field names by keyword, prefix, or type |
| `malcolm_field_values` | List distinct values for a field (e.g. what `event.dataset` values exist) |
| `malcolm_field_profile` | Show which `event.dataset` types contain a specific field |

### System Health

| Tool | Description |
|------|-------------|
| `malcolm_service_status` | Check readiness of all Malcolm services + version info |
| `malcolm_data_coverage` | Data freshness per sensor, document counts per dataset, index info |

### Asset Context (NetBox)

| Tool | Description |
|------|-------------|
| `malcolm_netbox_lookup` | Look up IP address, device, or network prefix in NetBox |

### Arkime

| Tool | Description |
|------|-------------|
| `arkime_sessions` | Search Arkime sessions using Arkime expression syntax |
| `arkime_pcap_info` | Get PCAP download URL for a session |

### Correlation

| Tool | Description |
|------|-------------|
| `malcolm_related_sessions` | Find all sessions related to a Zeek UID |

## Quick Start

### Install

```bash
pip install mcp-server-malcolm
```

Or install from source:

```bash
git clone https://github.com/user/mcp-server-malcolm.git
cd mcp-server-malcolm
pip install -e .
```

### Configure

Set environment variables for your Malcolm instance:

```bash
export MALCOLM_URL="https://malcolm-server"
export MALCOLM_USERNAME="admin"
export MALCOLM_PASSWORD="admin"
export MALCOLM_SSL_VERIFY="false"    # Malcolm uses self-signed certs by default
export MALCOLM_TIMEOUT="30"
```

### Run

```bash
# As MCP server (stdio transport)
mcp-server-malcolm

# Or via Python module
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
        "MALCOLM_URL": "https://malcolm-server",
        "MALCOLM_USERNAME": "admin",
        "MALCOLM_PASSWORD": "admin",
        "MALCOLM_SSL_VERIFY": "false"
      }
    }
  }
}
```

Consult your MCP client's documentation for the exact config-file location
(many use a project-level `.mcp.json` or a global config file).

### Python (Direct Import)

Use `MalcolmClient` directly without the MCP protocol layer:

```python
import asyncio
from mcp_server_malcolm import MalcolmClient

async def main():
    client = MalcolmClient(
        base_url="https://malcolm-server",
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

    # Check which datasets have a field
    profile = await client.field_profile("zeek.ssl.server_name")

    # Look up NetBox asset
    asset = await client.netbox_get(
        "api/ipam/ip-addresses/",
        params={"address": "192.0.2.77"},
    )

    await client.close()

asyncio.run(main())
```

## Malcolm Filter Syntax

Malcolm uses a simple JSON filter syntax (NOT OpenSearch DSL):

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

## Tool Examples

### Search for DNS queries to a suspicious domain

```
malcolm_search(
  filters='{"event.dataset": "dns", "zeek.dns.query": "*evil.com*"}',
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

### Search Suricata alerts

```
malcolm_alerts(
  signature="ET MALWARE",
  severity="1,2",
  time_from="24 hours ago"
)
```

### Discover field names before querying

```
# What fields are available for DNS?
malcolm_field_search(prefix="zeek.dns")

# What values does event.dataset have?
malcolm_field_values(field="event.dataset")

# Which datasets contain zeek.ssl.server_name?
malcolm_field_profile(field="zeek.ssl.server_name")
```

### Check data freshness before a hunt

```
malcolm_data_coverage()
```

Returns sensor timestamps, document counts per dataset, and index info — so you know what time ranges have data and what protocols are present.

### Look up an IP in NetBox

```
malcolm_netbox_lookup(ip="192.0.2.77")
```

Returns device name, role, site, interfaces, and network segment — context for determining if behavior is normal.

### Correlate sessions by Zeek UID

```
malcolm_related_sessions(uid="CYeji2z7CKmPRGyga")
```

Finds all sessions (conn, dns, ssl, files, etc.) related to a single connection.

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `MALCOLM_URL` | `https://localhost` | Malcolm base URL |
| `MALCOLM_USERNAME` | `admin` | Basic auth username |
| `MALCOLM_PASSWORD` | `admin` | Basic auth password |
| `MALCOLM_SSL_VERIFY` | `false` | Verify TLS certificates |
| `MALCOLM_TIMEOUT` | `30` | HTTP request timeout (seconds) |

## Malcolm API Endpoints Used

| Endpoint | Method | Used By |
|----------|--------|---------|
| `/mapi/document` | POST | `malcolm_search`, `malcolm_alerts`, `malcolm_related_sessions` |
| `/mapi/agg/<fields>` | POST | `malcolm_aggregate`, `malcolm_field_values`, `malcolm_field_profile`, `malcolm_data_coverage` |
| `/mapi/fields` | GET | `malcolm_field_search`, `malcolm_field_profile` |
| `/mapi/ready` | GET | `malcolm_service_status` |
| `/mapi/version` | GET | `malcolm_service_status` |
| `/mapi/ingest-stats` | GET | `malcolm_data_coverage` |
| `/mapi/indices` | GET | `malcolm_data_coverage` |
| `/mapi/opensearch/<index>/_search` | POST | `search_dsl` |
| `/mapi/opensearch/<index>/_count` | POST | `count` |
| `/mapi/opensearch/_cat/indices` | GET | `list_indices` |
| `/mapi/opensearch/<index>/_mapping` | GET | `index_mapping` |
| `/mapi/opensearch/_cluster/health` | GET | `cluster_health` |
| `/mapi/netbox/*` | GET | `malcolm_netbox_lookup` |
| `/arkime/api/sessions` | GET | `arkime_sessions` |
| `/arkime/api/session/<id>/pcap` | GET | `arkime_pcap_info` |

## Requirements

- Python 3.11+
- Malcolm instance with API access enabled
- Network connectivity to Malcolm (HTTPS)

## License

MIT
