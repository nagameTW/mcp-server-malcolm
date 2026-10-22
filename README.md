<!-- mcp-name: io.github.nagameTW/mcp-server-malcolm -->
<div align="center">
  <h1>Malcolm MCP Server</h1>
  <p>
    <a href="https://github.com/nagameTW/mcp-server-malcolm/actions/workflows/ci.yml"><img src="https://github.com/nagameTW/mcp-server-malcolm/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="https://pypi.org/project/mcp-server-malcolm/"><img src="https://img.shields.io/pypi/v/mcp-server-malcolm" alt="PyPI"></a>
    <a href="https://pypi.org/project/mcp-server-malcolm/"><img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+"></a>
    <a href="./LICENSE"><img src="https://img.shields.io/github/license/nagameTW/mcp-server-malcolm?style=flat-square&logo=opensourceinitiative&logoColor=white&color=3DA639" alt="License"></a>
    <a href="https://glama.ai/mcp/servers/nagameTW/mcp-server-malcolm"><img src="https://glama.ai/mcp/servers/nagameTW/mcp-server-malcolm/badges/score.svg" alt="Glama score"></a>
  </p>
  <p><a href="README.md">English</a> | <a href="README.zh-TW.md">繁體中文</a></p>
</div>

Malcolm MCP Server lets an AI agent ask questions about the traffic in your [Malcolm](https://malcolm.fyi) instance. The server uses the field names and the filter syntax that Malcolm uses. The agent does not guess them. It works with any MCP client, such as Claude Code, Claude Desktop or Cursor.

Example requests, and the tools that answer them:

- "Show every Suricata alert involving 192.0.2.15 in the last 24 hours, and which NetBox device owns that IP." This calls `malcolm_alerts` and `malcolm_netbox_lookup`.
- "Who were the top talkers by protocol over the last hour?" This calls `malcolm_aggregate`.
- "List the executables Zeek carved out of yesterday's traffic, with their hashes." This calls `malcolm_file_scans`.
- "Upload this PCAP, then hunt the stored packets for this string." This calls `malcolm_upload_pcap` and `arkime_create_hunt`. Both are write tools, and they are off by default.

A [recorded session](https://github.com/nagameTW/mcp-server-malcolm/blob/main/docs/usage.md#demo) shows an agent answering a question about Modbus alerts.

## Requirements

- Python 3.11 or newer.
- A Malcolm instance with API access, reachable over HTTPS.
- An MCP client.

## Quick start

**1. Install the server.** Then start it with stdin closed. It prints the state of the write classes and exits with code 0.

```bash
pip install mcp-server-malcolm
mcp-server-malcolm < /dev/null
# [mcp-server-malcolm] write classes: alerting=off arkime-tag=off hunt-job=off pcap-upload=off arkime-view=off
```

**2. Register it with Claude Code.** Replace the values with your own.

```bash
claude mcp add malcolm \
  -e MALCOLM_URL=https://malcolm.example \
  -e MALCOLM_USERNAME=analyst \
  -e MALCOLM_PASSWORD='your-password' \
  -e MALCOLM_SSL_VERIFY=/path/to/malcolm-ca.crt \
  -- mcp-server-malcolm
```

Everything after `--` is the launch command. Each `-e` sets one environment variable for it. A password typed in this command stays in your shell history. The [install page](https://github.com/nagameTW/mcp-server-malcolm/blob/main/docs/install.md) shows how to avoid that. It also covers other MCP clients and other ways to install.

**3. Check the connection.** Ask the agent to call `malcolm_ping`. If the call fails, read [Troubleshooting](https://github.com/nagameTW/mcp-server-malcolm/blob/main/docs/troubleshooting.md). A self-signed certificate is the most common cause.

## Connection settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `MALCOLM_URL` | `https://localhost` | Base URL of Malcolm |
| `MALCOLM_USERNAME` | `admin` | Basic-auth user |
| `MALCOLM_PASSWORD` | `admin` | Basic-auth password |
| `MALCOLM_SSL_VERIFY` | `true` | `true`, `false`, or the path of a CA bundle |

Malcolm ships a self-signed certificate. For a remote Malcolm, point `MALCOLM_SSL_VERIFY` at the CA bundle. The certificate must carry a `subjectAltName` that matches the host name. The certificate that Malcolm's own setup generates has none, so install one that does. Use `false` only on an isolated lab machine. The [configuration page](https://github.com/nagameTW/mcp-server-malcolm/blob/main/docs/configuration.md) lists every variable.

## Read-only by default

The write tools come in five classes, and each class has one flag. The server registers only read tools until you set a flag. A class that is off is not registered. Its tools do not appear in `tools/list`.

| Class | Flag | Tools |
| --- | --- | --- |
| alerting | `MALCOLM_MCP_ENABLE_ALERTING` | `malcolm_create_alert` |
| arkime-tag | `MALCOLM_MCP_ENABLE_ARKIME_TAGS` | `arkime_add_tags` |
| hunt-job | `MALCOLM_MCP_ENABLE_HUNT_JOBS` | `arkime_create_hunt`, `arkime_cancel_hunt` |
| pcap-upload | `MALCOLM_MCP_ENABLE_PCAP_UPLOAD` | `malcolm_upload_pcap` |
| arkime-view | `MALCOLM_MCP_ENABLE_ARKIME_VIEWS` | `arkime_create_view`, `arkime_create_shortcut` |

A flag is on only when its value is `true`. Every write attempt writes one audit line, to stderr or to the file in `MALCOLM_MCP_AUDIT_FILE`. The [security page](https://github.com/nagameTW/mcp-server-malcolm/blob/main/docs/security.md) describes the model.

## Tools

The server has 51 read tools. They cover Malcolm filter queries, aggregation, field lookup, Arkime sessions and packets, NetBox, Zeek file scans, saved objects and alerting monitors. The [tools page](https://github.com/nagameTW/mcp-server-malcolm/blob/main/docs/tools.md) lists them all.

The tool schemas use about 34,000 tokens in every session. To save tokens, set `MALCOLM_MCP_DISABLE_READ_GROUPS` to the groups you do not need. For example, `netbox,dashboards,detections,arkime-inventory` leaves 34 tools. See [Trimming the read surface](https://github.com/nagameTW/mcp-server-malcolm/blob/main/docs/tools.md#trimming-the-read-surface).

## Non-goals

Version 1 leaves these out on purpose:

- Destructive writes (Arkime session delete, tag removal, user management).
- Raw OpenSearch write or raw NetBox CRUD passthrough, behind a flag or otherwise.
- The `streamable-http` transport (stdio only).

## Repository structure

```
├── src/mcp_server_malcolm/    # The server
│   ├── server.py              #   Registers the tools, applies the write gate
│   ├── client.py              #   HTTP client for Malcolm
│   ├── config.py              #   Write-class flags
│   ├── audit.py               #   Audit output
│   └── tools/                 #   Read tools. Write tools are in write/
├── tests/                     # Tests
├── scripts/
│   └── api_parity_check.py    # Compares each tool with the Malcolm API
├── docs/
│   ├── install.md             #   Install, register, other install routes
│   ├── container.md           #   Run in a container
│   ├── configuration.md       #   Connection settings, every variable
│   ├── troubleshooting.md     #   The first call fails
│   ├── tools.md               #   Read tools, write tools, trimming
│   ├── security.md            #   Security model, audit
│   ├── usage.md               #   Demo, filter syntax, examples
│   ├── python.md              #   Use the client from Python
│   ├── design.md              #   Why an MCP layer, protocol notes
│   ├── verification.md        #   Parity check, tested platforms, API endpoints
│   └── zh-TW/                 #   Copy of these pages for README.zh-TW.md
├── Dockerfile                 # Container image
├── server.json                # MCP Registry manifest
├── SECURITY.md                # Report a vulnerability
├── CONTRIBUTING.md            # How to contribute
└── CHANGELOG.md               # Changes per version
```

## Development

```bash
pip install -e . pytest pytest-asyncio ruff
ruff check src tests
ruff format --check src tests
pytest
```

The tests do not need a Malcolm instance. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
