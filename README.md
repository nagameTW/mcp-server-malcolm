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

It gives any MCP-compatible AI agent structured access to Malcolm: search and aggregate network traffic, discover field names, query Suricata alerts, browse Arkime sessions, resolve NetBox assets, and check system health. Turn on the write classes and it can also create alerts, tag sessions, launch hunts, and upload PCAP. It is read-only until you turn one on.

## Contents

- [Why an MCP layer](#why-an-mcp-layer)
- [Quick start](#quick-start)
  - [1. Install](#1-install)
  - [2. Register it with your client](#2-register-it-with-your-client)
  - [3. Connection settings](#3-connection-settings)
  - [4. Enabling write tools (optional)](#4-enabling-write-tools-optional)
  - [Other ways to install](#other-ways-to-install)
- [Read-only until you opt in](#read-only-until-you-opt-in)
- [Read tools](#read-tools)
- [Write tools (opt-in)](#write-tools-opt-in)
- [Trimming the read surface](#trimming-the-read-surface)
- [Security model](#security-model)
- [Audit](#audit)
- [Python (direct import)](#python-direct-import)
- [Malcolm filter syntax](#malcolm-filter-syntax)
- [Examples](#examples)
- [Protocol notes](#protocol-notes)
- [Configuration reference](#configuration-reference)
- [Verifying against your own Malcolm](#verifying-against-your-own-malcolm)
- [Malcolm API endpoints used](#malcolm-api-endpoints-used)
- [Non-goals](#non-goals)
- [License](#license)

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

## Quick start

You don't write any code to use this. An MCP client (Claude Code, Claude Desktop, Cursor, …) launches the server as a subprocess and talks to it over stdio; your job is to tell the client how to launch it and which credentials to inject.

Every command in this chapter was run as printed, on Linux/aarch64 (kernel 6.14, Python 3.11.14 and 3.14.6) against a live Malcolm v26.07.1, and the error text is verbatim. The install in §1, its check, and the Claude Code registration in §2 were run a second time on macOS 26/arm64 with Python 3.14.6, against a live Malcolm 25.12.1. Where something was reasoned from source rather than executed, or was left untested (x86_64 hosts, GUI MCP clients, four of the five write classes), it says so at that point.

### 1. Install

You need Python 3.11 or newer, a Malcolm instance with API access, and an HTTPS route to it.

```bash
pip install mcp-server-malcolm      # published release
```

Check the install by starting the server with stdin closed. It prints its write-class banner, reaches EOF, and exits 0:

```bash
$ mcp-server-malcolm < /dev/null
[mcp-server-malcolm] write classes: alerting=off arkime-tag=off hunt-job=off pcap-upload=off arkime-view=off
$ echo $?
0
```

Nothing has to be configured for the process to start. Connection settings are read at startup but not used until a tool calls Malcolm, so a wrong URL or password surfaces as a failing tool call, not a failed launch.

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

Everything after `--` is the launch command; each `-e` is an environment variable injected into it. `claude mcp add --help` gives the signature as `claude mcp add [options] <name> <commandOrUrl> [args...]`, with `-e, --env <env...>` and `-s, --scope <scope>`.

Registering, health-checking and removing a server, run end to end:

```bash
$ claude mcp add malcolm-deploy-test -s local \
    -e MALCOLM_URL=https://malcolm.example \
    -e MALCOLM_USERNAME=analyst \
    -e MALCOLM_PASSWORD='your-password' \
    -e MALCOLM_SSL_VERIFY=false \
    -- /tmp/mcp-malcolm-deploy/venv/bin/mcp-server-malcolm
Added stdio MCP server malcolm-deploy-test with command: … to local config

$ claude mcp list
Checking MCP server health…
malcolm-deploy-test: /tmp/mcp-malcolm-deploy/venv/bin/mcp-server-malcolm  - ✔ Connected

$ claude mcp remove malcolm-deploy-test -s local
Removed MCP server malcolm-deploy-test from local config
```

Pick where the entry is stored with `-s`:

| Scope | Stored in | Use for |
| --- | --- | --- |
| `local` (default) | your own settings, this project only | credentials — nothing is committed |
| `user` | your own settings, every project | a Malcolm you use everywhere |
| `project` | `.mcp.json` at the repo root, **committed to git** | sharing with a team — never put a password here |

The password in that command is a literal, so it goes into your shell history, and for as long as `claude mcp add` runs it sits in `ps` where every other process on the host can read it. Read it in first and pass the variable:

```bash
read -rs MALCOLM_PASSWORD && export MALCOLM_PASSWORD
claude mcp add malcolm \
  -e MALCOLM_URL=https://malcolm.example \
  -e MALCOLM_USERNAME=analyst \
  -e MALCOLM_PASSWORD="$MALCOLM_PASSWORD" \
  -- mcp-server-malcolm
```

`read -rs` keeps the typing off the screen, and the shell records the unexpanded `"$MALCOLM_PASSWORD"`, so history holds the variable name instead of the secret. The `ps` window during the `add` itself stays open, the same way `docker inspect` keeps a container's copy readable. Either route ends with the password in cleartext in `~/.claude.json`, mode 0600 on the machine this was checked on, so file permissions are the only thing protecting it there.

`claude mcp get malcolm` prints the registered command and environment. Note that it prints `MALCOLM_PASSWORD` in cleartext, unmasked, so don't run it where the terminal is being recorded or shared.

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

That exact block was verified by driving its `command` and `env` fields through the MCP Python SDK's own `stdio_client` and `ClientSession`, which is what a generic client does with them. No GUI client was launched here: Claude Desktop reads `claude_desktop_config.json` and other clients vary, per their own docs, which this project has not independently confirmed.

If `mcp-server-malcolm` isn't on the `PATH` your client sees (common with a virtualenv), give the absolute path to the executable instead: `/path/to/.venv/bin/mcp-server-malcolm`.

### 3. Connection settings

Defaults below are what `MalcolmClient.from_env` reads (`client.py:294-304`).

| Variable | Default | Notes |
| --- | --- | --- |
| `MALCOLM_URL` | `https://localhost` | Malcolm base URL, e.g. `https://malcolm.example` |
| `MALCOLM_USERNAME` | `admin` | Basic-auth user |
| `MALCOLM_PASSWORD` | `admin` | Basic-auth password |
| `MALCOLM_SSL_VERIFY` | `true` | `true`, `false`, or a path to a CA bundle (anything that isn't `true`/`false` is passed to httpx as a CA path) |
| `MALCOLM_TIMEOUT` | `30` | HTTP timeout, seconds |
| `MALCOLM_MAX_CONCURRENCY` | `8` | Simultaneous upstream requests |
| `MALCOLM_MAX_REQUESTS_PER_MINUTE` | `600` | Upstream request-rate cap |

The `https://localhost` and `true` defaults were confirmed by running with the variable unset and observing the request that came out. The `admin`/`admin` credential defaults come from reading `client.py:296-297`: unsetting all three connection variables produced a 401 against `https://localhost`, which proves the URL default and proves the credentials are wrong for that lab, not that they are literally `admin`. The 30-second timeout is likewise a source read — an attempt to time it against a non-routable address returned in about 5 seconds, because the OS-level connect failure fired first, so the 30-second path was never exercised.

On TLS: verification is on by default, and Malcolm ships self-signed certs. Pointing `MALCOLM_SSL_VERIFY` at Malcolm's CA bundle only works if Malcolm's server certificate carries a `subjectAltName` matching the hostname you connect to — the certificate generated by Malcolm's own setup has no SAN extension, so verification fails against it even with the right CA. For a remote Malcolm, install a certificate with a correct SAN. `MALCOLM_SSL_VERIFY="false"` disables verification entirely and is only acceptable against an isolated localhost lab; over a network it would send credentials and query results down an unauthenticated channel.

#### When the first call fails

Three failures account for nearly every first run. All three were reproduced with `malcolm_ping`; the text is verbatim.

**Self-signed certificate with `MALCOLM_SSL_VERIFY` unset.** This is the most likely one, because the default is verify-on and a stock Malcolm's certificate does not pass verification:

```
Error executing tool malcolm_ping: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1082)
```

The `_ssl.c` line number tracks your interpreter, not this server: the same failure reads `_ssl.c:1016` on Python 3.11, which is what the Docker image and the CI floor both run.

The message never names `MALCOLM_SSL_VERIFY`, so it is easy to read as a broken install. Fix it by installing a certificate with a correct SAN and pointing `MALCOLM_SSL_VERIFY` at its CA bundle, or, on an isolated lab only, by setting `MALCOLM_SSL_VERIFY=false`.

**Wrong password.** Clear and actionable — the status and the URL are both in the message:

```
Error executing tool malcolm_ping: Client error '401 Unauthorized' for url 'https://malcolm.example/mapi/ping'
For more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/401
```

**Unreachable host** (typo'd `MALCOLM_URL`, firewalled port, wrong scheme):

```
Error executing tool malcolm_ping: ConnectTimeout for https://192.0.2.99:9999/mapi/ping
```

The two unreachable cases read differently. A port that actively refuses the connection answers `All connection attempts failed`; a host that simply never replies raises `ConnectTimeout`, whose `str()` httpx leaves empty — up to 1.0.1 that reached the caller as a bare `Error executing tool malcolm_ping: ` with nothing after the colon. The exception name and target are filled in now. Credentials embedded in `MALCOLM_URL` are stripped from that URL before it is shown.

### 4. Enabling write tools (optional)

All five write classes are off unless you set their flag, so the default install is read-only. Add the flags to the same `-e` / `env` block:

```bash
-e MALCOLM_MCP_ENABLE_ALERTING=true
-e MALCOLM_MCP_AUDIT_FILE=/var/log/malcolm-mcp-audit.jsonl
```

A disabled class is not registered rather than hidden, so the change shows up in `tools/list`. Counting the tools an MCP session sees, with nothing else changed:

```
env unmodified                          tool count: 51
MALCOLM_MCP_ENABLE_ARKIME_TAGS=true     tool count: 52   (new: arkime_add_tags)
```

Only `arkime_tags` was toggled and counted this way. The other four classes route through the identical `if cfg.<flag>:` gate in `tools/__init__.py::register_write_tools`, so the same behaviour follows from the code, but it was not separately measured.

A flag counts as on only for the exact string `true`, case-insensitive (`config.py:15`); anything else, including `1` and `yes`, leaves the class off. The startup banner is the check.

The full flag list is in [Configuration reference](#configuration-reference).

### Other ways to install

`pip install mcp-server-malcolm` and bare `uvx mcp-server-malcolm` install the latest published release. A version number alone cannot tell you whether a checkout matches it — a tree carrying unreleased changes still reports the version of the last release — so install from source when you specifically want the code documented in this tree.

From a checkout:

```bash
git clone https://github.com/nagameTW/mcp-server-malcolm.git
cd mcp-server-malcolm
pip install -e .
```

Or build a wheel and install it into a clean virtualenv, which is the path the commands in this chapter were verified through:

```bash
$ uv build --out-dir /tmp/mcp-malcolm-deploy/dist
Successfully built /tmp/mcp-malcolm-deploy/dist/mcp_server_malcolm-1.1.1.tar.gz
Successfully built /tmp/mcp-malcolm-deploy/dist/mcp_server_malcolm-1.1.1-py3-none-any.whl

$ python3 -m venv /tmp/mcp-malcolm-deploy/venv
$ /tmp/mcp-malcolm-deploy/venv/bin/pip install \
    /tmp/mcp-malcolm-deploy/dist/mcp_server_malcolm-1.1.1-py3-none-any.whl
```

That pulls 32 packages, most of them from `mcp>=2,<3` (resolved to `mcp 2.0.0`). The wheel itself is `py3-none-any`, pure Python; the compiled dependencies (`cryptography`, `pydantic-core`, `rpds-py`, `cffi`) all installed from prebuilt `manylinux_*_aarch64` wheels here, nothing compiled from source. PyPI publishes the same wheels for x86_64 and macOS. The macOS side has since been installed: 32 packages again, every compiled dependency from a prebuilt `macosx_11_0_arm64` wheel, nothing built from source, on Python 3.14.6. No install was run on x86_64, so treat that one as unverified.

To run this branch without installing it anywhere permanent, point `uvx` or `pipx` at the checkout:

```bash
uvx --from /path/to/mcp-server-malcolm mcp-server-malcolm
pipx run --spec /path/to/mcp-server-malcolm mcp-server-malcolm
```

### Running it by hand

Only useful for troubleshooting. A stdio MCP server has no interactive interface: started from a terminal it sits silently waiting for JSON-RPC on stdin, which is what a working server looks like. It does print the enabled write classes to stderr on startup, so this confirms the flags took effect. Both entry points behave identically:

```bash
$ mcp-server-malcolm
[mcp-server-malcolm] write classes: alerting=off arkime-tag=off hunt-job=off pcap-upload=off arkime-view=off

$ python -m mcp_server_malcolm
[mcp-server-malcolm] write classes: alerting=off arkime-tag=off hunt-job=off pcap-upload=off arkime-view=off
```

### Running it in a container

The repository ships a `Dockerfile` that installs the package from the build context and runs it as a non-root user:

```bash
$ docker build -t mcp-server-malcolm:local -f Dockerfile .
$ docker run --rm --entrypoint id mcp-server-malcolm:local
uid=10001(app) gid=10001(app) groups=10001(app)
```

The build took 23.7s cold and produced a 205MB image on `python:3.11-slim` (Debian 13 trixie). It is single-architecture: a plain `docker build` on this aarch64 host produced `linux/arm64` only, which will not run on an x86_64 host without emulation. A multi-architecture image would need `docker buildx build --platform linux/amd64,linux/arm64`; that was not attempted, and this Dockerfile does not produce one.

Point the client at `docker run -i --rm …` as the launch command:

```bash
docker run -i --rm --network host \
  -e MALCOLM_URL -e MALCOLM_USERNAME -e MALCOLM_PASSWORD -e MALCOLM_SSL_VERIFY \
  mcp-server-malcolm:local
```

`-e VAR` with no `=value` inherits the value from the invoking shell, so the password is never part of the command string and never lands in `ps` output or shell history. It is still readable afterwards through `docker inspect`, as below.

How the container reaches Malcolm decides whether anything works at all:

| Reaching Malcolm | Flags | Result |
| --- | --- | --- |
| Host loopback, URL unchanged | `--network host` | Works. `https://localhost` inside the container is the host's loopback. |
| Bridge network | none | Fails: `All connection attempts failed`. `localhost` is the container itself. The underlying errno 111 stays inside the exception chain and never reaches the client. |
| Bridge network | `--add-host=host.docker.internal:host-gateway`, `MALCOLM_URL=https://host.docker.internal` | Works. `host.docker.internal` is not auto-registered on Linux the way it is on Docker Desktop; the explicit `--add-host` is what makes it resolve (Docker 20.10+; tested on 28.5.1). |

Both working modes completed a full MCP session against the live Malcolm: `initialize`, `tools/list` returning 51 tools, and two tool calls (`malcolm_ping` → `pong`, `count` → 202,531 `conn` sessions). `MALCOLM_SSL_VERIFY` at its `true` default failed inside the container for the same self-signed-certificate reason it fails outside one.

On credentials: `docker inspect <container> --format '{{json .Config.Env}}'` prints `MALCOLM_PASSWORD` in cleartext, and does so regardless of whether the value was passed as `-e VAR`, `-e VAR=value`, or `--env-file` — Docker stores the resolved environment in the container's metadata either way. Anyone with Docker daemon or socket access can read the Malcolm password back out for as long as the container object exists. There is no `MALCOLM_PASSWORD_FILE`-style secrets-file input; `client.py:297` reads the environment variable and nothing else. Keeping containers ephemeral (`--rm`, one per client session, which is the model a stdio server already implies) shortens the window without closing it.

`MALCOLM_MCP_ENABLE_PCAP_UPLOAD` is the one feature that needs a bind mount, since `malcolm_upload_pcap` reads a file that must already sit inside `MALCOLM_MCP_UPLOAD_DIR`. The host directory mounted there has to be readable by uid 10001 inside the container. That requirement is read from `tools/write/pcap_upload.py`, not exercised — the write classes stayed off throughout this testing.

## Read-only until you opt in

With no configuration, this server exposes read tools only. It behaves like a read-only client, and nothing it does can change data in Malcolm.

The server splits write access into five classes, each behind its own environment flag and each off by default. It doesn't register a disabled class, so that class's tools never appear in `list_tools()` and can't be called. At startup it prints which classes are on:

```
[mcp-server-malcolm] write classes: alerting=off arkime-tag=off hunt-job=off pcap-upload=off arkime-view=off
```

Every write but one is additive: the exception is `arkime_cancel_hunt`, which stops a hunt job in progress rather than adding to it. None of them deletes data, removes a tag, or touches a user account — those stay out on purpose (see [Non-goals](#non-goals)).

## Read tools

All of these are registered by default — none of them needs a flag turned on. They can be dropped a group at a time; see [Trimming the read surface](#trimming-the-read-surface) for which tools each group holds.

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
| `arkime_sessions_summary` | Total sessions, bytes and packets for an expression, plus per-field breakdowns — size a match before something expensive (like a hunt) acts on it |
| `arkime_session_detail` | Fetch all fields (full SPI document) for one session |
| `arkime_session_pcap` | Fetch a session's PCAP and report its size and file-magic validity (metadata only, nothing written to disk) |
| `arkime_session_payload` | Read a session's decoded payload — the bytes that crossed the wire, not parsed fields (plain text, not JSON) |
| `arkime_session_file_by_hash` | Fetch the file ONE named session carried, by md5/sha256 (metadata only, nothing written to disk) — pins the answer to that session, unlike `arkime_file_by_hash`, which serves the most recent match across every session |
| `arkime_unique` | List distinct values of one field, with optional counts |
| `arkime_multiunique` | Unique value combinations across several fields (e.g. src.ip + dst.port pairs) |
| `arkime_spigraph` | Top values of one field with a time-series graph |
| `arkime_spiview` | Value profile across several fields in one call |
| `arkime_spigraphhierarchy` | Hierarchical top-N breakdown across fields (nested drill-down) |
| `arkime_connections` | Source/destination connection graph (nodes and links) |
| `arkime_file_by_hash` | Extract the transferred file whose md5/sha256 matches (metadata only, nothing written to disk) |
| `arkime_sessions_csv` | Export sessions as a compact CSV table — about half the tokens of the same rows as JSON |
| `arkime_build_query` | Compile an Arkime expression into the OpenSearch DSL it becomes, without running it — hand the result to `search_dsl` for a clause Arkime's syntax can't express |

### Arkime saved objects and capture health

| Tool | Description |
|------|-------------|
| `arkime_views` | List the saved search views the team curated, with each one's expression |
| `arkime_shortcuts` | List named value lists (IOC sets) and what each holds, plus the `$name` token to use in an expression |
| `arkime_crons` | List Arkime's cron queries — saved expressions that re-run on a schedule and explain where an unrecognized session tag came from |
| `arkime_reverse_dns` | Reverse-resolve one IP to its PTR hostname |
| `arkime_pcap_files` | List the PCAP files Arkime has indexed, with each file's size, packet/session counts and time span |
| `arkime_node_stats` | Capture-node health: dropped packets, disk, memory, queues — warns when a node is losing packets, since that turns a gap into what looks like an absence |
| `arkime_hunt_status` | List Arkime hunt jobs and their progress — queued, running or finished. Not gated by a write class: it only reads job status, so it stays available with every write class off (it is part of the `arkime-inventory` read group) |

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
| `malcolm_saved_object_detail` | Read one saved object's query, filters and index pattern already resolved — recovers the KQL/Lucene string behind a saved search or visualization |
| `malcolm_dashboard_export` | Export an OpenSearch Dashboards saved object as JSON |
| `malcolm_alerting_monitors` | List OpenSearch alerting monitors, what each watches, and whether any have fired — flags when every monitor is disabled |
| `malcolm_alerting_alerts` | List what OpenSearch alerting monitors have actually fired, in any lifecycle state (ACTIVE, ACKNOWLEDGED, COMPLETED, ERROR, DELETED) |
| `malcolm_alerting_monitor_detail` | Read one alerting monitor's full query and trigger conditions — tells a monitor watching nothing from one that is simply quiet |
| `malcolm_anomaly_detectors` | List anomaly detectors, what each models, and how many anomalies exist — flags when none were ever recorded |
| `malcolm_anomaly_results` | Read which entities one anomaly detector scored as anomalous in a time window, worst first — the window is epoch MILLISECONDS, unlike every `arkime_*` tool |

The 15 tools that build their own rows — the file, Arkime-inventory and Dashboards ones — declare a typed return, so a client receives `structuredContent` as well as the text. The rest pass an upstream response through verbatim and have no shape to declare.

## Write tools (opt-in)

Each class is enabled by setting its flag to `true`. Nothing here runs unless you ask for it.

| Class | Flag | Tools | Endpoint |
|-------|------|-------|----------|
| alerting | `MALCOLM_MCP_ENABLE_ALERTING` | `malcolm_create_alert` | `POST /mapi/event` |
| arkime-tag | `MALCOLM_MCP_ENABLE_ARKIME_TAGS` | `arkime_add_tags` | `POST /arkime/api/sessions/addtags` |
| hunt-job | `MALCOLM_MCP_ENABLE_HUNT_JOBS` | `arkime_create_hunt`, `arkime_cancel_hunt` | `POST /arkime/api/hunt`, `PUT /arkime/api/hunt/<id>/cancel` |
| pcap-upload | `MALCOLM_MCP_ENABLE_PCAP_UPLOAD` | `malcolm_upload_pcap` | `POST /server/php/submit.php` |
| arkime-view | `MALCOLM_MCP_ENABLE_ARKIME_VIEWS` | `arkime_create_view`, `arkime_create_shortcut` | `POST /arkime/api/view`, `POST /arkime/api/shortcut` |

- **alerting**: `malcolm_create_alert` indexes an analyst- or agent-generated finding as an alert document you can see in Malcolm's dashboards. It uses `/mapi/event`, Malcolm's own purpose-built write endpoint, which is the template the other classes follow.
- **arkime-tag**: `arkime_add_tags` adds tags to sessions. It only adds; tag removal needs a higher Arkime role and its own safety design, so it's deferred.
- **hunt-job**: `arkime_create_hunt` launches a cross-PCAP packet search (expensive, so scope the query first). `arkime_cancel_hunt` stops one that is queued or running — not additive, since a cancelled scan can't resume. Job progress is read with `arkime_hunt_status`, which is a read tool now and stays available with this class off (see [Arkime saved objects and capture health](#arkime-saved-objects-and-capture-health)).
- **pcap-upload**: `malcolm_upload_pcap` sends a local capture file to Malcolm for ingestion, with a client-side size cap. The file must live inside `MALCOLM_MCP_UPLOAD_DIR`; if that staging directory is unset, uploads are refused, so the tool can never be steered into reading an arbitrary file off the host.
- **arkime-view**: `arkime_create_view` saves a named search expression and `arkime_create_shortcut` saves a named value list (IOC set) referenced in expressions as `$name`. Both are additive — they let an agent persist hunting knowledge for the human team, and neither deletes or overwrites.

Every write tool carries the MCP annotation `readOnlyHint: false`, so an MCP client can apply its own confirmation step before the call runs. `destructiveHint` is `false` on every additive write and `true` on the one exception, `arkime_cancel_hunt`, which stops in-progress work rather than adding to it.

## Trimming the read surface

All 51 read tools are on by default, and their schemas are about 34,000 tokens that every session pays before the model has asked anything. That is affordable on a large frontier model and expensive on a small local one. It is also partly wasted: a Malcolm without NetBox will never answer a `malcolm_netbox_*` call, and plenty of deployments have no interest in handing an agent the OpenSearch alerting configuration.

`MALCOLM_MCP_DISABLE_READ_GROUPS` takes a comma-separated list of groups to leave unregistered. A disabled group is not hidden — its tools are absent from `tools/list`, exactly as a disabled write class is.

| Group | Tools | Schema tokens | Covers |
| --- | --- | --- | --- |
| `dsl` | 5 | ~2,300 | Raw OpenSearch: `search_dsl`, `count`, index and cluster metadata |
| `query` | 3 | ~2,350 | `malcolm_search`, `malcolm_aggregate`, `malcolm_alerts` |
| `fields` | 3 | ~1,780 | Field discovery — the anti-hallucination layer |
| `health` | 4 | ~1,730 | Service status, data coverage, ping, dashboard export |
| `netbox` | 3 | ~1,370 | NetBox asset lookup |
| `arkime` | 11 | ~8,450 | Arkime session search and the SPI analysis endpoints |
| `arkime-content` | 5 | ~3,270 | PCAP, payload and file-by-hash extraction |
| `correlation` | 1 | ~630 | `malcolm_related_sessions` |
| `files` | 2 | ~2,160 | Zeek file scans and extracted-file fetch |
| `arkime-inventory` | 7 | ~4,330 | Saved views, shortcuts, crons, capture-node stats, hunt status |
| `dashboards` | 2 | ~1,890 | OpenSearch Dashboards saved objects |
| `detections` | 5 | ~4,210 | Alerting monitors and anomaly detectors |
| **Total** | **51** | **~34,470** | |

Dropping the four groups a metadata-only hunt rarely reaches for takes the session from 51 tools to 34, and the schema bill from ~34,470 tokens to ~22,690:

```bash
-e MALCOLM_MCP_DISABLE_READ_GROUPS=netbox,dashboards,detections,arkime-inventory
```

```
[mcp-server-malcolm] read groups disabled: arkime-inventory, dashboards, detections, netbox
```

The banner line appears only when something is disabled, so a tool that has gone missing is traceable to the flag that removed it. A name matching no group aborts startup rather than being ignored — a typo that silently left the group registered is the failure this check exists to prevent:

```
ValueError: MALCOLM_MCP_DISABLE_READ_GROUPS: unknown read group(s) netboxx. Valid names: arkime, arkime-content, ...
```

Two groups deserve a warning before you drop them. `fields` is what stops the model inventing field names, and the server's own instructions tell it to look every unfamiliar field up before querying; without that group the instructions describe tools that are not there. `arkime` carries `arkime_sessions`, the only search that returns a session ID, so disabling it also strips the input every `arkime-content` tool needs.

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

## Python (direct import)

`MalcolmClient` is usable on its own, with no MCP client, no server process and no `mcp` transport in the loop. `mcp_server_malcolm`'s `__all__` is `["MalcolmClient", "__version__"]`, and that one class carries 62 public methods covering the entire read surface. Everything in this section was run against a live Malcolm v26.07.1 from a wheel built from this tree.

Build a client either from the environment or from explicit arguments:

```python
import asyncio
from mcp_server_malcolm import MalcolmClient

async def main():
    client = MalcolmClient.from_env()          # reads MALCOLM_URL, MALCOLM_USERNAME, …
    # or:
    # client = MalcolmClient(
    #     base_url="https://malcolm.example",
    #     username="analyst",
    #     password="…",
    #     ssl_verify=False,
    # )
    try:
        # Malcolm filter dict
        hits = await client.search(
            filters={"event.dataset": "conn"},
            limit=5,
        )

        # Top values of a field, over one 24-hour window
        agg = await client.aggregate(
            fields="destination.port",
            filters={"event.dataset": "conn"},
            limit=5,
            time_from="1714003200",
            time_to="1714089600",
        )

        # Check a field name before trusting a query that returned nothing
        ok = await client.resolve_field("http.useragent")
        bad = await client.resolve_field("http.user_agent")

        # Arkime expression syntax, epoch-second window
        sessions = await client.arkime_sessions(
            expression="protocols==dns",
            limit=3,
            time_from="1714003200",
            time_to="1714089600",
        )
    finally:
        await client.close()

asyncio.run(main())
```

What those calls actually returned:

```
search()     keys: ['filter', 'range', 'results']
aggregate()  {'destination.port': {'buckets': [{'doc_count': 82147, 'key': 53},
                                               {'doc_count': 31271, 'key': 80},
                                               {'doc_count': 27911, 'key': 8080}, …]}}
resolve_field('http.useragent')   {'exists': True,  'field': 'http.useragent', 'type': 'string'}
resolve_field('http.user_agent')  {'exists': False, 'field': 'http.user_agent',
                                   'suggestion': 'http.useragent', 'type': 'string'}
arkime_sessions()  recordsTotal: 6030807  recordsFiltered: 310414
                   first session id: 3@240425:240425-zT5pQlD2hY2Gwyzziep8Vg
```

`search()` returns `{"filter", "range", "results"}` on this Malcolm version, with the hits under `results` and **no** top-level `total` key. Read the payload you actually get rather than assuming a shape.

**Closing the client is the caller's job.** `MalcolmClient` has `close()` but no `__aenter__`/`__aexit__`, so `async with MalcolmClient(...)` raises:

```
TypeError: 'mcp_server_malcolm.client.MalcolmClient' object does not support
the asynchronous context manager protocol (missed __aexit__ method)
```

Use `try`/`finally` as above. Dropping the last reference without closing leaves a real open socket to Malcolm, reclaimed only when the garbage collector gets to it, and the warning is silent under normal interpreter settings — it appears only under `python -W always -X dev`:

```
ResourceWarning: unclosed <socket.socket fd=6, family=2, type=1, proto=6, …>
```

**Errors.** Three exceptions, all with `MalcolmToolError` as their base:

```python
from mcp_server_malcolm.errors import MalcolmToolError, ToolInputError, UpstreamError
```

| Raised | When | What it carries |
| --- | --- | --- |
| `ToolInputError` | An argument fails the client's own validation, before any HTTP request | The offending value and the expected shape |
| `UpstreamError` with `.status` set | Malcolm answered with an HTTP error | Status code, plus the URL and status text |
| `UpstreamError` with `.status is None` | The request never completed (DNS, TLS, connect, timeout) | The status, and nothing else — see below |

Observed messages:

```
ToolInputError:  invalid field name: '../../arkime/api/hunts' — expected a Malcolm
                 field name such as 'source.ip' (letters, digits and _ . - @ [ ])
UpstreamError:   status=404  message=Client error '404 Not Found' for url
                 'https://malcolm.example/dashboards/api/saved_objects/search/00000000-…'
UpstreamError:   status=None message=
```

That last one is the library-side view of the empty error message described under [When the first call fails](#when-the-first-call-fails): `str(exc)` is the empty string. It was traced past this project's code to `httpx.ConnectTimeout.__str__()`, which is empty for the same host when called through a bare `httpx.AsyncClient`. Branch on `exc.status is None` to detect an unreachable host; the message will not tell you anything.

**Rate limiting holds, it does not raise.** `MALCOLM_MAX_CONCURRENCY` (default 8) and `MALCOLM_MAX_REQUESTS_PER_MINUTE` (default 600) also exist as the constructor arguments `max_concurrency` and `max_requests_per_minute`. With `max_requests_per_minute=2`, three sequential `ping()` calls completed at:

```
request 1  t+0.0s
request 2  t+0.0s
request 3  t+60.1s
```

with `[malcolm] rate cap reached, holding https://…/mapi/ping for 60.0s` on the DEBUG log. There is no rate-limit exception: past the cap, a call is indistinguishable from a slow one, so a per-call timeout tighter than the window will fire on what is really a queued request. The 60-second window itself is a module constant (`_RATE_WINDOW_SECONDS`), not configurable — only the request count inside it is. A non-positive constructor argument is rejected outright:

```
ValueError: max_concurrency must be a positive integer, got 0
ValueError: max_requests_per_minute must be a positive integer, got 0
```

The environment path is deliberately more forgiving: an absent, blank or unparseable value is logged and replaced with the default (`client.py:68-82`), so a typo in a deployment's env file cannot switch the limiter off.

**There is no supported write path for a library user.** All seven write primitives are private — `_write_event`, `_write_arkime_tags`, `_write_arkime_view`, `_write_arkime_shortcut`, `_write_arkime_hunt`, `_write_arkime_hunt_cancel`, `_write_upload_pcap` — and each is called from exactly one place under `tools/write/`, which a seam test enforces. No public method indexes an alert, tags a session, creates or cancels a hunt, saves a view or shortcut, or uploads a PCAP. Calling an underscore method directly performs the mutation while skipping the audit record that `tools/write/_common.py::run_write` writes around every write reached through the MCP layer, so writes belong to the tool layer, and the direct-import path is a read client.

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
# vocabulary. Lines come back as "exp | db | type | group", e.g.
# "ip.src | srcIp | ip | general".
arkime_field_search(keyword="src")
```

Which of those columns a parameter wants is decided per parameter, not per tool. Measured on Malcolm v26.07.1:

- **`exp`** (`ip.src`, `port.dst`, `protocols`) — every `expression` argument, plus the field lists of `arkime_unique`, `arkime_multiunique` and `arkime_spigraphhierarchy`. Those three reject a db name outright: `srcIp,dstIp` returned the body "Unknown expression srcIp" under HTTP 200 from multiunique and HTTP 403 from spigraphhierarchy.
- **`db`** (`srcIp`, `dstPort`, `node`) — `arkime_connections`' `src_field` and `dst_field`, and nothing else. `srcIp`/`dstIp` returned a 10-node graph there; `ip.src`/`dstIp` returned HTTP 403 and `srcIp`/`port.dst` HTTP 500.
- **The storage path** — what `arkime_spigraph`'s `field` and `arkime_spiview`'s `spi` take. It is the same string as the db column for 4,034 of this deployment's 4,051 fields; the other seventeen print a camelCase db alias and store under a dotted name (`srcIp` is `source.ip`, `dstPort` is `destination.port`, `totBytes` is `network.bytes`), and those two parameters want the dotted one.

A dotted storage path is also accepted wherever the exp column is: `destination.port` returned the same 10,000 unique lines as `port.dst`, while `dstPort` returned none. It is the one spelling that answers on every route.

The HTTP responses quoted above are what Arkime itself answers. You will not see them through these tools: the server now recognises a db name on an exp parameter and refuses it before the request leaves, with a message naming the counterpart — `'srcIp' is an Arkime db name; this parameter takes expression names … Did you mean 'ip.src'?`. They are quoted because they are why the guard exists.

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

## Protocol notes

This is what a client sees when it connects, and where the two protocol eras differ. None of it needs a decision from you; it is here for anyone driving the server from an SDK.

**What the client sees on connection.** This server answers both protocol eras, and which one you get is decided by your first request, not by any setting here. A client that opens with `initialize` gets the handshake era; a client whose first request carries the `io.modelcontextprotocol/protocolVersion` key in `_meta` gets the stateless 2026-07-28 era, with no handshake at all. The SDK routes this in `serve_dual_era_loop`; nothing in this project configures it.

With no write flags set, an `initialize` plus `tools/list` returns:

```
protocol_version: 2025-11-25
server_info:      name='mcp-server-malcolm' version='1.1.1'
capabilities:     prompts, resources (subscribe=false), tools — all list_changed=false
instructions:     3753 characters
tools:            51
prompts:          1  — hunt_workflow
resources:        2  — malcolm://fields/malcolm, malcolm://fields/arkime
```

2025-11-25 is the ceiling of the handshake era, not this server's ceiling: `initialize` does not exist at 2026-07-28, so measuring through it can only ever report the older number. A 2026-07-28 client sends no handshake and calls `server/discover` instead:

```
server/discover  capabilities: prompts, resources (subscribe=true), tools — all listChanged=true
                 cacheScope=private  ttlMs=0  resultType=complete
tools/list       51 tools, cacheScope=public ttlMs=3600000 resultType=complete
_meta on results io.modelcontextprotocol/serverInfo = {name: mcp-server-malcolm, version: 1.1.1}
```

The two eras disagree about `listChanged`, and the modern side is the one that overstates: the SDK advertises `listChanged=true` there, while this server registers everything once in `create_server()` and never emits a change notification. Harmless, because a list that cannot change cannot go unannounced, but do not build on the promise.

The Arkime resource served 724,261 characters covering 4,051 expression fields on this deployment. One caveat for anyone scripting against the SDK: `mcp` 2.x uses snake_case attributes (`protocol_version`, `server_info`, `is_error`), not the camelCase of the wire protocol and the 1.x SDK. A script written against `serverInfo`/`isError` raises `AttributeError`.

## Configuration reference

| Variable | Default | Description |
|----------|---------|-------------|
| `MALCOLM_URL` | `https://localhost` | Malcolm base URL |
| `MALCOLM_USERNAME` | `admin` | Basic auth username |
| `MALCOLM_PASSWORD` | `admin` | Basic auth password |
| `MALCOLM_SSL_VERIFY` | `true` | Verify TLS certs. `true`/`false`, or a CA-bundle path (use the path for self-signed Malcolm) |
| `MALCOLM_TIMEOUT` | `30` | HTTP request timeout (seconds) |
| `MALCOLM_MAX_CONCURRENCY` | `8` | Simultaneous upstream requests |
| `MALCOLM_MAX_REQUESTS_PER_MINUTE` | `600` | Upstream requests allowed per rolling 60s window; past the cap a request is held, not rejected |
| `MALCOLM_MCP_DISABLE_READ_GROUPS` | unset | Comma-separated read groups to leave unregistered; an unknown name aborts startup. See [Trimming the read surface](#trimming-the-read-surface) |
| `MALCOLM_MCP_ENABLE_ALERTING` | `false` | Enable the alerting write class |
| `MALCOLM_MCP_ENABLE_ARKIME_TAGS` | `false` | Enable additive session tagging |
| `MALCOLM_MCP_ENABLE_HUNT_JOBS` | `false` | Enable Arkime hunt create + status |
| `MALCOLM_MCP_ENABLE_PCAP_UPLOAD` | `false` | Enable PCAP upload (also needs `MALCOLM_MCP_UPLOAD_DIR`) |
| `MALCOLM_MCP_ENABLE_ARKIME_VIEWS` | `false` | Enable saved-view + shortcut (value-list) create |
| `MALCOLM_MCP_UPLOAD_DIR` | unset | Staging dir that files must live inside to be uploadable; unset ⇒ uploads refused |
| `MALCOLM_MCP_AUDIT_FILE` | unset | Write-audit file (stderr when unset) |

## Verifying against your own Malcolm

Every tool here reshapes what Malcolm returns — trimming, renaming, and in a few
places correcting it. `scripts/api_parity_check.py` proves that reshaping never
changes the facts: for each of the 51 tools it asks the same question twice, once
through a real MCP stdio session and once with a direct HTTP call to Malcolm, and
compares the values that carry meaning.

```bash
MALCOLM_URL=https://malcolm.example \
MALCOLM_USERNAME=... MALCOLM_PASSWORD=... \
PARITY_TIME_FROM=<epoch-seconds> PARITY_TIME_TO=<epoch-seconds> \
uv run --with mcp python scripts/api_parity_check.py
```

The time window matters: Arkime defaults to a recent one, so point it at a period
your deployment actually holds. The script exits non-zero if any tool disagrees
with the API, and also if a tool is exposed but has no comparison written for it —
so adding a tool without a parity check fails the run.

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
| `/dashboards/api/saved_objects/<type>/<id>` | GET | `malcolm_saved_object_detail` |
| `/mapi/opensearch/_plugins/_alerting/monitors/*` | POST, GET | `malcolm_alerting_monitors`, `malcolm_alerting_monitor_detail`, `malcolm_alerting_alerts` |
| `/mapi/opensearch/_plugins/_anomaly_detection/detectors/*` | POST, GET | `malcolm_anomaly_detectors`, `malcolm_anomaly_results` |
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
| `/arkime/api/session/<node>/<id>/packets` | GET | `arkime_session_payload` |
| `/arkime/api/session/<node>/<id>/bodyhash/<hash>` | GET | `arkime_session_file_by_hash` |
| `/arkime/api/sessions/summary` | POST | `arkime_sessions_summary` |
| `/arkime/api/buildquery` | POST | `arkime_build_query` |
| `/arkime/api/unique`, `/arkime/api/multiunique` | GET | `arkime_unique`, `arkime_multiunique` |
| `/arkime/api/spigraph` | GET | `arkime_spigraph` |
| `/arkime/api/spiview` | GET | `arkime_spiview` |
| `/arkime/api/spigraphhierarchy` | GET | `arkime_spigraphhierarchy` |
| `/arkime/api/connections` | GET | `arkime_connections` |
| `/arkime/api/sessions/bodyhash/<hash>` | GET | `arkime_file_by_hash` |
| `/arkime/api/sessions.csv` | GET | `arkime_sessions_csv` |
| `/arkime/api/views`, `/arkime/api/shortcuts` | GET | `arkime_views`, `arkime_shortcuts` |
| `/arkime/api/crons` | GET | `arkime_crons` |
| `/arkime/api/reversedns` | GET | `arkime_reverse_dns` |
| `/arkime/api/files` | GET | `arkime_pcap_files` |
| `/arkime/api/stats` | GET | `arkime_node_stats` |
| `/arkime/api/sessions/addtags` | POST | `arkime_add_tags` (write) |
| `/arkime/api/hunt` | POST | `arkime_create_hunt` (write) |
| `/arkime/api/hunt/<id>/cancel` | PUT | `arkime_cancel_hunt` (write) |
| `/arkime/api/hunts` | GET | `arkime_hunt_status` |
| `/arkime/api/view`, `/arkime/api/shortcut` | POST | `arkime_create_view`, `arkime_create_shortcut` (write) |
| `/extracted-files/<name>` | GET | `malcolm_extract_file` |
| `/server/php/submit.php` | POST | `malcolm_upload_pcap` (write) |

These endpoint paths and body shapes match Malcolm `26.07.1` and Arkime `6.6.0`. Both drift between releases, so re-check against your own version if a write tool returns an unexpected error.

## Non-goals

Version 1 leaves these out on purpose:

- Destructive writes (Arkime session delete, tag removal, user management).
- Raw OpenSearch write or raw NetBox CRUD passthrough, behind a flag or otherwise.
- The `streamable-http` transport (stdio only).

## License

MIT © nagameTW
