# Tools

## Read tools

All of these are registered by default — none of them needs a flag turned on. They can be dropped a group at a time; see [Trimming the read surface](#trimming-the-read-surface) for which tools each group holds.

### DSL core (raw OpenSearch)

Plain OpenSearch DSL sent through Malcolm's `/mapi/opensearch` proxy, with no Malcolm filter syntax in between. Use these when a Malcolm filter cannot express the query. They need Malcolm's proxy, so they do not work against a bare OpenSearch node.

| Tool | Description |
|------|-------------|
| `search_dsl` | Run a raw OpenSearch DSL query (hits + aggregations, no hidden time window, at most 500 buckets per aggregation level) |
| `count` | Count documents matching a DSL query clause |
| `list_indices` | List indices (name/health/status/doc count) |
| `index_mapping` | Field mapping/schema for an index |
| `cluster_health` | OpenSearch cluster health |

### Core query

| Tool | Description |
|------|-------------|
| `malcolm_search` | Search network traffic with Malcolm filter syntax |
| `malcolm_aggregate` | Aggregate traffic by one or more fields (top-N with counts) |
| `malcolm_alerts` | Search Suricata alerts by signature, severity, IP; one compact row per alert |

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
| `arkime_sessions_csv` | Export sessions as a compact CSV table — far fewer tokens than the same rows as JSON |
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

Arkime's `connections.csv` is deliberately not wrapped: on Malcolm's public training instance it emits a nine-column header over seven-column rows, so every column after the second is mislabeled. `arkime_connections` answers the same question correctly.

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
| `malcolm_saved_objects` | Find the dashboards, visualizations and saved searches this Malcolm ships, without their multi-KB layout blobs |
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
- **arkime-view**: `arkime_create_view` saves a named search expression and `arkime_create_shortcut` saves a named value list (IOC set) referenced in expressions as `$name`. Both are additive — they let an agent persist hunting knowledge for analysts, and neither deletes or overwrites.

Every write tool carries the MCP annotation `readOnlyHint: false`, so an MCP client can apply its own confirmation step before the call runs. `destructiveHint` is `false` on every additive write and `true` on the one exception, `arkime_cancel_hunt`, which stops in-progress work rather than adding to it.

## Enabling write tools

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

The full flag list is in [Configuration reference](configuration.md#configuration-reference).

## Trimming the read surface

All 51 read tools are on by default, and their schemas are about 34,000 tokens that every session pays before the model has asked anything. That is affordable on a large frontier model and expensive on a model with a small context window. It is also partly wasted: a Malcolm without NetBox will never answer a `malcolm_netbox_*` call, and plenty of deployments have no interest in handing an agent the OpenSearch alerting configuration.

`MALCOLM_MCP_DISABLE_READ_GROUPS` takes a comma-separated list of groups to leave unregistered. A disabled group is not hidden — its tools are absent from `tools/list`, exactly as a disabled write class is.

| Group | Tools | Schema tokens | Covers |
| --- | --- | --- | --- |
| `dsl` | 5 | ~2,440 | Raw OpenSearch: `search_dsl`, `count`, index and cluster metadata |
| `query` | 3 | ~2,600 | `malcolm_search`, `malcolm_aggregate`, `malcolm_alerts` |
| `fields` | 3 | ~1,750 | Field discovery — the anti-hallucination layer |
| `health` | 4 | ~1,650 | Service status, data coverage, ping, dashboard export |
| `netbox` | 3 | ~1,370 | NetBox asset lookup |
| `arkime` | 11 | ~8,060 | Arkime session search and the SPI analysis endpoints |
| `arkime-content` | 5 | ~3,200 | PCAP, payload and file-by-hash extraction |
| `correlation` | 1 | ~620 | `malcolm_related_sessions` |
| `files` | 2 | ~2,160 | Zeek file scans and extracted-file fetch |
| `arkime-inventory` | 7 | ~4,260 | Saved views, shortcuts, crons, capture-node stats, hunt status |
| `dashboards` | 2 | ~1,880 | OpenSearch Dashboards saved objects |
| `detections` | 5 | ~4,150 | Alerting monitors and anomaly detectors |
| **Total** | **51** | **~34,150** | |

Dropping the four groups a metadata-only hunt rarely reaches for takes the session from 51 tools to 34, and the schema bill from ~34,150 tokens to ~22,510:

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

That makes `arkime` the largest group (~8,060 tokens) and the one a deployment usually has to keep. `MALCOLM_MCP_DISABLE_TOOLS` removes single read tools by name, applied after the groups, for what is left over inside a group that has to stay:

```bash
-e MALCOLM_MCP_DISABLE_READ_GROUPS=netbox,dashboards,detections
-e MALCOLM_MCP_DISABLE_TOOLS=arkime_spiview,arkime_spigraphhierarchy,arkime_multiunique
```

```
[mcp-server-malcolm] read tools disabled: arkime_multiunique, arkime_spigraphhierarchy, arkime_spiview
```

Names are exact tool names as `tools/list` shows them. A name that is not a registered read tool aborts startup: a typo, a tool whose group is already disabled, or a write tool, which only its `MALCOLM_MCP_ENABLE_*` flag controls. The per-tool list does not know which tools feed which. Keeping `arkime_session_detail` while dropping `arkime_sessions` is allowed, and leaves a tool with no way to get its input, so reach for groups first and use this for the remainder.
