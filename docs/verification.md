# Verification and API endpoints

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

## Where these docs were tested

The install and its check, and the Claude Code registration, in [Install and register](install.md) were run as printed on macOS 26/arm64 with Python 3.14.6, and the error text is verbatim. The direct-import calls under [Python (direct import)](python.md#python-direct-import) were run against Malcolm's public training instance. The failure messages in [Troubleshooting](troubleshooting.md) and the container notes were not re-run for this revision. Where something was reasoned from source rather than executed, or was left untested (x86_64 hosts, GUI MCP clients, four of the five write classes), it says so at that point.

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
| `/arkime/api/sessions` | GET | `arkime_sessions` |
| `/arkime/api/session/<id>` | GET | `arkime_session_detail` |
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

These endpoint paths and body shapes were written against Malcolm 26.x and Arkime 6.x. Both drift between releases, so re-check against your own version if a write tool returns an unexpected error.
