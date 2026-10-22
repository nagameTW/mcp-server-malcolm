# 驗證與 API 端點

## 對你自己的 Malcolm 做驗證

這裡每個工具都會重新整理 Malcolm 回來的東西——裁剪、改名，少數地方還會修正它。
`scripts/api_parity_check.py` 用來證明這些整理從來不會改變事實：51 個工具每一個都問同樣的問題兩次，
一次走真正的 MCP stdio 連線、一次直接對 Malcolm 發 HTTP，然後比對有意義的那些值。

```bash
MALCOLM_URL=https://malcolm.example \
MALCOLM_USERNAME=... MALCOLM_PASSWORD=... \
PARITY_TIME_FROM=<epoch-seconds> PARITY_TIME_TO=<epoch-seconds> \
uv run --with mcp python scripts/api_parity_check.py
```

時間範圍要給對：Arkime 預設只看近期，所以要指向你的部署實際持有資料的那段期間。
只要有任何工具跟 API 對不起來，腳本就會以非零狀態結束；工具有曝出來但沒有對應的比對項目時也一樣——
所以新增工具卻沒寫 parity check 會讓這個檢查失敗。

## 這些文件在哪裡測過

[安裝與註冊](install.md)裡的安裝和它的檢查指令，以及 Claude Code 註冊，都是在 macOS 26/arm64（Python 3.14.6）上照印出來的樣子跑過的，錯誤訊息一律原文照抄。[Python（直接 import）](python.md#python直接-import)那一節的呼叫，是對 Malcolm 公開的 training instance 跑的。[疑難排解](troubleshooting.md)裡的錯誤訊息和容器的說明，這次改版沒有重跑。凡是只從原始碼推論、沒有實際執行，或根本沒測到的（x86_64 主機、GUI 的 MCP 客戶端、五個 write class 裡的四個），都會在該處寫明。

## 用到的 Malcolm API 端點

| 端點 | 方法 | 使用者 |
|------|------|--------|
| `/mapi/document` | POST | `malcolm_search`、`malcolm_alerts`、`malcolm_related_sessions`、`malcolm_file_scans` |
| `/mapi/agg/<fields>` | POST | `malcolm_aggregate`、`malcolm_field_values`、`malcolm_field_profile`、`malcolm_data_coverage` |
| `/mapi/fields` | GET | `malcolm_field_search`、`malcolm_field_profile` |
| `/mapi/ready`、`/mapi/version` | GET | `malcolm_service_status` |
| `/mapi/ping` | GET | `malcolm_ping` |
| `/mapi/ingest-stats`、`/mapi/indices` | GET | `malcolm_data_coverage` |
| `/mapi/dashboard-export/<id>` | GET | `malcolm_dashboard_export` |
| `/dashboards/api/saved_objects/_find` | GET | `malcolm_saved_objects` |
| `/dashboards/api/saved_objects/<type>/<id>` | GET | `malcolm_saved_object_detail` |
| `/mapi/opensearch/_plugins/_alerting/monitors/*` | POST、GET | `malcolm_alerting_monitors`、`malcolm_alerting_monitor_detail`、`malcolm_alerting_alerts` |
| `/mapi/opensearch/_plugins/_anomaly_detection/detectors/*` | POST、GET | `malcolm_anomaly_detectors`、`malcolm_anomaly_results` |
| `/mapi/opensearch/<index>/_search` | POST | `search_dsl` |
| `/mapi/opensearch/<index>/_count` | POST | `count` |
| `/mapi/opensearch/_cat/indices` | GET | `list_indices` |
| `/mapi/opensearch/<index>/_mapping` | GET | `index_mapping` |
| `/mapi/opensearch/_cluster/health` | GET | `cluster_health` |
| `/mapi/netbox/*` | GET | `malcolm_netbox_lookup`、`malcolm_netbox_query` |
| `/mapi/netbox-sites` | GET | `malcolm_netbox_sites` |
| `/mapi/event` | POST | `malcolm_create_alert`（write） |
| `/arkime/api/fields` | GET | `arkime_field_search` |
| `/arkime/api/sessions` | GET | `arkime_sessions` |
| `/arkime/api/session/<id>` | GET | `arkime_session_detail` |
| `/arkime/api/sessions.pcap` | GET | `arkime_session_pcap` |
| `/arkime/api/session/<node>/<id>/packets` | GET | `arkime_session_payload` |
| `/arkime/api/session/<node>/<id>/bodyhash/<hash>` | GET | `arkime_session_file_by_hash` |
| `/arkime/api/sessions/summary` | POST | `arkime_sessions_summary` |
| `/arkime/api/buildquery` | POST | `arkime_build_query` |
| `/arkime/api/unique`、`/arkime/api/multiunique` | GET | `arkime_unique`、`arkime_multiunique` |
| `/arkime/api/spigraph` | GET | `arkime_spigraph` |
| `/arkime/api/spiview` | GET | `arkime_spiview` |
| `/arkime/api/spigraphhierarchy` | GET | `arkime_spigraphhierarchy` |
| `/arkime/api/connections` | GET | `arkime_connections` |
| `/arkime/api/sessions/bodyhash/<hash>` | GET | `arkime_file_by_hash` |
| `/arkime/api/sessions/addtags` | POST | `arkime_add_tags`（write） |
| `/extracted-files/<name>` | GET | `malcolm_extract_file` |
| `/arkime/api/sessions.csv` | GET | `arkime_sessions_csv` |
| `/arkime/api/views`、`/arkime/api/shortcuts` | GET | `arkime_views`、`arkime_shortcuts` |
| `/arkime/api/crons` | GET | `arkime_crons` |
| `/arkime/api/reversedns` | GET | `arkime_reverse_dns` |
| `/arkime/api/files` | GET | `arkime_pcap_files` |
| `/arkime/api/stats` | GET | `arkime_node_stats` |
| `/arkime/api/hunt` | POST | `arkime_create_hunt`（write） |
| `/arkime/api/hunt/<id>/cancel` | PUT | `arkime_cancel_hunt`（write） |
| `/arkime/api/hunts` | GET | `arkime_hunt_status` |
| `/arkime/api/view`、`/arkime/api/shortcut` | POST | `arkime_create_view`、`arkime_create_shortcut`（write） |
| `/server/php/submit.php` | POST | `malcolm_upload_pcap`（write） |

這些端點路徑和 body 結構是照 Malcolm 26.x 和 Arkime 6.x 寫的。兩者版本之間都會漂移，所以若某個 write 工具回傳非預期錯誤，拿你自己的版本重新核對。

## 收錄

[![mcp-server-malcolm MCP server](https://glama.ai/mcp/servers/nagameTW/mcp-server-malcolm/badges/card.svg)](https://glama.ai/mcp/servers/nagameTW/mcp-server-malcolm)
