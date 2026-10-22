# 工具

## 讀取工具

以下全部預設註冊，不需要開任何 flag。要拿掉的話是以 group 為單位，每個 group 包含哪些工具見[精簡讀取工具](#精簡讀取工具)。

### DSL 核心（原生 OpenSearch）

透過 Malcolm 的 `/mapi/opensearch` proxy 送純 OpenSearch DSL，中間不經過 Malcolm 的 filter 語法。Malcolm filter 表達不了的查詢就用這組。它們要靠 Malcolm 的 proxy，所以不能直接接一台單獨的 OpenSearch。

| 工具 | 說明 |
|------|------|
| `search_dsl` | 執行原生 OpenSearch DSL 查詢（hits + aggregations，無隱藏時間窗，每層 aggregation 最多 500 個 bucket） |
| `count` | 計算符合 DSL query 子句的文件數 |
| `list_indices` | 列出 index（名稱/健康/狀態/文件數） |
| `index_mapping` | 取得 index 的欄位 mapping/schema |
| `cluster_health` | OpenSearch cluster 健康狀態 |

### 核心查詢

| 工具 | 說明 |
|------|------|
| `malcolm_search` | 用 Malcolm filter 語法搜尋網路流量文件 |
| `malcolm_aggregate` | 依一個或多個欄位聚合流量（Top-N 計數） |
| `malcolm_alerts` | 依 signature、severity、IP 搜尋 Suricata 告警，每筆告警回一列精簡資料 |

### 欄位探索（防幻覺）

| 工具 | 說明 |
|------|------|
| `malcolm_field_search` | 依關鍵字、前綴、型別搜尋可用欄位名稱 |
| `malcolm_field_values` | 列出欄位的所有不同值 |
| `malcolm_field_profile` | 顯示某欄位存在於哪些 `event.dataset` 類型 |
| `arkime_field_search` | 搜尋 Arkime **expression** 能用的欄位名稱（[Arkime](#arkime) 一節也有列） |

上面三個 `malcolm_*` 涵蓋的是 ECS 名稱，給 `malcolm_search`、`malcolm_aggregate` 和 DSL 工具用。凡是要放進 `expression` 參數的，得改用 `arkime_field_search`：Arkime 的 parser 只認 `ip.src`，會拒絕 `source.ip`，而 Malcolm 的 `/mapi/fields` 根本沒有列出 expression 名稱。

### 系統健康

| 工具 | 說明 |
|------|------|
| `malcolm_service_status` | 所有 Malcolm 服務的就緒狀態，加版本資訊 |
| `malcolm_data_coverage` | 各 sensor 資料新鮮度、各 dataset 文件數、index 資訊 |
| `malcolm_ping` | Malcolm API 的快速存活檢查 |

### 資產上下文（NetBox）

| 工具 | 說明 |
|------|------|
| `malcolm_netbox_lookup` | 查詢 IP、裝置或網段在 NetBox 的資料 |
| `malcolm_netbox_sites` | 列出 NetBox 站點目錄（id、名稱、metadata） |
| `malcolm_netbox_query` | 讀取其他 NetBox 端點（服務、VLAN、介面、VM、聯絡人） |

### Arkime

| 工具 | 說明 |
|------|------|
| `arkime_field_search` | 查詢 Arkime expression 能用的欄位名稱（`ip.src`、`port.dst`）——跟 `malcolm_field_search` 回傳的 ECS 名稱是兩套字彙 |
| `arkime_sessions` | 用 Arkime expression 語法搜尋 session |
| `arkime_sessions_summary` | 統計某個 expression 命中的 session、bytes、packets 總量，並依欄位列出細分——在跑貴的動作（例如 hunt）之前先估算範圍 |
| `arkime_session_detail` | 抓單一 session 的全部欄位（完整 SPI 文件） |
| `arkime_session_pcap` | 抓某 session 的 PCAP，回報大小與 magic 驗證結果（只回 metadata，不落地） |
| `arkime_session_payload` | 讀出某個 session 解碼後的 payload——線路上實際傳輸的位元組，不是解析後的欄位（純文字，不是 JSON） |
| `arkime_session_file_by_hash` | 依 md5/sha256 抓「這一個」session 帶的檔案（只回 metadata，不落地）——答案釘死在這個 session 上，跟會回傳最近一次相符 session 的 `arkime_file_by_hash` 不同 |
| `arkime_unique` | 列出某欄位的不重複值，可帶計數 |
| `arkime_multiunique` | 跨多個欄位的不重複值組合（例如 src.ip + dst.port 配對） |
| `arkime_spigraph` | 某欄位的 top 值加時序圖 |
| `arkime_spiview` | 一次看多個欄位的值分布 |
| `arkime_spigraphhierarchy` | 跨欄位的階層式 top-N 分解（巢狀 drill-down） |
| `arkime_connections` | 來源/目的連線圖（nodes 與 links） |
| `arkime_file_by_hash` | 依 md5/sha256 萃取傳輸過的檔案（只回 metadata，不落地） |
| `arkime_sessions_csv` | 把 session 匯出成精簡 CSV 表（同樣的資料，token 比 JSON 少得多） |
| `arkime_build_query` | 把 Arkime expression 編譯成它對應的 OpenSearch DSL，但不執行——把結果交給 `search_dsl`，處理 Arkime 語法表達不出來的子句 |

### Arkime 儲存物件與擷取健康度

| 工具 | 說明 |
|------|------|
| `arkime_views` | 列出團隊存下來的搜尋 view，附各自的 expression |
| `arkime_shortcuts` | 列出具名值清單（IOC 集合）與內容，並給出在 expression 裡引用的 `$name` |
| `arkime_crons` | 列出 Arkime 的 cron query——排程重跑的搜尋，用來解釋 session 上莫名其妙的 tag 是哪來的 |
| `arkime_reverse_dns` | 把單一 IP 反解成 PTR 主機名 |
| `arkime_pcap_files` | 列出 Arkime 已索引的 PCAP 檔，含大小、封包/session 數與時間範圍 |
| `arkime_node_stats` | 擷取節點健康度：丟包、磁碟、記憶體、佇列——節點正在丟包時會特別警告，因為那會讓「資料缺口」看起來像「沒有這種流量」 |
| `arkime_hunt_status` | 列出 Arkime hunt 作業與其進度——排隊中、執行中或已完成。不受 write class 管制：只讀作業狀態，所以就算 write class 全關也拿得到（它屬於 `arkime-inventory` 讀取 group） |

Arkime 的 `connections.csv` 刻意沒有包裝：在 Malcolm 公開的 training instance 上，它的表頭有 9 欄、資料列只有 7 欄，所以第二欄之後全部對錯位置。同樣的問題用 `arkime_connections` 問，答案是對的。

### 檔案分析

| 工具 | 說明 |
|------|------|
| `malcolm_file_scans` | 列出 Zeek 從流量裡切出來的檔案——檔名、MIME type、大小、md5/sha256、來源與目的、Malcolm 的 severity，以及 Strelka/YARA/ClamAV 的掃描命中 |
| `malcolm_extract_file` | 從 Malcolm 的 extracted-files server 抓一個切出來的檔案，回報大小、sha256、file-magic（只回 metadata，不落地） |

`malcolm_file_scans` 讀的是 Zeek 對每次檔案傳輸的記錄，不需要開檔案萃取。要拿到檔案本身才需要：`malcolm_extract_file` 需要 `ZEEK_EXTRACTOR_MODE` 有設、extracted-files HTTP server 開著（`FILESCAN_HTTP_SERVER_ENABLE`），而掃描結果那幾個欄位只有跑 Strelka 才會有。切出來的檔案可能就是活的惡意程式，所以檔案內容不會進到 MCP 回應裡。

### 關聯與匯出

| 工具 | 說明 |
|------|------|
| `malcolm_related_sessions` | 找出與某個 Zeek UID 相關的所有 session |
| `malcolm_saved_objects` | 找出這套 Malcolm 內建的 dashboard、visualization 與 saved search（不含各自好幾 KB 的版面配置 JSON） |
| `malcolm_saved_object_detail` | 讀出單一 saved object 已經解析好的 query、filter 與 index pattern——把 saved search 或 visualization 背後的 KQL/Lucene 字串挖出來 |
| `malcolm_dashboard_export` | 把 OpenSearch Dashboards 的 saved object 匯出成 JSON |
| `malcolm_alerting_monitors` | 列出 OpenSearch alerting monitor、各自在監看什麼、以及有沒有觸發過——全部都停用時會特別標明 |
| `malcolm_alerting_alerts` | 列出 OpenSearch alerting monitor 實際觸發過的告警，涵蓋所有生命週期狀態（ACTIVE、ACKNOWLEDGED、COMPLETED、ERROR、DELETED） |
| `malcolm_alerting_monitor_detail` | 讀出單一 alerting monitor 完整的 query 與觸發條件——分辨一個 monitor 是「在看但沒事」還是「條件根本打不到」 |
| `malcolm_anomaly_detectors` | 列出 anomaly detector、各自在建模什麼、以及累積了多少異常——從來沒有記錄過異常時會特別標明 |
| `malcolm_anomaly_results` | 讀出某個 anomaly detector 在一段時間窗內判定為異常的實體，按嚴重度排序——時間窗是 epoch MILLISECONDS，跟其他 `arkime_*` 工具不同 |

其中 15 個會自行組出回傳內容的工具（檔案、Arkime inventory、Dashboards 那幾組）有宣告 typed return，所以客戶端除了文字之外還會拿到 `structuredContent`。其餘的工具是把上游回應原樣透傳，沒有形狀可以宣告。

## Write 工具（需自行開啟）

每個 class 把它的開關設成 `true` 才會啟用。你不開，這裡什麼都不會跑。

| Class | 開關 | 工具 | 端點 |
|-------|------|------|------|
| alerting | `MALCOLM_MCP_ENABLE_ALERTING` | `malcolm_create_alert` | `POST /mapi/event` |
| arkime-tag | `MALCOLM_MCP_ENABLE_ARKIME_TAGS` | `arkime_add_tags` | `POST /arkime/api/sessions/addtags` |
| hunt-job | `MALCOLM_MCP_ENABLE_HUNT_JOBS` | `arkime_create_hunt`、`arkime_cancel_hunt` | `POST /arkime/api/hunt`、`PUT /arkime/api/hunt/<id>/cancel` |
| pcap-upload | `MALCOLM_MCP_ENABLE_PCAP_UPLOAD` | `malcolm_upload_pcap` | `POST /server/php/submit.php` |
| arkime-view | `MALCOLM_MCP_ENABLE_ARKIME_VIEWS` | `arkime_create_view`、`arkime_create_shortcut` | `POST /arkime/api/view`、`POST /arkime/api/shortcut` |

- **alerting**：`malcolm_create_alert` 把分析師或 agent 產出的發現，寫成一筆能在 Malcolm dashboard 看到的告警文件。它走 `/mapi/event`，這是 Malcolm 自己設計的 write 端點，也是其他 class 效法的範本。
- **arkime-tag**：`arkime_add_tags` 幫 session 加 tag，只加不減。移除 tag 需要更高的 Arkime 角色和另一套安全設計，所以延後。
- **hunt-job**：`arkime_create_hunt` 發動一個跨 PCAP 的封包搜尋（很吃資源，所以先把查詢範圍縮小）。`arkime_cancel_hunt` 停掉一個排隊中或執行中的 hunt——不是新增性質，被取消的掃描沒辦法續跑。作業進度用 `arkime_hunt_status` 讀，它現在是讀取工具，這個 class 關著也拿得到（見 [Arkime 儲存物件與擷取健康度](#arkime-儲存物件與擷取健康度)）。
- **pcap-upload**：`malcolm_upload_pcap` 把本機的封包檔送進 Malcolm 做 ingestion，並在客戶端擋一道大小上限。檔案必須位於 `MALCOLM_MCP_UPLOAD_DIR` 內；若這個 staging 目錄未設定，一律拒絕上傳，讓這個工具不可能被誘導去讀主機上的任意檔案。
- **arkime-view**：`arkime_create_view` 存一個具名的搜尋 expression，`arkime_create_shortcut` 存一個具名的值清單（IOC 集合），在 expression 裡用 `$name` 引用。兩者都是 additive — 讓 agent 把 hunting 知識留給分析人員，不刪除也不覆寫。

每個 write 工具都帶著 MCP annotation `readOnlyHint: false`，讓 MCP 客戶端能在呼叫前套自己的確認步驟。`destructiveHint` 在每個新增性質的 write 上是 `false`，唯一的例外是 `arkime_cancel_hunt`——它停掉的是進行中的工作，不是新增內容，所以標成 `true`。

## 開啟 write 工具

五個 write class 不設開關就是關的，所以預設安裝是唯讀。要開就把開關加進同一組 `-e` / `env`：

```bash
-e MALCOLM_MCP_ENABLE_ALERTING=true
-e MALCOLM_MCP_AUDIT_FILE=/var/log/malcolm-mcp-audit.jsonl
```

關著的 class 是沒有註冊，不是被藏起來，所以這個改動在 `tools/list` 上看得到。其他什麼都不動，數一數 MCP session 看到的工具數：

```
env unmodified                          tool count: 51
MALCOLM_MCP_ENABLE_ARKIME_TAGS=true     tool count: 52   (new: arkime_add_tags)
```

用這個方式實際切換並計數過的只有 `arkime_tags`。另外四個 class 走的是 `tools/__init__.py::register_write_tools` 裡同一個 `if cfg.<flag>:` 閘門，所以同樣的行為由程式碼可以推得，但沒有分別量過。

一個開關只有在值剛好是 `true`（不分大小寫）時才算開（`config.py:15`）；其他任何值，包括 `1` 和 `yes`，都會讓那個 class 維持關閉。啟動橫幅就是確認的地方。

完整開關列表見 [設定參考](configuration.md#設定參考)。

## 精簡讀取工具

51 個讀取工具預設全開，光是它們的 schema 就約 34,000 個 token，每個 session 在模型還沒問任何問題之前就先付掉。這個成本在大型前沿模型上還好，換成 context window 小的模型就很吃緊。而且有一部分是白付的：沒裝 NetBox 的 Malcolm 永遠不會回應 `malcolm_netbox_*`，也有不少環境根本不想讓 agent 碰到 OpenSearch 的 alerting 設定。

`MALCOLM_MCP_DISABLE_READ_GROUPS` 接一串以逗號分隔的 group 名稱，列到的就不註冊。被關掉的 group 不是隱藏起來——它的工具不會出現在 `tools/list`，跟關掉的 write class 一樣。

| Group | 工具數 | Schema tokens | 內容 |
| --- | --- | --- | --- |
| `dsl` | 5 | ~2,440 | 原始 OpenSearch：`search_dsl`、`count`、index 與 cluster metadata |
| `query` | 3 | ~2,600 | `malcolm_search`、`malcolm_aggregate`、`malcolm_alerts` |
| `fields` | 3 | ~1,750 | 欄位探索——防幻覺那一層 |
| `health` | 4 | ~1,650 | 服務狀態、資料涵蓋範圍、ping、dashboard 匯出 |
| `netbox` | 3 | ~1,370 | NetBox 資產查詢 |
| `arkime` | 11 | ~8,060 | Arkime session 搜尋與各個 SPI 分析 endpoint |
| `arkime-content` | 5 | ~3,200 | PCAP、payload、依 hash 取檔 |
| `correlation` | 1 | ~620 | `malcolm_related_sessions` |
| `files` | 2 | ~2,160 | Zeek 檔案掃描結果與已擷取檔案下載 |
| `arkime-inventory` | 7 | ~4,260 | 儲存的 view、shortcut、cron、擷取節點狀態、hunt 狀態 |
| `dashboards` | 2 | ~1,880 | OpenSearch Dashboards 的 saved object |
| `detections` | 5 | ~4,150 | Alerting monitor 與異常偵測器 |
| **合計** | **51** | **~34,150** | |

以 metadata 為主的調查很少會用到的那四組關掉，session 就從 51 個工具降到 34 個，schema 帳單從約 34,150 token 降到約 22,510：

```bash
-e MALCOLM_MCP_DISABLE_READ_GROUPS=netbox,dashboards,detections,arkime-inventory
```

```
[mcp-server-malcolm] read groups disabled: arkime-inventory, dashboards, detections, netbox
```

只有真的關掉東西時才會印這行，所以少了哪個工具，都能回推到是哪個開關拿掉的。名稱對不上任何 group 會直接讓啟動失敗，而不是被忽略——打錯字卻讓那個 group 靜靜留著，正是這個檢查要擋的狀況：

```
ValueError: MALCOLM_MCP_DISABLE_READ_GROUPS: unknown read group(s) netboxx. Valid names: arkime, arkime-content, ...
```

有兩個 group 關掉之前要想清楚。`fields` 是擋住模型亂編欄位名稱的那一層，而 server 給模型的指示裡明寫了「查詢陌生欄位前先查名稱」；少了這個 group，指示講的工具就不存在了。`arkime` 裡有 `arkime_sessions`，那是唯一會回傳 session ID 的搜尋，關掉它等於同時抽掉每個 `arkime-content` 工具的輸入來源。

所以 `arkime` 是最大的一組（約 8,060 token），偏偏也是多數環境非留不可的一組。`MALCOLM_MCP_DISABLE_TOOLS` 可以照名稱拿掉單一讀取工具，在 group 處理完之後才套用，專門處理那些必須保留的 group 裡用不到的工具：

```bash
-e MALCOLM_MCP_DISABLE_READ_GROUPS=netbox,dashboards,detections
-e MALCOLM_MCP_DISABLE_TOOLS=arkime_spiview,arkime_spigraphhierarchy,arkime_multiunique
```

```
[mcp-server-malcolm] read tools disabled: arkime_multiunique, arkime_spigraphhierarchy, arkime_spiview
```

名稱要和 `tools/list` 裡的工具名稱完全一樣。只要有一個名稱不是已註冊的讀取工具，啟動就會失敗。常見的三種情況是打錯字、那個工具所屬的 group 已經關掉，或是填了 write 工具（write 工具只由各自的 `MALCOLM_MCP_ENABLE_*` 控制）。逐一列工具時，server 不會檢查工具之間的依賴。留下 `arkime_session_detail`、拿掉 `arkime_sessions` 是允許的，但前者就拿不到輸入了。建議先用 group 做粗的裁切，剩下的再用這個處理。
