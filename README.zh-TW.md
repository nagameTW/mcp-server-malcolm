# mcp-server-malcolm

[![CI](https://github.com/nagameTW/mcp-server-malcolm/actions/workflows/ci.yml/badge.svg)](https://github.com/nagameTW/mcp-server-malcolm/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mcp-server-malcolm)](https://pypi.org/project/mcp-server-malcolm/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://pypi.org/project/mcp-server-malcolm/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Glama score](https://glama.ai/mcp/servers/nagameTW/mcp-server-malcolm/badges/score.svg)](https://glama.ai/mcp/servers/nagameTW/mcp-server-malcolm)

[English](README.md) | **繁體中文**

[![mcp-server-malcolm MCP server](https://glama.ai/mcp/servers/nagameTW/mcp-server-malcolm/badges/card.svg)](https://glama.ai/mcp/servers/nagameTW/mcp-server-malcolm)

第一個給 [Malcolm](https://malcolm.fyi) 用的 MCP server。Malcolm 是開源的網路流量分析平台，整合 Zeek + Suricata + Arkime + OpenSearch，並可選配 NetBox。

它讓任何支援 MCP 協定的 AI agent 都能用結構化工具存取 Malcolm：搜尋與聚合網路流量、探索欄位名稱、查詢 Suricata 告警、瀏覽 Arkime session、查詢 NetBox 資產、檢查系統健康。開啟 write class 之後，它還能建立告警、標記 session、發動 hunt、上傳 PCAP。

## 預設唯讀，需要時再開

不做任何設定時，這個 server 只提供讀取工具。它就是個唯讀客戶端，做的任何事都不會動到 Malcolm 裡的資料。

write 存取分成五個 class，各自有一個環境變數開關，預設全關。沒開的 class 不會被註冊，所以它的工具不會出現在 `list_tools()`，也叫不到。啟動時 server 會印出哪些 class 是開的：

```
[mcp-server-malcolm] write classes: alerting=off arkime-tag=off hunt-job=off pcap-upload=off arkime-view=off
```

除了一個例外，每個 write 都是「新增」性質：例外是 `arkime_cancel_hunt`，它停掉的是進行中的 hunt 工作，不是新增內容。沒有任何工具會刪資料、移除 tag、或動到使用者帳號——這些是刻意不做的（見 [不做的事](#不做的事)）。

## 為什麼要有 MCP 這一層

Malcolm 把所有網路 metadata 存在單一 OpenSearch index（`arkime_sessions3-*`），欄位名稱非標準，還有自己一套 filter 語法。要 LLM 直接對這個 index 寫 OpenSearch DSL，多半會寫錯。這個 server 把這件事從模型身上接過來：

- 對外用 Malcolm 的 filter 語法，不是原生 DSL。
- 提供欄位探索，讓模型查詢前先確認欄位名稱。
- 提供欄位值列舉，讓模型看到欄位裡實際有哪些值。
- 兩套欄位字彙都涵蓋。Arkime expression 吃 Arkime 自己的名稱（`ip.src`），Malcolm 其他地方吃 ECS 名稱（`source.ip`），而 Malcolm 自己的欄位清單只有後者。前者由 `arkime_field_search` 補上。
- 封裝 Suricata 告警查詢，替它處理欄位映射（`suricata.alert.*` 對 `rule.*`）。
- 補上 NetBox 資產上下文（IP 對應裝置、網段）。

這一層真正要擋的失敗是無聲的那種。查一個 Malcolm 沒有索引的欄位，它不會報錯，只會回空結果；模型猜了個看似合理但錯誤的名稱，讀到的是「這種流量不存在」，然後就走掉了。所以當搜尋回空的時候，這個 server 會去比對查詢用到的欄位，把 Malcolm 實際存放該值的名稱回報出來。這個比對只在結果已經是空的之後才跑，查得到東西的時候不會多佔模型任何 context。

write 這邊也是同一個想法。與其把 Malcolm 對任何登入者都開著的 OpenSearch、NetBox 原始 passthrough 直接交給 agent，不如只開一組具名、有稽核的 write 動作。細節見 [安全模型](#安全模型)。

## 讀取工具

這些一律註冊。

### DSL 核心（與後端無關）

對設定好的端點（Malcolm 的 `/mapi/opensearch` proxy）送純 OpenSearch DSL。不綁 Malcolm 專屬的查詢格式：把 base URL 改指到任何相容 OpenSearch 的後端，它們照樣能用。

| 工具 | 說明 |
|------|------|
| `search_dsl` | 執行原生 OpenSearch DSL 查詢（hits + aggregations，無隱藏時間窗） |
| `count` | 計算符合 DSL query 子句的文件數 |
| `list_indices` | 列出 index（名稱/健康/狀態/文件數） |
| `index_mapping` | 取得 index 的欄位 mapping/schema |
| `cluster_health` | OpenSearch cluster 健康狀態 |

### 核心查詢

| 工具 | 說明 |
|------|------|
| `malcolm_search` | 用 Malcolm filter 語法搜尋網路流量文件 |
| `malcolm_aggregate` | 依一個或多個欄位聚合流量（Top-N 計數） |
| `malcolm_alerts` | 依 signature、severity、IP 搜尋 Suricata 告警 |

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
| `arkime_sessions_csv` | 把 session 匯出成精簡 CSV 表（同樣的資料，token 大約是 JSON 的一半） |
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
| `arkime_hunt_status` | 列出 Arkime hunt 作業與其進度——排隊中、執行中或已完成。一律註冊：只讀作業狀態，所以就算 write class 全關也拿得到 |

Arkime 的 `connections.csv` 刻意沒有包裝：在 Arkime 6.6.0 上它的表頭有 9 欄、資料列只有 7 欄，所以第二欄之後全部對錯位置。同樣的問題用 `arkime_connections` 問，答案是對的。

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
| `malcolm_saved_objects` | 找出這套 Malcolm 內建的 dashboard、visualization 與 saved search（111 個 dashboard，不含各自好幾 KB 的版面配置 JSON） |
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
- **arkime-view**：`arkime_create_view` 存一個具名的搜尋 expression，`arkime_create_shortcut` 存一個具名的值清單（IOC 集合），在 expression 裡用 `$name` 引用。兩者都是 additive — 讓 agent 把 hunting 知識留給人類團隊，不刪除也不覆寫。

每個 write 工具都帶著 MCP annotation `readOnlyHint: false`，讓 MCP 客戶端能在呼叫前套自己的確認步驟。`destructiveHint` 在每個新增性質的 write 上是 `false`，唯一的例外是 `arkime_cancel_hunt`——它停掉的是進行中的工作，不是新增內容，所以標成 `true`。

## 安全模型

Malcolm 的預設部署，本來就讓任何登入者都能不受限地寫入原始 OpenSearch（`/mapi/opensearch/*`）和整套 NetBox CRUD（`/mapi/netbox/*`）。這兩條都是不做 HTTP 動詞過濾的裸 reverse-proxy；Malcolm 自己的唯讀模式是把它們整條拿掉，而不是去過濾。在常見的驗證模式下，「登入了」就等於拿到 admin 等級權限。

在這裡開一個 write class，並不是打開一扇原本關著的門。那扇門在平台層早就開著。這個 server 給你一條規劃過的路走進去：

- 一組具名的 write 動作，而不是裸 passthrough。
- 預設全關，一次開一個 class。
- 每次 write 嘗試都有一行稽核。
- 帶 MCP annotation，讓客戶端能要求確認。

原始 OpenSearch 和 NetBox 的 write passthrough，這個 server 一律不開，開關後面也沒有。把這個介面收斂好，就是這個 server 要做的事。

## 稽核

每次 write 嘗試都吐一行 JSON，成功失敗都吐：

```json
{"ts": "2026-07-06T09:12:44Z", "tool": "arkime_add_tags", "class": "arkime-tag", "target": "ids=240601-abc", "params": {"tags": "suspicious"}, "outcome": "ok"}
```

`outcome` 是 `ok`、`http_4xx`、`http_5xx`、或 `error:<type>` 其中之一。過長的參數值會被截斷，PCAP bytes 永遠不進 log。sink 預設是 stderr；設 `MALCOLM_MCP_AUDIT_FILE` 就改成 append 到檔案。讀取工具不稽核。

## 快速開始

你不需要寫任何程式碼。MCP 客戶端（Claude Code、Claude Desktop、Cursor 等）會把這個 server 當子行程啟動，用 stdio 跟它溝通；你要做的只是告訴客戶端怎麼啟動它、以及要注入哪些憑證。

這一章的每一行指令都是照著印出來的樣子跑過的：Linux/aarch64（kernel 6.14，Python 3.11.14 與 3.14.6），對象是一台跑著的 Malcolm v26.07.1，錯誤訊息一律原文照抄。凡是只從原始碼推論、沒有實際執行，或根本沒測到的（x86_64 與 macOS 主機、GUI 的 MCP 客戶端、五個 write class 裡的四個），都會在該處寫明。

### 1. 安裝

**PyPI 上的版本比這個 repository 舊。**已發布的 `mcp-server-malcolm` 0.9.0 是從更早的 commit 切出來的；這棵樹的 `pyproject.toml` 同樣寫著 `0.9.0`，所以光看版號完全看不出兩者有差。`pip install mcp-server-malcolm` 和不帶參數的 `uvx mcp-server-malcolm` 裝到的是已發布的 release，不是這份文件寫的這份程式碼。下次發版之前，要拿到這棵樹就得從原始碼裝。

```bash
pip install mcp-server-malcolm      # published release
```

從 checkout 裝：

```bash
git clone https://github.com/nagameTW/mcp-server-malcolm.git
cd mcp-server-malcolm
pip install -e .
```

或者建一個 wheel、裝進乾淨的 virtualenv——底下所有東西都是走這條路驗證的：

```bash
$ uv build --out-dir /tmp/mcp-malcolm-deploy/dist
Successfully built /tmp/mcp-malcolm-deploy/dist/mcp_server_malcolm-0.9.0.tar.gz
Successfully built /tmp/mcp-malcolm-deploy/dist/mcp_server_malcolm-0.9.0-py3-none-any.whl

$ python3 -m venv /tmp/mcp-malcolm-deploy/venv
$ /tmp/mcp-malcolm-deploy/venv/bin/pip install \
    /tmp/mcp-malcolm-deploy/dist/mcp_server_malcolm-0.9.0-py3-none-any.whl
```

這會拉進 32 個套件，多數來自 `mcp>=2,<3`（解析到 `mcp 2.0.0`）。wheel 本身是 `py3-none-any`，純 Python；需要編譯的那幾個相依套件（`cryptography`、`pydantic-core`、`rpds-py`、`cffi`）在這裡全部是裝預先建好的 `manylinux_*_aarch64` wheel，沒有任何東西是從原始碼編的。PyPI 對 x86_64 和 macOS 發的是同一批 wheel，但這兩個平台都沒有實際裝過，請當作未驗證。

不想把這個 branch 永久裝到哪裡去，就把 `uvx` 或 `pipx` 指到 checkout：

```bash
uvx --from /path/to/mcp-server-malcolm mcp-server-malcolm
pipx run --spec /path/to/mcp-server-malcolm mcp-server-malcolm
```

把 stdin 關掉直接啟動 server，就能確認裝好了。它會印出 write class 橫幅、讀到 EOF、以 0 結束：

```bash
$ timeout 3 mcp-server-malcolm < /dev/null
[mcp-server-malcolm] write classes: alerting=off arkime-tag=off hunt-job=off pcap-upload=off arkime-view=off
$ echo $?
0
```

行程要啟動不需要先設定任何東西。連線設定在啟動時就讀進來，但要等到有工具去呼叫 Malcolm 才會用上，所以 URL 或密碼寫錯是以工具呼叫失敗的形式浮現，不是啟動失敗。

### 2. 註冊到你的客戶端

**Claude Code** — 一行指令，不用找設定檔在哪：

```bash
claude mcp add malcolm \
  -e MALCOLM_URL=https://malcolm.example \
  -e MALCOLM_USERNAME=analyst \
  -e MALCOLM_PASSWORD='your-password' \
  -e MALCOLM_SSL_VERIFY=/path/to/malcolm-ca.crt \
  -- mcp-server-malcolm
```

`--` 之後是啟動指令，前面每個 `-e` 是要注入的環境變數。`claude mcp add --help` 給出的簽名是 `claude mcp add [options] <name> <commandOrUrl> [args...]`，選項有 `-e, --env <env...>` 和 `-s, --scope <scope>`。

註冊、健康檢查、移除，整套跑一遍：

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

用 `-s` 決定這筆設定存在哪：

| scope | 存放位置 | 適用情境 |
| --- | --- | --- |
| `local`（預設） | 你個人的設定，只在這個專案目錄生效 | 含密碼的設定，不會被 commit |
| `user` | 你個人的設定，所有專案都看得到 | 到哪都會用到的 Malcolm |
| `project` | 專案根目錄的 `.mcp.json`，**會進 git** | 團隊共用，密碼絕對不要放這裡 |

`claude mcp get malcolm` 會印出註冊的指令和環境變數。要注意它是把 `MALCOLM_PASSWORD` 以明文、未遮蔽地印出來，所以終端機正在錄影或分享時不要跑它。

若要用 `project` scope 給團隊共用，把密碼留在各人的 shell 裡：

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

**其他 MCP 客戶端** — 沒有對應的 CLI，要自己編輯客戶端的 JSON 設定檔，格式一樣：

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

上面這個區塊是把它的 `command` 和 `env` 欄位餵進 MCP Python SDK 自己的 `stdio_client` 與 `ClientSession` 驗過的，那正是一般客戶端拿到這兩個欄位之後做的事。這裡沒有啟動任何 GUI 客戶端：Claude Desktop 讀 `claude_desktop_config.json`，其他客戶端各不相同，依各自文件為準，本專案沒有獨立確認過。

如果 `mcp-server-malcolm` 不在客戶端看得到的 `PATH` 上（用 virtualenv 時很常見），改填執行檔的絕對路徑：`/path/to/.venv/bin/mcp-server-malcolm`。

**客戶端連上時看到什麼。**這個 server 兩個協定世代都服務，拿到哪一個由客戶端的第一個請求決定，不是這裡的任何設定。以 `initialize` 開場的客戶端走交握世代；第一個請求在 `_meta` 裡帶 `io.modelcontextprotocol/protocolVersion` 的客戶端走 2026-07-28 無狀態世代，完全沒有交握。這條分流在 SDK 的 `serve_dual_era_loop` 裡，這個專案沒有設定它。

write 開關全都不設時，一次 `initialize` 加 `tools/list` 回的是：

```
protocol_version: 2025-11-25
server_info:      name='mcp-server-malcolm' version='1.0.2'
capabilities:     prompts, resources (subscribe=false), tools — all list_changed=false
instructions:     3624 characters
tools:            51
prompts:          1  — hunt_workflow
resources:        2  — malcolm://fields/malcolm, malcolm://fields/arkime
```

2025-11-25 是交握世代的天花板，不是這個 server 的天花板：`initialize` 在 2026-07-28 根本不存在，所以透過它量測只可能量到比較舊的那個數字。2026-07-28 的客戶端不送交握，改呼叫 `server/discover`：

```
server/discover  capabilities: prompts, resources (subscribe=true), tools — all listChanged=true
                 cacheScope=private  ttlMs=0  resultType=complete
tools/list       51 個工具，cacheScope=public ttlMs=3600000 resultType=complete
結果的 _meta     io.modelcontextprotocol/serverInfo = {name: mcp-server-malcolm, version: 1.0.2}
```

兩個世代對 `listChanged` 的說法不一致，而說多了的是新世代那邊：SDK 在那裡宣告 `listChanged=true`，但這個 server 在 `create_server()` 裡一次註冊完所有東西，從不送變更通知。這不會出事，因為不會變的清單也就無所謂沒有通知，但別把程式建立在那個承諾上。

在這套部署上，Arkime 那個 resource 送出 724,261 個字元，涵蓋 4,051 個 expression 欄位。要拿 SDK 寫腳本的人有一個地方要留意：`mcp` 2.x 用的是 snake_case 屬性（`protocol_version`、`server_info`、`is_error`），不是 wire protocol 和 1.x SDK 的 camelCase。照 `serverInfo`/`isError` 寫的腳本會拋 `AttributeError`。

### 3. 連線設定

底下的預設值就是 `MalcolmClient.from_env` 讀到的（`client.py:294-304`）。

| 變數 | 預設值 | 說明 |
| --- | --- | --- |
| `MALCOLM_URL` | `https://localhost` | Malcolm base URL，例如 `https://malcolm.example` |
| `MALCOLM_USERNAME` | `admin` | Basic auth 使用者名稱 |
| `MALCOLM_PASSWORD` | `admin` | Basic auth 密碼 |
| `MALCOLM_SSL_VERIFY` | `true` | `true`、`false`、或 CA bundle 的路徑（只要不是 `true`/`false`，就當成 CA 路徑交給 httpx） |
| `MALCOLM_TIMEOUT` | `30` | HTTP timeout 秒數 |
| `MALCOLM_MAX_CONCURRENCY` | `8` | 同時對上游發出的請求數 |
| `MALCOLM_MAX_REQUESTS_PER_MINUTE` | `600` | 上游請求速率上限 |

`https://localhost` 和 `true` 這兩個預設值，是把變數拿掉後看實際送出去的請求確認的。`admin`/`admin` 這組帳密預設值來自讀 `client.py:296-297`：把三個連線變數全部拿掉，對 `https://localhost` 會拿到 401，這證明了 URL 的預設值、也證明那組帳密在那個 lab 上是錯的，但不能證明它字面上就是 `admin`。30 秒的 timeout 同樣是讀原始碼得來的——試著對一個不可路由的位址計時，大約 5 秒就回來了，因為 OS 層的 connect 失敗先發生，所以 30 秒那條路從來沒有被走到。

關於 TLS：驗證預設開啟，而 Malcolm 出廠是自簽憑證。把 `MALCOLM_SSL_VERIFY` 指向 Malcolm 的 CA bundle，只有在 Malcolm 的 server 憑證帶有對應你連線主機名的 `subjectAltName` 時才有用 — Malcolm 自己的 setup 產出的憑證沒有 SAN 擴充欄位，所以就算 CA 指對了驗證還是會失敗。遠端的 Malcolm 請換上 SAN 正確的憑證。`MALCOLM_SSL_VERIFY="false"` 是完全關閉驗證，只有隔離的 localhost 實驗環境能接受；走網路的話，憑證和查詢結果都會經過未經驗證的通道。

#### 第一次呼叫失敗時

幾乎所有第一次執行踩到的問題，都落在三種失敗上。三種都是用 `malcolm_ping` 重現的，文字照抄。

**憑證是自簽的，而 `MALCOLM_SSL_VERIFY` 沒設。**這是最可能遇到的一種，因為預設就是開啟驗證，而原廠 Malcolm 的憑證過不了驗證：

```
Error executing tool malcolm_ping: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1082)
```

`_ssl.c` 後面的行號跟著你的直譯器走，不是這個 server 決定的：同一個錯誤在 Python 3.11 上是 `_ssl.c:1016`，而 Docker 映像和 CI 下限跑的都是 3.11。

訊息裡從頭到尾沒提到 `MALCOLM_SSL_VERIFY`，所以很容易被讀成安裝壞掉了。修法是換上 SAN 正確的憑證、再把 `MALCOLM_SSL_VERIFY` 指向它的 CA bundle；或者，僅限隔離的實驗環境，設 `MALCOLM_SSL_VERIFY=false`。

**密碼錯了。**清楚、而且知道下一步要做什麼——狀態碼和 URL 都在訊息裡：

```
Error executing tool malcolm_ping: Client error '401 Unauthorized' for url 'https://malcolm.example/mapi/ping'
For more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/401
```

**主機連不上**（`MALCOLM_URL` 打錯、連接埠被防火牆擋掉、scheme 錯了）：

```
Error executing tool malcolm_ping: ConnectTimeout for https://192.0.2.99:9999/mapi/ping
```

連不上有兩種，訊息不一樣。連接埠明確拒絕連線時是 `All connection attempts failed`；主機根本不回應時拋的是 `ConnectTimeout`，而 httpx 讓它的 `str()` 是空字串——1.0.1 以前這會變成一句光禿禿的 `Error executing tool malcolm_ping: `，冒號後面什麼都沒有。現在會補上例外名稱和目標。`MALCOLM_URL` 裡若嵌了憑證，顯示前會先被剝掉。

### 4. 開啟 write 工具（選用）

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

完整開關列表見 [設定參考](#設定參考)。

### 手動執行

只在除錯時有用。stdio MCP server 沒有互動介面：從終端機啟動它會安靜地停在那裡等 stdin 上的 JSON-RPC，這就是正常運作的樣子。它啟動時會把已開啟的 write class 印到 stderr，所以這可以確認開關有生效。兩個進入點的行為完全一樣：

```bash
$ mcp-server-malcolm
[mcp-server-malcolm] write classes: alerting=off arkime-tag=off hunt-job=off pcap-upload=off arkime-view=off

$ python -m mcp_server_malcolm
[mcp-server-malcolm] write classes: alerting=off arkime-tag=off hunt-job=off pcap-upload=off arkime-view=off
```

### 在容器裡執行

這個 repository 附了一份 `Dockerfile`，它從 build context 裝好套件，並以非 root 使用者執行：

```bash
$ docker build -t mcp-server-malcolm:local -f Dockerfile .
$ docker run --rm --entrypoint id mcp-server-malcolm:local
uid=10001(app) gid=10001(app) groups=10001(app)
```

冷建置花了 23.7 秒，在 `python:3.11-slim`（Debian 13 trixie）上產出 205MB 的 image。它是單一架構的：在這台 aarch64 主機上用普通的 `docker build` 只產出 `linux/arm64`，沒有模擬層的話在 x86_64 主機上跑不起來。多架構 image 得用 `docker buildx build --platform linux/amd64,linux/arm64`；這個沒試過，而且這份 Dockerfile 本身不會產出多架構 image。

把客戶端的啟動指令指向 `docker run -i --rm …`：

```bash
docker run -i --rm --network host \
  -e MALCOLM_URL -e MALCOLM_USERNAME -e MALCOLM_PASSWORD -e MALCOLM_SSL_VERIFY \
  mcp-server-malcolm:local
```

`-e VAR` 後面不接 `=value`，就是從呼叫它的 shell 繼承值，所以密碼不會成為指令字串的一部分，也不會落進 `ps` 輸出或 shell history。但它事後還是能透過 `docker inspect` 讀出來，見下。

容器怎麼連到 Malcolm，決定了整件事跑不跑得起來：

| 怎麼連到 Malcolm | 參數 | 結果 |
| --- | --- | --- |
| 主機 loopback，URL 不動 | `--network host` | 可以。容器裡的 `https://localhost` 就是主機的 loopback。 |
| bridge 網路 | 無 | 失敗：`All connection attempts failed`。`localhost` 指的是容器自己。底層的 errno 111 留在例外鏈裡，不會傳到 client。 |
| bridge 網路 | `--add-host=host.docker.internal:host-gateway`、`MALCOLM_URL=https://host.docker.internal` | 可以。Linux 上的 `host.docker.internal` 不像 Docker Desktop 那樣會自動註冊，是那個明寫的 `--add-host` 讓它解得出來（Docker 20.10+；實測在 28.5.1）。 |

兩種能通的模式都對著跑著的 Malcolm 完成了一次完整的 MCP session：`initialize`、回傳 51 個工具的 `tools/list`，以及兩次工具呼叫（`malcolm_ping` → `pong`，`count` → 202,531 筆 `conn` session）。`MALCOLM_SSL_VERIFY` 留在預設的 `true` 時，在容器裡失敗的理由跟在容器外一樣，都是自簽憑證。

關於帳密：`docker inspect <container> --format '{{json .Config.Env}}'` 會把 `MALCOLM_PASSWORD` 以明文印出來，而且不管值是用 `-e VAR`、`-e VAR=value` 還是 `--env-file` 傳進去的都一樣——不管哪一種，Docker 都把解析後的環境存進容器的 metadata。只要那個容器物件還在，任何拿得到 Docker daemon 或 socket 的人就能把 Malcolm 密碼讀回去。沒有 `MALCOLM_PASSWORD_FILE` 那種讀 secrets 檔的輸入方式；`client.py:297` 只讀環境變數，別無其他。讓容器保持用完即丟（`--rm`、一個客戶端 session 一個容器，這本來就是 stdio server 隱含的模型）能縮短這個窗口，但關不掉它。

`MALCOLM_MCP_ENABLE_PCAP_UPLOAD` 是唯一需要 bind mount 的功能，因為 `malcolm_upload_pcap` 要讀的檔案必須已經位於 `MALCOLM_MCP_UPLOAD_DIR` 內。掛到那裡的主機目錄，得讓容器內的 uid 10001 讀得到。這一條是從 `tools/write/pcap_upload.py` 讀出來的，沒有實測——整個測試過程 write class 都是關著的。

## 使用方式

### Python（直接 import）

`MalcolmClient` 可以單獨拿來用：不需要 MCP 客戶端、不需要 server 行程，迴圈裡也沒有 `mcp` 那一層傳輸。`mcp_server_malcolm` 的 `__all__` 是 `["MalcolmClient", "__version__"]`，而這一個 class 帶著 62 個 public method，涵蓋整個讀取面。這一節的每樣東西都是用這棵樹建出來的 wheel、對著跑著的 Malcolm v26.07.1 實際跑出來的。

client 可以從環境變數建，也可以用明確的參數建：

```python
import asyncio
from mcp_server_malcolm import MalcolmClient

async def main():
    client = MalcolmClient.from_env()          # 讀 MALCOLM_URL、MALCOLM_USERNAME、…
    # 或：
    # client = MalcolmClient(
    #     base_url="https://malcolm.example",
    #     username="analyst",
    #     password="…",
    #     ssl_verify=False,
    # )
    try:
        # Malcolm 的 filter dict
        hits = await client.search(
            filters={"event.dataset": "conn"},
            limit=5,
        )

        # 某欄位的 top 值，範圍是一個 24 小時的時間窗
        agg = await client.aggregate(
            fields="destination.port",
            filters={"event.dataset": "conn"},
            limit=5,
            time_from="1714003200",
            time_to="1714089600",
        )

        # 查詢回空的時候，先確認欄位名稱對不對，再決定信不信這個結果
        ok = await client.resolve_field("http.useragent")
        bad = await client.resolve_field("http.user_agent")

        # Arkime expression 語法，時間窗是 epoch 秒
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

這些呼叫實際回來的東西：

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

在這個 Malcolm 版本上，`search()` 回的是 `{"filter", "range", "results"}`，命中結果放在 `results` 底下，最上層**沒有** `total` 這個 key。別去假設形狀，讀你實際拿到的 payload。

**關掉 client 是呼叫端的責任。**`MalcolmClient` 有 `close()`，但沒有 `__aenter__`/`__aexit__`，所以 `async with MalcolmClient(...)` 會拋：

```
TypeError: 'mcp_server_malcolm.client.MalcolmClient' object does not support
the asynchronous context manager protocol (missed __aexit__ method)
```

照上面那樣用 `try`/`finally`。沒關就把最後一個 reference 丟掉，會留下一條真的還開著、連到 Malcolm 的 socket，要等 garbage collector 收到它才會回收；而且在直譯器的預設設定下這個警告是靜音的，只有 `python -W always -X dev` 才看得到：

```
ResourceWarning: unclosed <socket.socket fd=6, family=2, type=1, proto=6, …>
```

**錯誤。**三個 exception，共同的 base 都是 `MalcolmToolError`：

```python
from mcp_server_malcolm.errors import MalcolmToolError, ToolInputError, UpstreamError
```

| 拋出 | 時機 | 帶著什麼 |
| --- | --- | --- |
| `ToolInputError` | 某個參數沒通過 client 自己的驗證，發生在任何 HTTP 請求之前 | 出問題的值，以及預期的形狀 |
| `UpstreamError`，`.status` 有值 | Malcolm 回了一個 HTTP 錯誤 | 狀態碼，加上 URL 與狀態文字 |
| `UpstreamError`，`.status is None` | 請求根本沒完成（DNS、TLS、connect、timeout） | 只有那個 status，其他什麼都沒有——見下 |

實際觀察到的訊息：

```
ToolInputError:  invalid field name: '../../arkime/api/hunts' — expected a Malcolm
                 field name such as 'source.ip' (letters, digits and _ . - @ [ ])
UpstreamError:   status=404  message=Client error '404 Not Found' for url
                 'https://malcolm.example/dashboards/api/saved_objects/search/00000000-…'
UpstreamError:   status=None message=
```

最後那一筆，就是 [第一次呼叫失敗時](#第一次呼叫失敗時) 講的那個空錯誤訊息在函式庫這一側的樣子：`str(exc)` 是空字串。追下去發現它已經不在這個專案的程式碼裡，而是 `httpx.ConnectTimeout.__str__()`——對同一台主機，改用裸的 `httpx.AsyncClient` 呼叫也一樣是空的。要偵測主機連不上，就判斷 `exc.status is None`；訊息不會告訴你任何事。

**流量上限是用等的，不是拋錯。**`MALCOLM_MAX_CONCURRENCY`（預設 8）和 `MALCOLM_MAX_REQUESTS_PER_MINUTE`（預設 600）同時也是建構子參數 `max_concurrency` 與 `max_requests_per_minute`。把 `max_requests_per_minute=2`，連續三次 `ping()` 的完成時間是：

```
request 1  t+0.0s
request 2  t+0.0s
request 3  t+60.1s
```

DEBUG log 上會出現 `[malcolm] rate cap reached, holding https://…/mapi/ping for 60.0s`。沒有對應的 rate-limit exception：超過上限之後，一次呼叫跟一次很慢的呼叫分不出來，所以每次呼叫的 timeout 只要設得比這個窗短，就會打在其實只是在排隊的請求上。60 秒這個窗本身是模組常數（`_RATE_WINDOW_SECONDS`），不能設定——能設定的只有窗內的請求數。建構子參數給非正數會直接被擋下來：

```
ValueError: max_concurrency must be a positive integer, got 0
ValueError: max_requests_per_minute must be a positive integer, got 0
```

環境變數這條路刻意寬鬆一些：值不存在、空白或解析不出來，都會記一筆 log 然後換成預設值（`client.py:68-82`），所以部署環境的 env 檔打錯字不會把限流器關掉。

**函式庫使用者沒有任何受支援的 write 路徑。**七個 write primitive 全部是 private——`_write_event`、`_write_arkime_tags`、`_write_arkime_view`、`_write_arkime_shortcut`、`_write_arkime_hunt`、`_write_arkime_hunt_cancel`、`_write_upload_pcap`——每一個都只從 `tools/write/` 底下的唯一一處被呼叫，並且有 seam test 盯著。沒有任何 public method 能寫入告警、幫 session 加 tag、建立或取消 hunt、存下 view 或 shortcut、上傳 PCAP。直接呼叫底線開頭的 method 確實會把那個變更做出去，但會跳過 `tools/write/_common.py::run_write` 在每一次經過 MCP 層的 write 外圈寫下的稽核記錄；所以 write 屬於 tool 這一層，直接 import 這條路是一個讀取用的 client。

## Malcolm Filter 語法

Malcolm 用的是簡單的 JSON filter 語法，不是 OpenSearch DSL：

```python
# 精確比對
{"event.dataset": "conn"}

# 多值比對（OR）
{"network.direction": ["inbound", "outbound"]}

# 否定（排除）
{"!network.transport": "icmp"}

# 欄位必須存在（非 null）
{"!related.password": null}

# 組合條件（AND）
{"event.dataset": "dns", "source.ip": "192.0.2.77"}
```

值是**完全比對**。Malcolm 會把這個 dict 編成 OpenSearch 的 `terms` query，所以沒有萬用字元可用：
`{"rule.name": "*MALWARE*"}` 找的是名稱剛好叫 `*MALWARE*` 的 signature，結果一定是空的，而且不會報錯。
要做子字串比對，可以先用 `malcolm_field_values` 列出實際的值、挑出要的再以陣列傳入，或者改用
`search_dsl` 自己寫 wildcard query。`malcolm_alerts` 的 `signature` 和 `category` 參數已經幫你做掉這段列舉。

## 範例

### 搜尋連到可疑網域的 DNS 查詢

```
malcolm_search(
  filters='{"event.dataset": "dns", "zeek.dns.query": "ntp.ubuntu.com"}',
  limit=20,
  time_from="7 days ago"
)
```

### 依協定聚合 top talkers

```
malcolm_aggregate(
  fields="source.ip,destination.ip,network.protocol",
  filters='{"network.direction": ["inbound", "outbound"]}',
  limit=20
)
```

### 查詢前先確認欄位名稱

```
malcolm_field_search(prefix="zeek.dns")
malcolm_field_values(field="event.dataset")
malcolm_field_profile(field="zeek.ssl.server_name")

# 要寫 Arkime expression 之前，先到 Arkime 自己的字彙裡查。
# 回來的每一行是「exp | db | type | group」，例如
# 「ip.src | srcIp | ip | general」。
arkime_field_search(keyword="src")
```

哪個參數要哪一欄，是逐個參數決定的，不是逐個工具。在 Malcolm v26.07.1 上實測：

- **`exp`**（`ip.src`、`port.dst`、`protocols`）——每一個 `expression` 參數，加上 `arkime_unique`、`arkime_multiunique`、`arkime_spigraphhierarchy` 的欄位清單。這三個直接拒收 db 名稱：`srcIp,dstIp` 從 multiunique 拿到的是 HTTP 200 但內容為「Unknown expression srcIp」，從 spigraphhierarchy 拿到的是 HTTP 403 配同樣的內容。
- **`db`**（`srcIp`、`dstPort`、`node`）——`arkime_connections` 的 `src_field` 和 `dst_field`，就這樣，沒有別的地方。在那裡 `srcIp`/`dstIp` 回了一張 10 個節點的圖；`ip.src`/`dstIp` 回 HTTP 403，`srcIp`/`port.dst` 回 HTTP 500。
- **儲存路徑**——`arkime_spigraph` 的 `field` 和 `arkime_spiview` 的 `spi` 吃的是這個。這套部署的 4,051 個欄位裡有 4,034 個，它跟 db 那一欄是同一個字串；另外十七個印出來的是 camelCase 的 db 別名、實際存放用的卻是點分名稱（`srcIp` 是 `source.ip`，`dstPort` 是 `destination.port`，`totBytes` 是 `network.bytes`），而這兩個參數要的是點分的那個。

凡是吃 exp 那一欄的地方，也都接受點分的儲存路徑：`destination.port` 回的不重複行數跟 `port.dst` 一樣是 10,000 行，而 `dstPort` 一行都不回。它是唯一一個在每條路上都答得出來的寫法。

上面引的那些 HTTP 回應是 Arkime 自己答的，走這些工具你不會看到：server 現在認得出 exp 參數上收到 db 名，會在請求送出前就擋下來，並在訊息裡指出對應的那一個——`'srcIp' is an Arkime db name; this parameter takes expression names … Did you mean 'ip.src'?`。之所以還引它們，是因為那正是這道防護存在的理由。

### 建立告警（alerting class 已開）

```
malcolm_create_alert(
  title="Periodic beacon to 192.0.2.77",
  severity=2,
  description="60s-interval C2 candidate",
  source_ip="192.0.2.10",
  dest_ip="192.0.2.77"
)
```

### 標記 session 待審（arkime-tag class 已開）

```
arkime_add_tags(session_ids="240601-abc,240601-def", tags="review,beacon")
```

### 發動 hunt（hunt-job class 已開）

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

## 設定參考

| 環境變數 | 預設值 | 說明 |
|----------|--------|------|
| `MALCOLM_URL` | `https://localhost` | Malcolm 基礎 URL |
| `MALCOLM_USERNAME` | `admin` | Basic auth 使用者名稱 |
| `MALCOLM_PASSWORD` | `admin` | Basic auth 密碼 |
| `MALCOLM_SSL_VERIFY` | `true` | 是否驗證 TLS 憑證。`true`/`false`，或填 CA-bundle 路徑（自簽 Malcolm 請填路徑） |
| `MALCOLM_TIMEOUT` | `30` | HTTP 請求逾時（秒） |
| `MALCOLM_MAX_CONCURRENCY` | `8` | 同時對上游發出的請求數 |
| `MALCOLM_MAX_REQUESTS_PER_MINUTE` | `600` | 每個滾動 60 秒窗內允許的上游請求數；超過上限的請求是被壓著等，不是被拒絕 |
| `MALCOLM_MCP_ENABLE_ALERTING` | `false` | 開啟 alerting write class |
| `MALCOLM_MCP_ENABLE_ARKIME_TAGS` | `false` | 開啟 session 加 tag（只加不減） |
| `MALCOLM_MCP_ENABLE_HUNT_JOBS` | `false` | 開啟 Arkime hunt 建立 + 狀態查詢 |
| `MALCOLM_MCP_ENABLE_PCAP_UPLOAD` | `false` | 開啟 PCAP 上傳（另需 `MALCOLM_MCP_UPLOAD_DIR`） |
| `MALCOLM_MCP_ENABLE_ARKIME_VIEWS` | `false` | 開啟 saved-view + shortcut（值清單）建立 |
| `MALCOLM_MCP_UPLOAD_DIR` | 未設 | 允許上傳的檔案必須位於這個 staging 目錄內；未設 ⇒ 拒絕上傳 |
| `MALCOLM_MCP_AUDIT_FILE` | 未設 | write 稽核檔（未設時走 stderr） |

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
| `/arkime/api/sessions` | GET | `arkime_sessions`、`arkime_session_detail`（`id ==` 表達式） |
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

這些端點路徑和 body 結構是對 Malcolm `26.07.1` 和 Arkime `6.6.0` 核對過的。兩者版本之間都會漂移，所以若某個 write 工具回傳非預期錯誤，拿你自己的版本重新核對。

## 不做的事

v1 刻意不做：

- 破壞性寫入（Arkime session 刪除、tag 移除、使用者管理）。
- 原始 OpenSearch write 或原始 NetBox CRUD passthrough，開關後面也不放。
- `streamable-http` 傳輸（只做 stdio）。

## 系統需求

- Python 3.11+
- 已開放 API 存取的 Malcolm 實例
- 與 Malcolm 的網路連線（HTTPS）

## 授權

MIT © nagameTW
