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

所有 write 都是「新增」性質。v1 沒有任何工具會刪資料、移除 tag、或動到使用者帳號。這些是刻意不做的（見 [不做的事](#不做的事)）。

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
| `arkime_session_detail` | 抓單一 session 的全部欄位（完整 SPI 文件） |
| `arkime_session_pcap` | 抓某 session 的 PCAP，回報大小與 magic 驗證結果（只回 metadata，不落地） |
| `arkime_unique` | 列出某欄位的不重複值，可帶計數 |
| `arkime_multiunique` | 跨多個欄位的不重複值組合（例如 src.ip + dst.port 配對） |
| `arkime_spigraph` | 某欄位的 top 值加時序圖 |
| `arkime_spiview` | 一次看多個欄位的值分布 |
| `arkime_spigraphhierarchy` | 跨欄位的階層式 top-N 分解（巢狀 drill-down） |
| `arkime_connections` | 來源/目的連線圖（nodes 與 links） |
| `arkime_file_by_hash` | 依 md5/sha256 萃取傳輸過的檔案（只回 metadata，不落地） |

### 檔案分析

| 工具 | 說明 |
|------|------|
| `malcolm_file_scans` | 列出 Zeek 從流量裡切出來的檔案——檔名、MIME type、大小、md5/sha256、來源與目的、Malcolm 的 severity，以及 Strelka/YARA/ClamAV 的掃描命中 |
| `malcolm_extract_file` | 從 Malcolm 的 extracted-files server 抓一個切出來的檔案，回報大小、sha256、file-magic（只回 metadata，不落地） |

這兩個工具需要 Zeek 檔案萃取開著（`ZEEK_EXTRACTOR_MODE`），`malcolm_extract_file` 還需要 extracted-files HTTP server（`FILESCAN_HTTP_SERVER_ENABLE`）。切出來的檔案可能就是活的惡意程式，所以檔案內容不會進到 MCP 回應裡。

### 關聯與匯出

| 工具 | 說明 |
|------|------|
| `malcolm_related_sessions` | 找出與某個 Zeek UID 相關的所有 session |
| `malcolm_dashboard_export` | 把 OpenSearch Dashboards 的 saved object 匯出成 JSON |

## Write 工具（需自行開啟）

每個 class 把它的開關設成 `true` 才會啟用。你不開，這裡什麼都不會跑。

| Class | 開關 | 工具 | 端點 |
|-------|------|------|------|
| alerting | `MALCOLM_MCP_ENABLE_ALERTING` | `malcolm_create_alert` | `POST /mapi/event` |
| arkime-tag | `MALCOLM_MCP_ENABLE_ARKIME_TAGS` | `arkime_add_tags` | `POST /arkime/api/sessions/addtags` |
| hunt-job | `MALCOLM_MCP_ENABLE_HUNT_JOBS` | `arkime_create_hunt`、`arkime_hunt_status` | `POST /arkime/api/hunt` |
| pcap-upload | `MALCOLM_MCP_ENABLE_PCAP_UPLOAD` | `malcolm_upload_pcap` | `POST /server/php/submit.php` |
| arkime-view | `MALCOLM_MCP_ENABLE_ARKIME_VIEWS` | `arkime_create_view`、`arkime_create_shortcut` | `POST /arkime/api/view`、`POST /arkime/api/shortcut` |

- **alerting**：`malcolm_create_alert` 把分析師或 agent 產出的發現，寫成一筆能在 Malcolm dashboard 看到的告警文件。它走 `/mapi/event`，這是 Malcolm 自己設計的 write 端點，也是其他 class 效法的範本。
- **arkime-tag**：`arkime_add_tags` 幫 session 加 tag，只加不減。移除 tag 需要更高的 Arkime 角色和另一套安全設計，所以延後。
- **hunt-job**：`arkime_create_hunt` 發動一個跨 PCAP 的封包搜尋（很吃資源，所以先把查詢範圍縮小）。`arkime_hunt_status` 讀取作業進度，跟著這個 class 一起出。
- **pcap-upload**：`malcolm_upload_pcap` 把本機的封包檔送進 Malcolm 做 ingestion，並在客戶端擋一道大小上限。檔案必須位於 `MALCOLM_MCP_UPLOAD_DIR` 內；若這個 staging 目錄未設定，一律拒絕上傳，讓這個工具不可能被誘導去讀主機上的任意檔案。
- **arkime-view**：`arkime_create_view` 存一個具名的搜尋 expression，`arkime_create_shortcut` 存一個具名的值清單（IOC 集合），在 expression 裡用 `$name` 引用。兩者都是 additive — 讓 agent 把 hunting 知識留給人類團隊，不刪除也不覆寫。

每個 write 工具都帶著 MCP annotation `readOnlyHint: false` 和 `destructiveHint: false`，讓 MCP 客戶端能在呼叫前套自己的確認步驟。

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

### 1. 安裝

```bash
pip install mcp-server-malcolm
```

或從原始碼安裝：

```bash
git clone https://github.com/nagameTW/mcp-server-malcolm.git
cd mcp-server-malcolm
pip install -e .
```

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

`--` 之後是啟動指令，前面每個 `-e` 是要注入的環境變數。用 `-s` 決定這筆設定存在哪：

| scope | 存放位置 | 適用情境 |
| --- | --- | --- |
| `local`（預設） | 你個人的設定，只在這個專案目錄生效 | 含密碼的設定，不會被 commit |
| `user` | 你個人的設定，所有專案都看得到 | 到哪都會用到的 Malcolm |
| `project` | 專案根目錄的 `.mcp.json`，**會進 git** | 團隊共用，密碼絕對不要放這裡 |

用 `claude mcp list` 確認是否連上（它會對每個 server 做健康檢查），`claude mcp get malcolm` 看細節。

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

Claude Desktop 讀 `claude_desktop_config.json`；其他客戶端位置不一，查各自的文件。

如果 `mcp-server-malcolm` 不在客戶端看得到的 `PATH` 上（用 virtualenv 時很常見），改填執行檔的絕對路徑：`/path/to/.venv/bin/mcp-server-malcolm`。

### 3. 連線設定

| 變數 | 說明 |
| --- | --- |
| `MALCOLM_URL` | Malcolm base URL，例如 `https://malcolm.example` |
| `MALCOLM_USERNAME` / `MALCOLM_PASSWORD` | Malcolm 的 basic auth 帳密 |
| `MALCOLM_SSL_VERIFY` | `true`（預設）、`false`、或 CA bundle 的路徑 |
| `MALCOLM_TIMEOUT` | HTTP timeout 秒數，預設 `30` |

關於 TLS：驗證預設開啟，而 Malcolm 出廠是自簽憑證。把 `MALCOLM_SSL_VERIFY` 指向 Malcolm 的 CA bundle，只有在 Malcolm 的 server 憑證帶有對應你連線主機名的 `subjectAltName` 時才有用 — Malcolm 自己的 setup 產出的憑證沒有 SAN 擴充欄位，所以就算 CA 指對了驗證還是會失敗。遠端的 Malcolm 請換上 SAN 正確的憑證。`MALCOLM_SSL_VERIFY="false"` 是完全關閉驗證，只有隔離的 localhost 實驗環境能接受；走網路的話，憑證和查詢結果都會經過未經驗證的通道。

### 4. 開啟 write 工具（選用）

五個 write class 不設開關就是關的，所以預設安裝是唯讀。要開就把開關加進同一組 `-e` / `env`：

```bash
-e MALCOLM_MCP_ENABLE_ALERTING=true
-e MALCOLM_MCP_AUDIT_FILE=/var/log/malcolm-mcp-audit.jsonl
```

完整開關列表見 [設定](#設定-1)。

### 手動執行

只在除錯時有用。stdio MCP server 沒有互動介面：從終端機啟動它會安靜地停在那裡等 stdin 上的 JSON-RPC，這就是正常運作的樣子。它啟動時會把已開啟的 write class 印到 stderr，所以這可以確認開關有生效：

```bash
mcp-server-malcolm          # 或：python -m mcp_server_malcolm
```

## 使用方式

### Python（直接 import）

不經 MCP 層，直接用 `MalcolmClient`：

```python
import asyncio
from mcp_server_malcolm import MalcolmClient

async def main():
    client = MalcolmClient(
        base_url="https://malcolm.example",
        username="admin",
        password="admin",
    )

    # 搜尋網路流量
    results = await client.search(
        filters={"event.dataset": "conn", "source.ip": "192.0.2.77"},
        limit=10,
    )

    # 依協定聚合
    agg = await client.aggregate(
        fields="network.protocol",
        filters={"network.direction": ["inbound", "outbound"]},
    )

    # 探索欄位名稱
    fields = await client.search_fields(keyword="useragent")

    # 列舉欄位值
    datasets = await client.field_values(field="event.dataset")

    # 查詢 NetBox 資產
    asset = await client.netbox_get(
        "api/ipam/ip-addresses/",
        params={"address": "192.0.2.77"},
    )

    await client.close()

asyncio.run(main())
```

write primitive 藏在 `_write_*` method 後面。只有被 gate 的 write 工具能碰到它們，直接 import 這條路碰不到。

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
# 回傳長這樣：「ip.src | srcIp | ip | general」——前者放進 expression，
# 後者用在工具要求 db 欄位的地方。
arkime_field_search(keyword="src")
```

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
| `MALCOLM_MCP_ENABLE_ALERTING` | `false` | 開啟 alerting write class |
| `MALCOLM_MCP_ENABLE_ARKIME_TAGS` | `false` | 開啟 session 加 tag（只加不減） |
| `MALCOLM_MCP_ENABLE_HUNT_JOBS` | `false` | 開啟 Arkime hunt 建立 + 狀態查詢 |
| `MALCOLM_MCP_ENABLE_PCAP_UPLOAD` | `false` | 開啟 PCAP 上傳（另需 `MALCOLM_MCP_UPLOAD_DIR`） |
| `MALCOLM_MCP_ENABLE_ARKIME_VIEWS` | `false` | 開啟 saved-view + shortcut（值清單）建立 |
| `MALCOLM_MCP_UPLOAD_DIR` | 未設 | 允許上傳的檔案必須位於這個 staging 目錄內；未設 ⇒ 拒絕上傳 |
| `MALCOLM_MCP_AUDIT_FILE` | 未設 | write 稽核檔（未設時走 stderr） |

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
| `/arkime/api/unique`、`/arkime/api/multiunique` | GET | `arkime_unique`、`arkime_multiunique` |
| `/arkime/api/spigraph` | GET | `arkime_spigraph` |
| `/arkime/api/spiview` | GET | `arkime_spiview` |
| `/arkime/api/spigraphhierarchy` | GET | `arkime_spigraphhierarchy` |
| `/arkime/api/connections` | GET | `arkime_connections` |
| `/arkime/api/sessions/bodyhash/<hash>` | GET | `arkime_file_by_hash` |
| `/arkime/api/sessions/addtags` | POST | `arkime_add_tags`（write） |
| `/extracted-files/<name>` | GET | `malcolm_extract_file` |
| `/arkime/api/hunt`、`/arkime/api/hunts` | POST、GET | `arkime_create_hunt`、`arkime_hunt_status`（write + read） |
| `/arkime/api/view`、`/arkime/api/shortcut` | POST | `arkime_create_view`、`arkime_create_shortcut`（write） |
| `/server/php/submit.php` | POST | `malcolm_upload_pcap`（write） |

這些端點路徑和 body 結構是對 Malcolm `26.06.1` 和 Arkime `v6.5.0` 核對過的。兩者版本之間都會漂移，所以若某個 write 工具回傳非預期錯誤，拿你自己的版本重新核對。

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
