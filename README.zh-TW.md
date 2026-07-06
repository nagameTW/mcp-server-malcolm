# mcp-server-malcolm

[English](README.md) | **繁體中文**

[Malcolm](https://malcolm.fyi) 網路流量分析平台的 MCP server -- 整合 Zeek + Suricata + Arkime。

讓任何支援 MCP 協定的 AI agent 都能透過結構化工具存取 Malcolm 的統一 API，包括網路流量搜尋、聚合分析、欄位探索、Suricata 告警查詢、Arkime session 搜尋、NetBox 資產查詢及系統健康監控。

**設計上唯讀** -- 沒有任何工具會寫入、回傳或 ingest 資料。Server 採分層結構：**與後端無關的 DSL 核心**（5 個泛用 OpenSearch 查詢工具，可對任何相容 OpenSearch 的端點使用）加上**Malcolm 模組**（Malcolm 專屬便利工具），後者可整組移除而不影響核心。

## 為什麼需要這個

Malcolm 把所有網路 metadata 存在單一 OpenSearch index（`arkime_sessions3-*`），使用非標準欄位名稱和自訂的 filter 語法。LLM 直接寫 OpenSearch DSL 查詢 Malcolm，絕大多數情況都會寫錯。這個 MCP server 解決了以下問題：

- 暴露 Malcolm 的**簡易 filter 語法**，取代 OpenSearch DSL
- 提供**欄位探索工具**，讓 LLM 在查詢前驗證欄位名稱是否存在
- 提供**欄位值列舉工具**，讓 LLM 知道欄位裡實際有哪些值
- 封裝 **Suricata 告警查詢**，自動處理欄位映射（`suricata.alert.*` vs `rule.*`）
- 整合 **NetBox 資產上下文**（IP 對應裝置、網段資訊）

## 工具一覽

### DSL 核心（與後端無關）

直接對設定的端點（Malcolm 的 `/mapi/opensearch` proxy）送出純 OpenSearch DSL。
不含任何 Malcolm 專屬查詢形狀 -- 改指其他 base URL 即可用於任何相容
OpenSearch 的後端。

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
| `malcolm_search` | 使用 Malcolm filter 語法搜尋網路流量文件 |
| `malcolm_aggregate` | 依一個或多個欄位聚合流量（Top-N 計數） |
| `malcolm_alerts` | 依 signature、severity、IP 搜尋 Suricata 告警 |

### 欄位探索（防幻覺層）

| 工具 | 說明 |
|------|------|
| `malcolm_field_search` | 依關鍵字、前綴、型別搜尋/瀏覽可用欄位名稱 |
| `malcolm_field_values` | 列出欄位的所有不同值（例如 `event.dataset` 有哪些值） |
| `malcolm_field_profile` | 顯示特定欄位存在於哪些 `event.dataset` 類型中 |

### 系統健康

| 工具 | 說明 |
|------|------|
| `malcolm_service_status` | 檢查所有 Malcolm 服務就緒狀態 + 版本資訊 |
| `malcolm_data_coverage` | 各 sensor 資料新鮮度、各 dataset 文件數、index 資訊 |

### 資產上下文（NetBox）

| 工具 | 說明 |
|------|------|
| `malcolm_netbox_lookup` | 查詢 IP 位址、裝置或網段的 NetBox 資產資訊 |

### Arkime

| 工具 | 說明 |
|------|------|
| `arkime_sessions` | 使用 Arkime expression 語法搜尋 session |
| `arkime_pcap_info` | 取得 session 的 PCAP 下載 URL |

### 關聯

| 工具 | 說明 |
|------|------|
| `malcolm_related_sessions` | 尋找與某個 Zeek UID 相關的所有 session |

## 快速開始

### 安裝

```bash
pip install mcp-server-malcolm
```

或從原始碼安裝：

```bash
git clone https://github.com/user/mcp-server-malcolm.git
cd mcp-server-malcolm
pip install -e .
```

### 設定

設定 Malcolm 連線的環境變數：

```bash
export MALCOLM_URL="https://malcolm-server"
export MALCOLM_USERNAME="admin"
export MALCOLM_PASSWORD="admin"
export MALCOLM_SSL_VERIFY="false"    # Malcolm 預設使用自簽憑證
export MALCOLM_TIMEOUT="30"
```

### 執行

```bash
# 作為 MCP server 啟動（stdio 傳輸）
mcp-server-malcolm

# 或透過 Python module 啟動
python -m mcp_server_malcolm
```

## 使用方式

### MCP 用戶端(設定檔)

在你的 MCP 用戶端設定中加入此伺服器：

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

設定檔的實際位置請參考你的 MCP 用戶端文件(多數使用專案層級的 `.mcp.json` 或全域設定檔)。

### Python（直接 import）

不經過 MCP 協定層，直接使用 `MalcolmClient`：

```python
import asyncio
from mcp_server_malcolm import MalcolmClient

async def main():
    client = MalcolmClient(
        base_url="https://malcolm-server",
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

    # 查看欄位分布在哪些 dataset
    profile = await client.field_profile("zeek.ssl.server_name")

    # 查詢 NetBox 資產
    asset = await client.netbox_get(
        "api/ipam/ip-addresses/",
        params={"address": "192.0.2.77"},
    )

    await client.close()

asyncio.run(main())
```

## Malcolm Filter 語法

Malcolm 使用簡易的 JSON filter 語法（不是 OpenSearch DSL）：

```python
# 精確比對
{"event.dataset": "conn"}

# 多值比對（OR）
{"network.direction": ["inbound", "outbound"]}

# 否定（排除）
{"!network.transport": "icmp"}

# 欄位必須存在（非 null）
{"!related.password": null}

# 萬用字元
{"suricata.alert.signature": "*MALWARE*"}

# 組合條件（AND）
{"event.dataset": "dns", "source.ip": "192.0.2.77"}
```

## 工具使用範例

### 搜尋可疑網域的 DNS 查詢

```
malcolm_search(
  filters='{"event.dataset": "dns", "zeek.dns.query": "*evil.com*"}',
  limit=20,
  time_from="7 days ago"
)
```

### 聚合 Top Talkers（依協定分類）

```
malcolm_aggregate(
  fields="source.ip,destination.ip,network.protocol",
  filters='{"network.direction": ["inbound", "outbound"]}',
  limit=20
)
```

### 搜尋 Suricata 告警

```
malcolm_alerts(
  signature="ET MALWARE",
  severity="1,2",
  time_from="24 hours ago"
)
```

### 查詢前先驗證欄位（防幻覺）

```
# DNS 有哪些可用欄位？
malcolm_field_search(prefix="zeek.dns")

# event.dataset 有哪些值？
malcolm_field_values(field="event.dataset")

# zeek.ssl.server_name 存在於哪些 dataset？
malcolm_field_profile(field="zeek.ssl.server_name")
```

### 狩獵前檢查資料新鮮度

```
malcolm_data_coverage()
```

回傳各 sensor 最新時間戳、各 dataset 文件數量、index 資訊 -- 讓你知道哪些時間範圍有資料、有哪些協定。

### 查詢 IP 的 NetBox 資產資訊

```
malcolm_netbox_lookup(ip="192.0.2.77")
```

回傳裝置名稱、角色、站點、介面、網段 -- 判斷觀察到的行為是否正常的關鍵上下文。

### 依 Zeek UID 關聯 session

```
malcolm_related_sessions(uid="CYeji2z7CKmPRGyga")
```

尋找與單一連線相關的所有 session（conn、dns、ssl、files 等）。

## 設定參考

| 環境變數 | 預設值 | 說明 |
|----------|--------|------|
| `MALCOLM_URL` | `https://localhost` | Malcolm 基礎 URL |
| `MALCOLM_USERNAME` | `admin` | Basic auth 使用者名稱 |
| `MALCOLM_PASSWORD` | `admin` | Basic auth 密碼 |
| `MALCOLM_SSL_VERIFY` | `false` | 是否驗證 TLS 憑證 |
| `MALCOLM_TIMEOUT` | `30` | HTTP 請求逾時（秒） |

## 使用的 Malcolm API Endpoint

| Endpoint | 方法 | 使用者 |
|----------|------|--------|
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

## 系統需求

- Python 3.11+
- 已啟用 API 存取的 Malcolm 實例
- 與 Malcolm 的網路連線（HTTPS）

## 授權

MIT
