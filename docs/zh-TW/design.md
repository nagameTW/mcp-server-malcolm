# 設計

## 為什麼要有 MCP 這一層

Malcolm 把所有網路 metadata 存在單一 OpenSearch index（`arkime_sessions3-*`），欄位名稱非標準，還有自己一套 filter 語法。要 LLM 直接對這個 index 寫 OpenSearch DSL，多半會寫錯。這個 server 把這件事從模型身上接過來：

- 對外用 Malcolm 的 filter 語法，不是原生 DSL。
- 提供欄位探索，讓模型查詢前先確認欄位名稱。
- 提供欄位值列舉，讓模型看到欄位裡實際有哪些值。
- 兩套欄位字彙都涵蓋。Arkime expression 吃 Arkime 自己的名稱（`ip.src`），Malcolm 其他地方吃 ECS 名稱（`source.ip`），而 Malcolm 自己的欄位清單只有後者。前者由 `arkime_field_search` 補上。
- 封裝 Suricata 告警查詢，替它處理欄位映射（`suricata.alert.*` 對 `rule.*`）。
- 補上 NetBox 資產上下文（IP 對應裝置、網段）。

這一層真正要擋的失敗是無聲的那種。查一個 Malcolm 沒有索引的欄位，它不會報錯，只會回空結果；模型猜了個看似合理但錯誤的名稱，讀到的是「這種流量不存在」，然後就走掉了。所以當搜尋回空的時候，這個 server 會去比對查詢用到的欄位，把 Malcolm 實際存放該值的名稱回報出來。這個比對只在結果已經是空的之後才跑，查得到東西的時候不會多佔模型任何 context。

write 這邊也是同一個想法。與其把 Malcolm 對任何登入者都開著的 OpenSearch、NetBox 原始 passthrough 直接交給 agent，不如只開一組具名、有稽核的 write 動作。細節見 [安全模型](security.md#安全模型)。

## 協定細節

客戶端連上來會看到什麼，以及兩個協定世代差在哪裡，都寫在這一節。這裡不需要你做任何決定，是給直接用 SDK 驅動這個 server 的人看的。

**客戶端連上時看到什麼。**這個 server 兩個協定世代都服務，拿到哪一個由客戶端的第一個請求決定，不是這裡的任何設定。以 `initialize` 開場的客戶端走交握世代；第一個請求在 `_meta` 裡帶 `io.modelcontextprotocol/protocolVersion` 的客戶端走 2026-07-28 無狀態世代，完全沒有交握。這條分流在 SDK 的 `serve_dual_era_loop` 裡，這個專案沒有設定它。

write 開關全都不設時，一次 `initialize` 加 `tools/list` 回的是：

```
protocol_version: 2025-11-25
server_info:      name='mcp-server-malcolm' version='1.2.1'
capabilities:     prompts, resources (subscribe=false), tools — all list_changed=false
instructions:     3753 characters
tools:            51
prompts:          1  — hunt_workflow
resources:        2  — malcolm://fields/malcolm, malcolm://fields/arkime
```

2025-11-25 是交握世代的天花板，不是這個 server 的天花板：`initialize` 在 2026-07-28 根本不存在，所以透過它量測只可能量到比較舊的那個數字。2026-07-28 的客戶端不送交握，改呼叫 `server/discover`：

```
server/discover  capabilities: prompts, resources (subscribe=true), tools — all listChanged=true
                 cacheScope=private  ttlMs=0  resultType=complete
tools/list       51 個工具，cacheScope=public ttlMs=3600000 resultType=complete
結果的 _meta     io.modelcontextprotocol/serverInfo = {name: mcp-server-malcolm, version: 1.2.1}
```

兩個世代對 `listChanged` 的說法不一致，而說多了的是新世代那邊：SDK 在那裡宣告 `listChanged=true`，但這個 server 在 `create_server()` 裡一次註冊完所有東西，從不送變更通知。這不會出事，因為不會變的清單也就無所謂沒有通知，但別把程式建立在那個承諾上。

Arkime 那個 resource 會送出 Arkime 整份 expression 欄位目錄，文字量有好幾百 KB。要拿 SDK 寫腳本的人有一個地方要留意：`mcp` 2.x 用的是 snake_case 屬性（`protocol_version`、`server_info`、`is_error`），不是 wire protocol 和 1.x SDK 的 camelCase。照 `serverInfo`/`isError` 寫的腳本會拋 `AttributeError`。
