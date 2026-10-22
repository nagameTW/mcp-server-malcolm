# 用法

## 示範

<details>
<summary>Claude Code 實際操作錄影</summary>

![Claude Code 透過 mcp-server-malcolm 回答 Modbus 告警問題](../demo.gif)

未剪輯的 Claude Code 實際操作，連的是 Malcolm 官方公開的 training instance（training.malcolm.fyi）：呼叫兩次 `malcolm_aggregate`，接著給出答案。錄影時開了 `--verbose`，所以每次工具呼叫都看得到；預設模式會把它們收成一行「Calling malcolm」。

</details>

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

### 搜尋某個名稱的 DNS 查詢

```
malcolm_search(
  filters='{"event.dataset": "dns", "zeek.dns.query": "wpad.localdomain"}',
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

哪個參數要哪一欄，是逐個參數決定的，不是逐個工具：

- **`exp`**（`ip.src`、`port.dst`、`protocols`）——每一個 `expression` 參數，加上 `arkime_unique`、`arkime_multiunique`、`arkime_spigraphhierarchy` 的欄位清單。這三個直接拒收 db 名稱：`srcIp,dstIp` 從 multiunique 拿到的是 HTTP 200 但內容為「Unknown expression srcIp」，從 spigraphhierarchy 拿到的是 HTTP 403 配同樣的內容。
- **`db`**（`srcIp`、`dstPort`、`node`）——`arkime_connections` 的 `src_field` 和 `dst_field`，就這樣，沒有別的地方。在那裡 `srcIp`/`dstIp` 回了一張圖；`ip.src`/`dstIp` 回 HTTP 403，`srcIp`/`port.dst` 回 HTTP 500。
- **儲存路徑**——`arkime_spigraph` 的 `field` 和 `arkime_spiview` 的 `spi` 吃的是這個。大多數欄位的儲存路徑跟 db 那一欄是同一個字串；少數幾個印出來的是 camelCase 的 db 別名、實際存放用的卻是點分名稱（`srcIp` 是 `source.ip`，`dstPort` 是 `destination.port`，`totBytes` 是 `network.bytes`），而這兩個參數要的是點分的那個。

凡是吃 exp 那一欄的地方，也都接受點分的儲存路徑：`destination.port` 回的不重複值跟 `port.dst` 一樣，而 `dstPort` 一個都不回。它是唯一一個在每條路上都答得出來的寫法。

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
