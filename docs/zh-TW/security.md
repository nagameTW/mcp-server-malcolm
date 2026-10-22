# 安全

## 預設唯讀，需要時再開

不做任何設定時，這個 server 只提供讀取工具。它就是個唯讀客戶端，做的任何事都不會動到 Malcolm 裡的資料。

write 存取分成五個 class，各自有一個環境變數開關，預設全關。沒開的 class 不會被註冊，所以它的工具不會出現在 `list_tools()`，也叫不到。啟動時 server 會印出哪些 class 是開的：

```
[mcp-server-malcolm] write classes: alerting=off arkime-tag=off hunt-job=off pcap-upload=off arkime-view=off
```

除了一個例外，每個 write 都是「新增」性質：例外是 `arkime_cancel_hunt`，它停掉的是進行中的 hunt 工作，不是新增內容。沒有任何工具會刪資料、移除 tag、或動到使用者帳號——這些是刻意不做的（見 [不做的事](../../README.zh-TW.md#不做的事)）。

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
{"ts": "2023-11-15T09:41:07Z", "tool": "arkime_add_tags", "class": "arkime-tag", "target": "ids=240601-abc", "params": {"tags": "suspicious"}, "outcome": "ok"}
```

`outcome` 是 `ok`、`http_4xx`、`http_5xx`、或 `error:<type>` 其中之一。過長的參數值會被截斷，PCAP bytes 永遠不進 log。sink 預設是 stderr；設 `MALCOLM_MCP_AUDIT_FILE` 就改成 append 到檔案。讀取工具不稽核。
