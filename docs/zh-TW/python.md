# 在 Python 直接使用

## Python（直接 import）

`MalcolmClient` 可以單獨拿來用：不需要 MCP 客戶端、不需要 server 行程，迴圈裡也沒有 `mcp` 那一層傳輸。`mcp_server_malcolm` 的 `__all__` 是 `["MalcolmClient", "__version__"]`，而這一個 class 帶著 62 個 public method，涵蓋整個讀取面。下面這些呼叫是用 1.2.1 版，對 Malcolm 公開的 training instance（`training.malcolm.fyi`，Malcolm 26.09.0）實際跑出來的。

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
            time_from="1614556800",
            time_to="1614643200",
        )

        # 查詢回空的時候，先確認欄位名稱對不對，再決定信不信這個結果
        ok = await client.resolve_field("http.useragent")
        bad = await client.resolve_field("http.user_agent")

        # Arkime expression 語法，時間窗是 epoch 秒
        sessions = await client.arkime_sessions(
            expression="protocols==dns",
            limit=3,
            time_from="1614556800",
            time_to="1614643200",
        )
    finally:
        await client.close()

asyncio.run(main())
```

這些呼叫實際回來的東西：

```
search()     keys: ['filter', 'range', 'results']
aggregate()  {'destination.port': {'buckets': [{'doc_count': 12733, 'key': 389},
                                               {'doc_count': 6361, 'key': 53},
                                               {'doc_count': 4768, 'key': 80}, …]}}
resolve_field('http.useragent')   {'exists': True,  'field': 'http.useragent', 'type': 'string'}
resolve_field('http.user_agent')  {'exists': False, 'field': 'http.user_agent',
                                   'suggestion': 'http.useragent', 'type': 'string'}
arkime_sessions()  recordsTotal: 7718258  recordsFiltered: 6711
                   first session id: 3@21w08:21w08-QwZ9QRb977tLU5XWt-WTaQ0B
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

最後那一筆，就是 [第一次呼叫失敗時](troubleshooting.md#第一次呼叫失敗時) 講的那個空錯誤訊息在函式庫這一側的樣子：`str(exc)` 是空字串。追下去發現它已經不在這個專案的程式碼裡，而是 `httpx.ConnectTimeout.__str__()`——對同一台主機，改用裸的 `httpx.AsyncClient` 呼叫也一樣是空的。要偵測主機連不上，就判斷 `exc.status is None`；訊息不會告訴你任何事。

**流量上限是用等的，不是拋錯。**`MALCOLM_MAX_CONCURRENCY`（預設 8）和 `MALCOLM_MAX_REQUESTS_PER_MINUTE`（預設 600）同時也是建構子參數 `max_concurrency` 與 `max_requests_per_minute`。把 `max_requests_per_minute=2`，對 Malcolm 公開的 training instance 連續呼叫三次 `ping()`，完成時間是：

```
request 1  t+1.6s
request 2  t+1.8s
request 3  t+61.1s
```

DEBUG log 上會出現 `[malcolm] rate cap reached, holding https://…/mapi/ping for 58.5s`。沒有對應的 rate-limit exception：超過上限之後，一次呼叫跟一次很慢的呼叫分不出來，所以每次呼叫的 timeout 只要設得比這個窗短，就會打在其實只是在排隊的請求上。60 秒這個窗本身是模組常數（`_RATE_WINDOW_SECONDS`），不能設定——能設定的只有窗內的請求數。建構子參數給非正數會直接被擋下來：

```
ValueError: max_concurrency must be a positive integer, got 0
ValueError: max_requests_per_minute must be a positive integer, got 0
```

環境變數這條路刻意寬鬆一些：值不存在、空白或解析不出來，都會記一筆 log 然後換成預設值（`client.py:68-82`），所以部署環境的 env 檔打錯字不會把限流器關掉。

**函式庫使用者沒有任何受支援的 write 路徑。**七個 write primitive 全部是 private——`_write_event`、`_write_arkime_tags`、`_write_arkime_view`、`_write_arkime_shortcut`、`_write_arkime_hunt`、`_write_arkime_hunt_cancel`、`_write_upload_pcap`——每一個都只從 `tools/write/` 底下的唯一一處被呼叫，並且有 seam test 盯著。沒有任何 public method 能寫入告警、幫 session 加 tag、建立或取消 hunt、存下 view 或 shortcut、上傳 PCAP。直接呼叫底線開頭的 method 確實會把那個變更做出去，但會跳過 `tools/write/_common.py::run_write` 在每一次經過 MCP 層的 write 外圈寫下的稽核記錄；所以 write 屬於 tool 這一層，直接 import 這條路是一個讀取用的 client。
