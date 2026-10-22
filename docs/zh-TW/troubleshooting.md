# 疑難排解

## 第一次呼叫失敗時

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

先看主機名稱，再懷疑密碼。你的 Malcolm 明明在別台，401 卻來自 `https://localhost`，代表 `MALCOLM_URL` 和 `MALCOLM_BASE_URL` 都沒進到 server 的環境變數裡。它退回預設值，問錯了機器。

**主機連不上**（`MALCOLM_URL` 打錯、連接埠被防火牆擋掉、scheme 錯了）：

```
Error executing tool malcolm_ping: ConnectTimeout for https://192.0.2.99:9999/mapi/ping
```

連不上有兩種，訊息不一樣。連接埠明確拒絕連線時是 `All connection attempts failed`；主機根本不回應時拋的是 `ConnectTimeout`，而 httpx 讓它的 `str()` 是空字串——1.0.1 以前這會變成一句光禿禿的 `Error executing tool malcolm_ping: `，冒號後面什麼都沒有。現在會補上例外名稱和目標。`MALCOLM_URL` 裡若嵌了憑證，顯示前會先被剝掉。
