# 設定

## 連線設定

底下的預設值就是 `MalcolmClient.from_env` 讀到的（`client.py:327-355`）。

| 變數 | 預設值 | 說明 |
| --- | --- | --- |
| `MALCOLM_URL` | `https://localhost` | Malcolm base URL，例如 `https://malcolm.example`。沒設時會先讀 `MALCOLM_BASE_URL` 再退回預設值 |
| `MALCOLM_USERNAME` | `admin` | Basic auth 使用者名稱 |
| `MALCOLM_PASSWORD` | `admin` | Basic auth 密碼 |
| `MALCOLM_SSL_VERIFY` | `true` | `true`、`false`、或 CA bundle 的路徑（只要不是 `true`/`false`，就當成 CA 路徑交給 httpx） |
| `MALCOLM_TIMEOUT` | `30` | HTTP timeout 秒數 |
| `MALCOLM_MAX_CONCURRENCY` | `8` | 同時對上游發出的請求數 |
| `MALCOLM_MAX_REQUESTS_PER_MINUTE` | `600` | 上游請求速率上限 |

這些預設值是從程式碼讀出來的（`client.py:340-350`）：三個連線變數都沒設時，server 會拿 `admin`/`admin` 去連 `https://localhost`。30 秒的 timeout 同樣是讀原始碼得來的，沒有實際計時。

關於 TLS：驗證預設開啟，而 Malcolm 出廠是自簽憑證。把 `MALCOLM_SSL_VERIFY` 指向 Malcolm 的 CA bundle，只有在 Malcolm 的 server 憑證帶有對應你連線主機名的 `subjectAltName` 時才有用 — Malcolm 自己的 setup 產出的憑證沒有 SAN 擴充欄位，所以就算 CA 指對了驗證還是會失敗。遠端的 Malcolm 請換上 SAN 正確的憑證。`MALCOLM_SSL_VERIFY="false"` 是完全關閉驗證，只有隔離的 localhost 實驗環境能接受；走網路的話，憑證和查詢結果都會經過未經驗證的通道。

## 設定參考

| 環境變數 | 預設值 | 說明 |
|----------|--------|------|
| `MALCOLM_URL` | `https://localhost` | Malcolm 基礎 URL。沒設時會先讀 `MALCOLM_BASE_URL`，再退回預設值 |
| `MALCOLM_USERNAME` | `admin` | Basic auth 使用者名稱 |
| `MALCOLM_PASSWORD` | `admin` | Basic auth 密碼 |
| `MALCOLM_SSL_VERIFY` | `true` | 是否驗證 TLS 憑證。`true`/`false`，或填 CA-bundle 路徑（自簽 Malcolm 請填路徑） |
| `MALCOLM_TIMEOUT` | `30` | HTTP 請求逾時（秒） |
| `MALCOLM_MAX_CONCURRENCY` | `8` | 同時對上游發出的請求數 |
| `MALCOLM_MAX_REQUESTS_PER_MINUTE` | `600` | 每個滾動 60 秒窗內允許的上游請求數；超過上限的請求是被壓著等，不是被拒絕 |
| `MALCOLM_MCP_DISABLE_READ_GROUPS` | 未設定 | 以逗號分隔、不要註冊的讀取 group；名稱不存在會讓啟動失敗。見[精簡讀取工具](tools.md#精簡讀取工具) |
| `MALCOLM_MCP_DISABLE_TOOLS` | 未設定 | 以逗號分隔、在 group 之後才拿掉的讀取工具；名稱不是已註冊的讀取工具會讓啟動失敗。見[精簡讀取工具](tools.md#精簡讀取工具) |
| `MALCOLM_MCP_ENABLE_ALERTING` | `false` | 開啟 alerting write class |
| `MALCOLM_MCP_ENABLE_ARKIME_TAGS` | `false` | 開啟 session 加 tag（只加不減） |
| `MALCOLM_MCP_ENABLE_HUNT_JOBS` | `false` | 開啟 Arkime hunt 建立 + 狀態查詢 |
| `MALCOLM_MCP_ENABLE_PCAP_UPLOAD` | `false` | 開啟 PCAP 上傳（另需 `MALCOLM_MCP_UPLOAD_DIR`） |
| `MALCOLM_MCP_ENABLE_ARKIME_VIEWS` | `false` | 開啟 saved-view + shortcut（值清單）建立 |
| `MALCOLM_MCP_UPLOAD_DIR` | 未設 | 允許上傳的檔案必須位於這個 staging 目錄內；未設 ⇒ 拒絕上傳 |
| `MALCOLM_MCP_AUDIT_FILE` | 未設 | write 稽核檔（未設時走 stderr） |
