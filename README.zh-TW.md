<div align="center">
  <h1>Malcolm MCP Server</h1>
  <p>
    <a href="https://github.com/nagameTW/mcp-server-malcolm/actions/workflows/ci.yml"><img src="https://github.com/nagameTW/mcp-server-malcolm/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="https://pypi.org/project/mcp-server-malcolm/"><img src="https://img.shields.io/pypi/v/mcp-server-malcolm" alt="PyPI"></a>
    <a href="https://pypi.org/project/mcp-server-malcolm/"><img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+"></a>
    <a href="./LICENSE"><img src="https://img.shields.io/github/license/nagameTW/mcp-server-malcolm?style=flat-square&logo=opensourceinitiative&logoColor=white&color=3DA639" alt="License"></a>
    <a href="https://glama.ai/mcp/servers/nagameTW/mcp-server-malcolm"><img src="https://glama.ai/mcp/servers/nagameTW/mcp-server-malcolm/badges/score.svg" alt="Glama score"></a>
  </p>
  <p><a href="README.md">English</a> | <a href="README.zh-TW.md">繁體中文</a></p>
</div>

Malcolm MCP Server 讓 AI agent 查詢 [Malcolm](https://malcolm.fyi) 裡的流量。伺服器使用 Malcolm 實際採用的欄位名稱與 filter 語法，agent 不必自行猜測。Claude Code、Claude Desktop、Cursor 等 MCP 客戶端都能使用。

以下是範例問題，以及回答這些問題的工具：

- 「列出過去 24 小時跟 192.0.2.15 有關的 Suricata 告警，順便查這個 IP 是 NetBox 裡哪台裝置。」使用 `malcolm_alerts` 與 `malcolm_netbox_lookup`。
- 「過去一小時，各協定的 top talker 是誰？」使用 `malcolm_aggregate`。
- 「列出 Zeek 從昨天的流量裡切出來的執行檔，附上 hash。」使用 `malcolm_file_scans`。
- 「上傳這個 PCAP，再到已存的封包裡 hunt 這個字串。」使用 `malcolm_upload_pcap` 與 `arkime_create_hunt`。這兩個是 write 工具，預設關閉。

[錄影示範](docs/zh-TW/usage.md#示範)呈現 agent 回答 Modbus 告警問題的過程。

## 需求

- Python 3.11 或更新版本。
- 一個可用 API 的 Malcolm，並能以 HTTPS 連線。
- 一個 MCP 客戶端。

## 快速開始

**1. 安裝伺服器。**接著在 stdin 關閉的狀態下啟動，他會印出 write class 的狀態，並以代碼 0 結束。

```bash
pip install mcp-server-malcolm
mcp-server-malcolm < /dev/null
# [mcp-server-malcolm] write classes: alerting=off arkime-tag=off hunt-job=off pcap-upload=off arkime-view=off
```

**2. 註冊到 Claude Code。**把值換成實際的設定。

```bash
claude mcp add malcolm \
  -e MALCOLM_URL=https://malcolm.example \
  -e MALCOLM_USERNAME=analyst \
  -e MALCOLM_PASSWORD='your-password' \
  -e MALCOLM_SSL_VERIFY=/path/to/malcolm-ca.crt \
  -- mcp-server-malcolm
```

`--` 之後是啟動指令，每個 `-e` 為他設定一個環境變數。密碼若寫在這行指令裡，會留在 shell 歷史。避免的方式見[安裝頁](docs/zh-TW/install.md)，該頁也說明其他 MCP 客戶端與其他安裝方式。

**3. 確認連線。**請 agent 呼叫 `malcolm_ping`。若呼叫失敗，閱讀[疑難排解](docs/zh-TW/troubleshooting.md)。最常見的原因是自簽憑證。

## 連線設定

| 變數 | 預設值 | 說明 |
| --- | --- | --- |
| `MALCOLM_URL` | `https://localhost` | Malcolm 的 base URL |
| `MALCOLM_USERNAME` | `admin` | Basic auth 帳號 |
| `MALCOLM_PASSWORD` | `admin` | Basic auth 密碼 |
| `MALCOLM_SSL_VERIFY` | `true` | `true`、`false`，或 CA bundle 的路徑 |

Malcolm 預設使用自簽憑證。連線到遠端的 Malcolm 時，把 `MALCOLM_SSL_VERIFY` 指向 CA bundle。憑證必須帶有符合主機名稱的 `subjectAltName`。只有在隔離的實驗環境才使用 `false`。所有變數列在[設定頁](docs/zh-TW/configuration.md)。

## 預設唯讀

啟用 write class 之前，伺服器只註冊讀取工具。關閉的 class 不會註冊，他的工具也不會出現在 `tools/list`。

| Class | 旗標 | 工具 |
| --- | --- | --- |
| alerting | `MALCOLM_MCP_ENABLE_ALERTING` | `malcolm_create_alert` |
| arkime-tag | `MALCOLM_MCP_ENABLE_ARKIME_TAGS` | `arkime_add_tags` |
| hunt-job | `MALCOLM_MCP_ENABLE_HUNT_JOBS` | `arkime_create_hunt`、`arkime_cancel_hunt` |
| pcap-upload | `MALCOLM_MCP_ENABLE_PCAP_UPLOAD` | `malcolm_upload_pcap` |
| arkime-view | `MALCOLM_MCP_ENABLE_ARKIME_VIEWS` | `arkime_create_view`、`arkime_create_shortcut` |

旗標的值為 `true` 時才算開啟。每次 write 嘗試都會寫一行稽核紀錄，輸出到 stderr，或寫入 `MALCOLM_MCP_AUDIT_FILE` 指定的檔案。安全模型見[安全頁](docs/zh-TW/security.md)。

## 工具

伺服器有 51 個讀取工具，涵蓋 Malcolm filter 查詢、聚合、欄位查找、Arkime 的 session 與封包、NetBox、Zeek 檔案掃描、儲存物件與告警 monitor。完整清單在[工具頁](docs/zh-TW/tools.md)。

工具 schema 每個 session 約占 34,000 個 token。要節省 token，把 `MALCOLM_MCP_DISABLE_READ_GROUPS` 設為用不到的群組。例如 `netbox,dashboards,detections,arkime-inventory` 會留下 34 個工具。見[精簡讀取工具](docs/zh-TW/tools.md#精簡讀取工具)。

## 不做的事

第 1 版刻意不做以下項目：

- 破壞性的寫入（Arkime session 刪除、移除 tag、使用者管理）。
- 原生 OpenSearch 寫入或原生 NetBox CRUD 的轉送，不論有沒有旗標。
- `streamable-http` 傳輸（只支援 stdio）。

## 專案結構

```
├── src/mcp_server_malcolm/    # 伺服器
│   ├── server.py              #   註冊工具，套用 write 閘門
│   ├── client.py              #   Malcolm 的 HTTP 客戶端
│   ├── config.py              #   Write class 旗標
│   ├── audit.py               #   稽核輸出
│   └── tools/                 #   讀取工具。write 工具在 write/
├── tests/                     # 測試
├── scripts/
│   └── api_parity_check.py    # 比對每個工具與 Malcolm API
├── docs/
│   ├── install.md             #   安裝、註冊、其他安裝方式
│   ├── container.md           #   在容器裡執行
│   ├── configuration.md       #   連線設定、所有變數
│   ├── troubleshooting.md     #   第一次呼叫失敗
│   ├── tools.md               #   讀取工具、write 工具、精簡
│   ├── security.md            #   安全模型、稽核
│   ├── usage.md               #   示範、filter 語法、範例
│   ├── python.md              #   在 Python 直接使用
│   ├── design.md              #   為什麼要有 MCP 這一層、協定細節
│   ├── verification.md        #   一致性檢查、測試平台、API 端點
│   └── zh-TW/                 #   本 README 連結的中文頁面
├── Dockerfile                 # 容器映像
├── server.json                # MCP Registry manifest
├── SECURITY.md                # 回報漏洞
├── CONTRIBUTING.md            # 貢獻方式
└── CHANGELOG.md               # 各版本變更
```

## 開發

```bash
pip install -e . pytest pytest-asyncio ruff
ruff check src tests
ruff format --check src tests
pytest
```

測試不需要 Malcolm。見 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 授權

[MIT](LICENSE)
