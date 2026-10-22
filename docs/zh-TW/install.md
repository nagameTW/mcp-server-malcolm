# 安裝與註冊

你不需要寫任何程式碼。MCP 客戶端（Claude Code、Claude Desktop、Cursor 等）會把這個 server 當子行程啟動，用 stdio 跟它溝通；你要做的只是告訴客戶端怎麼啟動它、以及要注入哪些憑證。

這次改版照印出來的樣子跑過哪些指令、在什麼平台上跑，列在[這些文件在哪裡測過](verification.md#這些文件在哪裡測過)。從那些執行引用的錯誤訊息一律原文照抄。

## 1. 安裝

你需要 Python 3.11 以上、一台開放 API 存取的 Malcolm，以及一條連得到它的 HTTPS 網路。

```bash
pip install mcp-server-malcolm      # published release
```

把 stdin 關掉直接啟動 server，就能確認裝好了。它會印出 write class 橫幅、讀到 EOF、以 0 結束：

```bash
$ mcp-server-malcolm < /dev/null
[mcp-server-malcolm] write classes: alerting=off arkime-tag=off hunt-job=off pcap-upload=off arkime-view=off
$ echo $?
0
```

行程要啟動不需要先設定任何東西。連線設定在啟動時就讀進來，但要等到有工具去呼叫 Malcolm 才會用上，所以 URL 或密碼寫錯是以工具呼叫失敗的形式浮現，不是啟動失敗。

## 2. 註冊到你的客戶端

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

那行指令裡的密碼是字面值，所以它會進 shell history；而 `claude mcp add` 執行的那幾秒，主機上其他行程都能從 `ps` 讀到它。先把密碼讀進環境變數，改傳變數進去：

```bash
read -rs MALCOLM_PASSWORD && export MALCOLM_PASSWORD
claude mcp add malcolm \
  -e MALCOLM_URL=https://malcolm.example \
  -e MALCOLM_USERNAME=analyst \
  -e MALCOLM_PASSWORD="$MALCOLM_PASSWORD" \
  -- mcp-server-malcolm
```

`read -rs` 讓輸入不顯示在畫面上，history 存下來的是還沒展開的 `"$MALCOLM_PASSWORD"`，不是密碼本身。`add` 執行當下的那個 `ps` 窗口關不掉，就像 `docker inspect` 讀得到容器裡那份一樣。不管走哪一條路，密碼最後都會以明文寫進 `~/.claude.json`（在檢查的這台機器上權限是 0600），在那裡保護它的就只有檔案權限。

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

## 其他安裝方式

`pip install mcp-server-malcolm` 和不帶參數的 `uvx mcp-server-malcolm` 裝到的是最新的已發布 release。光看版號沒辦法判斷手上的 checkout 跟它是不是同一份——帶著未發布變更的樹，回報的仍然是上一次發版的版號——所以要拿到這份文件寫的這棵樹，就從原始碼裝。

從 checkout 裝：

```bash
git clone https://github.com/nagameTW/mcp-server-malcolm.git
cd mcp-server-malcolm
pip install -e .
```

或者建一個 wheel、裝進乾淨的 virtualenv，這一頁的指令都是走這條路驗證的：

```bash
$ uv build --out-dir /tmp/mcp-malcolm-deploy/dist
Successfully built /tmp/mcp-malcolm-deploy/dist/mcp_server_malcolm-1.2.1.tar.gz
Successfully built /tmp/mcp-malcolm-deploy/dist/mcp_server_malcolm-1.2.1-py3-none-any.whl

$ python3 -m venv /tmp/mcp-malcolm-deploy/venv
$ /tmp/mcp-malcolm-deploy/venv/bin/pip install \
    /tmp/mcp-malcolm-deploy/dist/mcp_server_malcolm-1.2.1-py3-none-any.whl
```

這會拉進 32 個套件，多數來自 `mcp>=2,<3`（1.2.1 發布時解析到 `mcp 2.2.0`）。wheel 本身是 `py3-none-any`，純 Python。在 macOS 26/arm64、Python 3.14.6 上，需要編譯的那幾個相依套件（`cryptography`、`pydantic-core`、`rpds-py`、`cffi`）全部裝預先建好的 `macosx_11_0_arm64` wheel，沒有任何東西是從原始碼編的。PyPI 也有發 Linux arm64 與 x86_64 的預建 wheel，但這些文件沒有在 Linux 或 x86_64 上實際裝過，請當作未驗證。

不想把這個 branch 永久裝到哪裡去，就把 `uvx` 或 `pipx` 指到 checkout：

```bash
uvx --from /path/to/mcp-server-malcolm mcp-server-malcolm
pipx run --spec /path/to/mcp-server-malcolm mcp-server-malcolm
```

## 手動執行

只在除錯時有用。stdio MCP server 沒有互動介面：從終端機啟動它會安靜地停在那裡等 stdin 上的 JSON-RPC，這就是正常運作的樣子。它啟動時會把已開啟的 write class 印到 stderr，所以這可以確認開關有生效。兩個進入點的行為完全一樣：

```bash
$ mcp-server-malcolm
[mcp-server-malcolm] write classes: alerting=off arkime-tag=off hunt-job=off pcap-upload=off arkime-view=off

$ python -m mcp_server_malcolm
[mcp-server-malcolm] write classes: alerting=off arkime-tag=off hunt-job=off pcap-upload=off arkime-view=off
```
