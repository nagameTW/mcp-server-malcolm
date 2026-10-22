# 在容器裡執行

## 在容器裡執行

這個 repository 附了一份 `Dockerfile`，它從 build context 裝好套件，並以非 root 使用者執行：

```bash
$ docker build -t mcp-server-malcolm:local -f Dockerfile .
$ docker run --rm --entrypoint id mcp-server-malcolm:local
uid=10001(app) gid=10001(app) groups=10001(app)
```

image 建在 `python:3.11-slim`（Debian 13 trixie）上。它是單一架構的：普通的 `docker build` 只會產出建置主機本身的架構，所以在 arm64 上建的 image，沒有模擬層的話在 x86_64 主機上跑不起來。多架構 image 得用 `docker buildx build --platform linux/amd64,linux/arm64`；這個沒試過，而且這份 Dockerfile 本身不會產出多架構 image。

把客戶端的啟動指令指向 `docker run -i --rm …`：

```bash
docker run -i --rm --network host \
  -e MALCOLM_URL -e MALCOLM_USERNAME -e MALCOLM_PASSWORD -e MALCOLM_SSL_VERIFY \
  mcp-server-malcolm:local
```

`-e VAR` 後面不接 `=value`，就是從呼叫它的 shell 繼承值，所以密碼不會成為指令字串的一部分，也不會落進 `ps` 輸出或 shell history。但它事後還是能透過 `docker inspect` 讀出來，見下。

容器怎麼連到 Malcolm，決定了整件事跑不跑得起來：

| 怎麼連到 Malcolm | 參數 | 結果 |
| --- | --- | --- |
| 主機 loopback，URL 不動 | `--network host` | 可以。容器裡的 `https://localhost` 就是主機的 loopback。 |
| bridge 網路 | 無 | 失敗：`All connection attempts failed`。`localhost` 指的是容器自己。底層的 errno 111 留在例外鏈裡，不會傳到 client。 |
| bridge 網路 | `--add-host=host.docker.internal:host-gateway`、`MALCOLM_URL=https://host.docker.internal` | 可以。Linux 上的 `host.docker.internal` 不像 Docker Desktop 那樣會自動註冊，是那個明寫的 `--add-host` 讓它解得出來（Docker 20.10+）。 |

兩種能通的模式都完成了一次完整的 MCP session：`initialize`、回傳 51 個工具的 `tools/list`，以及兩次工具呼叫（`malcolm_ping` → `pong`，以及 `count`）。`MALCOLM_SSL_VERIFY` 留在預設的 `true` 時，在容器裡失敗的理由跟在容器外一樣，都是自簽憑證。

關於帳密：`docker inspect <container> --format '{{json .Config.Env}}'` 會把 `MALCOLM_PASSWORD` 以明文印出來，而且不管值是用 `-e VAR`、`-e VAR=value` 還是 `--env-file` 傳進去的都一樣——不管哪一種，Docker 都把解析後的環境存進容器的 metadata。只要那個容器物件還在，任何拿得到 Docker daemon 或 socket 的人就能把 Malcolm 密碼讀回去。沒有 `MALCOLM_PASSWORD_FILE` 那種讀 secrets 檔的輸入方式；`client.py:324` 只讀環境變數，別無其他。讓容器保持用完即丟（`--rm`、一個客戶端 session 一個容器，這本來就是 stdio server 隱含的模型）能縮短這個窗口，但關不掉它。

`MALCOLM_MCP_ENABLE_PCAP_UPLOAD` 是唯一需要 bind mount 的功能，因為 `malcolm_upload_pcap` 要讀的檔案必須已經位於 `MALCOLM_MCP_UPLOAD_DIR` 內。掛到那裡的主機目錄，得讓容器內的 uid 10001 讀得到。這一條是從 `tools/write/pcap_upload.py` 讀出來的，沒有實測——整個測試過程 write class 都是關著的。
